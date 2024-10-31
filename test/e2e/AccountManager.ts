const { expect } = require("chai");
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const { secp256r1 } = require('@noble/curves/p256');
const curve_utils = require('@noble/curves/abstract/utils');

const SAPPHIRE_LOCALNET = 23293;
const GAS_LIMIT = 1000000;
const ACCOUNT_ABI = [
  'function signEIP155((uint64 nonce,uint256 gasPrice,uint64 gasLimit,address to,uint256 value,bytes data,uint256 chainId)) view returns (bytes)',
  'function sign(bytes32 digest) view returns ((bytes32 r,bytes32 s,uint256 v))',
  'function exportPrivateKey() view returns (bytes32)',
];

describe("AccountManager", function() {
  let WA, SALT, HELPER, owner, account1, account2, signer, gaspayingAddress;

  const GASLESS_TYPE_CREATE_ACCOUNT = 0;
  const GASLESS_TYPE_MANAGE_CREDENTIAL = 1;
  const GASLESS_TYPE_MANAGE_CREDENTIAL_PASSWORD = 2;

  const CREDENTIAL_ACTION_ADD = 0;
  const CREDENTIAL_ACTION_REMOVE = 1;

  const SIMPLE_PASSWORD = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const WRONG_PASSWORD  = "0x0000000000000000000000000000000000000000000000000000009999999999";

  const platform = "google";
  const socialId = "googleUniqueId123";
  const email = "user@example.com";

  const RANDOM_STRING  = "0x000000000000000000000000000000000000000000000000000000000000DEAD";

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  beforeEach(async () => {
    [ owner, account1, account2, signer ] = await ethers.getSigners();
    
    const helpFactory = await hre.ethers.getContractFactory("TestHelper");
    HELPER = await helpFactory.deploy();
    await HELPER.waitForDeployment();

    const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
    const curveLibrary = await curveFactory.deploy();
    await curveLibrary.waitForDeployment();

    const accountFactoryFactory = await hre.ethers.getContractFactory("AccountFactory");
    const accountFactory = await accountFactoryFactory.deploy();
    await accountFactory.waitForDeployment();

    const contractFactory = await ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
    const proxyFactory = await ethers.getContractFactory('AccountManagerProxy');
  
    const impl = await contractFactory.deploy();
    await impl.waitForDeployment();
    const WAProxy = await proxyFactory.deploy(
      await impl.getAddress(),
      contractFactory.interface.encodeFunctionData('initialize', [await accountFactory.getAddress(), signer.address]),
    );
    await WAProxy.waitForDeployment();

    WA = await ethers.getContractAt("AccountManager", await WAProxy.getAddress(), owner);

    gaspayingAddress = await WA.gaspayingAddress();
    await owner.sendTransaction({
      to: gaspayingAddress,
      value: ethers.parseEther("1.0"), // Sends exactly 1.0 ether to gaspaying address
    });

    SALT = ethers.toBeArray(await WA.salt());
  });

  it("Sign random string with new account", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('sign', [RANDOM_STRING]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, in_digest, in_data
    );

    const [sigRes] = iface.decodeFunctionResult('sign', resp).toArray();

    const recoveredAddress = ethers.recoverAddress(RANDOM_STRING, {r: sigRes[0], s: sigRes[1], v: sigRes[2]});
    expect(recoveredAddress).to.equal(accountData.publicKey);
  });

  it("Export PK of new account", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('exportPrivateKey', []);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    const unlockedWallet = new hre.ethers.Wallet(exportedPrivateKey);
    expect(unlockedWallet.address).to.equal(accountData.publicKey);
  });

  it("Register + preventing duplicates", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const credList = await WA.credentialIdsByUsername(username);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);

    // Try creating another user with same username
    try {
      await createAccount(username, SIMPLE_PASSWORD);
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }
  });

  it("Verify gasless signature", async function() {
    const gasPrice = (await owner.provider.getFeeData()).gasPrice;

    const username = hashedUsername("testuser");
    const keyPair = generateNewKeypair();

    let registerData = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      optionalPassword: SIMPLE_PASSWORD
    };

    let funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, bytes32 optionalPassword)" ], 
      [ registerData ]
    ); 

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_CREATE_ACCOUNT
        } 
      ]
    ); 

    const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;

    const dataHash = ethers.solidityPackedKeccak256(
      ['uint256', 'uint64', 'uint256', 'bytes32'],
      [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(gaslessData)],
    );
    
    const signature = await signer.signMessage(ethers.getBytes(dataHash));

    const resp = await WA.validateSignature(
      gasPrice,
      GAS_LIMIT,
      timestamp,
      ethers.keccak256(gaslessData),
      signature
    );

    expect(resp[0]).to.equal(dataHash);
    expect(resp[1]).to.equal(true);
  });

  it("Gasless register", async function() {
    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const username = hashedUsername("testuser");
    const keyPair = generateNewKeypair();

    let registerData = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      optionalPassword: SIMPLE_PASSWORD
    };

    let funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, bytes32 optionalPassword)" ], 
      [ registerData ]
    ); 

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_CREATE_ACCOUNT
        } 
      ]
    ); 

    const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;
    const dataHash = ethers.solidityPackedKeccak256(
      ['uint256', 'uint64', 'uint256', 'bytes32'],
      [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(gaslessData)],
    );
    const signature = await signer.signMessage(ethers.getBytes(dataHash));

    const signedTx = await WA.generateGaslessTx(
      gaslessData,
      nonce,
      gasPrice,
      GAS_LIMIT,
      timestamp,
      signature
    );

    const txHash = await owner.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);
    
    expect(await WA.userExists(username)).to.equal(true);

    const credList = await WA.credentialIdsByUsername(username);
    expect(credList[0]).to.equal(keyPair.credentialId);
  });

  it("proxyView with password", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    // Create raw transaction
    const txRequest = {
      to: account1.address,
      data: '0x',
      gasLimit: 1000000,
      value: ethers.parseEther("0.005"),
      nonce: 0,
      chainId: SAPPHIRE_LOCALNET,
      gasPrice: 100000000000, // 100 gwei
    };
    
    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('signEIP155', [txRequest]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, in_digest, in_data
    );

    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("proxyView with credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    const signedTx = await generateSignedTxWithCredential(
      accountData.publicKey, 
      accountData.credentials[0].credentialId,
      accountData.credentials[0].privateKey, 
      {
        to: account1.address,
        data: '0x',
        value: ethers.parseEther("0.005"),
      }
    );

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("proxyView FAIL with wrong credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const usernameHacker = hashedUsername("hacker");
    const accountDataHacker = await createAccount(usernameHacker, SIMPLE_PASSWORD);

    // Now try with no-ones PK
    const keyPair = generateNewKeypair();

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    let shortMessage = "";
    try {
      await generateSignedTxWithCredential(
        accountData.publicKey, 
        keyPair.credentialId,
        keyPair.privateKey, 
        {
          to: account1.address,
          data: '0x',
          value: ethers.parseEther("0.005"),
        }
      );
    } catch(e) {
      shortMessage = e.shortMessage;
    }
    expect(shortMessage).to.equal('execution reverted: "getCredentialAndUser"');

    shortMessage = "";
    try {
      await generateSignedTxWithCredential(
        accountData.publicKey, 
        accountData.credentials[0].credentialId,
        accountDataHacker.credentials[0].privateKey, 
        {
          to: account1.address,
          data: '0x',
          value: ethers.parseEther("0.005"),
        }
      );
    } catch(e) {
      shortMessage = e.shortMessage;
    }
    expect(shortMessage).to.equal('execution reverted: "verification failed"');
  });

  it("Add additional credential with password + try proxyView with new credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    
    const keyPair = generateNewKeypair();

    const data = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    // Try with wrong password
    try {
      const digest_wrong = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [WRONG_PASSWORD, encoded_data],
      );

      const tx_wrong = await WA.manageCredentialPassword(
        {
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }

    // Now try with correct password
    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    const tx = await WA.manageCredentialPassword(
      {
        digest,
        data: encoded_data
      }
    );
    await tx.wait();
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);

    // Now try proxyView with new credential

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    const signedTx = await generateSignedTxWithCredential(
      accountData.publicKey, 
      keyPair.credentialId,
      keyPair.privateKey, 
      {
        to: account1.address,
        data: '0x',
        value: ethers.parseEther("0.005"),
      }
    );

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("Add additional credential with credential + try proxyView with new credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    
    const keyPair = generateNewKeypair();

    const data = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(accountData.credentials[0].credentialId);

    // Create & encode challange
    const challange = await HELPER.createChallengeBase64(encoded_data, personalization);

    const authenticatorData = "0x";
    const clientDataTokens = [
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'challenge',
        v: challange
      },
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'type',
        v: 'webauthn.get'
      }
    ];

    let digest = await HELPER.createDigest(authenticatorData, clientDataTokens);
    digest = digest.replace("0x", "");

    const signature = secp256r1.sign(digest, accountData.credentials[0].privateKey);

    const in_resp = {
      authenticatorData,
      clientDataTokens,
      sigR: signature.r,
      sigS: signature.s,
    }

    const tx = await WA.manageCredential(
      {
        credentialIdHashed: credentialIdHashed,
        resp: in_resp,
        data: encoded_data
      }
    );
    await tx.wait();
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);

    // Now try proxyView with new credential

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    const signedTx = await generateSignedTxWithCredential(
      accountData.publicKey, 
      keyPair.credentialId,
      keyPair.privateKey, 
      {
        to: account1.address,
        data: '0x',
        value: ethers.parseEther("0.005"),
      }
    );

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("Gasless add credential to existing account with password", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const keyPair = generateNewKeypair();

    const credentialData = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    const credentialDataEncoded = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ credentialData ]
    );

    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, credentialDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 digest, bytes data)" ], 
      [ { digest, data: credentialDataEncoded } ]
    );

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_MANAGE_CREDENTIAL_PASSWORD
        } 
      ]
    ); 

    const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;
    const dataHash = ethers.solidityPackedKeccak256(
      ['uint256', 'uint64', 'uint256', 'bytes32'],
      [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(gaslessData)],
    );
    const signature = await signer.signMessage(ethers.getBytes(dataHash));

    const signedTx = await WA.generateGaslessTx(
      gaslessData,
      nonce,
      gasPrice,
      GAS_LIMIT,
      timestamp,
      signature
    );

    const txHash = await owner.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);
  });

  it("Remove credential with password + try proxyView with old credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    let shortMessage = '';
    
    const keyPair = generateNewKeypair();

    const data = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    let encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    // Try with wrong password
    try {
      const digest_wrong = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [WRONG_PASSWORD, encoded_data],
      );

      const tx_wrong = await WA.manageCredentialPassword(
        {
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }

    // Now try with correct password
    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        digest,
        data: encoded_data
      }
    );
    await tx.wait();
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);

    // Now try proxyView with new credential

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    const signedTx = await generateSignedTxWithCredential(
      accountData.publicKey, 
      keyPair.credentialId,
      keyPair.privateKey, 
      {
        to: account1.address,
        data: '0x',
        value: ethers.parseEther("0.005"),
      }
    );

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));

    // Remove default credential (added with registration)
    data.credentialId = accountData.credentials[0].credentialId;
    data.pubkey.x = accountData.credentials[0].decoded_x;
    data.pubkey.y = accountData.credentials[0].decoded_y;
    data.action = CREDENTIAL_ACTION_REMOVE;

    encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    // Now try with correct password
    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    const tx_remove = await WA.manageCredentialPassword(
      {
        digest,
        data: encoded_data
      }
    );
    await tx_remove.wait();

    const credListAfterRemoval = await WA.credentialIdsByUsername(username);
    expect(credListAfterRemoval.length).to.equal(1);
    expect(credListAfterRemoval[0]).to.equal(keyPair.credentialId);

    // Try with removed credential
    shortMessage = '';
    try {
      await generateSignedTxWithCredential(
        accountData.publicKey, 
        accountData.credentials[0].credentialId,
        accountData.credentials[0].privateKey, 
        {
          to: account1.address,
          data: '0x',
          value: ethers.parseEther("0.005"),
        }
      );
    } catch(e) {
      shortMessage = e.shortMessage;
    }
    expect(shortMessage).to.equal('execution reverted: "getCredentialAndUser"');

    // Try to remove last credential
    shortMessage = '';
    try {
      // Remove default credential (added with registration)
      data.credentialId = keyPair.credentialId;
      data.pubkey.x = keyPair.decoded_x;
      data.pubkey.y = keyPair.decoded_y;

      encoded_data = abiCoder.encode(
        [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
        [ data ]
      );

      // Now try with correct password
      digest = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [SIMPLE_PASSWORD, encoded_data],
      );

      tx = await WA.manageCredentialPassword(
        {
          digest,
          data: encoded_data
        }
      );

      await tx.wait();
    } catch(e) {
      shortMessage = e.shortMessage;
    }
    expect(shortMessage).to.equal('transaction execution reverted');
  });

  it("Remove credential with credential + try proxyView with old credential", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    let shortMessage = '';
    
    const keyPair = generateNewKeypair();

    const data = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    let encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    // Try with wrong password
    try {
      const digest_wrong = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [WRONG_PASSWORD, encoded_data],
      );

      const tx_wrong = await WA.manageCredentialPassword(
        {
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }

    // Now try with correct password
    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        digest,
        data: encoded_data
      }
    );
    await tx.wait();
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);

    // Now try proxyView with new credential

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await hre.ethers.provider.getBalance(account1.address);

    const signedTx = await generateSignedTxWithCredential(
      accountData.publicKey, 
      keyPair.credentialId,
      keyPair.privateKey, 
      {
        to: account1.address,
        data: '0x',
        value: ethers.parseEther("0.005"),
      }
    );

    // Broadcast transaction
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await hre.ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));

    // Remove default credential (added with registration)
    data.credentialId = accountData.credentials[0].credentialId;
    data.pubkey.x = accountData.credentials[0].decoded_x;
    data.pubkey.y = accountData.credentials[0].decoded_y;
    data.action = CREDENTIAL_ACTION_REMOVE;

    encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(accountData.credentials[0].credentialId);

    // Create & encode challange
    const challange = await HELPER.createChallengeBase64(encoded_data, personalization);

    const authenticatorData = "0x";
    const clientDataTokens = [
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'challenge',
        v: challange
      },
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'type',
        v: 'webauthn.get'
      }
    ];

    digest = await HELPER.createDigest(authenticatorData, clientDataTokens);
    digest = digest.replace("0x", "");

    const signature = secp256r1.sign(digest, accountData.credentials[0].privateKey);

    const in_resp = {
      authenticatorData,
      clientDataTokens,
      sigR: signature.r,
      sigS: signature.s,
    }

    const tx_remove = await WA.manageCredential(
      {
        credentialIdHashed: credentialIdHashed,
        resp: in_resp,
        data: encoded_data
      }
    );
    await tx_remove.wait();

    const credListAfterRemoval = await WA.credentialIdsByUsername(username);
    expect(credListAfterRemoval.length).to.equal(1);
    expect(credListAfterRemoval[0]).to.equal(keyPair.credentialId);

    // Try with removed credential
    shortMessage = '';
    try {
      await generateSignedTxWithCredential(
        accountData.publicKey, 
        accountData.credentials[0].credentialId,
        accountData.credentials[0].privateKey, 
        {
          to: account1.address,
          data: '0x',
          value: ethers.parseEther("0.005"),
        }
      );
    } catch(e) {
      shortMessage = e.shortMessage;
    }
    expect(shortMessage).to.equal('execution reverted: "getCredentialAndUser"');
  });

  it("Gasless remove credential from existing account with password", async function() {
    const username = hashedUsername("testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Firstly add additional credential
    const keyPair = generateNewKeypair();

    const data = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      action: CREDENTIAL_ACTION_ADD
    };

    let encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        digest,
        data: encoded_data
      }
    );
    await tx.wait();
    
    let credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const credentialData = {
      hashedUsername: username,
      credentialId: accountData.credentials[0].credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: accountData.credentials[0].decoded_x,
        y: accountData.credentials[0].decoded_y,
      },
      action: CREDENTIAL_ACTION_REMOVE
    };

    const credentialDataEncoded = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ credentialData ]
    );

    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, credentialDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 digest, bytes data)" ], 
      [ { digest, data: credentialDataEncoded } ]
    );

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_MANAGE_CREDENTIAL_PASSWORD
        } 
      ]
    ); 

    const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;
    const dataHash = ethers.solidityPackedKeccak256(
      ['uint256', 'uint64', 'uint256', 'bytes32'],
      [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(gaslessData)],
    );
    const signature = await signer.signMessage(ethers.getBytes(dataHash));

    const signedTx = await WA.generateGaslessTx(
      gaslessData,
      nonce,
      gasPrice,
      GAS_LIMIT,
      timestamp,
      signature
    );

    const txHash = await owner.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);
    
    credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(1);
    expect(credList[0]).to.equal(keyPair.credentialId);
  });

  it("Should add, verify and remove email authentication successfully", async function () {
    const usernamePlain = "plain_user";
    const emailToAdd = "plainuser@example.com";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add email
    const addEmailTx = await WA.addEmail(userData.hashedUsername, emailToAdd);
    await addEmailTx.wait();
  
    // Check email added
    const userAfterAddEmail = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterAddEmail.emailCredential.emailHash).to.equal(
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes(emailToAdd))
    );
    expect(userAfterAddEmail.emailCredential.verified).to.equal(false);
  
    // Generate signature for verification
    const message = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(
        "verify-email" +
          ethers.utils.hexlify(userData.hashedUsername) +
          emailToAdd
      )
    );
    const signature = await signer.signMessage(ethers.utils.arrayify(message));
  
    // Verify email
    const verifyEmailTx = await WA.verifyEmail(
      userData.hashedUsername,
      emailToAdd,
      signature
    );
    await verifyEmailTx.wait();
  
    // Check email verified
    const userAfterVerifyEmail = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterVerifyEmail.emailCredential.verified).to.equal(true);
  
    // Remove email
    const removeEmailTx = await WA.removeEmail(userData.hashedUsername);
    await removeEmailTx.wait();
  
    // Check email removed
    const userAfterRemoveEmail = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterRemoveEmail.emailCredential.emailHash).to.equal(
      ethers.constants.HashZero
    );
    expect(userAfterRemoveEmail.emailCredential.verified).to.equal(false);
  });
  
  it("Should add, verify and remove social recovery successfully", async function () {
    const usernamePlain = "social_user";
    const platform = "twitter";
    const socialId = "twitter_unique_id_123";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add social recovery
    const addSocialTx = await WA.addSocial(
      userData.hashedUsername,
      platform,
      socialId
    );
    await addSocialTx.wait();
  
    // Check social recovery added
    const userAfterAddSocial = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterAddSocial.socialCredentials.length).to.equal(1);
    expect(userAfterAddSocial.socialCredentials[0].platformHash).to.equal(
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes(platform))
    );
    expect(userAfterAddSocial.socialCredentials[0].socialIdHash).to.equal(
      ethers.utils.keccak256(ethers.utils.toUtf8Bytes(socialId))
    );
    expect(userAfterAddSocial.socialCredentials[0].verified).to.equal(false);
  
    // Generate signature for verification
    const message = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(
        "verify-social" +
          ethers.utils.hexlify(userData.hashedUsername) +
          platform +
          socialId
      )
    );
    const signature = await signer.signMessage(ethers.utils.arrayify(message));
  
    // Verify social recovery
    const verifySocialTx = await WA.verifySocial(
      userData.hashedUsername,
      platform,
      socialId,
      signature
    );
    await verifySocialTx.wait();
  
    // Check social recovery verified
    const userAfterVerifySocial = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterVerifySocial.socialCredentials[0].verified).to.equal(true);
  
    // Remove social recovery
    const removeSocialTx = await WA.removeSocial(
      userData.hashedUsername,
      platform,
      socialId
    );
    await removeSocialTx.wait();
  
    // Check social recovery removed
    const userAfterRemoveSocial = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterRemoveSocial.socialCredentials.length).to.equal(0);
  });

  it("Should restrict email and social recovery management to admins only", async function () {
    const usernamePlain = "adminuser";
    const emailToAdd = "adminuser@example.com";
    const platform = "linkedin";
    const socialId = "linkedin_id_123";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Get a non-admin signer (account2)
    const accountManagerNonAdmin = WA.connect(account2);
  
    // Attempt to add email as non-admin
    await expect(
      accountManagerNonAdmin.addEmail(userData.hashedUsername, emailToAdd)
    ).to.be.revertedWith(
      `AccessControl: account ${await account2.getAddress()} is missing role ${ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("DEFAULT_ADMIN_ROLE")
      )}`
    );
  
    // Attempt to remove email as non-admin
    await expect(
      accountManagerNonAdmin.removeEmail(userData.hashedUsername)
    ).to.be.revertedWith(
      `AccessControl: account ${await account2.getAddress()} is missing role ${ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("DEFAULT_ADMIN_ROLE")
      )}`
    );
  
    // Attempt to add social recovery as non-admin
    await expect(
      accountManagerNonAdmin.addSocial(
        userData.hashedUsername,
        platform,
        socialId
      )
    ).to.be.revertedWith(
      `AccessControl: account ${await account2.getAddress()} is missing role ${ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("DEFAULT_ADMIN_ROLE")
      )}`
    );
  
    // Attempt to remove social recovery as non-admin
    await expect(
      accountManagerNonAdmin.removeSocial(
        userData.hashedUsername,
        platform,
        socialId
      )
    ).to.be.revertedWith(
      `AccessControl: account ${await account2.getAddress()} is missing role ${ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes("DEFAULT_ADMIN_ROLE")
      )}`
    );
  });
  
  it("Should fail to verify email with invalid signature", async function () {
    const usernamePlain = "invalidsiguser";
    const emailToAdd = "invalidsig@example.com";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add email
    const addEmailTx = await WA.addEmail(userData.hashedUsername, emailToAdd);
    await addEmailTx.wait();
  
    // Generate invalid signature (wrong signer)
    const message = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(
        "verify-email" +
          ethers.utils.hexlify(userData.hashedUsername) +
          emailToAdd
      )
    );
    const signature = await owner.signMessage(ethers.utils.arrayify(message)); // 'owner' is not the designated 'signer'
  
    // Attempt to verify email with invalid signature
    await expect(
      WA.verifyEmail(userData.hashedUsername, emailToAdd, signature)
    ).to.be.revertedWith("verifyEmail: invalid signature");
  });
  
  it("Should prevent adding duplicate email", async function () {
    const usernamePlain = "duplicateemailuser";
    const emailToAdd = "duplicate@example.com";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add email first time
    const addEmailTx = await WA.addEmail(userData.hashedUsername, emailToAdd);
    await addEmailTx.wait();
  
    // Attempt to add the same email again
    await expect(
      WA.addEmail(userData.hashedUsername, emailToAdd)
    ).to.be.revertedWith("addEmail: email already exists");
  });
  
  it("Should ensure email is marked as verified after successful verification", async function () {
    const usernamePlain = "verifystatususer";
    const emailToAdd = "verifystatus@example.com";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add email
    const addEmailTx = await WA.addEmail(userData.hashedUsername, emailToAdd);
    await addEmailTx.wait();
  
    // Verify email
    const message = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(
        "verify-email" +
          ethers.utils.hexlify(userData.hashedUsername) +
          emailToAdd
      )
    );
    const signature = await signer.signMessage(ethers.utils.arrayify(message));
  
    const verifyEmailTx = await WA.verifyEmail(
      userData.hashedUsername,
      emailToAdd,
      signature
    );
    await verifyEmailTx.wait();
  
    // Check verification status
    const userAfterVerifyEmail = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterVerifyEmail.emailCredential.verified).to.equal(true);
  });
  
  it("Should ensure social recovery is marked as verified after successful verification", async function () {
    const usernamePlain = "verifysocialstatususer";
    const platform = "instagram";
    const socialId = "instagramUniqueId678";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Add social recovery
    const addSocialTx = await WA.addSocial(
      userData.hashedUsername,
      platform,
      socialId
    );
    await addSocialTx.wait();
  
    // Verify social recovery
    const message = ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(
        "verify-social" +
          ethers.utils.hexlify(userData.hashedUsername) +
          platform +
          socialId
      )
    );
    const signature = await signer.signMessage(ethers.utils.arrayify(message));
  
    const verifySocialTx = await WA.verifySocial(
      userData.hashedUsername,
      platform,
      socialId,
      signature
    );
    await verifySocialTx.wait();
  
    // Check verification status
    const userAfterVerifySocial = await WA.getAccount(
      ethers.utils.hexlify(userData.hashedUsername)
    );
    expect(userAfterVerifySocial.socialCredentials[0].verified).to.equal(true);
  });

  it("Should prevent removing a non-existent email", async function () {
    const usernamePlain = "nonexistentemailuser";
    const emailToRemove = "nonexistent@example.com";

    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);

    // Attempt to remove a non-existent email
    await expect(WA.removeEmail(userData.hashedUsername)).to.be.revertedWith(
      "removeEmail: email does not exist"
    );
  });

  it("Should prevent removing a non-existent social recovery method", async function () {
    const usernamePlain = "nonexistentsocialuser";
    const platform = "reddit";
    const socialId = "reddit_unique_id_123";
  
    // Create user
    const userData = await createAccount(usernamePlain, SIMPLE_PASSWORD);
  
    // Attempt to remove a non-existent social recovery method
    await expect(
      WA.removeSocial(userData.hashedUsername, platform, socialId)
    ).to.be.revertedWith("removeSocial: social credential not found");
  });
  
  it("Sign random string with new account", async function () {
    const username = hashedUsername("testuser");
    const accountData = await createAccount("testuser", SIMPLE_PASSWORD);
  
    expect(await WA.userExists(username)).to.equal(true);
  
    const iface = new ethers.utils.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData("sign", [RANDOM_STRING]);
  
    const in_digest = ethers.utils.solidityPackedKeccak256(
      ["bytes32", "bytes"],
      [SIMPLE_PASSWORD, in_data]
    );
  
    const resp = await WA.proxyViewPassword(username, in_digest, in_data);
  
    const [sigRes] = iface.decodeFunctionResult("sign", resp);
  
    const recoveredAddress = ethers.utils.recoverAddress(RANDOM_STRING, {
      r: sigRes.r,
      s: sigRes.s,
      v: sigRes.v,
    });
    expect(recoveredAddress).to.equal(accountData.publicKey);
  });

  function hashedUsername (username) {
    return pbkdf2Sync(username, SALT, 100_000, 32, 'sha256');
  }

  async function createAccount(username, password) {
    const keyPair = generateNewKeypair();

    let registerData = {
      hashedUsername: username,
      credentialId: keyPair.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair.decoded_x,
        y: keyPair.decoded_y,
      },
      optionalPassword: password
    };

    const tx = await WA.createAccount(registerData);
    await tx.wait();

    const userData = await WA.getAccount(username);

    return {
      ...registerData,
      publicKey: userData[1],
      credentials: [
        keyPair
      ]
    }
  }

  async function generateSignedTxWithCredential(senderAddress, credentialId, credentialPK, req) {
    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(credentialId);

    // Create raw transaction
    const txRequest = {
      to: req.to,
      data: req.data,
      gasLimit: GAS_LIMIT,
      value: req.value,
      nonce: await owner.provider.getTransactionCount(senderAddress),
      chainId: SAPPHIRE_LOCALNET,
      gasPrice: 100000000000, // 100 gwei
    };
    
    const iface = new ethers.Interface(ACCOUNT_ABI);
    const in_data = iface.encodeFunctionData('signEIP155', [txRequest]);

    // Create & encode challange
    const challange = await HELPER.createChallengeBase64(in_data, personalization);

    const authenticatorData = "0x";
    const clientDataTokens = [
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'challenge',
        v: challange
      },
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'type',
        v: 'webauthn.get'
      }
    ];

    let digest = await HELPER.createDigest(authenticatorData, clientDataTokens);
    digest = digest.replace("0x", "");

    const signature = secp256r1.sign(digest, credentialPK);

    const in_resp = {
      authenticatorData,
      clientDataTokens,
      sigR: signature.r,
      sigS: signature.s,
    }

    const resp = await WA.proxyView(
      credentialIdHashed, in_resp, in_data
    );

    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    return signedTx;
  }

  function generateNewKeypair() {
    const privateKey = secp256r1.utils.randomPrivateKey();
    const pubKey = secp256r1.getPublicKey(privateKey, false);
    const pubKeyString = "0x" + curve_utils.bytesToHex(pubKey);
    const credentialId = abiCoder.encode([ "string" ], [ pubKeyString ]);

    const coordsString = pubKeyString.slice(4, pubKeyString.length); // removes 0x04
    const decoded_x = BigInt('0x' + coordsString.slice(0, 64)); // x is the first half
    const decoded_y = BigInt('0x' + coordsString.slice(64, coordsString.length)); // y is the second half

    return {
      credentialId,
      privateKey,
      decoded_x,
      decoded_y,
    }
  }

  async function waitForTx(txHash) {
    while(true) {
      const tx = await owner.provider.getTransactionReceipt(txHash);
      if (tx) {
        break;
      }
      await new Promise(f => setTimeout(f, 500));
    }
    return;
  }
  
});