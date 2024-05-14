const { expect } = require("chai");
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const ECDSA = require('ecdsa-secp256r1');
const { secp256r1 } = require('@noble/curves/p256');
const curve_utils = require('@noble/curves/abstract/utils');

const SAPPHIRE_LOCALNET = 23293;
const ACCOUNT_ABI = [
  'function signEIP155((uint64 nonce,uint256 gasPrice,uint64 gasLimit,address to,uint256 value,bytes data,uint256 chainId)) view returns (bytes)',
  'function sign(bytes32 digest) view returns ((bytes32 r,bytes32 s,uint256 v))',
];

describe("AccountManager", function() {
  let WA, SALT, HELPER, owner, account1, account2, gaspayingAddress;

  const GASLESS_TYPE_CREATE_ACCOUNT = 0;
  const GASLESS_TYPE_CREDENTIAL_ADD = 1;
  const GASLESS_TYPE_CREDENTIAL_ADD_PASSWORD = 2;
  const GASLESS_TYPE_CREDENTIAL_REMOVE = 3;
  const GASLESS_TYPE_CREDENTIAL_REMOVE_PASSWORD = 4;

  const SIMPLE_PASSWORD = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const WRONG_PASSWORD  = "0x0000000000000000000000000000000000000000000000000000009999999999";

  const RANDOM_STRING  = "0x000000000000000000000000000000000000000000000000000000000000DEAD";

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  beforeEach(async () => {
    [ owner, account1, account2 ] = await ethers.getSigners();

    const helpFactory = await hre.ethers.getContractFactory("TestHelper");
    HELPER = await helpFactory.deploy();
    await HELPER.waitForDeployment();

    const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
    const curveLibrary = await curveFactory.deploy();
    await curveLibrary.waitForDeployment();

    const contractFactory = await ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
    WA = await contractFactory.deploy();
    await WA.waitForDeployment();

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

    const signedTx = await WA.generateGaslessTx(
      gaslessData,
      nonce,
      gasPrice,
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

    // Now try with no-ones PK
    const keyPair = generateNewKeypair();

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

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
      expect(e.shortMessage).to.equal('execution reverted: "getUserFromHashedCredentialId"');
    }
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
      }
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey)" ], 
      [ data ]
    );

    // Try with wrong password
    try {
      const digest_wrong = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [WRONG_PASSWORD, encoded_data],
      );

      const tx_wrong = await WA.addCredentialPassword(
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

    const tx = await WA.addCredentialPassword(
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

  // it("Add additional credential with credential", async function() {
  //   const username = hashedUsername("testuser");
  //   const credentialId = abiCoder.encode([ "uint256" ], [ 123456 ]);
  //   await createAccount(username, SIMPLE_PASSWORD, credentialId);

  //   const credentialIdNew = abiCoder.encode([ "uint256" ], [ 222222 ]);
  //   privateKey = ECDSA.generateKey();
  //   decoded_x = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.x, 0))[0];
  //   decoded_y = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.y, 0))[0];

  //   const data = {
  //     hashedUsername: username,
  //     credentialId: credentialIdNew,
  //     pubkey: {
  //       kty: 2, // Elliptic Curve format
  //       alg: -7, // ES256 algorithm
  //       crv: 1, // P-256 curve
  //       x: decoded_x,
  //       y: decoded_y,
  //     }
  //   };

  //   const encoded_data = abiCoder.encode(
  //     [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey)" ], 
  //     [ data ]
  //   );

  //   const personalization = await WA.personalization();

  //   const message = { text: 'hello' };
  //   const signature = privateKey.sign(JSON.stringify(message));
  //   console.log(signature);

  //   const buffer = Buffer.from(signature, 'base64');
  //   const bufString = '0x' + buffer.toString('hex');
    
  //   console.log(bufString);

  //   const r = bufString.slice(0, 66);
  //   const s = '0x' + bufString.slice(66, 130);
  //   const v = '0x' + bufString.slice(130, 132);

  //   console.log(r);
  //   console.log(s);
  //   console.log(v);

  //   // // Try with wrong password
  //   // try {
  //   //   const digest_wrong = ethers.solidityPackedKeccak256(
  //   //     ['bytes32', 'bytes'],
  //   //     [WRONG_PASSWORD, encoded_data],
  //   //   );

  //   //   const tx_wrong = await WA.addCredentialPassword(
  //   //     {
  //   //       digest: digest_wrong,
  //   //       data: encoded_data
  //   //     }
  //   //   );
  //   //   await tx_wrong.wait();
  //   // } catch(e) {
  //   //   expect(e.shortMessage).to.equal("transaction execution reverted");
  //   // }

  //   // // Now try with correct password
  //   // const digest = ethers.solidityPackedKeccak256(
  //   //   ['bytes32', 'bytes'],
  //   //   [SIMPLE_PASSWORD, encoded_data],
  //   // );

  //   // const tx = await WA.addCredentialPassword(
  //   //   {
  //   //     digest,
  //   //     data: encoded_data
  //   //   }
  //   // );
  //   // await tx.wait();
    
  //   // const credList = await WA.credentialIdsByUsername(username);
  //   // expect(credList.length).to.equal(2);
  //   // expect(credList[0]).to.equal(credentialId);
  //   // expect(credList[1]).to.equal(credentialIdNew);
  // });

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
      }
    };

    const credentialDataEncoded = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey)" ], 
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
          txType: GASLESS_TYPE_CREDENTIAL_ADD_PASSWORD
        } 
      ]
    ); 

    const signedTx = await WA.generateGaslessTx(
      gaslessData,
      nonce,
      gasPrice,
    );

    const txHash = await owner.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);
    
    const credList = await WA.credentialIdsByUsername(username);
    expect(credList.length).to.equal(2);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);
    expect(credList[1]).to.equal(keyPair.credentialId);
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
      gasLimit: 1000000,
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