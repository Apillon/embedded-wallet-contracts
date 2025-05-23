const { expect } = require("chai");
const { ethers } = require("hardhat");
const { secp256r1 } = require('@noble/curves/p256');
const { u8aToHex } = require('@polkadot/util');
const { sr25519PairFromSeed } = require('@polkadot/util-crypto');

const { 
  SAPPHIRE_LOCALNET, 
  GAS_LIMIT,
  ACCOUNT_EVM_ABI,
  GASLESS_TYPE_CREATE_ACCOUNT,
  GASLESS_TYPE_MANAGE_CREDENTIAL_PASSWORD,
  GASLESS_TYPE_ADD_WALLET_PASSWORD,
  GASLESS_TYPE_REMOVE_WALLET_PASSWORD,
  WALLET_TYPE_EVM,
  WALLET_TYPE_SUBSTRATE
} = require('./utils/constants');

const { 
  hashedUsername,
  generateNewKeypair 
} = require('./utils/helpers');

describe("AccountManager", function() {
  let WA: any, SALT: any, HELPER: any, owner: any, account1: any, account2: any, signer: any, gaspayingAddress: any ;

  const CREDENTIAL_ACTION_ADD = 0;
  const CREDENTIAL_ACTION_REMOVE = 1;

  const SHORT_PASSWORD = ethers.encodeBytes32String("test");
  const SIMPLE_PASSWORD = ethers.encodeBytes32String("testtest12");
  const WRONG_PASSWORD = ethers.encodeBytes32String("testtest13");

  const RANDOM_STRING  = "0x000000000000000000000000000000000000000000000000000000000000DEAD";

  const BYTES32_ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

  const WALLET_IDX_0 = 0;
  const WALLET_IDX_1 = 1;

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  beforeEach(async () => {
    [ owner, account1, account2, signer ] = await ethers.getSigners();
    
    const helpFactory = await ethers.getContractFactory("TestHelper");
    HELPER = await helpFactory.deploy();
    await HELPER.waitForDeployment();

    const curveFactory = await ethers.getContractFactory("SECP256R1Precompile");
    const curveLibrary = await curveFactory.deploy();
    await curveLibrary.waitForDeployment();

    const accountFactoryFactory = await ethers.getContractFactory("AccountFactory");
    const accountFactoryProxyFactory = await ethers.getContractFactory("AccountFactoryProxy");
    const accountFactoryImpl = await accountFactoryFactory.deploy();
    await accountFactoryImpl.waitForDeployment();

    const AFProxy = await accountFactoryProxyFactory.deploy(
      await accountFactoryImpl.getAddress(),
      accountFactoryFactory.interface.encodeFunctionData('initialize', []),
    );
    await AFProxy.waitForDeployment();

    const contractFactory = await ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
    const proxyFactory = await ethers.getContractFactory('AccountManagerProxy');
  
    const impl = await contractFactory.deploy();
    await impl.waitForDeployment();
    const WAProxy = await proxyFactory.deploy(
      await impl.getAddress(),
      contractFactory.interface.encodeFunctionData('initialize', [await AFProxy.getAddress(), signer.address]),
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

  it.skip("Test gas used when creating accounts with different password lengths", async function() {
    const username1 = hashedUsername(SALT, "testuser1");
    const username2 = hashedUsername(SALT, "testuser2");

    const keyPair1 = generateNewKeypair();
    const keyPair2 = generateNewKeypair();

    const password1 = SIMPLE_PASSWORD;
    const password2 = ethers.encodeBytes32String("testtest12testtest12");
 
    let registerData1 = {
      hashedUsername: username1,
      credentialId: keyPair1.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair1.decoded_x,
        y: keyPair1.decoded_y,
      },
      optionalPassword: password1,
      wallet: {
        walletType: WALLET_TYPE_EVM,
        keypairSecret: BYTES32_ZERO // create new wallet
      }
    };

    let registerData2 = {
      hashedUsername: username2,
      credentialId: keyPair2.credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: keyPair2.decoded_x,
        y: keyPair2.decoded_y,
      },
      optionalPassword: password2,
      wallet: {
        walletType: WALLET_TYPE_EVM,
        keypairSecret: BYTES32_ZERO // create new wallet
      }
    };

    const tx1 = await WA.createAccount(registerData1);
    const res1 = await tx1.wait();

    const tx2 = await WA.createAccount(registerData2);
    const res2 = await tx2.wait();

    console.log("gasUsed: ", res1.gasUsed);
    console.log("gasUsed: ", res2.gasUsed);
    console.log("gasUsed: ", res2.gasUsed - res1.gasUsed);

    expect(await WA.userExists(username1)).to.equal(true);
    expect(await WA.userExists(username2)).to.equal(true);
    expect(res1.gasUsed).to.equal(res2.gasUsed);
  });

  it("Should fail if password is too short", async function() {
    const username = hashedUsername(SALT, "testuser");
    try {
      await createAccount(username, SHORT_PASSWORD);
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }

    expect(await WA.userExists(username)).to.equal(false);
  });

  it("Sign random string with new account", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const in_data = iface.encodeFunctionData('sign', [WALLET_IDX_0, RANDOM_STRING]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, in_data
    );

    const [sigRes] = iface.decodeFunctionResult('sign', resp).toArray();

    const recoveredAddress = ethers.recoverAddress(RANDOM_STRING, {r: sigRes[0], s: sigRes[1], v: sigRes[2]});
    expect(recoveredAddress).to.equal(accountData.publicKey);
  });

  it("Export PK of new account", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now  
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_0, deadline]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    const unlockedWallet = new ethers.Wallet(exportedPrivateKey);
    expect(unlockedWallet.address).to.equal(accountData.publicKey);
  });

  it("Fail to export PK of new account with expired deadline", async function() {
    const username = hashedUsername(SALT, "testuser");
    await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const deadline = Math.ceil(new Date().getTime() / 1000) - 3600; // 1 hour before now  
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_0, deadline]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    try {
      await WA.proxyViewPassword(
        username, WALLET_TYPE_EVM, in_digest, in_data
      );
    } catch(e: any) {
      expect(e.toString()).to.have.string("execution reverted: Invalid deadline");
    }
  });

  it("Import PK EVM, import PK Substrate", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    // new EVM wallet
    // new EVM wallet
    // new EVM wallet
    const newWallet = ethers.Wallet.createRandom();
    let data = {
      walletType: WALLET_TYPE_EVM,
      keypairSecret: newWallet.privateKey
    };

    let encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // new SUBSTRATE wallet
    // new SUBSTRATE wallet
    // new SUBSTRATE wallet
    const newSubstratePK = ethers.Wallet.createRandom().privateKey;
    const newSubstrateWallet = sr25519PairFromSeed(newSubstratePK);
    data = {
      walletType: WALLET_TYPE_SUBSTRATE,
      keypairSecret: newSubstratePK
    };

    encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // Check if wallet correctly imported EVM
    const accountWalletsEVM = await getAccountWallets(username, WALLET_TYPE_EVM);
    expect(accountWalletsEVM.length).to.equal(2);
    expect(accountWalletsEVM[0]).to.equal(accountData.publicKey);
    expect(accountWalletsEVM[1]).to.equal(newWallet.address);

    // Check if wallet correctly imported SUBSTRATE
    const accountWalletsSUBSTRATE = await getAccountWallets(username, WALLET_TYPE_SUBSTRATE);
    expect(accountWalletsSUBSTRATE.length).to.equal(1);
    expect(accountWalletsSUBSTRATE[0]).to.equal(u8aToHex(newSubstrateWallet.publicKey));

    // Try to export, imported wallet
    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now  
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_1, deadline]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    expect(exportedPrivateKey).to.equal(newWallet.privateKey);
  });

  // Cannot remove wallet via the wallets private key anymore
  // it("Remove wallet", async function() {
  //   const username = hashedUsername(SALT, "testuser");
  //   const accountData = await createAccount(username, SIMPLE_PASSWORD);

  //   const newWallet = ethers.Wallet.createRandom();

  //   const data = {
  //     walletType: WALLET_TYPE_EVM,
  //     keypairSecret: newWallet.privateKey
  //   };

  //   const encoded_data = abiCoder.encode(
  //     [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
  //     [ data ]
  //   );

  //   let digest = ethers.solidityPackedKeccak256(
  //     ['bytes32', 'bytes'],
  //     [SIMPLE_PASSWORD, encoded_data],
  //   );

  //   let tx = await WA.addWalletPassword(
  //     {
  //       hashedUsername: username,
  //       digest,
  //       data: encoded_data
  //     }
  //   );
  //   await tx.wait();

  //   // Check if wallet correctly imported
  //   let accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);

  //   expect(accountWallets.length).to.equal(2);

  //   const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);

  //   const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
  //   let in_inner_data = iface.encodeFunctionData('removeWallet', [WALLET_IDX_1]);;

  //   // Remove second wallet
  //   let txRequest = {
  //     to: accountAddress,
  //     data: in_inner_data,
  //     gasLimit: 1000000,
  //     value: 0,
  //     nonce: 0,
  //     chainId: SAPPHIRE_LOCALNET,
  //     gasPrice: 100000000000, // 100 gwei
  //   };

  //   let in_data = iface.encodeFunctionData('signEIP155', [WALLET_IDX_0, txRequest]);

  //   let in_digest = ethers.solidityPackedKeccak256(
  //     ['bytes32', 'bytes'],
  //     [SIMPLE_PASSWORD, in_data],
  //   );

  //   let resp = await WA.proxyViewPassword(
  //     username, WALLET_TYPE_EVM, in_digest, in_data
  //   );

  //   let [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

  //   // Broadcast transaction
  //   const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
  //   const receipt = await waitForTx(txHash);
  //   console.log(receipt);

  //   // Check if wallet correctly imported
  //   accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);

  //   expect(accountWallets.length).to.equal(2);
  //   expect(accountWallets[1]).to.equal(ethers.ZeroAddress);

  //   // Try removing already removed address
  //   // Try removing already removed address
  //   // Try removing already removed address
  //   txRequest.nonce += 1;

  //   in_data = iface.encodeFunctionData('signEIP155', [WALLET_IDX_0, txRequest]);

  //   in_digest = ethers.solidityPackedKeccak256(
  //     ['bytes32', 'bytes'],
  //     [SIMPLE_PASSWORD, in_data],
  //   );

  //   resp = await WA.proxyViewPassword(
  //     username, WALLET_TYPE_EVM, in_digest, in_data
  //   );

  //   [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

  //   const txHashDupl = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
  //   const receiptDupl = await waitForTx(txHashDupl);

  //   // The status of a transaction is 1 is successful or 0 if it was reverted. 
  //   expect(receiptDupl.status).to.equal(0);

  //   // Try performing transaction with removed account (remove wallet 0)
  //   // Try performing transaction with removed account (remove wallet 0)
  //   // Try performing transaction with removed account (remove wallet 0)
  //   in_inner_data = iface.encodeFunctionData('removeWallet', [WALLET_IDX_0]);;

  //   // Remove second wallet
  //   txRequest = {
  //     to: accountAddress,
  //     data: in_inner_data,
  //     gasLimit: 1000000,
  //     value: 0,
  //     nonce: 0,
  //     chainId: SAPPHIRE_LOCALNET,
  //     gasPrice: 100000000000, // 100 gwei
  //   };

  //   in_data = iface.encodeFunctionData('signEIP155', [WALLET_IDX_1, txRequest]);

  //   in_digest = ethers.solidityPackedKeccak256(
  //     ['bytes32', 'bytes'],
  //     [SIMPLE_PASSWORD, in_data],
  //   );

  //   let shortMessage;
  //   try{
  //     resp = await WA.proxyViewPassword(
  //       username, WALLET_TYPE_EVM, in_digest, in_data
  //     );
  //   } catch(e: any) {
  //     shortMessage = e.toString();
  //   }
  //   expect(shortMessage).to.have.string('execution reverted: Wallet removed');
  // });

  it("Register + preventing duplicates", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    expect(await WA.userExists(username)).to.equal(true);

    const credList = await WA.credentialIdsByUsername(username);
    expect(credList[0]).to.equal(accountData.credentials[0].credentialId);

    // Try creating another user with same username
    try {
      await createAccount(username, SIMPLE_PASSWORD);
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }
  });

  it("Verify gasless signature", async function() {
    const gasPrice = (await owner.provider.getFeeData()).gasPrice;

    const username = hashedUsername(SALT, "testuser");
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

    const username = hashedUsername(SALT, "testuser");
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
      optionalPassword: SIMPLE_PASSWORD,
      wallet: {
        walletType: WALLET_TYPE_EVM,
        keypairSecret: BYTES32_ZERO // create new wallet
      }
    };

    let funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, bytes32 optionalPassword, tuple(uint256 walletType, bytes32 keypairSecret) wallet)" ], 
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
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    
    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const in_data = iface.encodeFunctionData('signEIP155', [WALLET_IDX_0, txRequest]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, in_data
    );

    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    // Broadcast transaction
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("proxyView with credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Fund new account
    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("0.5"),
    });

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("proxyView FAIL with wrong credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const usernameHacker = hashedUsername(SALT, "hacker");
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
    } catch(e: any) {
      shortMessage = e.toString();
    }
    expect(shortMessage).to.have.string('execution reverted: getCredentialAndUser');

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
    } catch(e: any) {
      shortMessage = e.toString();
    }
    expect(shortMessage).to.have.string('execution reverted: verification failed');
  });

  it("Add additional credential with password + try proxyView with new credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    
    const keyPair = generateNewKeypair();

    const data = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
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
          hashedUsername: username,
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e: any ) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }

    // Now try with correct password
    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    const tx = await WA.manageCredentialPassword(
      {
        hashedUsername: username,
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

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("Add additional credential with credential + try proxyView with new credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    
    const keyPair = generateNewKeypair();

    const data = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
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
        credentialIdHashed,
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

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));
  });

  it("Gasless add credential to existing account with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const keyPair = generateNewKeypair();

    const credentialData = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ credentialData ]
    );

    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, credentialDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes32 digest, bytes data)" ], 
      [ { hashedUsername: username, digest, data: credentialDataEncoded } ]
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
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    let shortMessage = '';
    
    const keyPair = generateNewKeypair();

    const data = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
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
          hashedUsername: username,
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }

    // Now try with correct password
    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        hashedUsername: username,
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

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));

    // Remove default credential (added with registration)
    data.credentialId = accountData.credentials[0].credentialId;
    data.pubkey.x = accountData.credentials[0].decoded_x;
    data.pubkey.y = accountData.credentials[0].decoded_y;
    data.action = CREDENTIAL_ACTION_REMOVE;

    encoded_data = abiCoder.encode(
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    // Now try with correct password
    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    const tx_remove = await WA.manageCredentialPassword(
      {
        hashedUsername: username,
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
    } catch(e: any) {
      shortMessage = e.toString();
    }
    expect(shortMessage).to.have.string('execution reverted: getCredentialAndUser');

    // Try to remove last credential
    shortMessage = '';
    try {
      // Remove default credential (added with registration)
      data.credentialId = keyPair.credentialId;
      data.pubkey.x = keyPair.decoded_x;
      data.pubkey.y = keyPair.decoded_y;

      encoded_data = abiCoder.encode(
        [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
        [ data ]
      );

      // Now try with correct password
      digest = ethers.solidityPackedKeccak256(
        ['bytes32', 'bytes'],
        [SIMPLE_PASSWORD, encoded_data],
      );

      tx = await WA.manageCredentialPassword(
        {
          hashedUsername: username,
          digest,
          data: encoded_data
        }
      );

      await tx.wait();
    } catch(e: any) {
      shortMessage = e.toString();
    }
    expect(shortMessage).to.have.string('transaction execution reverted');
  });

  it("Remove credential with credential + try proxyView with old credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);
    let shortMessage = '';
    
    const keyPair = generateNewKeypair();

    const data = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
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
          hashedUsername: username,
          digest: digest_wrong,
          data: encoded_data
        }
      );
      await tx_wrong.wait();
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }

    // Now try with correct password
    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        hashedUsername: username,
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

    const balanceBefore = await ethers.provider.getBalance(account1.address);

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
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    expect(await ethers.provider.getBalance(account1.address)).to.equal(balanceBefore + ethers.parseEther("0.005"));

    // Remove default credential (added with registration)
    data.credentialId = accountData.credentials[0].credentialId;
    data.pubkey.x = accountData.credentials[0].decoded_x;
    data.pubkey.y = accountData.credentials[0].decoded_y;
    data.action = CREDENTIAL_ACTION_REMOVE;

    encoded_data = abiCoder.encode(
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
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
        credentialIdHashed,
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
    } catch(e: any) {
      shortMessage = e.toString();
    }
    expect(shortMessage).to.have.string('execution reverted: getCredentialAndUser');
  });

  it("Gasless remove credential from existing account with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Firstly add additional credential
    const keyPair = generateNewKeypair();

    const data = {
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.manageCredentialPassword(
      {
        hashedUsername: username,
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
      [ "tuple(bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, uint8 action)" ], 
      [ credentialData ]
    );

    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, credentialDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes32 digest, bytes data)" ], 
      [ { hashedUsername: username, digest, data: credentialDataEncoded } ]
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

  it("Gasless add wallet with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const newWallet = ethers.Wallet.createRandom();

    // Gasless add wallet
    // Gasless add wallet
    // Gasless add wallet

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const addWalletData = {
      walletType: WALLET_TYPE_EVM,
      keypairSecret: newWallet.privateKey
    };

    const walletDataEncoded = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ addWalletData ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, walletDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes32 digest, bytes data)" ], 
      [ { hashedUsername: username, digest, data: walletDataEncoded } ]
    );

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_ADD_WALLET_PASSWORD
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

    // re-fetch account wallets
    const accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(newWallet.address);
  });

  it("Gasless remove wallet with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    const newWallet = ethers.Wallet.createRandom();

    const data = {
      walletType: WALLET_TYPE_EVM,
      keypairSecret: newWallet.privateKey
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // Check if wallet correctly imported
    let accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);

    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(newWallet.address);

    // Gasless remove wallet
    // Gasless remove wallet
    // Gasless remove wallet

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const walletDataEncoded = abiCoder.encode(
      [ "uint256", "uint256" ], 
      [ WALLET_TYPE_EVM, 1 /* walletId */ ]
    );

    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, walletDataEncoded],
    );

    const funcData = abiCoder.encode(
      [ "tuple(bytes32 hashedUsername, bytes32 digest, bytes data)" ], 
      [ { hashedUsername: username, digest, data: walletDataEncoded } ]
    );

    let gaslessData = abiCoder.encode(
      [ "tuple(bytes funcData, uint8 txType)" ], 
      [ 
        {
          funcData,
          txType: GASLESS_TYPE_REMOVE_WALLET_PASSWORD
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

    // re-fetch account wallets
    accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(ethers.ZeroAddress);
  });

  it("Remove wallet using password authentication", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Add a second wallet
    const newWallet = ethers.Wallet.createRandom();
    const data = {
      walletType: WALLET_TYPE_EVM,
      keypairSecret: newWallet.privateKey
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // Verify wallet was added
    let accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(newWallet.address);

    // Remove the second wallet using password authentication
    const removeWalletData = abiCoder.encode(
      [ "uint256", "uint256" ], 
      [ WALLET_TYPE_EVM, 1 /* walletId */ ]
    );

    digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, removeWalletData],
    );

    tx = await WA.removeWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: removeWalletData
      }
    );
    await tx.wait();

    // Verify wallet was removed
    accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(ethers.ZeroAddress);

    // Try removing already removed wallet
    try {
      tx = await WA.removeWalletPassword(
        {
          hashedUsername: username,
          digest,
          data: removeWalletData
        }
      );
      await tx.wait();
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }
  });

  it("Remove wallet using credential authentication", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Add a second wallet
    const newWallet = ethers.Wallet.createRandom();
    const data = {
      walletType: WALLET_TYPE_EVM,
      keypairSecret: newWallet.privateKey
    };

    const encoded_data = abiCoder.encode(
      [ "tuple(uint256 walletType, bytes32 keypairSecret)" ], 
      [ data ]
    );

    let digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, encoded_data],
    );

    let tx = await WA.addWalletPassword(
      {
        hashedUsername: username,
        digest,
        data: encoded_data
      }
    );
    await tx.wait();

    // Verify wallet was added
    let accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(newWallet.address);

    // Remove the second wallet using credential authentication
    const removeWalletData = abiCoder.encode(
      [ "uint256", "uint256" ], 
      [ WALLET_TYPE_EVM, 1 /* walletId */ ]
    );

    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(accountData.credentials[0].credentialId);

    // Create & encode challenge
    const challange = await HELPER.createChallengeBase64(removeWalletData, personalization);

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

    tx = await WA.removeWallet(
      {
        credentialIdHashed,
        resp: in_resp,
        data: removeWalletData
      }
    );
    await tx.wait();

    // Verify wallet was removed
    accountWallets = await getAccountWallets(username, WALLET_TYPE_EVM);
    expect(accountWallets.length).to.equal(2);
    expect(accountWallets[1]).to.equal(ethers.ZeroAddress);

    // Try removing already removed wallet
    try {
      tx = await WA.removeWallet(
        {
          credentialIdHashed,
          resp: in_resp,
          data: removeWalletData
        }
      );
      await tx.wait();
    } catch(e: any) {
      expect(e.toString()).to.have.string("transaction execution reverted");
    }
  });

  it("Modify controller on account via account manager with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Get the account address from the account manager
    const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);
    expect(accountAddress).to.not.equal(ethers.ZeroAddress);
    
    // Get the account contract
    const account = await ethers.getContractAt("AccountEVM", accountAddress);

    const address = await WA.getAddress();

    // Verify initial controller status
    expect(await account.isController(address)).to.be.true;
    expect(await account.isController(account1.address)).to.be.false;

    // Encode controller data
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now
    const controllerData = abiCoder.encode(
      ["uint256", "address", "bool", "uint256"],
      [WALLET_TYPE_EVM, account1.address, true, deadline]
    );

    // Create digest with password
    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, controllerData],
    );

    // Call modifyController via account manager
    await WA.modifyControllerPassword({
      hashedUsername: username,
      digest,
      data: controllerData
    });

    // Verify new controller status
    expect(await account.isController(account1.address)).to.be.true;

  });

  it("Modify controller fails with expired deadline via account manager with password", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Get the account address from the account manager
    const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);
    expect(accountAddress).to.not.equal(ethers.ZeroAddress);
    
    // Get the account contract
    const account = await ethers.getContractAt("AccountEVM", accountAddress);

    const address = await WA.getAddress();

    // Verify initial controller status
    expect(await account.isController(address)).to.be.true;
    expect(await account.isController(account1.address)).to.be.false;

    // Encode controller data
    const deadline = Math.ceil(new Date().getTime() / 1000) - 3600; // 1 hour before now
    const controllerData = abiCoder.encode(
      ["uint256", "address", "bool", "uint256"],
      [WALLET_TYPE_EVM, account1.address, true, deadline]
    );

    // Create digest with password
    const digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, controllerData],
    );

    // Call modifyController via account manager
    try {
      await WA.modifyControllerPassword({
        hashedUsername: username,
        digest,
        data: controllerData
      });
    } catch(e: any) {
      expect(e.toString()).to.have.string("execution reverted: Invalid deadline");
    }

  });

  it("Modify controller on account via account manager with credential", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Get the account address from the account manager
    const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);
    expect(accountAddress).to.not.equal(ethers.ZeroAddress);
    
    // Get the account contract
    const account = await ethers.getContractAt("AccountEVM", accountAddress);

    const address = await WA.getAddress();

    // Verify initial controller status
    expect(await account.isController(address)).to.be.true;
    expect(await account.isController(account1.address)).to.be.false;

    // Encode controller data
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now
    const controllerData = abiCoder.encode(
      ["uint256", "address", "bool", "uint256"],
      [WALLET_TYPE_EVM, account1.address, true, deadline]
    );

    // Create challenge and get credential response
    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(accountData.credentials[0].credentialId);

    // Create & encode challenge
    const challenge = await HELPER.createChallengeBase64(controllerData, personalization);

    const authenticatorData = "0x";
    const clientDataTokens = [
      {
        t: 0, // 0 = JSONString, 1 = JSONBool
        k: 'challenge',
        v: challenge
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

    const resp = {
      authenticatorData,
      clientDataTokens,
      sigR: signature.r,
      sigS: signature.s,
    }

    // Call modifyController via account manager
    await WA.modifyController({
      credentialIdHashed,
      data: controllerData,
      resp
    });

    // Verify new controller status
    expect(await account.isController(account1.address)).to.be.true;

  });

  it("Modify controller on account via account manager with gasless transaction", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    // Get the account address from the account manager
    const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);
    expect(accountAddress).to.not.equal(ethers.ZeroAddress);
    
    // Get the account contract
    const account = await ethers.getContractAt("AccountEVM", accountAddress);

    const address = await WA.getAddress();

    // Verify initial controller status
    expect(await account.isController(address)).to.be.true;
    expect(await account.isController(account1.address)).to.be.false;

    // Encode controller data
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now
    const controllerData = abiCoder.encode( 
      ["uint256", "address", "bool", "uint256"],
      [WALLET_TYPE_EVM, account1.address, true, deadline]
    );

    // Create challenge and get credential response
    const personalization = await WA.personalization();
    const credentialIdHashed = ethers.keccak256(accountData.credentials[0].credentialId);

    // Create & encode challenge
    const challenge = await HELPER.createChallengeBase64(controllerData, personalization);

    const authenticatorData = "0x";
    const clientDataTokens = [
      {
        t: 0,
        k: 'challenge',
        v: challenge
      },
      {
        t: 0,
        k: 'type',
        v: 'webauthn.get'
      }
    ];

    let digest = await HELPER.createDigest(authenticatorData, clientDataTokens);
    digest = digest.replace("0x", "");

    const signature = secp256r1.sign(digest, accountData.credentials[0].privateKey);

    const resp = {
      authenticatorData,
      clientDataTokens,
      sigR: signature.r,
      sigS: signature.s,
    }

    // Create ActionCred struct
    const actionCred = {
      credentialIdHashed,
      resp,
      data: controllerData
    };

    // Create GaslessData
    const gaslessData = {
      funcData: abiCoder.encode(
        ["tuple(bytes32 credentialIdHashed, tuple(bytes authenticatorData, tuple(uint8 t, string k, string v)[] clientDataTokens, uint256 sigR, uint256 sigS) resp, bytes data)"],
        [actionCred]
      ),
      txType: 7 // TxType.ModifyController
    };

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());
    const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;

    const dataHash = ethers.solidityPackedKeccak256(
      ['uint256', 'uint64', 'uint256', 'bytes32'],
      [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(abiCoder.encode(["tuple(bytes funcData, uint8 txType)"], [gaslessData]))],
    );
    const signature2 = await signer.signMessage(ethers.getBytes(dataHash));

    const signedTx = await WA.generateGaslessTx(
      abiCoder.encode(["tuple(bytes funcData, uint8 txType)"], [gaslessData]),
      nonce,
      gasPrice,
      GAS_LIMIT,
      timestamp,
      signature2
    );

    // Execute gasless transaction
    const txHash = await owner.provider.send('eth_sendRawTransaction', [signedTx]);
    await waitForTx(txHash);

    // Verify new controller status
    expect(await account.isController(account1.address)).to.be.true;

    await account.connect(account1).transfer(account2.address, ethers.parseEther("0.0"), 0);

  });

  it("Transfer using proxyView and transfer with password authentication", async function() {
 
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD);

    await owner.sendTransaction({
      to: accountData.publicKey,
      value: ethers.parseEther("1.0"),
    });

    const accountAddress = await WA.getAccount(username, WALLET_TYPE_EVM);

    // Create the transfer function call data
    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const transferData = iface.encodeFunctionData('transfer', [
      account1.address, // target address
      ethers.parseEther("0.0"), // amount
      WALLET_IDX_0 // walletId
    ]);

    // Create the transaction request
    const txRequest = {
      to: accountAddress,
      data: transferData,
      gasLimit: GAS_LIMIT,
      value: 0,
      nonce: await owner.provider.getTransactionCount(accountData.publicKey),
      chainId: SAPPHIRE_LOCALNET,
      gasPrice: 100000000000, // 100 gwei
    };

    // Create signEIP155 function call data
    const signData = iface.encodeFunctionData('signEIP155', [WALLET_IDX_0, txRequest]);

    // Create digest with password
    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, signData],
    );

    // Get signed transaction via proxyView
    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, signData
    );

    // Decode the signed transaction
    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    // Execute the signed transaction
    const txHash = await ethers.provider.send('eth_sendRawTransaction', [signedTx]);
    const res = await waitForTx(txHash);
    expect(res.from).to.equal(accountData.publicKey);

  });

  async function createAccount(username: any, password: any) {
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
      optionalPassword: password,
      wallet: {
        walletType: WALLET_TYPE_EVM,
        keypairSecret: BYTES32_ZERO // create new wallet
      }
    };

    const tx = await WA.createAccount(registerData);
    await tx.wait();

    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const in_data = iface.encodeFunctionData('walletAddress', [WALLET_IDX_0]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_EVM, in_digest, in_data
    );

    let [publicKey] = iface.decodeFunctionResult('walletAddress', resp).toArray();

    // convert from bytes32 to native address (checksumed)
    publicKey = ethers.getAddress(`0x${publicKey.slice(-40)}`);

    return {
      ...registerData,
      publicKey,
      credentials: [
        keyPair
      ]
    }
  }

  async function generateSignedTxWithCredential(senderAddress: any, credentialId: any, credentialPK: any, req: any) {
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
    
    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const in_data = iface.encodeFunctionData('signEIP155', [WALLET_IDX_0, txRequest]);

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
      credentialIdHashed, in_resp, WALLET_TYPE_EVM, in_data
    );

    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    return signedTx;
  }

  async function waitForTx(txHash: any) {
    while(true) {
      const tx = await owner.provider.getTransactionReceipt(txHash);
      if (tx) {
        return tx;
      }
      await new Promise(f => setTimeout(f, 500));
    }
    return;
  }

  async function getAccountWallets(username: any, walletType: any) {
    const iface = new ethers.Interface(ACCOUNT_EVM_ABI);
    const in_data = iface.encodeFunctionData('getWalletList', []);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, walletType, in_digest, in_data
    );

    let [accountWallets] = iface.decodeFunctionResult('getWalletList', resp).toArray();

    if (walletType == WALLET_TYPE_EVM) {
      // convert from bytes32 to native address (checksumed)
      accountWallets = accountWallets.map((x: any) => ethers.getAddress(`0x${x.slice(-40)}`));
    }

    return accountWallets;
  }
  
});
