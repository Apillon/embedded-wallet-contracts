const { expect } = require("chai");
const { ethers } = require("hardhat");
const { sr25519PairFromSeed } = require('@polkadot/util-crypto');
const { u8aToHex, hexToU8a } = require('@polkadot/util');

const { 
  ACCOUNT_SUBSTRATE_ABI,
  WALLET_TYPE_SUBSTRATE
} = require('./utils/constants');

const { hashedUsername, generateNewKeypair } = require('./utils/helpers');

const {
  construct,
  getRegistry,
  methods
} = require('@substrate/txwrapper-polkadot');
const { Keyring } = require('@polkadot/keyring');

describe("Substrate", function() {
  let WA: any, SALT: any, HELPER: any, owner: any, account1: any, account2: any, signer: any, gaspayingAddress: any, SENDER_PAIR: any, keyring: any;

  const SIMPLE_PASSWORD = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const WRONG_PASSWORD  = "0x0000000000000000000000000000000000000000000000000000009999999999";

  const RANDOM_STRING  = "0x000000000000000000000000000000000000000000000000000000000000DEAD";

  const BYTES32_ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";

  const WALLET_IDX_0 = 0;
  const WALLET_IDX_1 = 1;

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  const SUBSTRATE_SEED = "0x4cea7f38eef57a59916a68b5cdbd20077a3c4a161a6c47cef8a2996c9067c7a9";

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

    // Construct the keyring after the API (crypto has an async init)
    keyring = new Keyring({ type: 'sr25519' });
    SENDER_PAIR = keyring.addFromUri(SUBSTRATE_SEED);
  });

  it("Export PK of new account", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD, BYTES32_ZERO);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const deadline = Math.ceil(new Date().getTime() / 1000) + 3600; // 1 hour from now
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_0, deadline]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    const unlockedWallet = sr25519PairFromSeed(exportedPrivateKey);
    expect(accountData.publicKey).to.equal(u8aToHex(unlockedWallet.publicKey));
  });

  it("Import PK", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD, BYTES32_ZERO);

    expect(await WA.userExists(username)).to.equal(true);

    // generate substrate key with ethers
    const newWalletPK = ethers.Wallet.createRandom().privateKey;
    const newWallet = sr25519PairFromSeed(newWalletPK);
    
    const data = {
      walletType: WALLET_TYPE_SUBSTRATE,
      keypairSecret: newWalletPK
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
    const accountWallets = await getAccountWallets(username);

    expect(accountWallets[0]).to.equal(accountData.publicKey);
    expect(accountWallets[1]).to.equal(u8aToHex(newWallet.publicKey));

    // Try to export, imported wallet
    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const in_data = iface.encodeFunctionData('exportPrivateKey', [WALLET_IDX_1]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    const [exportedPrivateKey] = iface.decodeFunctionResult('exportPrivateKey', resp).toArray();

    expect(exportedPrivateKey).to.equal(newWalletPK);
  });

  it("Sign & verify random bytes", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD, SUBSTRATE_SEED);

    expect(await WA.userExists(username)).to.equal(true);

    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const in_data = iface.encodeFunctionData('sign', [WALLET_IDX_0, RANDOM_STRING]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [signature] = iface.decodeFunctionResult('sign', resp).toArray();

    const isValid = SENDER_PAIR.verify(RANDOM_STRING, signature, SENDER_PAIR.publicKey);

    expect(isValid).to.equal(true);
  });

  it("Sign extrinsic payload (transfer 0.0005 SBY) with funded wallet & execute on shibuya testnet", async function() {
    const username = hashedUsername(SALT, "testuser");
    const accountData = await createAccount(username, SIMPLE_PASSWORD, SUBSTRATE_SEED);

    expect(await WA.userExists(username)).to.equal(true);

    const {
      metadataRpc,
      registry,
      signingPayload,
      unsigned
    } = await prepareUnsignedPayload();

    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const in_data = iface.encodeFunctionData('sign', [WALLET_IDX_0, signingPayload]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [signature] = iface.decodeFunctionResult('sign', resp).toArray();

    const sigWithType = `0x01${signature.substring(2, signature.length)}`;
    signature = hexToU8a(sigWithType);

    // Serialize a signed transaction.
    const tx = construct.signedTx(unsigned, signature, {
      metadataRpc,
      registry,
    });

    // Derive the tx hash of a signed transaction offline.
    const expectedTxHash = construct.txHash(tx);
    const actualTxHash = await rpcToLocalNode('author_submitExtrinsic', [tx]);

    expect(expectedTxHash).to.equal(actualTxHash);
  });

  async function createAccount(username: any, password: any, walletSeed: any) {
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
        walletType: WALLET_TYPE_SUBSTRATE,
        keypairSecret: walletSeed // import existing wallet or create new if bytes32_zero
      }
    };

    const tx = await WA.createAccount(registerData);
    await tx.wait();

    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const in_data = iface.encodeFunctionData('walletAddress', [WALLET_IDX_0]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [publicKey] = iface.decodeFunctionResult('walletAddress', resp).toArray();

    return {
      ...registerData,
      publicKey,
      credentials: [
        keyPair
      ]
    }
  }

  async function getAccountWallets(username: any) {
    const iface = new ethers.Interface(ACCOUNT_SUBSTRATE_ABI);
    const in_data = iface.encodeFunctionData('getWalletList', []);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [SIMPLE_PASSWORD, in_data],
    );

    const resp = await WA.proxyViewPassword(
      username, WALLET_TYPE_SUBSTRATE, in_digest, in_data
    );

    let [accountWallets] = iface.decodeFunctionResult('getWalletList', resp).toArray();

    return accountWallets;
  }

  function rpcToLocalNode(
    method: string,
    params: any[] = [],
  ): Promise<any> {
    // return fetch('https://asset-hub-westend-rpc.dwellir.com', {
    return fetch('https://rpc.shibuya.astar.network', {
      body: JSON.stringify({
        id: 1,
        jsonrpc: '2.0',
        method,
        params,
      }),
      headers: {
        'Content-Type': 'application/json',
        connection: 'keep-alive',
      },
      method: 'POST',
    })
      .then((response) => response.json())
      .then(({ error, result }) => {
        if (error) {
          throw new Error(
            `${error.code} ${error.message}: ${JSON.stringify(error.data)}`,
          );
        }
  
        return result;
      });
  }

  async function prepareUnsignedPayload(): Promise<any> {

    // prepare raw transaciton

    // sender
    // publickey: 5GxmLBv2spqsU5Lm1LifRzix9aHYnuSrFJdMn3PZR8tHnwBg // assethub westend
    // publickey: aqMmUt7f4UyguNbVeAnTetEEczfm89bGW8W1kbRHVtFPC7e // shibuya

    // recipient
    // const BOB = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty'; // assethub westend
    const BOB = 'b8y3VagnT7sXX2oTvRAqeoyPRWzfaXQXXPJEpUV7teAjSfm'; // shibuya

    const { block } = await rpcToLocalNode('chain_getBlock');
    const blockHash = await rpcToLocalNode('chain_getBlockHash');
    const genesisHash = await rpcToLocalNode('chain_getBlockHash', [0]);
    const metadataRpc = await rpcToLocalNode('state_getMetadata');
    const { specVersion, transactionVersion, specName } = await rpcToLocalNode(
      'state_getRuntimeVersion',
    );

    const registry = getRegistry({
      chainName: 'Westend',
      specName,
      specVersion,
      metadataRpc,
    });

    const index = await rpcToLocalNode('system_accountNextIndex', [SENDER_PAIR.address]);

    const unsigned = methods.balances.transferAllowDeath(
      {
        value: '500000000000000', // 0.0005 SBY
        dest: { id: BOB }, // Bob
      },
      {
        address: SENDER_PAIR.address,
        blockHash,
        blockNumber: registry
          .createType('BlockNumber', block.header.number)
          .toNumber(),
        eraPeriod: 4, // 64,
        genesisHash,
        metadataRpc,
        nonce: index, // Assuming this is Alice's first tx on the chain
        specVersion,
        tip: 0,
        transactionVersion,
      },
      {
        metadataRpc,
        registry,
      },
    );

    // Construct the signing payload from an unsigned transaction.
    let signingPayload = construct.signingPayload(unsigned, { registry });

    // fix payload trim first 2 characters -- otherwise it doesn't work
    signingPayload = `0x${signingPayload.substring(4,signingPayload.length)}`;

    return {
      metadataRpc,
      registry,
      signingPayload,
      unsigned
    };
  }
  
});