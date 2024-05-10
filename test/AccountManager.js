const { expect } = require("chai");
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const ECDSA = require('ecdsa-secp256r1');
const { secp256r1 } = require('@noble/curves/p256');
const curve_utils = require('@noble/curves/abstract/utils');

describe("AccountManager", function() {
  let WA, SALT, owner, account1, account2, gaspayingAddress;

  const GASLESS_TYPE_CREATE_ACCOUNT = 0;
  const GASLESS_TYPE_CREDENTIAL_ADD = 1;
  const GASLESS_TYPE_CREDENTIAL_ADD_PASSWORD = 2;
  const GASLESS_TYPE_CREDENTIAL_REMOVE = 3;
  const GASLESS_TYPE_CREDENTIAL_REMOVE_PASSWORD = 4;

  const SIMPLE_PASSWORD = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const WRONG_PASSWORD  = "0x0000000000000000000000000000000000000000000000000000009999999999";

  const abiCoder = ethers.AbiCoder.defaultAbiCoder();

  beforeEach(async () => {
    [ owner, account1, account2 ] = await ethers.getSigners();

    const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
    const curveLibrary = await curveFactory.deploy();
    await curveLibrary.waitForDeployment();

    const contractFactory = await ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
    // WA = await contractFactory.deploy({value: '1000000000000000000'}); -- for some reason sending value doesn't work
    WA = await contractFactory.deploy();
    await WA.waitForDeployment();

    gaspayingAddress = await WA.gaspayingAddress();
    await owner.sendTransaction({
      to: gaspayingAddress,
      value: ethers.parseEther("1.0"), // Sends exactly 1.0 ether to gaspaying address
    });

    SALT = ethers.toBeArray(await WA.salt());
  });

  it("Register + preventing duplicates", async function() {
    const username = hashedUsername("testuser");
    const credentialId = abiCoder.encode([ "uint256" ], [ 123456 ]);

    await createAccount(username, SIMPLE_PASSWORD, credentialId);

    expect(await WA.userExists(username)).to.equal(true);

    const credList = await WA.credentialIdsByUsername(username);
    expect(credList[0]).to.equal(credentialId);

    // Try creating another user with same username
    try {
      await createAccount(username, SIMPLE_PASSWORD, abiCoder.encode([ "uint256" ], [ 111111 ]));
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }

    // Try creating another user with same credentialId
    try {
      await createAccount(hashedUsername("anotheruser"), SIMPLE_PASSWORD, credentialId);
    } catch(e) {
      expect(e.shortMessage).to.equal("transaction execution reverted");
    }
  });

  it("Gasless register", async function() {
    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());

    const username = hashedUsername("testuser");

    let credentialId = abiCoder.encode([ "uint256" ], [ 123456 ]);

    let privateKey = ECDSA.generateKey();
    let decoded_x = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.x, 0))[0];
    let decoded_y = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.y, 0))[0];

    let registerData = {
      hashedUsername: username,
      credentialId: credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: decoded_x,
        y: decoded_y,
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
    expect(credList[0]).to.equal(credentialId);
  });

  it("Add additional credential with password", async function() {
    const username = hashedUsername("testuser");
    const credentialId = abiCoder.encode([ "uint256" ], [ 123456 ]);
    await createAccount(username, SIMPLE_PASSWORD, credentialId);

    const credentialIdNew = abiCoder.encode([ "uint256" ], [ 222222 ]);
    privateKey = ECDSA.generateKey();
    decoded_x = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.x, 0))[0];
    decoded_y = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.y, 0))[0];

    const data = {
      hashedUsername: username,
      credentialId: credentialIdNew,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: decoded_x,
        y: decoded_y,
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
    expect(credList[0]).to.equal(credentialId);
    expect(credList[1]).to.equal(credentialIdNew);
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
    const credentialId = abiCoder.encode([ "uint256" ], [ 123456 ]);
    await createAccount(username, SIMPLE_PASSWORD, credentialId);

    const gasPrice = (await owner.provider.getFeeData()).gasPrice;
    const nonce = await owner.provider.getTransactionCount(await WA.gaspayingAddress());
    const credentialIdNew = abiCoder.encode([ "uint256" ], [ 222222 ]);
    privateKey = ECDSA.generateKey();
    decoded_x = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.x, 0))[0];
    decoded_y = abiCoder.decode(['uint256'], ethers.dataSlice(privateKey.y, 0))[0];

    const credentialData = {
      hashedUsername: username,
      credentialId: credentialIdNew,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: decoded_x,
        y: decoded_y,
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
    expect(credList[0]).to.equal(credentialId);
    expect(credList[1]).to.equal(credentialIdNew);
  });

  function hashedUsername (username) {
    return pbkdf2Sync(username, SALT, 100_000, 32, 'sha256');
  }

  async function createAccount(username, password, credentialId) {
    const priv = secp256r1.utils.randomPrivateKey();
    const privateKey = "0x" + curve_utils.bytesToHex(priv);

    const pubKey2 = secp256r1.getPublicKey(priv, false);
    const pubKeyString = "0x" + curve_utils.bytesToHex(pubKey2);

    // const message = "dead";
    // const signature = secp256r1.sign(message, priv);
    // console.log(signature);

    const coordsString = pubKeyString.slice(4, pubKeyString.length); // removes 0x04
    const decoded_x = BigInt('0x' + coordsString.slice(0, 64)); // x is the first half
    const decoded_y = BigInt('0x' + coordsString.slice(64, coordsString.length)); // y is the second half

    let registerData = {
      hashedUsername: username,
      credentialId: credentialId,
      pubkey: {
        kty: 2, // Elliptic Curve format
        alg: -7, // ES256 algorithm
        crv: 1, // P-256 curve
        x: decoded_x,
        y: decoded_y,
      },
      optionalPassword: password
    };

    const tx = await WA.createAccount(registerData);
    await tx.wait();

    return {
      ...registerData,
      privateKey
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