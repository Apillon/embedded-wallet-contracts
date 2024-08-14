import { ethers } from "ethers";
import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"

const { secp256r1 } = require('@noble/curves/p256');
const curve_utils = require('@noble/curves/abstract/utils');
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

async function main() {

  // DATA to be set
  const accountManagerAddress = "0x2a9E1363D590a414C973029d476D4C9fe93d44E2";
  const usernamePlain = "someUniqueUsername";
  const password = "0x0000000000000000000000000000000000000000000000000000000000000001";
  // Data to be set [END]

  const GAS_LIMIT = 1000000;

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const gasPrice = (await signer.provider.getFeeData()).gasPrice;
  const gasPayingAddress = await contract.gaspayingAddress();
  const nonce = await signer.provider.getTransactionCount(gasPayingAddress);

  const saltOrig = await contract.salt();
  const salt = ethers.toBeArray(saltOrig);

  const keyPair = generateNewKeypair();

  const username = await hashedUsername(usernamePlain, salt);
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

  let funcData = abiCoder.encode(
    [ "tuple(bytes32 hashedUsername, bytes credentialId, tuple(uint8 kty, int8 alg, uint8 crv, uint256 x, uint256 y) pubkey, bytes32 optionalPassword)" ], 
    [ registerData ]
  ); 

  let gaslessData = abiCoder.encode(
    [ "tuple(bytes funcData, uint8 txType)" ], 
    [ 
      {
        funcData,
        txType: 0, // GASLESS_TYPE_CREATE_ACCOUNT
      } 
    ]
  ); 

  const timestamp = Math.ceil(new Date().getTime() / 1000) + 3600;
  const dataHash = ethers.solidityPackedKeccak256(
    ['uint256', 'uint64', 'uint256', 'bytes32'],
    [gasPrice, GAS_LIMIT, timestamp, ethers.keccak256(gaslessData)],
  );
  const signature = await signer.signMessage(ethers.getBytes(dataHash));

  const signedTx = await contract.generateGaslessTx(
    gaslessData,
    nonce,
    gasPrice,
    GAS_LIMIT,
    timestamp,
    signature
  );

  const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]) as string;
  console.log(`txHash: ${txHash}`);
  console.log(`----------------------`);
  console.log(`credential:`);
  console.log(keyPair);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


async function hashedUsername (username, salt) {
  if( ! username ) {
      throw new Error('Cannot hash undefined username!');
  }
  const result = pbkdf2Sync(username, salt, 100_000, 32, 'sha256');
  return result;
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
