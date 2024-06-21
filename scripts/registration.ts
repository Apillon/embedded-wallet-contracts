import { ethers } from "ethers";
import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"

const { secp256r1 } = require('@noble/curves/p256');
const curve_utils = require('@noble/curves/abstract/utils');
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

async function main() {

  // DATA to be set
  const accountManagerAddress = "0xDc9e8B6894E4754631887486BcF583B6B3158c4E";
  const usernamePlain = "someUniqueUsername";
  const password = "0x0000000000000000000000000000000000000000000000000000000000000001";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

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

  const tx = await contract.createAccount(registerData);
  await tx.wait();

  console.log(`txHash: ${tx.hash}`);
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
