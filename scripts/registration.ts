// const hre = require("hardhat");
// const { pbkdf2Sync } = require("pbkdf2");
// const { credentialCreate } = require("./lib/webauthn.ts");

import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"
// import { credentialCreate, credentialGet } from "./lib/webauthn.ts";
// import { getRandomValues } from 'get-random-values';
import { ZeroHash } from "ethers";

// let a = new Uint8Array(24);
// console.log(crypto.getRandomValues(a));

/*
VITE_WEBAUTH_ADDR=0x9152322be84Aa52622C5Fd757DF15F5ed5965faF
VITE_TOTP_CONTRACT=0xd7C9BB2Cb510B7096D384AD1F59006A20Fb419f7
*/

async function main() {

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('WebAuthNExample', '0xb1058eD01451B947A836dA3609f88C91804D0663', signer);

  const gasPrice = (await signer.provider.getFeeData()).gasPrice;
  const nonce = await signer.provider.getTransactionCount(await contract.gaspayingAddress());

  console.log(gasPrice);
  console.log(nonce);

  const saltOrig = await contract.salt();
  const salt = ethers.toBeArray(saltOrig);
  const usernameHash = await hashedUsername('mkkalmia4', salt);

  const password = "0x0000000000000000000000000000000000000000000000000000000000000001";

  const signedTx = await contract.gasless_registerECES256P256(
    {
      hashedUsername: usernameHash,
      credentialId: "0x",
      pubkey: {
        kty: 0,
        alg: 0,
        crv: 0,
        x: 0,
        y: 0,
      },
      optionalPassword: password
    },
    nonce, 
    gasPrice
  );

  // console.log(signedTx);

  const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]) as string;
  // await txHash.wait();
  console.log(txHash);

  // const res = await contract.encrypted_registerECES256P256 (bytes32 nonce, bytes memory ciphertext);
  // console.log(res);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


async function hashedUsername (username, salt) {
  // if( ! username ) {
  //     username = this.username;
  // }
  if( ! username ) {
      throw new Error('Cannot hash undefined username!');
  }
  // if( username in this._usernameHashesCache ) { // Cache pbkdf2 hashed usernames locally
  //     return this._usernameHashesCache[username];
  // }

  const start = new Date();
  const result = pbkdf2Sync(username, salt, 100_000, 32, 'sha256');
  const end = new Date();
  // console.log('pbkdf2', username, '=', end.getTime() - start.getTime(), 'ms');
  // this._usernameHashesCache[username] = result;
  return result;
}
