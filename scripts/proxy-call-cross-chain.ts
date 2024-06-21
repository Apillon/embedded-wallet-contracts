import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"

async function main() {
  const RUN_MODE = 0; // 0 = GENERATE on Sapphire, 1 = EXECUTE ON some EVM chain{

  const signer = (await hre.ethers.getSigners())[0];

  if (RUN_MODE == 0) {
    const contract = await hre.ethers.getContractAt('AccountManager', '0xb1058eD01451B947A836dA3609f88C91804D0663', signer);

    const saltOrig = await contract.salt();
    const salt = hre.ethers.toBeArray(saltOrig);
    const usernameHash = await hashedUsername('mkkalmia2', salt);

    const password = "0x0000000000000000000000000000000000000000000000000000000000000001";

    const txRequest = {
      to: '0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d',
      from: '0x593DdF251Aa0279D49EfE97B70A3cAdf39d532e3',
      data: '0x',
      gasLimit: 1000000,
      value: 100000000000000,
      nonce: 0,
      chainId: 80002, // amoy testnet
      gasPrice: 20000000000, // 20 gwei
      type: 0
    }

    console.log(txRequest);

    const stripBNTx = Object.entries(txRequest).reduce((acc, entry ) => {
      const [key, value] = entry;
      const modValue = typeof value === "bigint" ? value.toString() : value;
      return {
        ...acc,
        [key]: modValue
      }
    }, {});

    const jsonAbi = require("../artifacts/contracts/Account.sol/Account.json").abi;
    
    const iface = new ethers.Interface(jsonAbi);
    const in_data = iface.encodeFunctionData('signEIP155', [{
      ...stripBNTx,
    }]);

    const in_digest = ethers.solidityPackedKeccak256(
      ['bytes32', 'bytes'],
      [password, in_data],
    );

    const resp = await contract.proxyViewPassword(
      usernameHash, in_digest, in_data
    );

    const [signedTx] = iface.decodeFunctionResult('signEIP155', resp).toArray();

    console.log("COPY signed TX:");
    console.log(signedTx);

  } else if (RUN_MODE == 1) {

    const signedTx = "PASTE_SIGNED_TX_HERE";
    const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]) as string;
    console.log(txHash);
  }
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
