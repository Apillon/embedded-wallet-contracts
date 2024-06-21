import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"
import { VoidSigner } from "ethers";

async function main() {

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', '0xb1058eD01451B947A836dA3609f88C91804D0663', signer);

  const saltOrig = await contract.salt();
  const salt = hre.ethers.toBeArray(saltOrig);
  const usernameHash = await hashedUsername('mkkalmia2', salt);

  const password = "0x0000000000000000000000000000000000000000000000000000000000000001";

  // Prepare tx
  const from = '0x593DdF251Aa0279D49EfE97B70A3cAdf39d532e3';
  const voidSigner = new VoidSigner(from, hre.ethers.provider);

  const txRequest = await voidSigner.populateTransaction({
    from,
    to: '0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d',
    gasLimit: 1000000,
    value: hre.ethers.parseEther('0.0001'),
    data: "0x"
  });

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

  const txHash = await hre.ethers.provider.send('eth_sendRawTransaction', [signedTx]) as string;
  console.log(txHash);
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
