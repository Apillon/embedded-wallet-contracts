import hre from "hardhat";
import { pbkdf2Sync } from "pbkdf2"
import { VoidSigner } from "ethers";

async function main() {

  // DATA to be set
  const accountManagerAddress = "0x2a9E1363D590a414C973029d476D4C9fe93d44E2";
  const usernamePlain = "someUniqueUsername";
  const password = "0x0000000000000000000000000000000000000000000000000000000000000001";
  const receiverAddress = "0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const saltOrig = await contract.salt();
  const salt = ethers.toBeArray(saltOrig);
  const usernameHash = await hashedUsername(usernamePlain, salt);

  // Get account
  const accountData = await contract.getAccount(usernameHash);

  // Prepare tx
  const from = accountData[1];
  const voidSigner = new VoidSigner(from, hre.ethers.provider);

  const txRequest = await voidSigner.populateTransaction({
    from,
    to: receiverAddress,
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

  const jsonAbi = require("../../artifacts/contracts/Account.sol/Account.json").abi;
  
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
