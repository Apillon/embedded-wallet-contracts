const hre = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('WebAuthNExample', '0xb1058eD01451B947A836dA3609f88C91804D0663', signer);

  const saltOrig = await contract.salt();
  const salt = ethers.toBeArray(saltOrig);
  
  const username = await hashedUsername('mkkalmia3', salt);
  const res = await contract.userExists(username);
  console.log(res);

  const res2 = await contract.getAccount(username);
  console.log(res2);
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
