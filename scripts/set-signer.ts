const hre = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0x2a9E1363D590a414C973029d476D4C9fe93d44E2";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const tx = await contract.setSigner('SIGNER_ADDRESS');

  await tx.wait();

  const signerAddress = await contract.signer();
  console.log(`signer: ${signerAddress}`);
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
