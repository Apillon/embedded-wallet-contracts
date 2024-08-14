const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0x2a9E1363D590a414C973029d476D4C9fe93d44E2";
  const newSigner = "SIGNER_ADDRESS";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const tx = await contract.setSigner(newSigner);

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
