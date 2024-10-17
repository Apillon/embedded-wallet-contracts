const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0xe1D85Aa3449690185371193DD46D60c3DA9FC709";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const gasPayingAddress = await contract.gaspayingAddress();
  console.log(`gasPayingAddress: ${gasPayingAddress}`);

  const signerAddress = await contract.signer();
  console.log(`signer: ${signerAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
