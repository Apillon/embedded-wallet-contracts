const hre = require("hardhat");

async function main() {
  const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
  const curveLibrary = await curveFactory.deploy();
  await curveLibrary.waitForDeployment();

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
  const contract = await contractFactory.deploy(
    '0x03f039b54373591B39d9524A5baA4dAa25A0B4E4', // Signer address
    {
      value: hre.ethers.parseEther('0.3') // Value to be transfered to gaspaying address
    }
  );
  await contract.waitForDeployment();

  console.log(`ACCOUNT_MANAGER_ADDR=${await contract.getAddress()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
