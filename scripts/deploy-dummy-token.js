const hre = require("hardhat");

async function main() {

  const contractFactory = await hre.ethers.getContractFactory("DummyToken");
  const contract = await contractFactory.deploy(
    "Dummy",
    "DMY",
    "0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d"
  );
  await contract.waitForDeployment();

  console.log(`Dummytoken=${await contract.getAddress()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
