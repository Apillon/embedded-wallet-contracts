const hre = require("hardhat");

async function main() {
  // Get the owner account
  const [deployer] = await hre.ethers.getSigners();

  const accountManagerProxy = "0xe1D85Aa3449690185371193DD46D60c3DA9FC709";
  const curveLibrary = "0x335E865F8F40e59D5AF3f6F85738962dD2D9aBEa";

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: curveLibrary}});
  const impl = await contractFactory.deploy();
  await impl.waitForDeployment();

  const proxyContract = new hre.ethers.Contract(
    accountManagerProxy, 
    ["function upgradeToAndCall(address newImplementation, bytes memory data) external payable"],
    deployer
  );

  const tx = await proxyContract.upgradeToAndCall(await impl.getAddress(), "0x");
  await tx.wait();

  console.log(
    "accountManagerProxy upgraded to: %saddress/%s",
    hre.network.config.explorer,
    accountManagerProxy
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
