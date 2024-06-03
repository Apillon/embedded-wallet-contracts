const hre = require("hardhat");

async function main() {
  const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
  const curveLibrary = await curveFactory.deploy();
  await curveLibrary.waitForDeployment();

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
  const contract = await contractFactory.deploy('0x5f2B7077a7e5B4fdD97cBb56D9aD02a4f326896d', {value: hre.ethers.parseEther('0.3')});
  await contract.waitForDeployment();

  console.log(`VITE_WEBAUTH_ADDR=${await contract.getAddress()}`);
  const chainId = (await hre.provider.getNetwork()).chainId;
  console.log(`VITE_SAPPHIRE_CHAIN_ID=0x${Number(chainId).toString(16)}`);

  console.log(`VITE_SAPPHIRE_JSONRPC=${hre.network.config.url}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
