const hre = require("hardhat");

async function main() {
  const curveFactory = await hre.ethers.getContractFactory("SECP256R1Precompile");
  const curveLibrary = await curveFactory.deploy();
  await curveLibrary.waitForDeployment();

  const contractFactory = await hre.ethers.getContractFactory("AccountManager", {libraries: {SECP256R1Precompile: await curveLibrary.getAddress()}});
  const contract = await contractFactory.deploy({value: hre.ethers.parseEther('0.3')});
  await contract.waitForDeployment();

  // const sha1Factory = await hre.ethers.getContractFactory("SHA1");
  // const sha1Library = await sha1Factory.deploy();
  // await sha1Library.waitForDeployment();

  // const totpFactory = await hre.ethers.getContractFactory('TOTPExample', { libraries: { SHA1: await sha1Library.getAddress() } });
  // const totpContract = await totpFactory.deploy();
  // await totpContract.waitForDeployment();

  console.log(`VITE_WEBAUTH_ADDR=${await contract.getAddress()}`);
  // console.log(`VITE_TOTP_CONTRACT=${await totpContract.getAddress()}`);
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
