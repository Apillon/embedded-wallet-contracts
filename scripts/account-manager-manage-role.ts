const hre = require("hardhat");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0xecA57229b21Fc814cb273775c2a8722C7404f33B";
  const wallet = "0x1a64B581Ee6bf7Ab991ca627AB2CF5479dd6dC78";
  // Data to be set [END]

  const signer = (await hre.ethers.getSigners())[0];
  const contract = await hre.ethers.getContractAt('AccountManager', accountManagerAddress, signer);

  const DEFAULT_ADMIN_ROLE = await contract.DEFAULT_ADMIN_ROLE();
  // console.log(`DEFAULT_ADMIN_ROLE: ${DEFAULT_ADMIN_ROLE}`);

  // const tx = await contract.revokeRole(DEFAULT_ADMIN_ROLE, signer.address);
  // const tx = await contract.grantRole(DEFAULT_ADMIN_ROLE, signer.address);
  // await tx.wait();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
