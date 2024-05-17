async function main() {

    const jsonAbi = require("../artifacts/contracts/Account.sol/Account.json").abi;
  
    const iface = new ethers.Interface(jsonAbi);
    console.log(iface.format(""));

    // const contract = await ethers.getContractFactory("Account");
    // console.log(JSON.stringify(contract.interface.fragments));
  
  }
  
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
    