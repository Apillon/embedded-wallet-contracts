async function main() {

    //const jsonAbi = require("../../artifacts/contracts/AccountManager.sol/AccountManager.json").abi;
    const jsonAbi = require("../../artifacts/contracts/AccountSubstrate.sol/AccountSubstrate.json").abi;
    //const jsonAbi = require("../../artifacts/contracts/AccountEVM.sol/AccountEVM.json").abi;
  
    const iface = new ethers.Interface(jsonAbi);
    console.log(iface.format(""));
  
  }
  
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
    