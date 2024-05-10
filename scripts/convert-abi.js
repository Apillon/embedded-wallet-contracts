async function main() {

    const jsonAbi = require("../artifacts/contracts/DummyToken.sol/DummyToken.json").abi;
  
    const iface = new ethers.Interface(jsonAbi);
    console.log(iface);
    // console.log(iface.format(ethers.utils.FormatTypes.full).slice(0));

    // const contract = await ethers.getContractFactory("Account");
    // console.log(JSON.stringify(contract.interface.fragments));
  
  }
  
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
    