const hre = require("hardhat");

async function main() {
    const acc = hre.ethers.Wallet.createRandom();
    console.log("Address: %s", acc.address);
    console.log("mnemonic: %s", acc.mnemonic['phrase']);
    console.log("privateKey: %s", acc.privateKey);
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });
