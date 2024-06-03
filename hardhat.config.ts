import '@oasisprotocol/sapphire-hardhat';
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";

const { privateKeyMainnet, privateKeyTestnet } = require("./secrets.json");

// Hardhat Node and sapphireLocalnet test mnemonic.
const TEST_HDWALLET = {
  mnemonic: "test test test test test test test test test test test junk",
  path: "m/44'/60'/0'/0",
  initialIndex: 0,
  count: 20,
  passphrase: "",
};

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.21',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    // hardhat: {
    //   hardfork: "shanghai",
    // },
    hardhat: { // https://hardhat.org/metamask-issue.html
      chainId: 1337,
    },
    sapphire: {
      url: 'https://sapphire.oasis.io',
      chainId: 0x5afe, // 23294
      accounts: [privateKeyTestnet],
    },
    sapphireTestnet: {
      url: 'https://testnet.sapphire.oasis.dev',
      chainId: 0x5aff, // 23295
      accounts: [privateKeyTestnet],
    },
    sapphireLocalnet: { // docker run -it -p8545:8545 -p8546:8546 ghcr.io/oasisprotocol/sapphire-localnet -test-mnemonic
      url: 'http://localhost:8545',
      chainId: 0x5afd,
      accounts: TEST_HDWALLET,
    },
    polygonAmoy: {
      url: "https://polygon-amoy.g.alchemy.com/v2/_Kpo60K9na2S0-E-dvsHYinINcDXBR-8", 
      chainId: 80002,
      gasPrice: 13000000000, // 130gwei
      gas: 2000000,
      accounts: [privateKeyTestnet],
      // explorer: "https://www.oklink.com/amoy/",
    },
  },
  // etherscan: {
  //   apiKey: {
  //      polygonMumbai: polygonScanApiKey,
  //      polygon: polygonScanApiKey,
  //    },
  // }
};

export default config;
