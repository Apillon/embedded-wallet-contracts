
import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-ethers";

// When deploying, comment out sapphire-hardhat import, this way we can later verify contract
import '@oasisprotocol/sapphire-hardhat';

const { privateKeyMainnet, privateKeyTestnet, polygonAmoyRPC } = require("./secrets.json");

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
    version: '0.8.22',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  mocha: {
    timeout: 100000000
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
      accounts: [privateKeyMainnet],
    },
    sapphireTestnet: {
      url: 'https://testnet.sapphire.oasis.dev',
      chainId: 0x5aff, // 23295
      accounts: [privateKeyTestnet],
    },
    sapphireLocalnet: { // docker run -it -p8545:8545 -p8546:8546 ghcr.io/oasisprotocol/sapphire-localnet
      // docker run -it -p8544-8548:8544-8548 -e OASIS_NODE_LOG_LEVEL=debug ghcr.io/oasisprotocol/sapphire-localnet
      url: 'http://localhost:8545',
      chainId: 0x5afd,
      accounts: TEST_HDWALLET,
    },
    polygonAmoy: {
      url: polygonAmoyRPC, 
      chainId: 80002,
      gasPrice: 13000000000, // 130gwei
      gas: 2000000,
      accounts: [privateKeyTestnet],
      explorer: "https://amoy.polygonscan.com/",
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
