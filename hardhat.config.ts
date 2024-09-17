import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";
import "@nomicfoundation/hardhat-verify";
import "./tasks"
require('dotenv').config();
import { config as envEncConfig } from '@chainlink/env-enc'

const isMainnet = process.env.STAGE === 'mainnet';

if (isMainnet) {
  console.log('Using mainnet .env.enc')
} else {
  console.log('Using testnet .env.enc')
}

envEncConfig({
  path: process.env.STAGE === 'mainnet'
  ? '/Volumes/TUNNL/encryptedEnvVars/.env.enc.mainnet'
  : '/Volumes/TUNNL/encryptedEnvVars/.env.enc.testnet'
});

const SOLC_SETTINGS = {
  optimizer: {
    enabled: true,
    runs: 1,
  },
}

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: SOLC_SETTINGS,
      },
    ],
  },
  networks: {
    base: {
      url: process.env.RPC_URL,
      chainId: 8453,
      accounts: [process.env.PRIVATE_KEY!],
    },
    baseSepolia: {
      url: process.env.RPC_URL,
      chainId: 84532,
      accounts: [process.env.PRIVATE_KEY!],
    },
    optimismSepolia: {
      url: process.env.RPC_URL,
      chainId: 11155420,
      accounts: [process.env.PRIVATE_KEY!],
    },
    polygonMumbai: {
      url: process.env.RPC_URL,
      chainId: 80001,
      accounts: [process.env.PRIVATE_KEY!],
    },
  },
  defaultNetwork: "optimismSepolia",
  etherscan: {
    apiKey: {
      base: process.env.SCANNER_API_KEY!,
      baseSepolia: process.env.SCANNER_API_KEY!,
      optimismSepolia: process.env.SCANNER_API_KEY!,
      polygonMumbai: process.env.SCANNER_API_KEY!,
    },
    customChains: [
      {
        network: "base",
        chainId: 8453,
        urls: {
          apiURL: "https://api.basescan.org/api",
          browserURL: "https://basescan.org/"
        }
      },
      {
        network: "baseSepolia",
        chainId: 84532,
        urls: {
          apiURL: "https://api-sepolia.basescan.org/api",
          browserURL: "https://sepolia.basescan.org/"
        }
      },
      {
        network: "optimismSepolia",
        chainId: 11155420,
        urls: {
          apiURL: "https://api-sepolia-optimistic.etherscan.io/api",
          browserURL: "https://sepolia-optimism.etherscan.io/"
        }
      },
      {
        network: "polygonMumbai",
        chainId: 80001,
        urls: {
          apiURL: "https://api-mumbai.polygonscan.com/api",
          browserURL: "https://mumbai.polygonscan.com/"
        }
      },
    ]
  }
};

export default config;