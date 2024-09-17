import { task } from 'hardhat/config';
import { ethers } from 'ethers';
import deploymentArguments from '../deploymentArguments';
import * as readline from 'readline';
import { abi, bytecode } from '../artifacts/contracts/TunnlTwitterOffers.sol/TunnlTwitterOffers.json';
require('dotenv').config()
export default task('set-config', 'Sets the config from ./deploymentArguments.ts')
  .addParam('contract', 'The address of the TunnlTwitterOffers contract')
  .setAction(async (taskArgs, hre) => {
    const provider = new ethers.JsonRpcProvider(process.env.RPC_URL!);
    const signer = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);
    const tunnlTwitterOffersContractFactory = new ethers.ContractFactory(abi, bytecode, signer);

    const tunnlTwitterOffersContract = tunnlTwitterOffersContractFactory.attach(taskArgs.contract) as any;

    const currentConfig: Config = await tunnlTwitterOffersContract.getConfig();
    console.log('Current config\n', getConfigObject(currentConfig));

    const newConfig: Config = convertToConfig(deploymentArguments[2]);
    console.log('New config\n', newConfig);

    let diff: Partial<Config> = {};
    for (const key in newConfig) {
      const currentVal = currentConfig[key as keyof Config];
      const newVal = newConfig[key as keyof Config];
      if (typeof newVal === 'string' || typeof currentVal === 'string') {
        if (newVal !== currentVal) {
          diff[key as keyof Config] = newVal;
        }
        continue;
      }
      if (typeof newVal === 'bigint' || typeof currentVal === 'bigint') {
        if (BigInt(newVal) !== BigInt(currentVal)) {
          diff[key as keyof Config] = newVal;
        }
        continue;
      }
    }
    console.log('Difference between configs\n', diff);

    if (!await promptUser()) {
      console.log('Cancelled');
      return;
    }

    const tx = await tunnlTwitterOffersContract.setConfig(getConfigObject(newConfig));
    console.log('Config set on:', taskArgs.contract);
    console.log('Transaction hash:', tx.hash);
  });

interface Config {
  [key: string]: bigint | string;
  automationUpkeepBatchSize: bigint;
  advertiserFeePercentageBP: bigint;
  creatorFeePercentageBP: bigint;
  functionsCallbackGasLimit: bigint;
  flatFeeUsdc: bigint;
  minOfferDurationSeconds: bigint;
  minAcceptanceDurationSeconds: bigint;
  maxVerificationDelaySeconds: bigint;
  functionsSubscriptionId: bigint;
  functionsDonId: string;
  functionsEncryptedSecretsReference: string;
  functionsVerificationRequestScript: string;
  functionsPayoutRequestScript: string;
}

function getConfigObject(config: Config): (bigint | string)[] {
  return Object.values(config);
}

function convertToConfig(obj: any): Config {
  return {
    automationUpkeepBatchSize: BigInt(obj.automationUpkeepBatchSize),
    advertiserFeePercentageBP: BigInt(obj.advertiserFeePercentageBP),
    creatorFeePercentageBP: BigInt(obj.creatorFeePercentageBP),
    functionsCallbackGasLimit: BigInt(obj.functionsCallbackGasLimit),
    flatFeeUsdc: BigInt(obj.flatFeeUsdc),
    minOfferDurationSeconds: BigInt(obj.minOfferDurationSeconds),
    minAcceptanceDurationSeconds: BigInt(obj.minAcceptanceDurationSeconds),
    maxVerificationDelaySeconds: BigInt(obj.maxVerificationDelaySeconds),
    functionsSubscriptionId: BigInt(obj.functionsSubscriptionId),
    functionsDonId: obj.functionsDonId,
    functionsEncryptedSecretsReference: obj.functionsEncryptedSecretsReference,
    functionsVerificationRequestScript: obj.functionsVerificationRequestScript,
    functionsPayoutRequestScript: obj.functionsPayoutRequestScript,
  };
}

function promptUser(): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question('Press "y" to proceed or any other key to cancel: ', (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}