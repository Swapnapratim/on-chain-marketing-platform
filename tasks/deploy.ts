import { task } from 'hardhat/config';
import deploymentArguments from '../deploymentArguments';

export default task('deploy', 'Deploy the contract')
  .setAction(async (taskArgs, hre) => {
    await hre.run('compile');
    console.log('Successfully compiled');
    
    const tunnlTwitterOffersContractFactory = await hre.ethers.getContractFactory('TunnlTwitterOffers');

    const functionsRouterAddress = deploymentArguments[0];
    const usdcTokenAddress = deploymentArguments[1];
    const contractConfig = deploymentArguments[2];

    const deployTx = await tunnlTwitterOffersContractFactory.deploy(
      functionsRouterAddress,
      usdcTokenAddress,
      contractConfig,
    );
    console.log("deployed");
    const tunnlTwitterOffersContract = await deployTx.waitForDeployment();
    const contractAddress = await tunnlTwitterOffersContract.getAddress();
    console.log('TunnlTwitterOffers deployed to:', contractAddress);

    // Add admin
    console.log('Adding admin...');
    const isMainnet = process.env.STAGE === 'mainnet';
    const backendAdminAddress = isMainnet ? "0xA3dE2Cad3945d88B77B083B725f7166332E1238D" : '0x53238DFb7c7C3936929666Df17A2f403558723C6';
    await tunnlTwitterOffersContract.addAdmin(backendAdminAddress);
    console.log('Admin added:', backendAdminAddress);

    // Verify the contract after deployment
    console.log('Verifying contract...');
    await hre.run('verify:verify', {
      address: contractAddress,
      constructorArguments: deploymentArguments,
    });
  });