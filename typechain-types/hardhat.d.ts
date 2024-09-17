/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { ethers } from "ethers";
import {
  DeployContractOptions,
  FactoryOptions,
  HardhatEthersHelpers as HardhatEthersHelpersBase,
} from "@nomicfoundation/hardhat-ethers/types";

import * as Contracts from ".";

declare module "hardhat/types/runtime" {
  interface HardhatEthersHelpers extends HardhatEthersHelpersBase {
    getContractFactory(
      name: "AutomationBase",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AutomationBase__factory>;
    getContractFactory(
      name: "AutomationCompatible",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AutomationCompatible__factory>;
    getContractFactory(
      name: "AutomationCompatibleInterface",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AutomationCompatibleInterface__factory>;
    getContractFactory(
      name: "FunctionsClient",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.FunctionsClient__factory>;
    getContractFactory(
      name: "IFunctionsClient",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IFunctionsClient__factory>;
    getContractFactory(
      name: "IFunctionsRouter",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IFunctionsRouter__factory>;
    getContractFactory(
      name: "IFunctionsSubscriptions",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IFunctionsSubscriptions__factory>;
    getContractFactory(
      name: "FunctionsRequest",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.FunctionsRequest__factory>;
    getContractFactory(
      name: "Ownable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Ownable__factory>;
    getContractFactory(
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC1155Errors__factory>;
    getContractFactory(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Errors__factory>;
    getContractFactory(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Errors__factory>;
    getContractFactory(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20__factory>;
    getContractFactory(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Metadata__factory>;
    getContractFactory(
      name: "IERC20Permit",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Permit__factory>;
    getContractFactory(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20__factory>;
    getContractFactory(
      name: "SafeERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.SafeERC20__factory>;
    getContractFactory(
      name: "Address",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Address__factory>;
    getContractFactory(
      name: "Math",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Math__factory>;
    getContractFactory(
      name: "ReentrancyGuard",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ReentrancyGuard__factory>;
    getContractFactory(
      name: "TunnlTwitterOffers",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.TunnlTwitterOffers__factory>;

    getContractAt(
      name: "AutomationBase",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AutomationBase>;
    getContractAt(
      name: "AutomationCompatible",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AutomationCompatible>;
    getContractAt(
      name: "AutomationCompatibleInterface",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.AutomationCompatibleInterface>;
    getContractAt(
      name: "FunctionsClient",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.FunctionsClient>;
    getContractAt(
      name: "IFunctionsClient",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IFunctionsClient>;
    getContractAt(
      name: "IFunctionsRouter",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IFunctionsRouter>;
    getContractAt(
      name: "IFunctionsSubscriptions",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IFunctionsSubscriptions>;
    getContractAt(
      name: "FunctionsRequest",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.FunctionsRequest>;
    getContractAt(
      name: "Ownable",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Ownable>;
    getContractAt(
      name: "IERC1155Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC1155Errors>;
    getContractAt(
      name: "IERC20Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Errors>;
    getContractAt(
      name: "IERC721Errors",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC721Errors>;
    getContractAt(
      name: "ERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ERC20>;
    getContractAt(
      name: "IERC20Metadata",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Metadata>;
    getContractAt(
      name: "IERC20Permit",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20Permit>;
    getContractAt(
      name: "IERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.IERC20>;
    getContractAt(
      name: "SafeERC20",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.SafeERC20>;
    getContractAt(
      name: "Address",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Address>;
    getContractAt(
      name: "Math",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.Math>;
    getContractAt(
      name: "ReentrancyGuard",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.ReentrancyGuard>;
    getContractAt(
      name: "TunnlTwitterOffers",
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<Contracts.TunnlTwitterOffers>;

    deployContract(
      name: "AutomationBase",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationBase>;
    deployContract(
      name: "AutomationCompatible",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationCompatible>;
    deployContract(
      name: "AutomationCompatibleInterface",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationCompatibleInterface>;
    deployContract(
      name: "FunctionsClient",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.FunctionsClient>;
    deployContract(
      name: "IFunctionsClient",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsClient>;
    deployContract(
      name: "IFunctionsRouter",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsRouter>;
    deployContract(
      name: "IFunctionsSubscriptions",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsSubscriptions>;
    deployContract(
      name: "FunctionsRequest",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.FunctionsRequest>;
    deployContract(
      name: "Ownable",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Ownable>;
    deployContract(
      name: "IERC1155Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC20>;
    deployContract(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Metadata>;
    deployContract(
      name: "IERC20Permit",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Permit>;
    deployContract(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20>;
    deployContract(
      name: "SafeERC20",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SafeERC20>;
    deployContract(
      name: "Address",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Address>;
    deployContract(
      name: "Math",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Math>;
    deployContract(
      name: "ReentrancyGuard",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ReentrancyGuard>;
    deployContract(
      name: "TunnlTwitterOffers",
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TunnlTwitterOffers>;

    deployContract(
      name: "AutomationBase",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationBase>;
    deployContract(
      name: "AutomationCompatible",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationCompatible>;
    deployContract(
      name: "AutomationCompatibleInterface",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.AutomationCompatibleInterface>;
    deployContract(
      name: "FunctionsClient",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.FunctionsClient>;
    deployContract(
      name: "IFunctionsClient",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsClient>;
    deployContract(
      name: "IFunctionsRouter",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsRouter>;
    deployContract(
      name: "IFunctionsSubscriptions",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IFunctionsSubscriptions>;
    deployContract(
      name: "FunctionsRequest",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.FunctionsRequest>;
    deployContract(
      name: "Ownable",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Ownable>;
    deployContract(
      name: "IERC1155Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC1155Errors>;
    deployContract(
      name: "IERC20Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Errors>;
    deployContract(
      name: "IERC721Errors",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC721Errors>;
    deployContract(
      name: "ERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ERC20>;
    deployContract(
      name: "IERC20Metadata",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Metadata>;
    deployContract(
      name: "IERC20Permit",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20Permit>;
    deployContract(
      name: "IERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.IERC20>;
    deployContract(
      name: "SafeERC20",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.SafeERC20>;
    deployContract(
      name: "Address",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Address>;
    deployContract(
      name: "Math",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.Math>;
    deployContract(
      name: "ReentrancyGuard",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.ReentrancyGuard>;
    deployContract(
      name: "TunnlTwitterOffers",
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<Contracts.TunnlTwitterOffers>;

    // default types
    getContractFactory(
      name: string,
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<ethers.ContractFactory>;
    getContractFactory(
      abi: any[],
      bytecode: ethers.BytesLike,
      signer?: ethers.Signer
    ): Promise<ethers.ContractFactory>;
    getContractAt(
      nameOrAbi: string | any[],
      address: string | ethers.Addressable,
      signer?: ethers.Signer
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
    deployContract(
      name: string,
      args: any[],
      signerOrOptions?: ethers.Signer | DeployContractOptions
    ): Promise<ethers.Contract>;
  }
}
