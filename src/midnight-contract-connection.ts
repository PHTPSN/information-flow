import {
  deployContract,
  findDeployedContract,
  type DeployedContract,
  type FoundContract,
} from "@midnight-ntwrk/midnight-js-contracts";
import type { ContractAddress } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";

import {
  informationFlowCompiledContract,
  type InformationFlowContract,
} from "./midnight-information-flow-contract.js";
import type { InformationFlowProviders } from "./midnight-providers.js";

export type DeployedInformationFlowContract =
  DeployedContract<InformationFlowContract>;
export type ConnectedInformationFlowContract =
  FoundContract<InformationFlowContract>;

export type DeployInformationFlow = (
  providers: InformationFlowProviders,
  options: { readonly compiledContract: typeof informationFlowCompiledContract },
) => Promise<DeployedInformationFlowContract>;

export type FindInformationFlow = (
  providers: InformationFlowProviders,
  options: {
    readonly compiledContract: typeof informationFlowCompiledContract;
    readonly contractAddress: ContractAddress;
  },
) => Promise<ConnectedInformationFlowContract>;

/** Deploy the stateless Information Flow contract without application data. */
export async function deployInformationFlowContract(
  providers: InformationFlowProviders,
  deploy: DeployInformationFlow = (receivedProviders, options) =>
    deployContract<InformationFlowContract>(receivedProviders, options),
): Promise<DeployedInformationFlowContract> {
  return deploy(providers, {
    compiledContract: informationFlowCompiledContract,
  });
}

/** Reconnect to a deployment using only its public contract address. */
export async function connectInformationFlowContract(
  providers: InformationFlowProviders,
  contractAddress: ContractAddress,
  find: FindInformationFlow = (receivedProviders, options) =>
    findDeployedContract<InformationFlowContract>(receivedProviders, options),
): Promise<ConnectedInformationFlowContract> {
  return find(providers, {
    compiledContract: informationFlowCompiledContract,
    contractAddress,
  });
}
