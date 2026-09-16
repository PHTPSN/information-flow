import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { ContractAddress } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";

import {
  connectInformationFlowContract,
  deployInformationFlowContract,
  type ConnectedInformationFlowContract,
  type DeployedInformationFlowContract,
} from "../src/midnight-contract-connection.js";
import { informationFlowCompiledContract } from "../src/midnight-information-flow-contract.js";
import type { InformationFlowProviders } from "../src/midnight-providers.js";

describe("Information Flow contract deployment and connection", () => {
  it("deploys with only providers and the compiled contract", async () => {
    const providers = {} as InformationFlowProviders;
    const deployed = { callTx: { registerFlow: async () => ({}) } } as unknown as
      DeployedInformationFlowContract;
    let receivedOptions: unknown;

    const result = await deployInformationFlowContract(
      providers,
      async (receivedProviders, options) => {
        assert.equal(receivedProviders, providers);
        receivedOptions = options;
        return deployed;
      },
    );

    assert.equal(result, deployed);
    assert.deepEqual(receivedOptions, {
      compiledContract: informationFlowCompiledContract,
    });
  });

  it("connects with only providers, compiled contract, and public address", async () => {
    const providers = {} as InformationFlowProviders;
    const contractAddress = "00".repeat(32) as ContractAddress;
    const connected = { callTx: { registerFlow: async () => ({}) } } as unknown as
      ConnectedInformationFlowContract;
    let receivedOptions: unknown;

    const result = await connectInformationFlowContract(
      providers,
      contractAddress,
      async (receivedProviders, options) => {
        assert.equal(receivedProviders, providers);
        receivedOptions = options;
        return connected;
      },
    );

    assert.equal(result, connected);
    assert.deepEqual(receivedOptions, {
      compiledContract: informationFlowCompiledContract,
      contractAddress,
    });
  });
});
