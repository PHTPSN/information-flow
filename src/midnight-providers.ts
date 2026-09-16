import { Buffer } from "node:buffer";

import type { ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import {
  levelPrivateStateProvider,
  type PrivateStoragePasswordProvider,
} from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type { Contract as CompactContract } from "@midnight-ntwrk/midnight-js-protocol/compact-js/effect/Contract";
import type {
  MidnightProvider,
  PrivateStateId,
  WalletProvider,
} from "@midnight-ntwrk/midnight-js-types";

import {
  INFORMATION_FLOW_COMPILED_ASSETS_PATH,
  type InformationFlowContract,
} from "./midnight-information-flow-contract.js";

export const INFORMATION_FLOW_PRIVATE_STATE_STORE =
  "information-flow-private-state";
export const INFORMATION_FLOW_SIGNING_KEY_STORE =
  "information-flow-signing-keys";

export interface MidnightProviderEndpoints {
  readonly indexer: string;
  readonly indexerWS: string;
  readonly proofServer: string;
}

/**
 * A wallet capability that can both balance and submit Midnight transactions.
 * The wallet's mnemonic, seed, and signing keys remain outside this interface.
 */
export type MidnightWalletCapability = WalletProvider & MidnightProvider;

export interface CreateInformationFlowProvidersOptions {
  readonly endpoints: MidnightProviderEndpoints;
  readonly wallet: MidnightWalletCapability;
  readonly privateStoragePasswordProvider: PrivateStoragePasswordProvider;
  /** Optional isolated LevelDB path, primarily for disposable live tests. */
  readonly privateStateDatabaseName?: string;
}

type InformationFlowCircuitId = CompactContract.ProvableCircuitId<InformationFlowContract>;

export type InformationFlowProviders = ContractProviders<InformationFlowContract>;

/**
 * Assemble the provider set used by Midnight.js to deploy and call the
 * Information Flow contract. Construction is local and performs no network
 * requests or wallet transactions.
 */
export function createInformationFlowProviders(
  options: CreateInformationFlowProvidersOptions,
): InformationFlowProviders {
  const zkConfigProvider =
    new NodeZkConfigProvider<InformationFlowCircuitId>(
      INFORMATION_FLOW_COMPILED_ASSETS_PATH,
    );
  const accountId = Buffer.from(options.wallet.getCoinPublicKey()).toString(
    "hex",
  );

  return {
    privateStateProvider: levelPrivateStateProvider<PrivateStateId, undefined>({
      privateStateStoreName: INFORMATION_FLOW_PRIVATE_STATE_STORE,
      signingKeyStoreName: INFORMATION_FLOW_SIGNING_KEY_STORE,
      privateStoragePasswordProvider:
        options.privateStoragePasswordProvider,
      accountId,
      ...(options.privateStateDatabaseName === undefined
        ? {}
        : { midnightDbName: options.privateStateDatabaseName }),
    }),
    publicDataProvider: indexerPublicDataProvider(
      options.endpoints.indexer,
      options.endpoints.indexerWS,
    ),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(
      options.endpoints.proofServer,
      zkConfigProvider,
    ),
    walletProvider: options.wallet,
    midnightProvider: options.wallet,
  };
}
