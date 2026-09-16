import type { Logger } from "pino";

import {
  MidnightCommitmentAnchor,
  type MidnightRegisterFlowContract,
} from "./midnight-commitment-anchor.js";
import {
  informationFlowCompiledContract,
  type InformationFlowContract,
} from "./midnight-information-flow-contract.js";
import {
  createInformationFlowProviders,
  type InformationFlowProviders,
} from "./midnight-providers.js";
import {
  createLocalMidnightWallet,
  type CreateLocalMidnightWalletOptions,
  type ManagedMidnightWallet,
} from "./midnight-wallet.js";
import type { PrivateStoragePasswordProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";

/**
 * The assembled application-facing runtime. The compiled contract is paired
 * with a connected contract interface supplied by the deployment/lookup step.
 */
export interface InformationFlowComposition {
  readonly wallet: ManagedMidnightWallet;
  readonly providers: InformationFlowProviders;
  readonly compiledContract: typeof informationFlowCompiledContract;
  readonly contract: MidnightRegisterFlowContract;
  readonly anchor: MidnightCommitmentAnchor;
  readonly close: () => Promise<void>;
}

export interface CreateInformationFlowCompositionOptions
  extends Pick<
    CreateLocalMidnightWalletOptions,
    "environment" | "secretProvider" | "logger" | "buildAndSynchronize"
  > {
  /** A previously deployed/connected contract's narrow public call surface. */
  readonly contract: MidnightRegisterFlowContract;
  /** Password callback retained by encrypted private-state storage. */
  readonly privateStoragePasswordProvider: PrivateStoragePasswordProvider;
}

function invalid(message: string): never {
  throw new TypeError(`Information Flow composition: ${message}`);
}

function assertContract(contract: MidnightRegisterFlowContract): void {
  if (
    typeof contract !== "object" ||
    contract === null ||
    typeof contract.callTx !== "object" ||
    contract.callTx === null ||
    typeof contract.callTx.registerFlow !== "function"
  ) {
    invalid("contract must expose callTx.registerFlow");
  }
}

/**
 * Assemble the local wallet, Midnight.js providers, compiled contract, and
 * privacy-preserving commitment anchor. This function does not deploy a
 * contract or submit a transaction.
 */
export async function createInformationFlowComposition(
  options: CreateInformationFlowCompositionOptions,
): Promise<InformationFlowComposition> {
  if (typeof options !== "object" || options === null) {
    invalid("options must be an object");
  }
  assertContract(options.contract);

  const walletOptions = {
    environment: options.environment,
    secretProvider: options.secretProvider,
    ...(options.logger === undefined ? {} : { logger: options.logger }),
    ...(options.buildAndSynchronize === undefined
      ? {}
      : { buildAndSynchronize: options.buildAndSynchronize }),
  } satisfies CreateLocalMidnightWalletOptions;
  const wallet = await createLocalMidnightWallet(walletOptions);

  try {
    const providers = createInformationFlowProviders({
      endpoints: {
        indexer: options.environment.indexer,
        indexerWS: options.environment.indexerWS,
        proofServer: options.environment.proofServer,
      },
      wallet,
      privateStoragePasswordProvider:
        options.privateStoragePasswordProvider,
    });
    const anchor = new MidnightCommitmentAnchor(options.contract);

    let closed = false;
    const close = async (): Promise<void> => {
      if (closed) return;
      closed = true;
      await wallet.stop();
    };

    return {
      wallet,
      providers,
      compiledContract: informationFlowCompiledContract,
      contract: options.contract,
      anchor,
      close,
    };
  } catch (error) {
    await wallet.stop().catch(() => undefined);
    throw error;
  }
}

/** Keep the generated contract type visible to composition callers. */
export type { InformationFlowContract };
