import path from "node:path";
import { fileURLToPath } from "node:url";

import { CompiledContract } from "@midnight-ntwrk/midnight-js-protocol/compact-js";

import { Contract as GeneratedContract } from "../contracts/managed/information-flow/contract/index.js";

export type InformationFlowContract = GeneratedContract<undefined>;

export const INFORMATION_FLOW_CONTRACT_TAG = "information-flow";

export const INFORMATION_FLOW_COMPILED_ASSETS_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../contracts/managed/information-flow",
);

/**
 * The generated Compact binding paired with its prover, verifier, and ZKIR
 * files. This definition contains no wallet, private flow, nonce, or network
 * connection.
 */
export const informationFlowCompiledContract = CompiledContract.make<InformationFlowContract>(
  INFORMATION_FLOW_CONTRACT_TAG,
  GeneratedContract,
).pipe(
  CompiledContract.withVacantWitnesses,
  CompiledContract.withCompiledFileAssets(
    INFORMATION_FLOW_COMPILED_ASSETS_PATH,
  ),
);
