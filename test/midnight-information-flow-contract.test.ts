import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import path from "node:path";
import { describe, it } from "node:test";

import { CompiledContract } from "@midnight-ntwrk/midnight-js-protocol/compact-js";

import {
  INFORMATION_FLOW_COMPILED_ASSETS_PATH,
  INFORMATION_FLOW_CONTRACT_TAG,
  informationFlowCompiledContract,
} from "../src/midnight-information-flow-contract.js";

describe("Information Flow compiled contract", () => {
  it("binds the generated contract to its compiled ZK assets", async () => {
    assert.equal(
      informationFlowCompiledContract.tag,
      INFORMATION_FLOW_CONTRACT_TAG,
    );
    assert.equal(
      CompiledContract.getCompiledAssetsPath(informationFlowCompiledContract),
      INFORMATION_FLOW_COMPILED_ASSETS_PATH,
    );

    await Promise.all(
      [
        "contract/index.js",
        "keys/registerFlow.prover",
        "keys/registerFlow.verifier",
        "zkir/registerFlow.zkir",
      ].map((relativePath) =>
        access(path.join(INFORMATION_FLOW_COMPILED_ASSETS_PATH, relativePath)),
      ),
    );
  });
});
