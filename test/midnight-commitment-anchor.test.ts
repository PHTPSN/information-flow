import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  MidnightCommitmentAnchor,
  type MidnightRegisterFlowContract,
} from "../src/midnight-commitment-anchor.js";
import type { CommitmentAnchor } from "../src/register-information-flow.js";

const COMMITMENT = "ab".repeat(32);

describe("MidnightCommitmentAnchor", () => {
  it("forwards only the commitment and returns only the public transaction ID", async () => {
    const observedArguments: unknown[][] = [];
    const contract: MidnightRegisterFlowContract = {
      callTx: {
        async registerFlow(...args: [string]) {
          observedArguments.push(args);
          return {
            public: { txId: "midnight-public-tx-001" },
            private: { sensitiveTransactionData: "must-not-cross-boundary" },
          };
        },
      },
    };
    const anchor: CommitmentAnchor = new MidnightCommitmentAnchor(contract);

    const receipt = await anchor.registerFlow(COMMITMENT);

    assert.deepEqual(observedArguments, [[COMMITMENT]]);
    assert.deepEqual(receipt, { transactionId: "midnight-public-tx-001" });
    assert.equal("private" in receipt, false);
    assert.equal(
      JSON.stringify(receipt).includes("must-not-cross-boundary"),
      false,
    );
  });

  it("propagates a failed Midnight submission", async () => {
    const failure = new Error("Midnight transaction failed");
    const contract: MidnightRegisterFlowContract = {
      callTx: {
        async registerFlow() {
          throw failure;
        },
      },
    };
    const anchor = new MidnightCommitmentAnchor(contract);

    await assert.rejects(anchor.registerFlow(COMMITMENT), (error) => {
      assert.equal(error, failure);
      return true;
    });
  });
});
