import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FLOW_NONCE_BYTES,
  type InformationFlow,
} from "../src/information-flow.js";
import {
  prepareInformationFlowRegistration,
  registerInformationFlow,
  type CommitmentAnchor,
} from "../src/register-information-flow.js";

const FIXED_NONCE = Uint8Array.from(
  { length: FLOW_NONCE_BYTES },
  (_, index) => index,
);

function exampleFlow(): InformationFlow {
  return {
    schemaVersion: 2,
    flowId: "private-flow-001",
    context: {
      kind: "support",
      policyVersion: "support-policy-1",
    },
    actors: [
      { id: "private-person-123" },
      { id: "private-issuer-789" },
      { id: "private-recipient-456" },
    ],
    senderId: "private-person-123",
    records: [
      { id: "private-record-001", digest: "sha256:private-record" },
    ],
    claims: [
      {
        id: "private-claim-001",
        type: "support-eligibility",
        value: "private-eligible-value",
        issuerId: "private-issuer-789",
      },
    ],
    view: {
      recipient: {
        kind: "actor",
        actorId: "private-recipient-456",
      },
      visibleClaimIds: ["private-claim-001"],
    },
  };
}

describe("InformationFlow registration use case", () => {
  it("sends only the commitment across the anchor boundary", async () => {
    const flow = exampleFlow();
    const observedArguments: unknown[][] = [];
    const anchor: CommitmentAnchor = {
      async registerFlow(...args: [string]) {
        observedArguments.push(args);
        return { transactionId: "tx-public-001" };
      },
    };

    const prepared = prepareInformationFlowRegistration(flow, FIXED_NONCE);
    const receipt = await registerInformationFlow(prepared, anchor);

    assert.deepEqual(observedArguments, [[prepared.commitment]]);
    assert.deepEqual(receipt, {
      commitment: prepared.commitment,
      transactionId: "tx-public-001",
    });

    const boundaryPayload = JSON.stringify(observedArguments);
    assert.equal(boundaryPayload.includes(flow.flowId), false);
    assert.equal(boundaryPayload.includes(flow.claims[0]!.value), false);
    assert.equal(boundaryPayload.includes(flow.actors[0]!.id), false);
    assert.equal(
      boundaryPayload.includes(Buffer.from(FIXED_NONCE).toString("hex")),
      false,
    );
    assert.equal("privateNonce" in receipt, false);
  });

  it("rejects an invalid flow before an anchor can be called", () => {
    let anchorWasCalled = false;
    const anchor: CommitmentAnchor = {
      async registerFlow() {
        anchorWasCalled = true;
        return { transactionId: "unexpected" };
      },
    };
    const flow = exampleFlow();

    assert.throws(
      () =>
        prepareInformationFlowRegistration(
          {
            ...flow,
            view: {
              ...flow.view,
              recipient: {
                kind: "actor",
                actorId: "missing-recipient",
              },
            },
          },
          FIXED_NONCE,
        ),
      /no actor exists/,
    );
    assert.equal(anchorWasCalled, false);

    // Keep the anchor in scope to make the boundary assertion explicit.
    assert.equal(typeof anchor.registerFlow, "function");
  });

  it("retries a failed submission with the same commitment", async () => {
    const observedCommitments: string[] = [];
    const anchor: CommitmentAnchor = {
      async registerFlow(commitment) {
        observedCommitments.push(commitment);
        if (observedCommitments.length === 1) {
          throw new Error("temporary network failure");
        }
        return { transactionId: "tx-public-retry" };
      },
    };
    const prepared = prepareInformationFlowRegistration(
      exampleFlow(),
      FIXED_NONCE,
    );

    await assert.rejects(
      registerInformationFlow(prepared, anchor),
      /temporary network failure/,
    );
    const receipt = await registerInformationFlow(prepared, anchor);

    assert.deepEqual(observedCommitments, [
      prepared.commitment,
      prepared.commitment,
    ]);
    assert.equal(receipt.commitment, prepared.commitment);
  });

  it("rejects malformed commitments and anchor receipts", async () => {
    let anchorWasCalled = false;
    const unusedAnchor: CommitmentAnchor = {
      async registerFlow() {
        anchorWasCalled = true;
        return { transactionId: "unexpected" };
      },
    };

    await assert.rejects(
      registerInformationFlow({ commitment: "not-a-commitment" }, unusedAnchor),
      /64-character lowercase hex value/,
    );
    assert.equal(anchorWasCalled, false);

    const invalidReceiptAnchor = {
      async registerFlow() {
        return { transactionId: "" };
      },
    } satisfies CommitmentAnchor;
    const prepared = prepareInformationFlowRegistration(
      exampleFlow(),
      FIXED_NONCE,
    );

    await assert.rejects(
      registerInformationFlow(prepared, invalidReceiptAnchor),
      /non-empty transaction identifier/,
    );
  });
});
