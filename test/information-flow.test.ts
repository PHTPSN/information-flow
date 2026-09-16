import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FLOW_NONCE_BYTES,
  canonicalizeInformationFlow,
  commitInformationFlow,
  generateFlowNonce,
  type InformationFlow,
} from "../src/information-flow.js";

const FIXED_NONCE = Uint8Array.from(
  { length: FLOW_NONCE_BYTES },
  (_, index) => index,
);

function exampleFlow(): InformationFlow {
  return {
    schemaVersion: 2,
    flowId: "flow-2026-001",
    context: {
      kind: "support",
      policyVersion: "support-policy-1",
    },
    actors: [
      { id: "person-123" },
      { id: "registry-789" },
      { id: "agency-456" },
    ],
    senderId: "person-123",
    records: [
      { id: "income-record-001", digest: "sha256:income-record" },
      { id: "identity-record-001", digest: "sha256:identity-record" },
    ],
    claims: [
      {
        id: "claim-income",
        type: "income-eligibility",
        value: "eligible",
        issuerId: "registry-789",
      },
      {
        id: "claim-age",
        type: "age-threshold",
        value: "over-18",
        issuerId: "registry-789",
      },
    ],
    view: {
      recipient: { kind: "actor", actorId: "agency-456" },
      visibleClaimIds: ["claim-income", "claim-age"],
    },
  };
}

describe("InformationFlow commitment", () => {
  it("is stable for the same flow and nonce", () => {
    const flow = exampleFlow();
    const first = commitInformationFlow(flow, FIXED_NONCE);
    const second = commitInformationFlow(flow, FIXED_NONCE);

    assert.equal(first, second);
    assert.match(first, /^[0-9a-f]{64}$/);
  });

  it("ignores object-key and collection ordering", () => {
    const flow = exampleFlow();
    const reordered: InformationFlow = {
      view: {
        visibleClaimIds: [...flow.view.visibleClaimIds].reverse(),
        recipient: flow.view.recipient,
      },
      claims: [...flow.claims]
        .reverse()
        .map(({ id, type, value, issuerId }) => ({
          value,
          issuerId,
          type,
          id,
        })),
      records: [...flow.records].reverse(),
      actors: [...flow.actors].reverse(),
      senderId: flow.senderId,
      context: {
        policyVersion: flow.context.policyVersion,
        kind: flow.context.kind,
      },
      flowId: flow.flowId,
      schemaVersion: flow.schemaVersion,
    };

    assert.notEqual(JSON.stringify(flow), JSON.stringify(reordered));
    assert.equal(
      canonicalizeInformationFlow(flow),
      canonicalizeInformationFlow(reordered),
    );
    assert.equal(
      commitInformationFlow(flow, FIXED_NONCE),
      commitInformationFlow(reordered, FIXED_NONCE),
    );
  });

  it("changes when meaningful flow data changes", () => {
    const flow = exampleFlow();
    const changed: InformationFlow = {
      ...flow,
      claims: flow.claims.map((claim) =>
        claim.id === "claim-income"
          ? { ...claim, value: "not-eligible" }
          : claim,
      ),
    };

    assert.notEqual(
      commitInformationFlow(flow, FIXED_NONCE),
      commitInformationFlow(changed, FIXED_NONCE),
    );
  });

  it("separates identical flows with different nonces", () => {
    const otherNonce = Uint8Array.from(FIXED_NONCE);
    otherNonce[0] = 255;

    assert.notEqual(
      commitInformationFlow(exampleFlow(), FIXED_NONCE),
      commitInformationFlow(exampleFlow(), otherNonce),
    );
  });

  it("normalizes visually equivalent Unicode text", () => {
    const composed = { ...exampleFlow(), flowId: "flow-caf\u00e9" };
    const decomposed = { ...exampleFlow(), flowId: "flow-cafe\u0301" };

    assert.equal(
      commitInformationFlow(composed, FIXED_NONCE),
      commitInformationFlow(decomposed, FIXED_NONCE),
    );
  });

  it("rejects invalid references, unknown fields, and nonce sizes", () => {
    const flow = exampleFlow();

    assert.throws(
      () =>
        commitInformationFlow(
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

    assert.throws(
      () => canonicalizeInformationFlow({ ...flow, debug: true }),
      /unexpected debug/,
    );

    assert.throws(
      () => commitInformationFlow(flow, generateFlowNonce().subarray(1)),
      /expected exactly 32 bytes/,
    );
  });
});
