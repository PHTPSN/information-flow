import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as signPayload,
  type KeyObject,
} from "node:crypto";
import { describe, it } from "node:test";

import {
  BehaviorDerivedInformationFlowSystem,
  PolicyDeniedError,
  authorityGrantSigningPayload,
  evidenceBridgeSigningPayload,
  hashHolderSecret,
  purchaseCredentialSigningPayload,
  supportDecisionSigningPayload,
  type PolicyDenialCode,
  type SignedAuthorityGrant,
  type SignedEvidenceBridge,
  type SignedPurchaseCredential,
  type SignedSupportDecision,
} from "../src/behavior-derived-system.js";

function signingIdentity(): {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
} {
  const pair = generateKeyPairSync("ed25519");
  return {
    publicKey: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: pair.privateKey,
  };
}

function sign(payload: string, privateKey: KeyObject): string {
  return signPayload(null, Buffer.from(payload, "utf8"), privateKey).toString(
    "base64url",
  );
}

function expectPolicyDenial(
  operation: () => unknown,
  code: PolicyDenialCode,
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof PolicyDeniedError);
    assert.equal(error.code, code);
    return true;
  });
}

function scenarioFixture(): {
  readonly system: BehaviorDerivedInformationFlowSystem;
  readonly authority: ReturnType<typeof signingIdentity>;
  readonly actors: Readonly<Record<string, ReturnType<typeof signingIdentity>>>;
} {
  const authority = signingIdentity();
  const actors = {
    "actor-a": signingIdentity(),
    "actor-b": signingIdentity(),
    "actor-c": signingIdentity(),
    "actor-d": signingIdentity(),
  } as const;
  let nonceIndex = 0;
  const system = new BehaviorDerivedInformationFlowSystem({
    trustedAuthorityId: "test-authority",
    trustedAuthorityPublicKey: authority.publicKey,
    regulatoryScopeId: "consumer-products-demo",
    nonceFactory: () => {
      nonceIndex += 1;
      return Uint8Array.from({ length: 32 }, (_, index) =>
        (index + nonceIndex) % 256,
      );
    },
  });
  return { system, authority, actors };
}

function registerFourNeutralActors(
  system: BehaviorDerivedInformationFlowSystem,
  actors: Readonly<Record<string, ReturnType<typeof signingIdentity>>>,
): void {
  for (const actorId of ["actor-a", "actor-b", "actor-c", "actor-d"] as const) {
    const registration = system.registerActor({
      actorId,
      signingPublicKey: actors[actorId]!.publicKey,
    });
    assert.deepEqual(Object.keys(registration).sort(), [
      "actorId",
      "signingPublicKey",
    ]);
    assert.deepEqual(system.deriveCapabilities(actorId), []);
  }
}

describe("four neutral actors gain contextual capabilities through behavior", () => {
  it("starts blank and rejects a permanent role at registration", () => {
    const { system, actors } = scenarioFixture();

    assert.deepEqual(system.listActors(), []);
    assert.deepEqual(system.getEvents(), []);
    assert.deepEqual(system.getPublicCommitmentRecords(), []);

    assert.throws(
      () =>
        system.registerActor({
          actorId: "actor-a",
          signingPublicKey: actors["actor-a"]!.publicKey,
          role: "buyer",
        }),
      /unexpected role/,
    );

    registerFourNeutralActors(system, actors);
    assert.equal("setRole" in system, false);
    assert.equal(
      system.listActors().every((actor) => !("role" in actor)),
      true,
    );
  });

  it("executes Acme H1 review, support, and REG-443 without a registered role", () => {
    const { system, authority, actors } = scenarioFixture();
    registerFourNeutralActors(system, actors);

    system.registerOrganization({
      organizationId: "acme-audio",
      name: "Acme Audio",
      registeredBy: "actor-b",
    });
    system.registerProduct({
      productId: "H1",
      name: "H1 Headphones",
      organizationId: "acme-audio",
      registeredBy: "actor-b",
    });

    assert.deepEqual(system.canIssuePurchaseCredential("actor-b", "H1"), {
      allowed: false,
      code: "AUTHORITY_REQUIRED",
      reason:
        "actor-b has no signed authority grant to issue H1 purchase credentials",
    });
    for (const actorId of ["actor-a", "actor-c", "actor-d"]) {
      assert.equal(
        system.canIssuePurchaseCredential(actorId, "H1").allowed,
        false,
      );
    }

    const selfDeclaredGrant = {
      grantId: "self-declared-issuer",
      authorityId: "actor-b",
      granteeId: "actor-b",
      capability: "issue-purchase-credential",
      scopeId: "H1",
      issuedAt: "2026-09-01T00:00:00.000Z",
    } as const;
    expectPolicyDenial(
      () =>
        system.grantAuthority({
          ...selfDeclaredGrant,
          signature: sign(
            authorityGrantSigningPayload(selfDeclaredGrant),
            actors["actor-b"]!.privateKey,
          ),
        }),
      "SIGNATURE_INVALID",
    );

    const issuerGrant = {
      grantId: "grant-acme-h1-issuer",
      authorityId: "test-authority",
      granteeId: "actor-b",
      capability: "issue-purchase-credential",
      scopeId: "H1",
      issuedAt: "2026-09-01T00:00:00.000Z",
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    system.grantAuthority({
      ...issuerGrant,
      signature: sign(
        authorityGrantSigningPayload(issuerGrant),
        authority.privateKey,
      ),
    });

    assert.equal(
      system.canIssuePurchaseCredential("actor-b", "H1").allowed,
      true,
    );
    assert.equal(
      system.canIssuePurchaseCredential("actor-a", "H1").allowed,
      false,
    );

    const holderSecret = "actor-a-private-holder-secret";
    const unsignedCredential = {
      credentialId: "credential-h1-a",
      productId: "H1",
      issuerId: "actor-b",
      holderId: "actor-a",
      orderId: "ORD-88421",
      purchasedAt: "2026-09-01T00:00:00.000Z",
      holderSecretHash: hashHolderSecret(holderSecret),
    } as const satisfies Omit<SignedPurchaseCredential, "signature">;
    system.issuePurchaseCredential({
      ...unsignedCredential,
      signature: sign(
        purchaseCredentialSigningPayload(unsignedCredential),
        actors["actor-b"]!.privateKey,
      ),
    });

    const actorACapabilities = system.deriveCapabilities("actor-a");
    assert.deepEqual(
      actorACapabilities.map(({ action, resourceId }) => ({ action, resourceId })),
      [
        { action: "publish-product-review", resourceId: "H1" },
        { action: "request-product-support", resourceId: "H1" },
        { action: "authorize-regulatory-bridge", resourceId: "H1" },
      ],
    );
    assert.deepEqual(system.deriveCapabilities("actor-c"), []);
    assert.deepEqual(system.deriveCapabilities("actor-d"), []);

    const publicReview = system.publishReview({
      reviewId: "review-h1-a",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret,
      rating: 2,
      text: "The battery swelled after twelve days of normal use.",
      publishedAt: "2026-09-13T09:00:00.000Z",
    });

    assert.match(publicReview.commitment, /^[0-9a-f]{64}$/);
    assert.match(publicReview.scopedNullifier, /^[0-9a-f]{64}$/);
    assert.deepEqual(
      {
        productId: publicReview.productId,
        rating: publicReview.rating,
        text: publicReview.text,
        verifiedPurchase: publicReview.verifiedPurchase,
      },
      {
        productId: "H1",
        rating: 2,
        text: "The battery swelled after twelve days of normal use.",
        verifiedPurchase: true,
      },
    );
    const publicReviewJson = JSON.stringify(publicReview);
    for (const forbidden of [
      "actor-a",
      "ORD-88421",
      "2026-09-01",
      "credential-h1-a",
      holderSecret,
    ]) {
      assert.equal(publicReviewJson.includes(forbidden), false);
    }

    expectPolicyDenial(
      () =>
        system.publishReview({
          reviewId: "review-h1-a-duplicate",
          actorId: "actor-a",
          credentialId: "credential-h1-a",
          holderSecret,
          rating: 3,
          text: "A duplicate attempt.",
          publishedAt: "2026-09-13T09:01:00.000Z",
        }),
      "DUPLICATE_SCOPED_USE",
    );

    const reviewReadByActorC = system.readPublicReview(
      "actor-c",
      "review-h1-a",
    );
    assert.deepEqual(reviewReadByActorC, publicReview);
    assert.deepEqual(system.deriveCapabilities("actor-c"), []);

    const supportView = system.requestSupport({
      caseId: "CASE-992",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret,
      organizationId: "acme-audio",
      request: "replacement",
      requestedAt: "2026-09-13T10:00:00.000Z",
      policyVersion: "support-policy-1",
    });
    assert.deepEqual(supportView.eligibility, {
      issuedByOrganization: true,
      purchasedWithinThirtyDays: true,
      replacementEntitlementUnused: true,
    });
    assert.notEqual(supportView.contextSubjectId, publicReview.scopedNullifier);
    const supportJson = JSON.stringify(supportView);
    for (const forbidden of [
      "actor-a",
      "ORD-88421",
      "review-h1-a",
      publicReview.text,
      holderSecret,
    ]) {
      assert.equal(supportJson.includes(forbidden), false);
    }
    expectPolicyDenial(
      () => system.readSupportCase("actor-c", "CASE-992"),
      "RECIPIENT_MISMATCH",
    );

    const unsignedDecision = {
      decisionId: "decision-case-992",
      caseId: "CASE-992",
      issuerId: "actor-b",
      outcome: "rejected",
      reason: "Inspection is required before replacement approval.",
      decidedAt: "2026-09-13T11:00:00.000Z",
      policyVersion: "support-policy-1",
    } as const satisfies Omit<SignedSupportDecision, "signature">;
    system.recordSupportDecision({
      ...unsignedDecision,
      signature: sign(
        supportDecisionSigningPayload(unsignedDecision),
        actors["actor-b"]!.privateKey,
      ),
    });
    assert.equal(system.verifySupportDecision("decision-case-992"), true);

    const regulatorGrant = {
      grantId: "grant-regulator-d",
      authorityId: "test-authority",
      granteeId: "actor-d",
      capability: "verify-regulatory-evidence",
      scopeId: "consumer-products-demo",
      issuedAt: "2026-09-13T12:00:00.000Z",
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    system.grantAuthority({
      ...regulatorGrant,
      signature: sign(
        authorityGrantSigningPayload(regulatorGrant),
        authority.privateKey,
      ),
    });
    assert.equal(
      system
        .deriveCapabilities("actor-d")
        .some(({ action }) => action === "verify-regulatory-evidence"),
      true,
    );

    system.openRegulatoryCase({
      caseId: "REG-443",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret,
      respondentOrganizationId: "acme-audio",
      purpose: "investigate the H1 battery safety dispute",
      openedAt: "2026-09-13T13:00:00.000Z",
    });

    const recordIds = [
      "credential-h1-a",
      "review-h1-a",
      "CASE-992",
      "decision-case-992",
    ] as const;
    const unsignedBridge = {
      bridgeId: "bridge-reg-443",
      caseId: "REG-443",
      authorizerId: "actor-a",
      recipientId: "actor-d",
      purpose: "investigate the H1 battery safety dispute",
      recordIds,
      authorizedAt: "2026-09-13T13:05:00.000Z",
    } as const satisfies Omit<SignedEvidenceBridge, "signature">;
    const bridgeCommitment = system.authorizeEvidenceBridge({
      ...unsignedBridge,
      signature: sign(
        evidenceBridgeSigningPayload(unsignedBridge),
        actors["actor-a"]!.privateKey,
      ),
    });
    assert.match(bridgeCommitment, /^[0-9a-f]{64}$/);

    for (const actorId of ["actor-b", "actor-c"]) {
      const denied = system.canVerifyEvidenceBridge({
        bridgeId: "bridge-reg-443",
        actorId,
        caseId: "REG-443",
        purpose: "investigate the H1 battery safety dispute",
        recordIds,
      });
      assert.equal(denied.allowed, false);
      if (!denied.allowed) {
        assert.equal(denied.code, "RECIPIENT_MISMATCH");
      }
    }

    const wrongCase = system.canVerifyEvidenceBridge({
      bridgeId: "bridge-reg-443",
      actorId: "actor-d",
      caseId: "REG-999",
      purpose: "investigate the H1 battery safety dispute",
      recordIds,
    });
    assert.equal(wrongCase.allowed, false);
    if (!wrongCase.allowed) assert.equal(wrongCase.code, "CASE_MISMATCH");

    const wrongPurpose = system.canVerifyEvidenceBridge({
      bridgeId: "bridge-reg-443",
      actorId: "actor-d",
      caseId: "REG-443",
      purpose: "general customer profiling",
      recordIds,
    });
    assert.equal(wrongPurpose.allowed, false);
    if (!wrongPurpose.allowed) {
      assert.equal(wrongPurpose.code, "PURPOSE_MISMATCH");
    }

    const wrongRecords = system.canVerifyEvidenceBridge({
      bridgeId: "bridge-reg-443",
      actorId: "actor-d",
      caseId: "REG-443",
      purpose: "investigate the H1 battery safety dispute",
      recordIds: ["review-h1-a"],
    });
    assert.equal(wrongRecords.allowed, false);
    if (!wrongRecords.allowed) {
      assert.equal(wrongRecords.code, "RECORD_SET_MISMATCH");
    }

    const verification = system.verifyEvidenceBridge({
      bridgeId: "bridge-reg-443",
      actorId: "actor-d",
      caseId: "REG-443",
      purpose: "investigate the H1 battery safety dispute",
      recordIds,
    });
    assert.deepEqual(verification, {
      bridgeId: "bridge-reg-443",
      caseId: "REG-443",
      productId: "H1",
      sameCredentialHolder: true,
      samePurchaseTransaction: true,
      reviewIntegrityVerified: true,
      supportDecisionIntegrityVerified: true,
      commitment: bridgeCommitment,
    });

    const eventsJson = JSON.stringify(system.getEvents());
    for (const forbidden of [
      holderSecret,
      "ORD-88421",
      "2026-09-01T00:00:00.000Z",
    ]) {
      assert.equal(eventsJson.includes(forbidden), false);
    }
    const supportEvents = system
      .getEvents()
      .filter(({ type }) =>
        ["SupportRequested", "SupportDecisionRecorded"].includes(type),
      );
    assert.equal(JSON.stringify(supportEvents).includes("review-h1-a"), false);

    const commitmentRecords = system.getPublicCommitmentRecords();
    assert.deepEqual(
      commitmentRecords.map(({ actionId }) => actionId),
      [
        "review-h1-a",
        "CASE-992",
        "decision-case-992",
        "bridge-reg-443",
      ],
    );
    assert.equal(
      commitmentRecords.every(({ commitment }) =>
        /^[0-9a-f]{64}$/.test(commitment),
      ),
      true,
    );
    assert.equal(
      system.auditCommitments().every(({ matchesPrivateRecord }) =>
        matchesPrivateRecord,
      ),
      true,
    );
  });
});
