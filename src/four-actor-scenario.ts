import {
  generateKeyPairSync,
  sign as signPayload,
  type KeyObject,
} from "node:crypto";

import {
  BehaviorDerivedInformationFlowSystem,
  authorityGrantSigningPayload,
  evidenceBridgeSigningPayload,
  hashHolderSecret,
  purchaseCredentialSigningPayload,
  supportDecisionSigningPayload,
  type PublicCommitmentRecord,
  type PublicReview,
  type SignedAuthorityGrant,
  type SignedEvidenceBridge,
  type SignedPurchaseCredential,
  type SignedSupportDecision,
  type SupportRecipientView,
} from "./behavior-derived-system.js";

export const DEMO_VIEWERS = [
  "test-operator",
  "public",
  "actor-a",
  "actor-b",
  "actor-c",
  "actor-d",
] as const;

export type DemoViewer = (typeof DEMO_VIEWERS)[number];

export const FOUR_ACTOR_SCENARIO_STEPS = [
  {
    id: "register-actors",
    label: "Register four identical actors",
    description:
      "Create Actor A, B, C, and D with the same registration schema and no role field.",
  },
  {
    id: "register-acme-h1",
    label: "Register Acme Audio and H1",
    description:
      "Actor B registers Acme Audio and H1; the test authority signs B's H1 issuer grant.",
  },
  {
    id: "issue-purchase",
    label: "Issue the private H1 purchase",
    description:
      "Actor B signs Actor A's private credential for order ORD-88421.",
  },
  {
    id: "publish-review",
    label: "Publish the verified H1 review",
    description:
      "Actor A proves credential control and publishes one rating without exposing the order or actor ID.",
  },
  {
    id: "read-review",
    label: "Let Actor C read the public review",
    description:
      "Actor C verifies the public record but receives no private capability.",
  },
  {
    id: "request-support",
    label: "Request a replacement",
    description:
      "Actor A opens CASE-992; Actor B sees only the eligibility results needed for support.",
  },
  {
    id: "record-decision",
    label: "Record Acme's signed decision",
    description:
      "Actor B signs the CASE-992 rejection without learning which public review belongs to the claimant.",
  },
  {
    id: "authorize-regulatory-bridge",
    label: "Authorize REG-443 for Actor D",
    description:
      "The authority grants D regulatory permission, then A opens REG-443 and signs a case-bound evidence bridge.",
  },
  {
    id: "verify-regulatory-evidence",
    label: "Verify REG-443 evidence",
    description:
      "Actor D verifies the selected purchase, review, support case, and decision belong to the same transaction.",
  },
] as const;

export interface ScenarioTimelineEntry {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly context: "setup" | "reputation" | "support" | "regulatory";
}

export interface ScenarioPanel {
  readonly context: "purchase" | "reputation" | "support" | "regulatory";
  readonly title: string;
  readonly status: "empty" | "visible" | "private" | "denied";
  readonly summary: string;
  readonly facts: readonly string[];
}

export interface ScenarioActorCard {
  readonly actorId: "actor-a" | "actor-b" | "actor-c" | "actor-d";
  readonly label: string;
  readonly registration: "not registered" | "neutral actor";
  readonly availableActions: readonly string[];
  readonly explanation: string;
}

export interface ScenarioSnapshot {
  readonly stage: number;
  readonly complete: boolean;
  readonly viewer: DemoViewer;
  readonly viewerLabel: string;
  readonly nextStep: (typeof FOUR_ACTOR_SCENARIO_STEPS)[number] | null;
  readonly counts: {
    readonly actors: number;
    readonly commitments: number;
  };
  readonly actors: readonly ScenarioActorCard[];
  readonly panels: readonly ScenarioPanel[];
  readonly timeline: readonly ScenarioTimelineEntry[];
  readonly commitments: readonly PublicCommitmentRecord[];
  readonly privacyChecks: readonly {
    readonly label: string;
    readonly passed: boolean;
  }[];
}

interface SigningIdentity {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

type ActorId = "actor-a" | "actor-b" | "actor-c" | "actor-d";

function identity(): SigningIdentity {
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

const ACTOR_LABELS: Readonly<Record<ActorId, string>> = {
  "actor-a": "Actor A",
  "actor-b": "Actor B",
  "actor-c": "Actor C",
  "actor-d": "Actor D",
};

const HOLDER_SECRET = "actor-a-private-holder-secret";
const REGULATORY_PURPOSE = "investigate the H1 battery safety dispute";
const EVIDENCE_RECORDS = [
  "credential-h1-a",
  "review-h1-a",
  "CASE-992",
  "decision-case-992",
] as const;

export class FourActorScenario {
  readonly #authority = identity();
  readonly #actors: Readonly<Record<ActorId, SigningIdentity>> = {
    "actor-a": identity(),
    "actor-b": identity(),
    "actor-c": identity(),
    "actor-d": identity(),
  };
  readonly #system = new BehaviorDerivedInformationFlowSystem({
    trustedAuthorityId: "test-authority",
    trustedAuthorityPublicKey: this.#authority.publicKey,
    regulatoryScopeId: "consumer-products-demo",
  });
  readonly #timeline: ScenarioTimelineEntry[] = [];
  #stage = 0;
  #review: PublicReview | undefined;
  #supportView: SupportRecipientView | undefined;
  #regulatoryVerified = false;

  advance(): ScenarioSnapshot {
    if (this.#stage >= FOUR_ACTOR_SCENARIO_STEPS.length) {
      return this.snapshot();
    }

    const operations: readonly (() => void)[] = [
      () => this.#registerActors(),
      () => this.#registerAcmeAndH1(),
      () => this.#issuePurchase(),
      () => this.#publishReview(),
      () => this.#readReview(),
      () => this.#requestSupport(),
      () => this.#recordDecision(),
      () => this.#authorizeRegulatoryBridge(),
      () => this.#verifyRegulatoryEvidence(),
    ];
    operations[this.#stage]!();
    this.#stage += 1;
    return this.snapshot();
  }

  runToCompletion(): ScenarioSnapshot {
    while (this.#stage < FOUR_ACTOR_SCENARIO_STEPS.length) {
      this.advance();
    }
    return this.snapshot();
  }

  snapshot(viewer: DemoViewer = "test-operator"): ScenarioSnapshot {
    if (!DEMO_VIEWERS.includes(viewer)) {
      throw new TypeError(`viewer: unsupported ${viewer}`);
    }
    return {
      stage: this.#stage,
      complete: this.#stage === FOUR_ACTOR_SCENARIO_STEPS.length,
      viewer,
      viewerLabel: this.#viewerLabel(viewer),
      nextStep: FOUR_ACTOR_SCENARIO_STEPS[this.#stage] ?? null,
      counts: {
        actors: this.#system.listActors().length,
        commitments: this.#system.getPublicCommitmentRecords().length,
      },
      actors: this.#actorCards(viewer),
      panels: this.#panels(viewer),
      timeline: this.#timelineForViewer(viewer),
      commitments: this.#system.getPublicCommitmentRecords(),
      privacyChecks: this.#privacyChecks(viewer),
    };
  }

  commitmentRecords(): readonly PublicCommitmentRecord[] {
    return this.#system.getPublicCommitmentRecords();
  }

  commitmentAuditPassed(): boolean {
    return this.#system
      .auditCommitments()
      .every(({ matchesPrivateRecord }) => matchesPrivateRecord);
  }

  #registerActors(): void {
    for (const actorId of Object.keys(this.#actors) as ActorId[]) {
      this.#system.registerActor({
        actorId,
        signingPublicKey: this.#actors[actorId].publicKey,
      });
    }
    this.#timeline.push({
      id: "actors-registered",
      title: "Four neutral actors registered",
      detail:
        "A, B, C, and D have the same fields and no buyer, merchant, observer, or regulator role.",
      context: "setup",
    });
  }

  #registerAcmeAndH1(): void {
    this.#system.registerOrganization({
      organizationId: "acme-audio",
      name: "Acme Audio",
      registeredBy: "actor-b",
    });
    this.#system.registerProduct({
      productId: "H1",
      name: "H1 Headphones",
      organizationId: "acme-audio",
      registeredBy: "actor-b",
    });
    const grant = {
      grantId: "grant-acme-h1-issuer",
      authorityId: "test-authority",
      granteeId: "actor-b",
      capability: "issue-purchase-credential",
      scopeId: "H1",
      issuedAt: "2026-09-01T00:00:00.000Z",
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    this.#system.grantAuthority({
      ...grant,
      signature: sign(
        authorityGrantSigningPayload(grant),
        this.#authority.privateKey,
      ),
    });
    this.#timeline.push({
      id: "acme-h1-registered",
      title: "Actor B can issue H1 credentials",
      detail:
        "This ability comes from grant-acme-h1-issuer, not from B's registration.",
      context: "setup",
    });
  }

  #issuePurchase(): void {
    const credential = {
      credentialId: "credential-h1-a",
      productId: "H1",
      issuerId: "actor-b",
      holderId: "actor-a",
      orderId: "ORD-88421",
      purchasedAt: "2026-09-01T00:00:00.000Z",
      holderSecretHash: hashHolderSecret(HOLDER_SECRET),
    } as const satisfies Omit<SignedPurchaseCredential, "signature">;
    this.#system.issuePurchaseCredential({
      ...credential,
      signature: sign(
        purchaseCredentialSigningPayload(credential),
        this.#actors["actor-b"].privateKey,
      ),
    });
    this.#timeline.push({
      id: "h1-purchase-issued",
      title: "Actor A now controls the H1 purchase",
      detail:
        "The signed private credential for ORD-88421 is the basis for A's buyer actions.",
      context: "setup",
    });
  }

  #publishReview(): void {
    this.#review = this.#system.publishReview({
      reviewId: "review-h1-a",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret: HOLDER_SECRET,
      rating: 2,
      text: "The battery swelled after twelve days of normal use.",
      publishedAt: "2026-09-13T09:00:00.000Z",
    });
    this.#timeline.push({
      id: "h1-review-published",
      title: "A verified H1 review is public",
      detail:
        "The public record shows rating 2 and the battery report, but not Actor A or ORD-88421.",
      context: "reputation",
    });
  }

  #readReview(): void {
    this.#system.readPublicReview("actor-c", "review-h1-a");
    this.#timeline.push({
      id: "h1-review-read",
      title: "Actor C read the review",
      detail:
        "C can verify the public commitment but cannot resolve the reviewer or purchase order.",
      context: "reputation",
    });
  }

  #requestSupport(): void {
    this.#supportView = this.#system.requestSupport({
      caseId: "CASE-992",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret: HOLDER_SECRET,
      organizationId: "acme-audio",
      request: "replacement",
      requestedAt: "2026-09-13T10:00:00.000Z",
      policyVersion: "support-policy-1",
    });
    this.#timeline.push({
      id: "case-992-opened",
      title: "Actor A requested an H1 replacement",
      detail:
        "Acme sees that the purchase is eligible and unused; the support record carries no public-review link.",
      context: "support",
    });
  }

  #recordDecision(): void {
    const decision = {
      decisionId: "decision-case-992",
      caseId: "CASE-992",
      issuerId: "actor-b",
      outcome: "rejected",
      reason: "Inspection is required before replacement approval.",
      decidedAt: "2026-09-13T11:00:00.000Z",
      policyVersion: "support-policy-1",
    } as const satisfies Omit<SignedSupportDecision, "signature">;
    this.#system.recordSupportDecision({
      ...decision,
      signature: sign(
        supportDecisionSigningPayload(decision),
        this.#actors["actor-b"].privateKey,
      ),
    });
    this.#timeline.push({
      id: "case-992-decided",
      title: "Actor B signed the CASE-992 rejection",
      detail:
        "The reason and policy version are integrity-protected; Acme still cannot identify A's review.",
      context: "support",
    });
  }

  #authorizeRegulatoryBridge(): void {
    const regulatorGrant = {
      grantId: "grant-regulator-d",
      authorityId: "test-authority",
      granteeId: "actor-d",
      capability: "verify-regulatory-evidence",
      scopeId: "consumer-products-demo",
      issuedAt: "2026-09-13T12:00:00.000Z",
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    this.#system.grantAuthority({
      ...regulatorGrant,
      signature: sign(
        authorityGrantSigningPayload(regulatorGrant),
        this.#authority.privateKey,
      ),
    });
    this.#system.openRegulatoryCase({
      caseId: "REG-443",
      actorId: "actor-a",
      credentialId: "credential-h1-a",
      holderSecret: HOLDER_SECRET,
      respondentOrganizationId: "acme-audio",
      purpose: REGULATORY_PURPOSE,
      openedAt: "2026-09-13T13:00:00.000Z",
    });
    const bridge = {
      bridgeId: "bridge-reg-443",
      caseId: "REG-443",
      authorizerId: "actor-a",
      recipientId: "actor-d",
      purpose: REGULATORY_PURPOSE,
      recordIds: EVIDENCE_RECORDS,
      authorizedAt: "2026-09-13T13:05:00.000Z",
    } as const satisfies Omit<SignedEvidenceBridge, "signature">;
    this.#system.authorizeEvidenceBridge({
      ...bridge,
      signature: sign(
        evidenceBridgeSigningPayload(bridge),
        this.#actors["actor-a"].privateKey,
      ),
    });
    this.#timeline.push({
      id: "reg-443-authorized",
      title: "Actor A authorized REG-443 to Actor D",
      detail:
        "The bridge is bound to D, REG-443, the battery-safety purpose, and exactly four selected records.",
      context: "regulatory",
    });
  }

  #verifyRegulatoryEvidence(): void {
    const result = this.#system.verifyEvidenceBridge({
      bridgeId: "bridge-reg-443",
      actorId: "actor-d",
      caseId: "REG-443",
      purpose: REGULATORY_PURPOSE,
      recordIds: EVIDENCE_RECORDS,
    });
    this.#regulatoryVerified =
      result.sameCredentialHolder && result.samePurchaseTransaction;
    this.#timeline.push({
      id: "reg-443-verified",
      title: "Actor D verified the REG-443 evidence",
      detail:
        "D learned that the four selected records concern the same holder and purchase, without receiving a reusable bridge.",
      context: "regulatory",
    });
  }

  #viewerLabel(viewer: DemoViewer): string {
    if (viewer === "test-operator") return "Test operator — acceptance view";
    if (viewer === "public") return "Public visitor";
    return `${ACTOR_LABELS[viewer]} — private perspective`;
  }

  #actorCards(viewer: DemoViewer): readonly ScenarioActorCard[] {
    const registrations = new Set(
      this.#system.listActors().map(({ actorId }) => actorId),
    );
    return (Object.keys(ACTOR_LABELS) as ActorId[]).map((actorId) => {
      const registered = registrations.has(actorId);
      const capabilities = registered
        ? this.#system.deriveCapabilities(actorId)
        : [];
      const availableActions = capabilities.map((capability) => {
        switch (capability.action) {
          case "register-product":
            return `Register products for ${capability.resourceId}`;
          case "issue-purchase-credential":
            return `Issue signed ${capability.resourceId} purchase credentials`;
          case "publish-product-review":
            return `Publish one verified ${capability.resourceId} review`;
          case "request-product-support":
            return `Request ${capability.resourceId} support`;
          case "decide-support-case":
            return `Sign a decision for ${capability.resourceId}`;
          case "authorize-regulatory-bridge":
            return `Authorize selected ${capability.resourceId} evidence`;
          case "verify-regulatory-evidence":
            return `Verify assigned evidence in ${capability.resourceId}`;
        }
      });
      const mayShowActions =
        viewer === "test-operator" || viewer === actorId;
      return {
        actorId,
        label: ACTOR_LABELS[actorId],
        registration: registered ? "neutral actor" : "not registered",
        availableActions: mayShowActions ? availableActions : [],
        explanation: !registered
          ? "No account exists yet."
          : availableActions.length === 0
            ? "Registration alone grants no product, support, or regulatory action."
            : mayShowActions
              ? "Each action is shown with the credential, grant, organization, or case that enabled it."
              : "This actor's private capabilities are hidden from the selected perspective.",
      };
    });
  }

  #panels(viewer: DemoViewer): readonly ScenarioPanel[] {
    return [
      this.#purchasePanel(viewer),
      this.#reputationPanel(),
      this.#supportPanel(viewer),
      this.#regulatoryPanel(viewer),
    ];
  }

  #purchasePanel(viewer: DemoViewer): ScenarioPanel {
    if (this.#stage < 3) {
      return {
        context: "purchase",
        title: "Private H1 purchase",
        status: "empty",
        summary: "No H1 purchase credential has been issued.",
        facts: [],
      };
    }
    if (["actor-a", "actor-b", "test-operator"].includes(viewer)) {
      return {
        context: "purchase",
        title: "Private H1 purchase",
        status: "private",
        summary:
          viewer === "actor-a"
            ? "You control the credential for ORD-88421."
            : "Actor B issued the credential; this does not reveal who authored a public review.",
        facts: [
          "Product: H1 Headphones",
          "Order: ORD-88421",
          "Purchased: 1 September 2026",
          "Credential: signed by Actor B",
        ],
      };
    }
    return {
      context: "purchase",
      title: "Private H1 purchase",
      status: "denied",
      summary: "This perspective cannot read the purchase credential.",
      facts: ["The public H1 review does not expose its order."],
    };
  }

  #reputationPanel(): ScenarioPanel {
    if (this.#review === undefined) {
      return {
        context: "reputation",
        title: "Public H1 reputation",
        status: "empty",
        summary: "No H1 review is public yet.",
        facts: [],
      };
    }
    return {
      context: "reputation",
      title: "Public H1 reputation",
      status: "visible",
      summary: `Rating ${this.#review.rating}/5 — ${this.#review.text}`,
      facts: [
        "Verified purchase: yes",
        "Reviewer identity: hidden",
        "Order number: hidden",
        `One-use marker: ${this.#review.scopedNullifier.slice(0, 12)}…`,
      ],
    };
  }

  #supportPanel(viewer: DemoViewer): ScenarioPanel {
    if (this.#supportView === undefined) {
      return {
        context: "support",
        title: "Customer support — CASE-992",
        status: "empty",
        summary: "No replacement request exists.",
        facts: [],
      };
    }
    if (["actor-a", "actor-b", "test-operator"].includes(viewer)) {
      return {
        context: "support",
        title: "Customer support — CASE-992",
        status: "private",
        summary:
          this.#stage >= 7
            ? "Acme rejected the replacement pending inspection."
            : "The replacement request is eligible and awaiting a decision.",
        facts: [
          "Product: H1",
          "Purchase age: within 30 days",
          "Replacement entitlement: unused",
          "Public review attached: no",
        ],
      };
    }
    return {
      context: "support",
      title: "Customer support — CASE-992",
      status: "denied",
      summary: "This perspective is not the claimant or Acme support recipient.",
      facts: ["Public-review access does not grant support-case access."],
    };
  }

  #regulatoryPanel(viewer: DemoViewer): ScenarioPanel {
    if (this.#stage < 8) {
      return {
        context: "regulatory",
        title: "Regulatory escalation — REG-443",
        status: "empty",
        summary: "No regulatory evidence bridge exists.",
        facts: [],
      };
    }
    if (["actor-a", "actor-d", "test-operator"].includes(viewer)) {
      return {
        context: "regulatory",
        title: "Regulatory escalation — REG-443",
        status: "private",
        summary: this.#regulatoryVerified
          ? "Actor D verified that the selected evidence concerns the same holder and purchase."
          : "Actor A authorized the selected evidence only to Actor D.",
        facts: [
          "Recipient: Actor D",
          `Purpose: ${REGULATORY_PURPOSE}`,
          "Selected records: purchase, review, CASE-992, signed decision",
          "Reusable by Actor B or C: no",
        ],
      };
    }
    return {
      context: "regulatory",
      title: "Regulatory escalation — REG-443",
      status: "denied",
      summary: `${ACTOR_LABELS[viewer as ActorId] ?? "The public"} is not the authorized recipient.`,
      facts: ["The bridge is recipient-, case-, purpose-, and record-bound."],
    };
  }

  #timelineForViewer(viewer: DemoViewer): readonly ScenarioTimelineEntry[] {
    if (viewer === "test-operator" || viewer === "actor-a") {
      return structuredClone(this.#timeline);
    }

    const publicReview: ScenarioTimelineEntry = {
      id: "h1-review-published",
      title: "Verified H1 review published",
      detail:
        "The public record shows rating 2 and the battery report; the reviewer and purchase order remain hidden.",
      context: "reputation",
    };
    const byId = new Map(this.#timeline.map((entry) => [entry.id, entry]));
    const select = (ids: readonly string[]): ScenarioTimelineEntry[] =>
      ids.flatMap((id) => {
        if (id === publicReview.id && byId.has(id)) return [publicReview];
        const entry = byId.get(id);
        return entry === undefined ? [] : [structuredClone(entry)];
      });

    if (viewer === "public") {
      return select(["h1-review-published"]);
    }
    if (viewer === "actor-c") {
      const result = select(["h1-review-published"]);
      if (byId.has("h1-review-read")) {
        result.push({
          id: "h1-review-read",
          title: "You read the public H1 review",
          detail:
            "The permitted public record gives you no purchase, support, or regulatory access.",
          context: "reputation",
        });
      }
      return result;
    }
    if (viewer === "actor-b") {
      return select([
        "actors-registered",
        "acme-h1-registered",
        "h1-purchase-issued",
        "h1-review-published",
        "case-992-opened",
        "case-992-decided",
      ]);
    }
    return select([
      "h1-review-published",
      "reg-443-authorized",
      "reg-443-verified",
    ]);
  }

  #privacyChecks(viewer: DemoViewer): ScenarioSnapshot["privacyChecks"] {
    const reviewJson = JSON.stringify(this.#review ?? {});
    const supportJson = JSON.stringify(this.#supportView ?? {});
    const checks: ScenarioSnapshot["privacyChecks"] = [
      {
        label: "Actor registration has no role field",
        passed: this.#system
          .listActors()
          .every((registration) => !("role" in registration)),
      },
      {
        label: "Public review hides Actor A and ORD-88421",
        passed:
          this.#review === undefined ||
          (!reviewJson.includes("actor-a") && !reviewJson.includes("ORD-88421")),
      },
      {
        label: "Support view carries no public-review link",
        passed:
          this.#supportView === undefined ||
          (!supportJson.includes("review-h1-a") &&
            !supportJson.includes("battery swelled")),
      },
      {
        label: "Every prepared action commitment recomputes exactly",
        passed: this.commitmentAuditPassed(),
      },
    ];
    if (viewer === "test-operator") return checks;
    return [
      checks[0]!,
      {
        label: "Public review contains no actor or order identifier",
        passed: checks[1]!.passed,
      },
      {
        label: "Public access grants no private-context access",
        passed: checks[2]!.passed,
      },
      checks[3]!,
    ];
  }
}
