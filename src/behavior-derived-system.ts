import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";

import {
  FLOW_NONCE_BYTES,
  commitInformationFlow,
  generateFlowNonce,
  type Claim,
  type ContextKind,
  type InformationFlow,
  type RecipientRef,
  type RecordRef,
} from "./information-flow.js";

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1_000;

export const POLICY_DENIAL_CODES = [
  "ACTOR_NOT_REGISTERED",
  "AUTHORITY_REQUIRED",
  "CREDENTIAL_REQUIRED",
  "CREDENTIAL_HOLDER_MISMATCH",
  "CREDENTIAL_SECRET_MISMATCH",
  "DUPLICATE_SCOPED_USE",
  "ORGANIZATION_CONTROL_REQUIRED",
  "REGULATORY_AUTHORITY_REQUIRED",
  "RECIPIENT_MISMATCH",
  "CASE_MISMATCH",
  "PURPOSE_MISMATCH",
  "RECORD_SET_MISMATCH",
  "SIGNATURE_INVALID",
] as const;

export type PolicyDenialCode = (typeof POLICY_DENIAL_CODES)[number];

export type PolicyDecision =
  | { readonly allowed: true; readonly code: "ALLOWED"; readonly reason: string }
  | {
      readonly allowed: false;
      readonly code: PolicyDenialCode;
      readonly reason: string;
    };

export class PolicyDeniedError extends Error {
  readonly code: PolicyDenialCode;

  constructor(code: PolicyDenialCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "PolicyDeniedError";
    this.code = code;
  }
}

export interface ActorRegistration {
  readonly actorId: string;
  readonly signingPublicKey: string;
}

export interface OrganizationRegistration {
  readonly organizationId: string;
  readonly name: string;
  readonly registeredBy: string;
}

export interface ProductRegistration {
  readonly productId: string;
  readonly name: string;
  readonly organizationId: string;
  readonly registeredBy: string;
}

export type AuthorityCapability =
  | "issue-purchase-credential"
  | "verify-regulatory-evidence";

export interface SignedAuthorityGrant {
  readonly grantId: string;
  readonly authorityId: string;
  readonly granteeId: string;
  readonly capability: AuthorityCapability;
  readonly scopeId: string;
  readonly issuedAt: string;
  readonly signature: string;
}

export interface SignedPurchaseCredential {
  readonly credentialId: string;
  readonly productId: string;
  readonly issuerId: string;
  readonly holderId: string;
  readonly orderId: string;
  readonly purchasedAt: string;
  readonly holderSecretHash: string;
  readonly signature: string;
}

export interface PublishReviewInput {
  readonly reviewId: string;
  readonly actorId: string;
  readonly credentialId: string;
  readonly holderSecret: string;
  readonly rating: number;
  readonly text: string;
  readonly publishedAt: string;
}

export interface PublicReview {
  readonly reviewId: string;
  readonly productId: string;
  readonly rating: number;
  readonly text: string;
  readonly verifiedPurchase: true;
  readonly publishedAt: string;
  readonly scopedNullifier: string;
  readonly commitment: string;
}

export interface SupportRequestInput {
  readonly caseId: string;
  readonly actorId: string;
  readonly credentialId: string;
  readonly holderSecret: string;
  readonly organizationId: string;
  readonly request: "replacement";
  readonly requestedAt: string;
  readonly policyVersion: string;
}

export interface SupportRecipientView {
  readonly caseId: string;
  readonly productId: string;
  readonly request: "replacement";
  readonly contextSubjectId: string;
  readonly eligibility: {
    readonly issuedByOrganization: true;
    readonly purchasedWithinThirtyDays: true;
    readonly replacementEntitlementUnused: true;
  };
  readonly policyVersion: string;
  readonly commitment: string;
}

export interface SignedSupportDecision {
  readonly decisionId: string;
  readonly caseId: string;
  readonly issuerId: string;
  readonly outcome: "rejected" | "approved";
  readonly reason: string;
  readonly decidedAt: string;
  readonly policyVersion: string;
  readonly signature: string;
}

export interface RegulatoryCaseInput {
  readonly caseId: string;
  readonly actorId: string;
  readonly credentialId: string;
  readonly holderSecret: string;
  readonly respondentOrganizationId: string;
  readonly purpose: string;
  readonly openedAt: string;
}

export interface SignedEvidenceBridge {
  readonly bridgeId: string;
  readonly caseId: string;
  readonly authorizerId: string;
  readonly recipientId: string;
  readonly purpose: string;
  readonly recordIds: readonly string[];
  readonly authorizedAt: string;
  readonly signature: string;
}

export interface EvidenceVerificationRequest {
  readonly bridgeId: string;
  readonly actorId: string;
  readonly caseId: string;
  readonly purpose: string;
  readonly recordIds: readonly string[];
}

export interface EvidenceVerificationResult {
  readonly bridgeId: string;
  readonly caseId: string;
  readonly productId: string;
  readonly sameCredentialHolder: true;
  readonly samePurchaseTransaction: true;
  readonly reviewIntegrityVerified: true;
  readonly supportDecisionIntegrityVerified: true;
  readonly commitment: string;
}

export interface DerivedCapability {
  readonly action:
    | "register-product"
    | "issue-purchase-credential"
    | "publish-product-review"
    | "request-product-support"
    | "decide-support-case"
    | "authorize-regulatory-bridge"
    | "verify-regulatory-evidence";
  readonly resourceId: string;
  readonly basisId: string;
}

export type DomainEvent =
  | { readonly type: "ActorRegistered"; readonly actorId: string }
  | {
      readonly type: "OrganizationRegistered";
      readonly organizationId: string;
      readonly registeredBy: string;
    }
  | {
      readonly type: "ProductRegistered";
      readonly productId: string;
      readonly organizationId: string;
      readonly registeredBy: string;
    }
  | {
      readonly type: "AuthorityGranted";
      readonly grantId: string;
      readonly granteeId: string;
      readonly capability: AuthorityCapability;
      readonly scopeId: string;
    }
  | {
      readonly type: "PurchaseCredentialIssued";
      readonly credentialId: string;
      readonly productId: string;
      readonly issuerId: string;
      readonly holderId: string;
    }
  | {
      readonly type: "ReviewPublished";
      readonly reviewId: string;
      readonly productId: string;
      readonly actorId: string;
      readonly commitment: string;
    }
  | {
      readonly type: "PublicReviewRead";
      readonly reviewId: string;
      readonly actorId: string;
    }
  | {
      readonly type: "SupportRequested";
      readonly caseId: string;
      readonly actorId: string;
      readonly recipientId: string;
      readonly productId: string;
      readonly commitment: string;
    }
  | {
      readonly type: "SupportDecisionRecorded";
      readonly decisionId: string;
      readonly caseId: string;
      readonly issuerId: string;
      readonly commitment: string;
    }
  | {
      readonly type: "RegulatoryCaseOpened";
      readonly caseId: string;
      readonly actorId: string;
      readonly purpose: string;
    }
  | {
      readonly type: "EvidenceBridgeAuthorized";
      readonly bridgeId: string;
      readonly caseId: string;
      readonly authorizerId: string;
      readonly recipientId: string;
      readonly commitment: string;
    }
  | {
      readonly type: "EvidenceVerified";
      readonly bridgeId: string;
      readonly caseId: string;
      readonly actorId: string;
    };

interface StoredSupportCase {
  readonly input: SupportRequestInput;
  readonly credentialId: string;
  readonly productId: string;
  readonly recipientId: string;
  readonly view: SupportRecipientView;
}

interface StoredRegulatoryCase {
  readonly input: RegulatoryCaseInput;
  readonly productId: string;
}

interface StoredActionCommitment {
  readonly actionId: string;
  readonly flow: InformationFlow;
  readonly nonce: Uint8Array;
  readonly commitment: string;
}

export interface PublicCommitmentRecord {
  readonly actionId: string;
  readonly commitment: string;
}

export interface CommitmentAudit extends PublicCommitmentRecord {
  readonly matchesPrivateRecord: boolean;
}

export interface BehaviorDerivedSystemOptions {
  readonly trustedAuthorityId: string;
  readonly trustedAuthorityPublicKey: string;
  readonly regulatoryScopeId: string;
  readonly nonceFactory?: () => Uint8Array;
}

type UnknownObject = Record<string, unknown>;

function text(value: string, field: string): string {
  const normalized = value.normalize("NFC").trim();
  if (normalized.length === 0) {
    throw new TypeError(`${field}: must not be empty`);
  }
  return normalized;
}

function timestamp(value: string, field: string): string {
  const normalized = text(value, field);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed)) {
    throw new TypeError(`${field}: expected an ISO timestamp`);
  }
  return normalized;
}

function exactObject(
  input: unknown,
  expectedKeys: readonly string[],
  field: string,
): UnknownObject {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new TypeError(`${field}: expected a plain object`);
  }
  const object = input as UnknownObject;
  const actualKeys = Object.keys(object);
  const missing = expectedKeys.filter((key) => !(key in object));
  const unexpected = actualKeys.filter((key) => !expectedKeys.includes(key));
  if (missing.length > 0 || unexpected.length > 0) {
    const details = [
      missing.length > 0 ? `missing ${missing.join(", ")}` : "",
      unexpected.length > 0 ? `unexpected ${unexpected.join(", ")}` : "",
    ]
      .filter(Boolean)
      .join("; ");
    throw new TypeError(`${field}: ${details}`);
  }
  return object;
}

function hashParts(domain: string, ...parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of [domain, ...parts]) {
    const bytes = Buffer.from(part, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(bytes.byteLength);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function secretHash(secret: string): string {
  return hashParts(
    "midnight-buildathon:information-flow:holder-secret:v1",
    text(secret, "holderSecret"),
  );
}

function sortedUnique(values: readonly string[], field: string): string[] {
  const normalized = values.map((value, index) => text(value, `${field}[${index}]`));
  const sorted = [...normalized].sort();
  if (new Set(sorted).size !== sorted.length) {
    throw new TypeError(`${field}: duplicate record id`);
  }
  return sorted;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function publicKey(value: string, field: string): string {
  const normalized = text(value, field);
  const key = createPublicKey(normalized);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`${field}: expected an Ed25519 public key`);
  }
  return normalized;
}

function verifyEd25519(
  signingPublicKey: string,
  payload: string,
  signature: string,
): boolean {
  try {
    return verifySignature(
      null,
      Buffer.from(payload, "utf8"),
      createPublicKey(signingPublicKey),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

function allow(reason: string): PolicyDecision {
  return { allowed: true, code: "ALLOWED", reason };
}

function deny(code: PolicyDenialCode, reason: string): PolicyDecision {
  return { allowed: false, code, reason };
}

function enforce(decision: PolicyDecision): void {
  if (!decision.allowed) {
    throw new PolicyDeniedError(decision.code, decision.reason);
  }
}

function signatureDigest(signature: string): string {
  return hashParts(
    "midnight-buildathon:information-flow:signature:v1",
    signature,
  );
}

export function authorityGrantSigningPayload(
  grant: Omit<SignedAuthorityGrant, "signature">,
): string {
  return JSON.stringify({
    type: "AuthorityGrant",
    version: 1,
    grantId: grant.grantId,
    authorityId: grant.authorityId,
    granteeId: grant.granteeId,
    capability: grant.capability,
    scopeId: grant.scopeId,
    issuedAt: grant.issuedAt,
  });
}

export function purchaseCredentialSigningPayload(
  credential: Omit<SignedPurchaseCredential, "signature">,
): string {
  return JSON.stringify({
    type: "PurchaseCredential",
    version: 1,
    credentialId: credential.credentialId,
    productId: credential.productId,
    issuerId: credential.issuerId,
    holderId: credential.holderId,
    orderId: credential.orderId,
    purchasedAt: credential.purchasedAt,
    holderSecretHash: credential.holderSecretHash,
  });
}

export function supportDecisionSigningPayload(
  decision: Omit<SignedSupportDecision, "signature">,
): string {
  return JSON.stringify({
    type: "SupportDecision",
    version: 1,
    decisionId: decision.decisionId,
    caseId: decision.caseId,
    issuerId: decision.issuerId,
    outcome: decision.outcome,
    reason: decision.reason,
    decidedAt: decision.decidedAt,
    policyVersion: decision.policyVersion,
  });
}

export function evidenceBridgeSigningPayload(
  bridge: Omit<SignedEvidenceBridge, "signature">,
): string {
  return JSON.stringify({
    type: "EvidenceBridge",
    version: 1,
    bridgeId: bridge.bridgeId,
    caseId: bridge.caseId,
    authorizerId: bridge.authorizerId,
    recipientId: bridge.recipientId,
    purpose: bridge.purpose,
    recordIds: [...bridge.recordIds].sort(),
    authorizedAt: bridge.authorizedAt,
  });
}

export function hashHolderSecret(secret: string): string {
  return secretHash(secret);
}

export class BehaviorDerivedInformationFlowSystem {
  readonly #options: Required<BehaviorDerivedSystemOptions>;
  readonly #actors = new Map<string, ActorRegistration>();
  readonly #organizations = new Map<string, OrganizationRegistration>();
  readonly #products = new Map<string, ProductRegistration>();
  readonly #grants = new Map<string, SignedAuthorityGrant>();
  readonly #credentials = new Map<string, SignedPurchaseCredential>();
  readonly #reviews = new Map<string, PublicReview>();
  readonly #reviewCredentialIds = new Map<string, string>();
  readonly #usedReviewNullifiers = new Set<string>();
  readonly #supportCases = new Map<string, StoredSupportCase>();
  readonly #supportDecisions = new Map<string, SignedSupportDecision>();
  readonly #regulatoryCases = new Map<string, StoredRegulatoryCase>();
  readonly #bridges = new Map<string, SignedEvidenceBridge>();
  readonly #actions = new Map<string, StoredActionCommitment>();
  readonly #events: DomainEvent[] = [];

  constructor(options: BehaviorDerivedSystemOptions) {
    this.#options = {
      trustedAuthorityId: text(
        options.trustedAuthorityId,
        "trustedAuthorityId",
      ),
      trustedAuthorityPublicKey: publicKey(
        options.trustedAuthorityPublicKey,
        "trustedAuthorityPublicKey",
      ),
      regulatoryScopeId: text(
        options.regulatoryScopeId,
        "regulatoryScopeId",
      ),
      nonceFactory: options.nonceFactory ?? generateFlowNonce,
    };
  }

  registerActor(input: unknown): ActorRegistration {
    const object = exactObject(
      input,
      ["actorId", "signingPublicKey"],
      "ActorRegistration",
    );
    const actor: ActorRegistration = {
      actorId: text(String(object.actorId), "ActorRegistration.actorId"),
      signingPublicKey: publicKey(
        String(object.signingPublicKey),
        "ActorRegistration.signingPublicKey",
      ),
    };
    if (this.#actors.has(actor.actorId)) {
      throw new TypeError(`ActorRegistration.actorId: duplicate ${actor.actorId}`);
    }
    this.#actors.set(actor.actorId, actor);
    this.#events.push({ type: "ActorRegistered", actorId: actor.actorId });
    return { ...actor };
  }

  listActors(): readonly ActorRegistration[] {
    return [...this.#actors.values()].map((actor) => ({ ...actor }));
  }

  registerOrganization(
    input: OrganizationRegistration,
  ): OrganizationRegistration {
    const organization: OrganizationRegistration = {
      organizationId: text(input.organizationId, "organizationId"),
      name: text(input.name, "name"),
      registeredBy: text(input.registeredBy, "registeredBy"),
    };
    this.#requireActor(organization.registeredBy);
    if (this.#organizations.has(organization.organizationId)) {
      throw new TypeError(
        `organizationId: duplicate ${organization.organizationId}`,
      );
    }
    this.#organizations.set(organization.organizationId, organization);
    this.#events.push({
      type: "OrganizationRegistered",
      organizationId: organization.organizationId,
      registeredBy: organization.registeredBy,
    });
    return { ...organization };
  }

  registerProduct(input: ProductRegistration): ProductRegistration {
    const product: ProductRegistration = {
      productId: text(input.productId, "productId"),
      name: text(input.name, "name"),
      organizationId: text(input.organizationId, "organizationId"),
      registeredBy: text(input.registeredBy, "registeredBy"),
    };
    this.#requireActor(product.registeredBy);
    const organization = this.#requireOrganization(product.organizationId);
    if (organization.registeredBy !== product.registeredBy) {
      throw new PolicyDeniedError(
        "ORGANIZATION_CONTROL_REQUIRED",
        `${product.registeredBy} does not control ${product.organizationId}`,
      );
    }
    if (this.#products.has(product.productId)) {
      throw new TypeError(`productId: duplicate ${product.productId}`);
    }
    this.#products.set(product.productId, product);
    this.#events.push({
      type: "ProductRegistered",
      productId: product.productId,
      organizationId: product.organizationId,
      registeredBy: product.registeredBy,
    });
    return { ...product };
  }

  grantAuthority(grant: SignedAuthorityGrant): void {
    this.#requireActor(grant.granteeId);
    if (grant.authorityId !== this.#options.trustedAuthorityId) {
      throw new PolicyDeniedError(
        "SIGNATURE_INVALID",
        `${grant.authorityId} is not the trusted test authority`,
      );
    }
    if (grant.capability === "issue-purchase-credential") {
      this.#requireProduct(grant.scopeId);
    } else if (grant.scopeId !== this.#options.regulatoryScopeId) {
      throw new PolicyDeniedError(
        "REGULATORY_AUTHORITY_REQUIRED",
        `regulatory authority must be scoped to ${this.#options.regulatoryScopeId}`,
      );
    }
    if (this.#grants.has(grant.grantId)) {
      throw new TypeError(`grantId: duplicate ${grant.grantId}`);
    }
    const unsigned: Omit<SignedAuthorityGrant, "signature"> = {
      grantId: text(grant.grantId, "grantId"),
      authorityId: text(grant.authorityId, "authorityId"),
      granteeId: text(grant.granteeId, "granteeId"),
      capability: grant.capability,
      scopeId: text(grant.scopeId, "scopeId"),
      issuedAt: timestamp(grant.issuedAt, "issuedAt"),
    };
    if (
      !verifyEd25519(
        this.#options.trustedAuthorityPublicKey,
        authorityGrantSigningPayload(unsigned),
        grant.signature,
      )
    ) {
      throw new PolicyDeniedError(
        "SIGNATURE_INVALID",
        `authority grant ${grant.grantId} is not signed by ${this.#options.trustedAuthorityId}`,
      );
    }
    const stored = { ...unsigned, signature: text(grant.signature, "signature") };
    this.#grants.set(stored.grantId, stored);
    this.#events.push({
      type: "AuthorityGranted",
      grantId: stored.grantId,
      granteeId: stored.granteeId,
      capability: stored.capability,
      scopeId: stored.scopeId,
    });
  }

  canIssuePurchaseCredential(actorId: string, productId: string): PolicyDecision {
    if (!this.#actors.has(actorId)) {
      return deny("ACTOR_NOT_REGISTERED", `${actorId} is not registered`);
    }
    if (!this.#products.has(productId)) {
      return deny("AUTHORITY_REQUIRED", `${productId} is not a registered product`);
    }
    const grant = this.#findGrant(
      actorId,
      "issue-purchase-credential",
      productId,
    );
    if (grant === undefined) {
      return deny(
        "AUTHORITY_REQUIRED",
        `${actorId} has no signed authority grant to issue ${productId} purchase credentials`,
      );
    }
    return allow(
      `${actorId} may issue ${productId} purchase credentials because of ${grant.grantId}`,
    );
  }

  issuePurchaseCredential(credential: SignedPurchaseCredential): void {
    this.#requireActor(credential.holderId);
    enforce(
      this.canIssuePurchaseCredential(credential.issuerId, credential.productId),
    );
    if (this.#credentials.has(credential.credentialId)) {
      throw new TypeError(`credentialId: duplicate ${credential.credentialId}`);
    }
    const unsigned: Omit<SignedPurchaseCredential, "signature"> = {
      credentialId: text(credential.credentialId, "credentialId"),
      productId: text(credential.productId, "productId"),
      issuerId: text(credential.issuerId, "issuerId"),
      holderId: text(credential.holderId, "holderId"),
      orderId: text(credential.orderId, "orderId"),
      purchasedAt: timestamp(credential.purchasedAt, "purchasedAt"),
      holderSecretHash: text(
        credential.holderSecretHash,
        "holderSecretHash",
      ),
    };
    this.#assertActorSignature(
      unsigned.issuerId,
      purchaseCredentialSigningPayload(unsigned),
      credential.signature,
      `purchase credential ${unsigned.credentialId}`,
    );
    const stored = {
      ...unsigned,
      signature: text(credential.signature, "signature"),
    };
    this.#credentials.set(stored.credentialId, stored);
    this.#events.push({
      type: "PurchaseCredentialIssued",
      credentialId: stored.credentialId,
      productId: stored.productId,
      issuerId: stored.issuerId,
      holderId: stored.holderId,
    });
  }

  canPublishReview(
    actorId: string,
    credentialId: string,
    holderSecret: string,
  ): PolicyDecision {
    const control = this.#credentialControlDecision(
      actorId,
      credentialId,
      holderSecret,
    );
    if (!control.allowed) {
      return control;
    }
    const credential = this.#credentials.get(credentialId)!;
    const nullifier = this.#reviewNullifier(credential);
    if (this.#usedReviewNullifiers.has(nullifier)) {
      return deny(
        "DUPLICATE_SCOPED_USE",
        `${credentialId} has already been used for an ${credential.productId} review`,
      );
    }
    return allow(
      `${actorId} may review ${credential.productId} because they control valid credential ${credentialId}`,
    );
  }

  #credentialControlDecision(
    actorId: string,
    credentialId: string,
    holderSecret: string,
  ): PolicyDecision {
    if (!this.#actors.has(actorId)) {
      return deny("ACTOR_NOT_REGISTERED", `${actorId} is not registered`);
    }
    const credential = this.#credentials.get(credentialId);
    if (credential === undefined) {
      return deny(
        "CREDENTIAL_REQUIRED",
        `${credentialId} is not a valid purchase credential`,
      );
    }
    if (credential.holderId !== actorId) {
      return deny(
        "CREDENTIAL_HOLDER_MISMATCH",
        `${actorId} is not the holder of ${credentialId}`,
      );
    }
    if (credential.holderSecretHash !== secretHash(holderSecret)) {
      return deny(
        "CREDENTIAL_SECRET_MISMATCH",
        `${actorId} did not prove control of ${credentialId}`,
      );
    }
    return allow(
      `${actorId} controls valid credential ${credentialId}`,
    );
  }

  publishReview(input: PublishReviewInput): PublicReview {
    enforce(
      this.canPublishReview(
        input.actorId,
        input.credentialId,
        input.holderSecret,
      ),
    );
    if (!Number.isInteger(input.rating) || input.rating < 1 || input.rating > 5) {
      throw new TypeError("rating: expected an integer from 1 through 5");
    }
    if (this.#reviews.has(input.reviewId)) {
      throw new TypeError(`reviewId: duplicate ${input.reviewId}`);
    }
    const credential = this.#requireCredential(input.credentialId);
    const scopedNullifier = this.#reviewNullifier(credential);
    const publishedAt = timestamp(input.publishedAt, "publishedAt");
    const reviewText = text(input.text, "text");
    const flow = this.#makeFlow({
      flowId: `review:${input.reviewId}`,
      context: "reputation",
      policyVersion: "reputation-policy-1",
      actorIds: [credential.holderId, credential.issuerId],
      senderId: credential.holderId,
      records: [
        {
          id: credential.credentialId,
          digest: this.#credentialDigest(credential),
        },
      ],
      claims: [
        {
          id: `${input.reviewId}:product`,
          type: "product",
          value: credential.productId,
          issuerId: credential.issuerId,
        },
        {
          id: `${input.reviewId}:verified-purchase`,
          type: "verified-purchase",
          value: "true",
          issuerId: credential.issuerId,
        },
        {
          id: `${input.reviewId}:rating`,
          type: "rating",
          value: String(input.rating),
          issuerId: credential.holderId,
        },
        {
          id: `${input.reviewId}:text`,
          type: "review-text",
          value: reviewText,
          issuerId: credential.holderId,
        },
      ],
      recipient: { kind: "public" },
      visibleClaimIds: [
        `${input.reviewId}:product`,
        `${input.reviewId}:verified-purchase`,
        `${input.reviewId}:rating`,
        `${input.reviewId}:text`,
      ],
    });
    const commitment = this.#recordAction(input.reviewId, flow);
    const review: PublicReview = {
      reviewId: text(input.reviewId, "reviewId"),
      productId: credential.productId,
      rating: input.rating,
      text: reviewText,
      verifiedPurchase: true,
      publishedAt,
      scopedNullifier,
      commitment,
    };
    this.#reviews.set(review.reviewId, review);
    this.#reviewCredentialIds.set(review.reviewId, credential.credentialId);
    this.#usedReviewNullifiers.add(scopedNullifier);
    this.#events.push({
      type: "ReviewPublished",
      reviewId: review.reviewId,
      productId: review.productId,
      actorId: input.actorId,
      commitment,
    });
    return { ...review };
  }

  readPublicReview(actorId: string, reviewId: string): PublicReview {
    this.#requireActor(actorId);
    const review = this.#reviews.get(reviewId);
    if (review === undefined) {
      throw new TypeError(`reviewId: unknown ${reviewId}`);
    }
    this.#events.push({ type: "PublicReviewRead", reviewId, actorId });
    return { ...review };
  }

  requestSupport(input: SupportRequestInput): SupportRecipientView {
    const credential = this.#assertCredentialControl(
      input.actorId,
      input.credentialId,
      input.holderSecret,
    );
    const product = this.#requireProduct(credential.productId);
    if (product.organizationId !== input.organizationId) {
      throw new TypeError(
        `organizationId: ${input.organizationId} did not issue ${credential.productId}`,
      );
    }
    if (this.#supportCases.has(input.caseId)) {
      throw new TypeError(`caseId: duplicate ${input.caseId}`);
    }
    const organization = this.#requireOrganization(input.organizationId);
    const requestedAt = timestamp(input.requestedAt, "requestedAt");
    const age = Date.parse(requestedAt) - Date.parse(credential.purchasedAt);
    if (age < 0 || age > THIRTY_DAYS_MS) {
      throw new PolicyDeniedError(
        "CREDENTIAL_REQUIRED",
        `${credential.credentialId} is not within the 30-day replacement window`,
      );
    }
    const contextSubjectId = hashParts(
      "midnight-buildathon:information-flow:support-subject:v1",
      organization.organizationId,
      credential.credentialId,
    );
    const flow = this.#makeFlow({
      flowId: `support:${input.caseId}`,
      context: "support",
      policyVersion: text(input.policyVersion, "policyVersion"),
      actorIds: [credential.holderId, organization.registeredBy],
      senderId: credential.holderId,
      records: [
        {
          id: credential.credentialId,
          digest: this.#credentialDigest(credential),
        },
      ],
      claims: [
        {
          id: `${input.caseId}:product`,
          type: "product",
          value: credential.productId,
          issuerId: credential.issuerId,
        },
        {
          id: `${input.caseId}:within-thirty-days`,
          type: "purchased-within-thirty-days",
          value: "true",
          issuerId: credential.issuerId,
        },
        {
          id: `${input.caseId}:unused-entitlement`,
          type: "replacement-entitlement-unused",
          value: "true",
          issuerId: credential.issuerId,
        },
      ],
      recipient: { kind: "actor", actorId: organization.registeredBy },
      visibleClaimIds: [
        `${input.caseId}:product`,
        `${input.caseId}:within-thirty-days`,
        `${input.caseId}:unused-entitlement`,
      ],
    });
    const commitment = this.#recordAction(input.caseId, flow);
    const view: SupportRecipientView = {
      caseId: text(input.caseId, "caseId"),
      productId: credential.productId,
      request: input.request,
      contextSubjectId,
      eligibility: {
        issuedByOrganization: true,
        purchasedWithinThirtyDays: true,
        replacementEntitlementUnused: true,
      },
      policyVersion: text(input.policyVersion, "policyVersion"),
      commitment,
    };
    this.#supportCases.set(view.caseId, {
      input: { ...input, requestedAt },
      credentialId: credential.credentialId,
      productId: credential.productId,
      recipientId: organization.registeredBy,
      view,
    });
    this.#events.push({
      type: "SupportRequested",
      caseId: view.caseId,
      actorId: input.actorId,
      recipientId: organization.registeredBy,
      productId: credential.productId,
      commitment,
    });
    return structuredClone(view);
  }

  readSupportCase(actorId: string, caseId: string): SupportRecipientView {
    this.#requireActor(actorId);
    const supportCase = this.#requireSupportCase(caseId);
    if (
      actorId !== supportCase.input.actorId &&
      actorId !== supportCase.recipientId
    ) {
      throw new PolicyDeniedError(
        "RECIPIENT_MISMATCH",
        `${actorId} is neither the claimant nor support recipient for ${caseId}`,
      );
    }
    return structuredClone(supportCase.view);
  }

  recordSupportDecision(decision: SignedSupportDecision): void {
    const supportCase = this.#requireSupportCase(decision.caseId);
    if (decision.issuerId !== supportCase.recipientId) {
      throw new PolicyDeniedError(
        "ORGANIZATION_CONTROL_REQUIRED",
        `${decision.issuerId} is not the support recipient for ${decision.caseId}`,
      );
    }
    if (this.#supportDecisions.has(decision.decisionId)) {
      throw new TypeError(`decisionId: duplicate ${decision.decisionId}`);
    }
    const unsigned: Omit<SignedSupportDecision, "signature"> = {
      decisionId: text(decision.decisionId, "decisionId"),
      caseId: text(decision.caseId, "caseId"),
      issuerId: text(decision.issuerId, "issuerId"),
      outcome: decision.outcome,
      reason: text(decision.reason, "reason"),
      decidedAt: timestamp(decision.decidedAt, "decidedAt"),
      policyVersion: text(decision.policyVersion, "policyVersion"),
    };
    this.#assertActorSignature(
      unsigned.issuerId,
      supportDecisionSigningPayload(unsigned),
      decision.signature,
      `support decision ${unsigned.decisionId}`,
    );
    const stored = {
      ...unsigned,
      signature: text(decision.signature, "signature"),
    };
    const credential = this.#requireCredential(supportCase.credentialId);
    const flow = this.#makeFlow({
      flowId: `support-decision:${stored.decisionId}`,
      context: "support",
      policyVersion: stored.policyVersion,
      actorIds: [stored.issuerId, supportCase.input.actorId],
      senderId: stored.issuerId,
      records: [
        {
          id: stored.caseId,
          digest: hashParts(
            "midnight-buildathon:information-flow:support-case:v1",
            supportCase.view.commitment,
          ),
        },
      ],
      claims: [
        {
          id: `${stored.decisionId}:outcome`,
          type: "support-outcome",
          value: stored.outcome,
          issuerId: stored.issuerId,
        },
        {
          id: `${stored.decisionId}:reason`,
          type: "support-reason",
          value: stored.reason,
          issuerId: stored.issuerId,
        },
        {
          id: `${stored.decisionId}:signature`,
          type: "signature-digest",
          value: signatureDigest(stored.signature),
          issuerId: stored.issuerId,
        },
      ],
      recipient: { kind: "actor", actorId: credential.holderId },
      visibleClaimIds: [
        `${stored.decisionId}:outcome`,
        `${stored.decisionId}:reason`,
        `${stored.decisionId}:signature`,
      ],
    });
    const commitment = this.#recordAction(stored.decisionId, flow);
    this.#supportDecisions.set(stored.decisionId, stored);
    this.#events.push({
      type: "SupportDecisionRecorded",
      decisionId: stored.decisionId,
      caseId: stored.caseId,
      issuerId: stored.issuerId,
      commitment,
    });
  }

  verifySupportDecision(decisionId: string): boolean {
    const decision = this.#supportDecisions.get(decisionId);
    if (decision === undefined) {
      return false;
    }
    const { signature, ...unsigned } = decision;
    const actor = this.#actors.get(decision.issuerId);
    return (
      actor !== undefined &&
      verifyEd25519(
        actor.signingPublicKey,
        supportDecisionSigningPayload(unsigned),
        signature,
      )
    );
  }

  openRegulatoryCase(input: RegulatoryCaseInput): void {
    const credential = this.#assertCredentialControl(
      input.actorId,
      input.credentialId,
      input.holderSecret,
    );
    const product = this.#requireProduct(credential.productId);
    if (product.organizationId !== input.respondentOrganizationId) {
      throw new TypeError(
        `respondentOrganizationId: ${input.respondentOrganizationId} does not own ${credential.productId}`,
      );
    }
    if (this.#regulatoryCases.has(input.caseId)) {
      throw new TypeError(`caseId: duplicate ${input.caseId}`);
    }
    const stored: StoredRegulatoryCase = {
      input: {
        ...input,
        caseId: text(input.caseId, "caseId"),
        actorId: text(input.actorId, "actorId"),
        credentialId: text(input.credentialId, "credentialId"),
        holderSecret: text(input.holderSecret, "holderSecret"),
        respondentOrganizationId: text(
          input.respondentOrganizationId,
          "respondentOrganizationId",
        ),
        purpose: text(input.purpose, "purpose"),
        openedAt: timestamp(input.openedAt, "openedAt"),
      },
      productId: credential.productId,
    };
    this.#regulatoryCases.set(stored.input.caseId, stored);
    this.#events.push({
      type: "RegulatoryCaseOpened",
      caseId: stored.input.caseId,
      actorId: stored.input.actorId,
      purpose: stored.input.purpose,
    });
  }

  authorizeEvidenceBridge(bridge: SignedEvidenceBridge): string {
    const regulatoryCase = this.#requireRegulatoryCase(bridge.caseId);
    if (bridge.authorizerId !== regulatoryCase.input.actorId) {
      throw new PolicyDeniedError(
        "CREDENTIAL_HOLDER_MISMATCH",
        `${bridge.authorizerId} did not open ${bridge.caseId}`,
      );
    }
    if (bridge.purpose !== regulatoryCase.input.purpose) {
      throw new PolicyDeniedError(
        "PURPOSE_MISMATCH",
        `${bridge.purpose} is not the declared purpose for ${bridge.caseId}`,
      );
    }
    enforce(this.#canReceiveRegulatoryEvidence(bridge.recipientId));
    if (this.#bridges.has(bridge.bridgeId)) {
      throw new TypeError(`bridgeId: duplicate ${bridge.bridgeId}`);
    }
    const recordIds = sortedUnique(bridge.recordIds, "recordIds");
    this.#assertBridgeRecords(regulatoryCase, recordIds);
    const unsigned: Omit<SignedEvidenceBridge, "signature"> = {
      bridgeId: text(bridge.bridgeId, "bridgeId"),
      caseId: text(bridge.caseId, "caseId"),
      authorizerId: text(bridge.authorizerId, "authorizerId"),
      recipientId: text(bridge.recipientId, "recipientId"),
      purpose: text(bridge.purpose, "purpose"),
      recordIds,
      authorizedAt: timestamp(bridge.authorizedAt, "authorizedAt"),
    };
    this.#assertActorSignature(
      unsigned.authorizerId,
      evidenceBridgeSigningPayload(unsigned),
      bridge.signature,
      `evidence bridge ${unsigned.bridgeId}`,
    );
    const stored: SignedEvidenceBridge = {
      ...unsigned,
      signature: text(bridge.signature, "signature"),
    };
    const flow = this.#makeFlow({
      flowId: `regulatory-bridge:${stored.bridgeId}`,
      context: "regulatory",
      policyVersion: "regulatory-policy-1",
      actorIds: [stored.authorizerId, stored.recipientId],
      senderId: stored.authorizerId,
      records: stored.recordIds.map((recordId) => ({
        id: recordId,
        digest: this.#recordDigest(recordId),
      })),
      claims: [
        {
          id: `${stored.bridgeId}:authorization`,
          type: "holder-authorized-evidence-bridge",
          value: "true",
          issuerId: stored.authorizerId,
        },
        {
          id: `${stored.bridgeId}:same-holder`,
          type: "same-credential-holder",
          value: "true",
          issuerId: stored.authorizerId,
        },
        {
          id: `${stored.bridgeId}:same-transaction`,
          type: "same-purchase-transaction",
          value: "true",
          issuerId: stored.authorizerId,
        },
      ],
      recipient: { kind: "actor", actorId: stored.recipientId },
      visibleClaimIds: [
        `${stored.bridgeId}:authorization`,
        `${stored.bridgeId}:same-holder`,
        `${stored.bridgeId}:same-transaction`,
      ],
    });
    const commitment = this.#recordAction(stored.bridgeId, flow);
    this.#bridges.set(stored.bridgeId, stored);
    this.#events.push({
      type: "EvidenceBridgeAuthorized",
      bridgeId: stored.bridgeId,
      caseId: stored.caseId,
      authorizerId: stored.authorizerId,
      recipientId: stored.recipientId,
      commitment,
    });
    return commitment;
  }

  canVerifyEvidenceBridge(
    request: EvidenceVerificationRequest,
  ): PolicyDecision {
    if (!this.#actors.has(request.actorId)) {
      return deny(
        "ACTOR_NOT_REGISTERED",
        `${request.actorId} is not registered`,
      );
    }
    const bridge = this.#bridges.get(request.bridgeId);
    if (bridge === undefined) {
      return deny(
        "REGULATORY_AUTHORITY_REQUIRED",
        `${request.bridgeId} is not an authorized evidence bridge`,
      );
    }
    if (bridge.recipientId !== request.actorId) {
      return deny(
        "RECIPIENT_MISMATCH",
        `${request.actorId} is not the authorized recipient of ${request.bridgeId}`,
      );
    }
    const authority = this.#canReceiveRegulatoryEvidence(request.actorId);
    if (!authority.allowed) {
      return authority;
    }
    if (bridge.caseId !== request.caseId) {
      return deny(
        "CASE_MISMATCH",
        `${request.bridgeId} is bound to ${bridge.caseId}, not ${request.caseId}`,
      );
    }
    if (bridge.purpose !== request.purpose) {
      return deny(
        "PURPOSE_MISMATCH",
        `${request.bridgeId} is bound to purpose ${bridge.purpose}`,
      );
    }
    let requestedRecords: string[];
    try {
      requestedRecords = sortedUnique(request.recordIds, "recordIds");
    } catch {
      return deny(
        "RECORD_SET_MISMATCH",
        `${request.bridgeId} requires its exact authorized record set`,
      );
    }
    if (!sameStrings([...bridge.recordIds].sort(), requestedRecords)) {
      return deny(
        "RECORD_SET_MISMATCH",
        `${request.bridgeId} requires its exact authorized record set`,
      );
    }
    return allow(
      `${request.actorId} may verify ${request.bridgeId} only for ${request.caseId}, ${request.purpose}, and the authorized records`,
    );
  }

  verifyEvidenceBridge(
    request: EvidenceVerificationRequest,
  ): EvidenceVerificationResult {
    enforce(this.canVerifyEvidenceBridge(request));
    const bridge = this.#bridges.get(request.bridgeId)!;
    const regulatoryCase = this.#requireRegulatoryCase(bridge.caseId);
    const action = this.#actions.get(bridge.bridgeId)!;
    this.#events.push({
      type: "EvidenceVerified",
      bridgeId: bridge.bridgeId,
      caseId: bridge.caseId,
      actorId: request.actorId,
    });
    return {
      bridgeId: bridge.bridgeId,
      caseId: bridge.caseId,
      productId: regulatoryCase.productId,
      sameCredentialHolder: true,
      samePurchaseTransaction: true,
      reviewIntegrityVerified: true,
      supportDecisionIntegrityVerified: true,
      commitment: action.commitment,
    };
  }

  deriveCapabilities(actorId: string): readonly DerivedCapability[] {
    this.#requireActor(actorId);
    const capabilities: DerivedCapability[] = [];
    for (const event of this.#events) {
      switch (event.type) {
        case "OrganizationRegistered":
          if (event.registeredBy === actorId) {
            capabilities.push({
              action: "register-product",
              resourceId: event.organizationId,
              basisId: event.organizationId,
            });
          }
          break;
        case "AuthorityGranted":
          if (event.granteeId === actorId) {
            capabilities.push({
              action:
                event.capability === "issue-purchase-credential"
                  ? "issue-purchase-credential"
                  : "verify-regulatory-evidence",
              resourceId: event.scopeId,
              basisId: event.grantId,
            });
          }
          break;
        case "PurchaseCredentialIssued":
          if (event.holderId === actorId) {
            capabilities.push(
              {
                action: "publish-product-review",
                resourceId: event.productId,
                basisId: event.credentialId,
              },
              {
                action: "request-product-support",
                resourceId: event.productId,
                basisId: event.credentialId,
              },
              {
                action: "authorize-regulatory-bridge",
                resourceId: event.productId,
                basisId: event.credentialId,
              },
            );
          }
          break;
        case "SupportRequested":
          if (event.recipientId === actorId) {
            capabilities.push({
              action: "decide-support-case",
              resourceId: event.caseId,
              basisId: event.caseId,
            });
          }
          break;
        default:
          break;
      }
    }
    return capabilities;
  }

  getEvents(): readonly DomainEvent[] {
    return structuredClone(this.#events);
  }

  getPublicCommitmentRecords(): readonly PublicCommitmentRecord[] {
    return [...this.#actions.values()].map(({ actionId, commitment }) => ({
      actionId,
      commitment,
    }));
  }

  auditCommitments(): readonly CommitmentAudit[] {
    return [...this.#actions.values()].map((action) => ({
      actionId: action.actionId,
      commitment: action.commitment,
      matchesPrivateRecord:
        commitInformationFlow(action.flow, action.nonce) === action.commitment,
    }));
  }

  #requireActor(actorId: string): ActorRegistration {
    const actor = this.#actors.get(actorId);
    if (actor === undefined) {
      throw new PolicyDeniedError(
        "ACTOR_NOT_REGISTERED",
        `${actorId} is not registered`,
      );
    }
    return actor;
  }

  #requireOrganization(organizationId: string): OrganizationRegistration {
    const organization = this.#organizations.get(organizationId);
    if (organization === undefined) {
      throw new TypeError(`organizationId: unknown ${organizationId}`);
    }
    return organization;
  }

  #requireProduct(productId: string): ProductRegistration {
    const product = this.#products.get(productId);
    if (product === undefined) {
      throw new TypeError(`productId: unknown ${productId}`);
    }
    return product;
  }

  #requireCredential(credentialId: string): SignedPurchaseCredential {
    const credential = this.#credentials.get(credentialId);
    if (credential === undefined) {
      throw new PolicyDeniedError(
        "CREDENTIAL_REQUIRED",
        `${credentialId} is not a valid purchase credential`,
      );
    }
    return credential;
  }

  #requireSupportCase(caseId: string): StoredSupportCase {
    const supportCase = this.#supportCases.get(caseId);
    if (supportCase === undefined) {
      throw new TypeError(`caseId: unknown support case ${caseId}`);
    }
    return supportCase;
  }

  #requireRegulatoryCase(caseId: string): StoredRegulatoryCase {
    const regulatoryCase = this.#regulatoryCases.get(caseId);
    if (regulatoryCase === undefined) {
      throw new TypeError(`caseId: unknown regulatory case ${caseId}`);
    }
    return regulatoryCase;
  }

  #assertCredentialControl(
    actorId: string,
    credentialId: string,
    holderSecret: string,
  ): SignedPurchaseCredential {
    enforce(
      this.#credentialControlDecision(actorId, credentialId, holderSecret),
    );
    return this.#requireCredential(credentialId);
  }

  #findGrant(
    actorId: string,
    capability: AuthorityCapability,
    scopeId: string,
  ): SignedAuthorityGrant | undefined {
    return [...this.#grants.values()].find(
      (grant) =>
        grant.granteeId === actorId &&
        grant.capability === capability &&
        grant.scopeId === scopeId,
    );
  }

  #canReceiveRegulatoryEvidence(actorId: string): PolicyDecision {
    if (!this.#actors.has(actorId)) {
      return deny("ACTOR_NOT_REGISTERED", `${actorId} is not registered`);
    }
    const grant = this.#findGrant(
      actorId,
      "verify-regulatory-evidence",
      this.#options.regulatoryScopeId,
    );
    if (grant === undefined) {
      return deny(
        "REGULATORY_AUTHORITY_REQUIRED",
        `${actorId} has no signed regulatory authority for ${this.#options.regulatoryScopeId}`,
      );
    }
    return allow(
      `${actorId} may receive assigned regulatory evidence because of ${grant.grantId}`,
    );
  }

  #assertActorSignature(
    actorId: string,
    payload: string,
    signature: string,
    description: string,
  ): void {
    const actor = this.#requireActor(actorId);
    if (!verifyEd25519(actor.signingPublicKey, payload, signature)) {
      throw new PolicyDeniedError(
        "SIGNATURE_INVALID",
        `${description} is not signed by ${actorId}`,
      );
    }
  }

  #assertBridgeRecords(
    regulatoryCase: StoredRegulatoryCase,
    recordIds: readonly string[],
  ): void {
    const credentialId = regulatoryCase.input.credentialId;
    const review = [...this.#reviewCredentialIds.entries()].find(
      ([, reviewCredentialId]) => reviewCredentialId === credentialId,
    );
    const supportCase = [...this.#supportCases.values()].find(
      (candidate) => candidate.credentialId === credentialId,
    );
    const supportDecision = [...this.#supportDecisions.values()].find(
      (candidate) => candidate.caseId === supportCase?.input.caseId,
    );
    const expected = sortedUnique(
      [
        credentialId,
        review?.[0] ?? "missing-review",
        supportCase?.input.caseId ?? "missing-support-case",
        supportDecision?.decisionId ?? "missing-support-decision",
      ],
      "expectedRecordIds",
    );
    if (!sameStrings(expected, [...recordIds].sort())) {
      throw new PolicyDeniedError(
        "RECORD_SET_MISMATCH",
        `${regulatoryCase.input.caseId} requires the selected purchase, review, support case, and signed decision`,
      );
    }
  }

  #recordDigest(recordId: string): string {
    const credential = this.#credentials.get(recordId);
    if (credential !== undefined) {
      return this.#credentialDigest(credential);
    }
    const review = this.#reviews.get(recordId);
    if (review !== undefined) {
      return hashParts(
        "midnight-buildathon:information-flow:review-record:v1",
        review.commitment,
      );
    }
    const supportCase = this.#supportCases.get(recordId);
    if (supportCase !== undefined) {
      return hashParts(
        "midnight-buildathon:information-flow:support-record:v1",
        supportCase.view.commitment,
      );
    }
    const decision = this.#supportDecisions.get(recordId);
    if (decision !== undefined) {
      return hashParts(
        "midnight-buildathon:information-flow:decision-record:v1",
        supportDecisionSigningPayload(decision),
        decision.signature,
      );
    }
    throw new TypeError(`recordId: unknown ${recordId}`);
  }

  #credentialDigest(credential: SignedPurchaseCredential): string {
    const { signature, ...unsigned } = credential;
    return hashParts(
      "midnight-buildathon:information-flow:purchase-record:v1",
      purchaseCredentialSigningPayload(unsigned),
      signature,
    );
  }

  #reviewNullifier(credential: SignedPurchaseCredential): string {
    return hashParts(
      "midnight-buildathon:information-flow:review-nullifier:v1",
      credential.productId,
      credential.credentialId,
    );
  }

  #makeFlow(input: {
    readonly flowId: string;
    readonly context: ContextKind;
    readonly policyVersion: string;
    readonly actorIds: readonly string[];
    readonly senderId: string;
    readonly records: readonly RecordRef[];
    readonly claims: readonly Claim[];
    readonly recipient: RecipientRef;
    readonly visibleClaimIds: readonly string[];
  }): InformationFlow {
    const actorIds = [...new Set(input.actorIds)].sort();
    return {
      schemaVersion: 2,
      flowId: input.flowId,
      context: {
        kind: input.context,
        policyVersion: input.policyVersion,
      },
      actors: actorIds.map((id) => ({ id })),
      senderId: input.senderId,
      records: input.records,
      claims: input.claims,
      view: {
        recipient: input.recipient,
        visibleClaimIds: input.visibleClaimIds,
      },
    };
  }

  #recordAction(actionId: string, flow: InformationFlow): string {
    if (this.#actions.has(actionId)) {
      throw new TypeError(`actionId: duplicate ${actionId}`);
    }
    const nonce = this.#options.nonceFactory();
    if (!(nonce instanceof Uint8Array) || nonce.byteLength !== FLOW_NONCE_BYTES) {
      throw new TypeError(
        `nonceFactory: expected exactly ${FLOW_NONCE_BYTES} bytes`,
      );
    }
    const privateNonce = Uint8Array.from(nonce);
    const commitment = commitInformationFlow(flow, privateNonce);
    this.#actions.set(actionId, {
      actionId,
      flow,
      nonce: privateNonce,
      commitment,
    });
    return commitment;
  }
}
