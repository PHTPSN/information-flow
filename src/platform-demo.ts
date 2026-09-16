import {
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign as signPayload,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

import {
  BehaviorDerivedInformationFlowSystem,
  authorityGrantSigningPayload,
  evidenceBridgeSigningPayload,
  hashHolderSecret,
  purchaseCredentialSigningPayload,
  supportDecisionSigningPayload,
  type EvidenceVerificationResult,
  type PublicReview,
  type SignedAuthorityGrant,
  type SignedEvidenceBridge,
  type SignedPurchaseCredential,
  type SignedSupportDecision,
  type SupportRecipientView,
} from "./behavior-derived-system.js";

export const DEMO_PASSWORD = "123456";
export const MANAGER_USERNAME = "manager";

const PRODUCT_ID = "H1";
const PRODUCT_NAME = "H1 Headphones";
const ORGANIZATION_ID = "acme-audio";
const ORGANIZATION_NAME = "Acme Audio";
const REGULATORY_SCOPE = "consumer-products-demo";
const REGULATORY_PURPOSE = "investigate the H1 battery safety dispute";

interface SigningIdentity {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

interface StoredAccount {
  readonly userId: string;
  readonly username: string;
  readonly displayName: string;
  readonly passwordSalt: Buffer;
  readonly passwordHash: Buffer;
  readonly signing: SigningIdentity;
  readonly createdAt: string;
}

interface StoredPurchase {
  readonly credentialId: string;
  readonly buyerId: string;
  readonly issuerId: string;
  readonly orderId: string;
  readonly purchasedAt: string;
  readonly holderSecret: string;
  reviewId: string | null;
  supportCaseId: string | null;
  regulatoryCaseId: string | null;
}

interface StoredSupportCase {
  readonly caseId: string;
  readonly buyerId: string;
  readonly merchantId: string;
  readonly credentialId: string;
  readonly view: SupportRecipientView;
  decisionId: string | null;
  outcome: "pending" | "approved" | "rejected";
  reason: string | null;
}

interface StoredRegulatoryCase {
  readonly caseId: string;
  readonly bridgeId: string;
  readonly buyerId: string;
  readonly recipientId: string;
  readonly credentialId: string;
  readonly recordIds: readonly string[];
  verified: boolean;
  result: EvidenceVerificationResult | null;
}

type SessionPrincipal =
  | { readonly kind: "manager" }
  | { readonly kind: "user"; readonly userId: string };

export interface PublicAccount {
  readonly userId: string;
  readonly username: string;
  readonly displayName: string;
  readonly createdAt: string;
}

export interface PlatformDashboard {
  readonly account: {
    readonly kind: "manager" | "user";
    readonly username: string;
    readonly displayName: string;
  };
  readonly product: {
    readonly id: string;
    readonly name: string;
    readonly organization: string;
  } | null;
  readonly manager: {
    readonly users: readonly PublicAccount[];
    readonly configured: boolean;
    readonly merchantUsername: string | null;
    readonly regulatorUsername: string | null;
  } | null;
  readonly reviews: readonly {
    readonly reviewId: string;
    readonly productName: string;
    readonly rating: number;
    readonly text: string;
    readonly verifiedPurchase: true;
    readonly publishedAt: string;
    readonly openedByYou: boolean;
  }[];
  readonly purchases: readonly {
    readonly purchaseId: string;
    readonly productName: string;
    readonly orderId: string;
    readonly purchasedAt: string;
    readonly canReview: boolean;
    readonly canRequestSupport: boolean;
    readonly canEscalate: boolean;
    readonly reviewId: string | null;
    readonly support: {
      readonly caseId: string;
      readonly outcome: "pending" | "approved" | "rejected";
      readonly reason: string | null;
    } | null;
    readonly regulatoryCase: {
      readonly caseId: string;
      readonly verified: boolean;
    } | null;
  }[];
  readonly canIssuePurchases: boolean;
  readonly availableBuyers: readonly PublicAccount[];
  readonly supportInbox: readonly {
    readonly caseId: string;
    readonly productName: string;
    readonly customerReference: string;
    readonly purchasedWithinThirtyDays: boolean;
    readonly replacementAvailable: boolean;
    readonly outcome: "pending" | "approved" | "rejected";
    readonly reason: string | null;
  }[];
  readonly assignedCases: readonly {
    readonly caseId: string;
    readonly productName: string;
    readonly purpose: string;
    readonly verified: boolean;
    readonly result: {
      readonly samePurchase: boolean;
      readonly reviewIntegrity: boolean;
      readonly supportDecisionIntegrity: boolean;
    } | null;
  }[];
  readonly activity: readonly {
    readonly message: string;
    readonly at: string;
  }[];
  readonly counts: {
    readonly registeredUsers: number;
    readonly publicReviews: number;
    readonly publicCommitments: number;
  };
}

export class PlatformError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "PlatformError";
    this.status = status;
    this.code = code;
  }
}

function signingIdentity(): SigningIdentity {
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

function requiredText(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new PlatformError(400, "INVALID_INPUT", `${field} is required`);
  }
  const normalized = value.normalize("NFC").trim();
  if (normalized.length === 0) {
    throw new PlatformError(400, "INVALID_INPUT", `${field} is required`);
  }
  return normalized;
}

function displayName(value: unknown, fallback: string): string {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value !== "string") {
    throw new PlatformError(400, "INVALID_INPUT", "Display name must be text");
  }
  return value.normalize("NFC").trim() || fallback;
}

function username(value: unknown): string {
  const normalized = requiredText(value, "Username").toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,23}$/.test(normalized)) {
    throw new PlatformError(
      400,
      "INVALID_USERNAME",
      "Username must be 3–24 characters using letters, numbers, dots, dashes, or underscores",
    );
  }
  if (normalized === MANAGER_USERNAME) {
    throw new PlatformError(409, "USERNAME_TAKEN", "That username is unavailable");
  }
  return normalized;
}

function passwordHash(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

function publicAccount(account: StoredAccount): PublicAccount {
  return {
    userId: account.userId,
    username: account.username,
    displayName: account.displayName,
    createdAt: account.createdAt,
  };
}

export class InformationFlowPlatform {
  readonly #authority = signingIdentity();
  readonly #system: BehaviorDerivedInformationFlowSystem;
  readonly #clock: () => Date;
  readonly #accountsByUsername = new Map<string, StoredAccount>();
  readonly #accountsById = new Map<string, StoredAccount>();
  readonly #sessions = new Map<string, SessionPrincipal>();
  readonly #purchases = new Map<string, StoredPurchase>();
  readonly #reviews = new Map<string, PublicReview>();
  readonly #reviewReaders = new Map<string, Set<string>>();
  readonly #supportCases = new Map<string, StoredSupportCase>();
  readonly #regulatoryCases = new Map<string, StoredRegulatoryCase>();
  readonly #activity = new Map<
    string,
    Array<{ readonly message: string; readonly at: string }>
  >();
  #userSequence = 0;
  #purchaseSequence = 0;
  #reviewSequence = 0;
  #supportSequence = 0;
  #regulatorySequence = 0;
  #configured = false;
  #merchantId: string | null = null;
  #regulatorId: string | null = null;

  constructor(options: { readonly clock?: () => Date } = {}) {
    this.#clock = options.clock ?? (() => new Date());
    this.#system = new BehaviorDerivedInformationFlowSystem({
      trustedAuthorityId: "platform-authority",
      trustedAuthorityPublicKey: this.#authority.publicKey,
      regulatoryScopeId: REGULATORY_SCOPE,
    });
  }

  register(input: {
    readonly username: unknown;
    readonly displayName: unknown;
    readonly password: unknown;
  }): PublicAccount {
    const normalizedUsername = username(input.username);
    const normalizedDisplayName = displayName(
      input.displayName,
      normalizedUsername,
    );
    const password = requiredText(input.password, "Password");
    if (password !== DEMO_PASSWORD) {
      throw new PlatformError(
        400,
        "DEMO_PASSWORD_REQUIRED",
        `Use ${DEMO_PASSWORD} for this local demo`,
      );
    }
    if (this.#accountsByUsername.has(normalizedUsername)) {
      throw new PlatformError(409, "USERNAME_TAKEN", "That username is already registered");
    }

    this.#userSequence += 1;
    const userId = `user-${this.#userSequence}`;
    const signing = signingIdentity();
    const salt = randomBytes(16);
    const account: StoredAccount = {
      userId,
      username: normalizedUsername,
      displayName: normalizedDisplayName,
      passwordSalt: salt,
      passwordHash: passwordHash(password, salt),
      signing,
      createdAt: this.#now(),
    };
    this.#system.registerActor({
      actorId: userId,
      signingPublicKey: signing.publicKey,
    });
    this.#accountsByUsername.set(normalizedUsername, account);
    this.#accountsById.set(userId, account);
    this.#activity.set(userId, [
      { message: "Account created", at: account.createdAt },
    ]);
    return publicAccount(account);
  }

  loginUser(input: {
    readonly username: unknown;
    readonly password: unknown;
  }): string {
    const normalizedUsername = requiredText(input.username, "Username").toLowerCase();
    const password = requiredText(input.password, "Password");
    const account = this.#accountsByUsername.get(normalizedUsername);
    if (account === undefined) {
      throw new PlatformError(401, "LOGIN_FAILED", "Incorrect username or password");
    }
    const candidate = passwordHash(password, account.passwordSalt);
    if (!timingSafeEqual(candidate, account.passwordHash)) {
      throw new PlatformError(401, "LOGIN_FAILED", "Incorrect username or password");
    }
    return this.#createSession({ kind: "user", userId: account.userId });
  }

  loginManager(input: { readonly password: unknown }): string {
    if (requiredText(input.password, "Password") !== DEMO_PASSWORD) {
      throw new PlatformError(401, "LOGIN_FAILED", "Incorrect manager password");
    }
    return this.#createSession({ kind: "manager" });
  }

  logout(token: string): void {
    this.#sessions.delete(token);
  }

  session(token: string | null): PlatformDashboard["account"] | null {
    if (token === null) return null;
    const principal = this.#sessions.get(token);
    if (principal === undefined) return null;
    if (principal.kind === "manager") {
      return { kind: "manager", username: MANAGER_USERNAME, displayName: "Manager" };
    }
    const account = this.#requireAccountById(principal.userId);
    return {
      kind: "user",
      username: account.username,
      displayName: account.displayName,
    };
  }

  configure(
    token: string,
    input: { readonly merchantUsername: unknown; readonly regulatorUsername: unknown },
  ): PlatformDashboard {
    this.#requireManager(token);
    if (this.#configured) {
      throw new PlatformError(409, "ALREADY_CONFIGURED", "The H1 workspace is already configured");
    }
    const merchant = this.#requireAccountByUsername(input.merchantUsername);
    const regulator = this.#requireAccountByUsername(input.regulatorUsername);
    if (merchant.userId === regulator.userId) {
      throw new PlatformError(
        400,
        "ACCOUNTS_MUST_DIFFER",
        "Choose different accounts for Acme operations and case review",
      );
    }

    this.#system.registerOrganization({
      organizationId: ORGANIZATION_ID,
      name: ORGANIZATION_NAME,
      registeredBy: merchant.userId,
    });
    this.#system.registerProduct({
      productId: PRODUCT_ID,
      name: PRODUCT_NAME,
      organizationId: ORGANIZATION_ID,
      registeredBy: merchant.userId,
    });

    const issuedAt = this.#now();
    const issuerGrant = {
      grantId: "grant-h1-sales",
      authorityId: "platform-authority",
      granteeId: merchant.userId,
      capability: "issue-purchase-credential",
      scopeId: PRODUCT_ID,
      issuedAt,
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    this.#system.grantAuthority({
      ...issuerGrant,
      signature: sign(
        authorityGrantSigningPayload(issuerGrant),
        this.#authority.privateKey,
      ),
    });

    const regulatorGrant = {
      grantId: "grant-consumer-case-review",
      authorityId: "platform-authority",
      granteeId: regulator.userId,
      capability: "verify-regulatory-evidence",
      scopeId: REGULATORY_SCOPE,
      issuedAt,
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    this.#system.grantAuthority({
      ...regulatorGrant,
      signature: sign(
        authorityGrantSigningPayload(regulatorGrant),
        this.#authority.privateKey,
      ),
    });

    this.#merchantId = merchant.userId;
    this.#regulatorId = regulator.userId;
    this.#configured = true;
    this.#addActivity(merchant.userId, "Acme Audio workspace connected");
    this.#addActivity(regulator.userId, "Consumer case review access assigned");
    return this.dashboard(token);
  }

  issuePurchase(
    token: string,
    input: { readonly buyerUsername: unknown; readonly orderId: unknown },
  ): PlatformDashboard {
    const merchant = this.#requireUser(token);
    if (!this.#configured || merchant.userId !== this.#merchantId) {
      throw new PlatformError(403, "NOT_AVAILABLE", "Sales tools are not available for this account");
    }
    const buyer = this.#requireAccountByUsername(input.buyerUsername);
    if (buyer.userId === merchant.userId) {
      throw new PlatformError(400, "INVALID_BUYER", "Choose another registered customer");
    }
    const orderId = requiredText(input.orderId, "Order number");
    if ([...this.#purchases.values()].some((purchase) => purchase.orderId === orderId)) {
      throw new PlatformError(409, "ORDER_EXISTS", "That order number already exists");
    }

    this.#purchaseSequence += 1;
    const credentialId = `purchase-${String(this.#purchaseSequence).padStart(3, "0")}`;
    const holderSecret = randomBytes(32).toString("base64url");
    const purchasedAt = this.#now();
    const credential = {
      credentialId,
      productId: PRODUCT_ID,
      issuerId: merchant.userId,
      holderId: buyer.userId,
      orderId,
      purchasedAt,
      holderSecretHash: hashHolderSecret(holderSecret),
    } as const satisfies Omit<SignedPurchaseCredential, "signature">;
    this.#system.issuePurchaseCredential({
      ...credential,
      signature: sign(
        purchaseCredentialSigningPayload(credential),
        merchant.signing.privateKey,
      ),
    });
    this.#purchases.set(credentialId, {
      credentialId,
      buyerId: buyer.userId,
      issuerId: merchant.userId,
      orderId,
      purchasedAt,
      holderSecret,
      reviewId: null,
      supportCaseId: null,
      regulatoryCaseId: null,
    });
    this.#addActivity(merchant.userId, `Order ${orderId} issued for ${PRODUCT_NAME}`);
    this.#addActivity(buyer.userId, `${PRODUCT_NAME} added to your purchases`);
    return this.dashboard(token);
  }

  publishReview(
    token: string,
    input: { readonly purchaseId: unknown; readonly rating: unknown; readonly text: unknown },
  ): PlatformDashboard {
    const account = this.#requireUser(token);
    const purchase = this.#requireOwnedPurchase(account.userId, input.purchaseId);
    if (purchase.reviewId !== null) {
      throw new PlatformError(409, "REVIEW_EXISTS", "This purchase already has a review");
    }
    const rating = Number(input.rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      throw new PlatformError(400, "INVALID_RATING", "Rating must be from 1 to 5");
    }
    this.#reviewSequence += 1;
    const reviewId = `review-${String(this.#reviewSequence).padStart(3, "0")}`;
    const review = this.#system.publishReview({
      reviewId,
      actorId: account.userId,
      credentialId: purchase.credentialId,
      holderSecret: purchase.holderSecret,
      rating,
      text: requiredText(input.text, "Review"),
      publishedAt: this.#now(),
    });
    purchase.reviewId = reviewId;
    this.#reviews.set(reviewId, review);
    this.#reviewReaders.set(reviewId, new Set([account.userId]));
    this.#addActivity(account.userId, `Your ${PRODUCT_NAME} review was published`);
    return this.dashboard(token);
  }

  openReview(token: string, input: { readonly reviewId: unknown }): PlatformDashboard {
    const account = this.#requireUser(token);
    const reviewId = requiredText(input.reviewId, "Review");
    this.#system.readPublicReview(account.userId, reviewId);
    const readers = this.#reviewReaders.get(reviewId) ?? new Set<string>();
    readers.add(account.userId);
    this.#reviewReaders.set(reviewId, readers);
    return this.dashboard(token);
  }

  requestSupport(token: string, input: { readonly purchaseId: unknown }): PlatformDashboard {
    const buyer = this.#requireUser(token);
    const purchase = this.#requireOwnedPurchase(buyer.userId, input.purchaseId);
    if (purchase.supportCaseId !== null) {
      throw new PlatformError(409, "CASE_EXISTS", "A support request already exists for this purchase");
    }
    if (this.#merchantId === null) {
      throw new PlatformError(409, "WORKSPACE_NOT_READY", "Acme Audio is not configured yet");
    }
    this.#supportSequence += 1;
    const caseId = `CASE-${String(this.#supportSequence).padStart(3, "0")}`;
    const view = this.#system.requestSupport({
      caseId,
      actorId: buyer.userId,
      credentialId: purchase.credentialId,
      holderSecret: purchase.holderSecret,
      organizationId: ORGANIZATION_ID,
      request: "replacement",
      requestedAt: this.#now(),
      policyVersion: "support-policy-1",
    });
    purchase.supportCaseId = caseId;
    this.#supportCases.set(caseId, {
      caseId,
      buyerId: buyer.userId,
      merchantId: this.#merchantId,
      credentialId: purchase.credentialId,
      view,
      decisionId: null,
      outcome: "pending",
      reason: null,
    });
    this.#addActivity(buyer.userId, `Replacement request ${caseId} submitted`);
    this.#addActivity(this.#merchantId, `New replacement request ${caseId}`);
    return this.dashboard(token);
  }

  decideSupport(
    token: string,
    input: { readonly caseId: unknown; readonly outcome: unknown; readonly reason: unknown },
  ): PlatformDashboard {
    const merchant = this.#requireUser(token);
    const caseId = requiredText(input.caseId, "Case");
    const supportCase = this.#supportCases.get(caseId);
    if (supportCase === undefined || supportCase.merchantId !== merchant.userId) {
      throw new PlatformError(404, "CASE_NOT_FOUND", "Support request not found");
    }
    if (supportCase.decisionId !== null) {
      throw new PlatformError(409, "DECISION_EXISTS", "This request already has a decision");
    }
    const outcome = requiredText(input.outcome, "Decision");
    if (outcome !== "approved" && outcome !== "rejected") {
      throw new PlatformError(400, "INVALID_DECISION", "Choose approved or rejected");
    }
    const decisionId = `decision-${caseId.toLowerCase()}`;
    const decision = {
      decisionId,
      caseId,
      issuerId: merchant.userId,
      outcome,
      reason: requiredText(input.reason, "Reason"),
      decidedAt: this.#now(),
      policyVersion: "support-policy-1",
    } as const satisfies Omit<SignedSupportDecision, "signature">;
    this.#system.recordSupportDecision({
      ...decision,
      signature: sign(
        supportDecisionSigningPayload(decision),
        merchant.signing.privateKey,
      ),
    });
    supportCase.decisionId = decisionId;
    supportCase.outcome = outcome;
    supportCase.reason = decision.reason;
    this.#addActivity(merchant.userId, `${caseId} marked ${outcome}`);
    this.#addActivity(supportCase.buyerId, `${caseId} has a new decision`);
    return this.dashboard(token);
  }

  escalate(token: string, input: { readonly purchaseId: unknown }): PlatformDashboard {
    const buyer = this.#requireUser(token);
    const purchase = this.#requireOwnedPurchase(buyer.userId, input.purchaseId);
    if (purchase.regulatoryCaseId !== null) {
      throw new PlatformError(409, "CASE_EXISTS", "This purchase has already been escalated");
    }
    if (purchase.reviewId === null || purchase.supportCaseId === null) {
      throw new PlatformError(
        409,
        "EVIDENCE_INCOMPLETE",
        "Publish a review and complete support before escalating",
      );
    }
    const supportCase = this.#supportCases.get(purchase.supportCaseId)!;
    if (supportCase.decisionId === null || this.#regulatorId === null) {
      throw new PlatformError(409, "EVIDENCE_INCOMPLETE", "A support decision is required first");
    }

    this.#regulatorySequence += 1;
    const caseId = `REG-${String(this.#regulatorySequence).padStart(3, "0")}`;
    this.#system.openRegulatoryCase({
      caseId,
      actorId: buyer.userId,
      credentialId: purchase.credentialId,
      holderSecret: purchase.holderSecret,
      respondentOrganizationId: ORGANIZATION_ID,
      purpose: REGULATORY_PURPOSE,
      openedAt: this.#now(),
    });
    const bridgeId = `bridge-${caseId.toLowerCase()}`;
    const recordIds = [
      purchase.credentialId,
      purchase.reviewId,
      supportCase.caseId,
      supportCase.decisionId,
    ];
    const bridge = {
      bridgeId,
      caseId,
      authorizerId: buyer.userId,
      recipientId: this.#regulatorId,
      purpose: REGULATORY_PURPOSE,
      recordIds,
      authorizedAt: this.#now(),
    } as const satisfies Omit<SignedEvidenceBridge, "signature">;
    this.#system.authorizeEvidenceBridge({
      ...bridge,
      signature: sign(
        evidenceBridgeSigningPayload(bridge),
        buyer.signing.privateKey,
      ),
    });
    purchase.regulatoryCaseId = caseId;
    this.#regulatoryCases.set(caseId, {
      caseId,
      bridgeId,
      buyerId: buyer.userId,
      recipientId: this.#regulatorId,
      credentialId: purchase.credentialId,
      recordIds,
      verified: false,
      result: null,
    });
    this.#addActivity(buyer.userId, `Case ${caseId} submitted for independent review`);
    this.#addActivity(this.#regulatorId, `New case ${caseId} assigned`);
    return this.dashboard(token);
  }

  verifyCase(token: string, input: { readonly caseId: unknown }): PlatformDashboard {
    const reviewer = this.#requireUser(token);
    const caseId = requiredText(input.caseId, "Case");
    const regulatoryCase = this.#regulatoryCases.get(caseId);
    if (
      regulatoryCase === undefined ||
      regulatoryCase.recipientId !== reviewer.userId
    ) {
      throw new PlatformError(404, "CASE_NOT_FOUND", "Assigned case not found");
    }
    if (!regulatoryCase.verified) {
      regulatoryCase.result = this.#system.verifyEvidenceBridge({
        bridgeId: regulatoryCase.bridgeId,
        actorId: reviewer.userId,
        caseId,
        purpose: REGULATORY_PURPOSE,
        recordIds: regulatoryCase.recordIds,
      });
      regulatoryCase.verified = true;
      this.#addActivity(reviewer.userId, `${caseId} evidence verified`);
      this.#addActivity(regulatoryCase.buyerId, `${caseId} evidence verification completed`);
    }
    return this.dashboard(token);
  }

  dashboard(token: string): PlatformDashboard {
    const principal = this.#requireSession(token);
    const counts = {
      registeredUsers: this.#accountsById.size,
      publicReviews: this.#reviews.size,
      publicCommitments: this.#system.getPublicCommitmentRecords().length,
    };
    const product = this.#configured
      ? { id: PRODUCT_ID, name: PRODUCT_NAME, organization: ORGANIZATION_NAME }
      : null;
    if (principal.kind === "manager") {
      return {
        account: {
          kind: "manager",
          username: MANAGER_USERNAME,
          displayName: "Manager",
        },
        product,
        manager: {
          users: [...this.#accountsById.values()].map(publicAccount),
          configured: this.#configured,
          merchantUsername: this.#usernameFor(this.#merchantId),
          regulatorUsername: this.#usernameFor(this.#regulatorId),
        },
        reviews: this.#publicReviews(null),
        purchases: [],
        canIssuePurchases: false,
        availableBuyers: [],
        supportInbox: [],
        assignedCases: [],
        activity: [],
        counts,
      };
    }

    const account = this.#requireAccountById(principal.userId);
    const capabilities = this.#system.deriveCapabilities(account.userId);
    const canIssuePurchases = capabilities.some(
      ({ action, resourceId }) =>
        action === "issue-purchase-credential" && resourceId === PRODUCT_ID,
    );
    const purchases = [...this.#purchases.values()]
      .filter((purchase) => purchase.buyerId === account.userId)
      .map((purchase) => this.#purchaseCard(purchase));
    const supportInbox = [...this.#supportCases.values()]
      .filter((supportCase) => supportCase.merchantId === account.userId)
      .map((supportCase) => ({
        caseId: supportCase.caseId,
        productName: PRODUCT_NAME,
        customerReference: supportCase.view.contextSubjectId.slice(0, 12),
        purchasedWithinThirtyDays:
          supportCase.view.eligibility.purchasedWithinThirtyDays,
        replacementAvailable:
          supportCase.view.eligibility.replacementEntitlementUnused,
        outcome: supportCase.outcome,
        reason: supportCase.reason,
      }));
    const assignedCases = [...this.#regulatoryCases.values()]
      .filter((regulatoryCase) => regulatoryCase.recipientId === account.userId)
      .map((regulatoryCase) => ({
        caseId: regulatoryCase.caseId,
        productName: PRODUCT_NAME,
        purpose: REGULATORY_PURPOSE,
        verified: regulatoryCase.verified,
        result:
          regulatoryCase.result === null
            ? null
            : {
                samePurchase: regulatoryCase.result.samePurchaseTransaction,
                reviewIntegrity: regulatoryCase.result.reviewIntegrityVerified,
                supportDecisionIntegrity:
                  regulatoryCase.result.supportDecisionIntegrityVerified,
              },
      }));
    return {
      account: {
        kind: "user",
        username: account.username,
        displayName: account.displayName,
      },
      product,
      manager: null,
      reviews: this.#publicReviews(account.userId),
      purchases,
      canIssuePurchases,
      availableBuyers: canIssuePurchases
        ? [...this.#accountsById.values()]
            .filter((candidate) => candidate.userId !== account.userId)
            .map(publicAccount)
        : [],
      supportInbox,
      assignedCases,
      activity: [...(this.#activity.get(account.userId) ?? [])].reverse(),
      counts,
    };
  }

  auditCommitments(): readonly {
    readonly actionId: string;
    readonly commitment: string;
    readonly matchesPrivateRecord: boolean;
  }[] {
    return this.#system.auditCommitments();
  }

  #purchaseCard(purchase: StoredPurchase): PlatformDashboard["purchases"][number] {
    const support =
      purchase.supportCaseId === null
        ? null
        : this.#supportCases.get(purchase.supportCaseId)!;
    const regulatory =
      purchase.regulatoryCaseId === null
        ? null
        : this.#regulatoryCases.get(purchase.regulatoryCaseId)!;
    return {
      purchaseId: purchase.credentialId,
      productName: PRODUCT_NAME,
      orderId: purchase.orderId,
      purchasedAt: purchase.purchasedAt,
      canReview: purchase.reviewId === null,
      canRequestSupport: purchase.supportCaseId === null,
      canEscalate:
        purchase.reviewId !== null &&
        support !== null &&
        support.decisionId !== null &&
        purchase.regulatoryCaseId === null,
      reviewId: purchase.reviewId,
      support:
        support === null
          ? null
          : {
              caseId: support.caseId,
              outcome: support.outcome,
              reason: support.reason,
            },
      regulatoryCase:
        regulatory === null
          ? null
          : { caseId: regulatory.caseId, verified: regulatory.verified },
    };
  }

  #publicReviews(userId: string | null): PlatformDashboard["reviews"] {
    return [...this.#reviews.values()].map((review) => ({
      reviewId: review.reviewId,
      productName: PRODUCT_NAME,
      rating: review.rating,
      text: review.text,
      verifiedPurchase: review.verifiedPurchase,
      publishedAt: review.publishedAt,
      openedByYou:
        userId !== null &&
        Boolean(this.#reviewReaders.get(review.reviewId)?.has(userId)),
    }));
  }

  #createSession(principal: SessionPrincipal): string {
    const token = randomBytes(32).toString("base64url");
    this.#sessions.set(token, principal);
    return token;
  }

  #requireSession(token: string): SessionPrincipal {
    const principal = this.#sessions.get(token);
    if (principal === undefined) {
      throw new PlatformError(401, "AUTH_REQUIRED", "Please log in to continue");
    }
    return principal;
  }

  #requireManager(token: string): void {
    if (this.#requireSession(token).kind !== "manager") {
      throw new PlatformError(403, "MANAGER_REQUIRED", "Manager access required");
    }
  }

  #requireUser(token: string): StoredAccount {
    const principal = this.#requireSession(token);
    if (principal.kind !== "user") {
      throw new PlatformError(403, "USER_REQUIRED", "Sign in with a user account");
    }
    return this.#requireAccountById(principal.userId);
  }

  #requireAccountByUsername(value: unknown): StoredAccount {
    const normalized = requiredText(value, "Username").toLowerCase();
    const account = this.#accountsByUsername.get(normalized);
    if (account === undefined) {
      throw new PlatformError(404, "USER_NOT_FOUND", "Registered user not found");
    }
    return account;
  }

  #requireAccountById(userId: string): StoredAccount {
    const account = this.#accountsById.get(userId);
    if (account === undefined) {
      throw new PlatformError(404, "USER_NOT_FOUND", "Registered user not found");
    }
    return account;
  }

  #requireOwnedPurchase(userId: string, value: unknown): StoredPurchase {
    const purchaseId = requiredText(value, "Purchase");
    const purchase = this.#purchases.get(purchaseId);
    if (purchase === undefined || purchase.buyerId !== userId) {
      throw new PlatformError(404, "PURCHASE_NOT_FOUND", "Purchase not found");
    }
    return purchase;
  }

  #usernameFor(userId: string | null): string | null {
    if (userId === null) return null;
    return this.#accountsById.get(userId)?.username ?? null;
  }

  #addActivity(userId: string, message: string): void {
    const entries = this.#activity.get(userId) ?? [];
    entries.push({ message, at: this.#now() });
    this.#activity.set(userId, entries);
  }

  #now(): string {
    return this.#clock().toISOString();
  }
}
