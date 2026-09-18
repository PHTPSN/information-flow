import {
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  scryptSync,
  sign as signPayload,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

import { ApplicationError } from "./application-error.js";
import {
  AuthorizationPolicy,
  authorityGrantStatus,
} from "./authorization-policy.js";

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
import {
  ApplicationStore,
  sessionTokenHash,
  type AccountRecord,
  type GrantCapability,
  type ProductRecord,
  type SpecialRole,
} from "./persistence.js";

export const DEFAULT_ADMIN_USERNAME = "manager";
export const DEFAULT_ADMIN_DISPLAY_NAME = "Manager";
export const DEFAULT_ADMIN_PASSWORD = "12345678";
const REGULATORY_SCOPE = "case-specific-disclosure";
const DEFAULT_DISCLOSURE_PURPOSE = "independent review of the disclosed case";
const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1_000;

interface SigningIdentity {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

type StoredAccount = AccountRecord;

interface StoredPurchase {
  readonly credentialId: string;
  readonly productId: string;
  readonly organizationId: string;
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
  readonly productId: string;
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
  readonly productId: string;
  readonly purpose: string;
  readonly recordIds: readonly string[];
  verified: boolean;
  result: EvidenceVerificationResult | null;
}

export interface PublicAccount {
  readonly userId: string;
  readonly username: string;
  readonly displayName: string;
  readonly createdAt: string;
}

export interface PlatformDashboard {
  readonly account: {
    readonly kind: "user";
    readonly username: string;
    readonly displayName: string;
    readonly isAdministrator: boolean;
    readonly specialRoles: readonly SpecialRole[];
  };
  readonly product: {
    readonly id: string;
    readonly name: string;
    readonly organization: string;
  } | null;
  readonly organizations: readonly {
    readonly organizationId: string;
    readonly name: string;
    readonly members: readonly PublicAccount[];
    readonly products: readonly {
      readonly productId: string;
      readonly name: string;
    }[];
  }[];
  readonly memberships: readonly {
    readonly organizationId: string;
    readonly organizationName: string;
    readonly joinedAt: string;
  }[];
  readonly availableOrganizations: readonly {
    readonly organizationId: string;
    readonly name: string;
  }[];
  readonly organizationRequests: readonly {
    readonly requestId: string;
    readonly organizationId: string;
    readonly name: string;
    readonly status: "pending" | "approved" | "rejected";
    readonly submittedAt: string;
  }[];
  readonly membershipRequests: readonly {
    readonly requestId: string;
    readonly organizationId: string;
    readonly organizationName: string;
    readonly status: "pending" | "approved" | "rejected";
    readonly submittedAt: string;
  }[];
  readonly pendingMembershipApprovals: readonly {
    readonly requestId: string;
    readonly organizationId: string;
    readonly organizationName: string;
    readonly requesterUsername: string;
    readonly requesterDisplayName: string;
    readonly submittedAt: string;
  }[];
  readonly specialRoleRequests: readonly {
    readonly requestId: string;
    readonly role: SpecialRole;
    readonly justification: string;
    readonly status: "pending" | "approved" | "rejected";
    readonly submittedAt: string;
  }[];
  readonly administratorApprovals: {
    readonly organizationRequests: readonly {
      readonly requestId: string;
      readonly requesterUsername: string;
      readonly organizationId: string;
      readonly name: string;
      readonly submittedAt: string;
    }[];
    readonly specialRoleRequests: readonly {
      readonly requestId: string;
      readonly requesterUsername: string;
      readonly requesterDisplayName: string;
      readonly role: SpecialRole;
      readonly justification: string;
      readonly submittedAt: string;
    }[];
  };
  readonly products: readonly {
    readonly productId: string;
    readonly name: string;
    readonly organizationId: string;
    readonly organizationName: string;
    readonly belongsToAccountOrganization: boolean;
    readonly canPurchase: boolean;
    readonly reviewCount: number;
  }[];
  readonly authorityGrants: readonly {
    readonly grantId: string;
    readonly organizationName: string;
    readonly productId: string;
    readonly productName: string;
    readonly granteeUsername: string;
    readonly capability: GrantCapability;
    readonly status: "active" | "expired" | "revoked";
    readonly expiresAt: string | null;
    readonly receivedByYou: boolean;
    readonly canRevoke: boolean;
  }[];
  readonly availableAccounts: readonly PublicAccount[];
  readonly availableRegulators: readonly PublicAccount[];
  readonly issuableProducts: readonly {
    readonly productId: string;
    readonly name: string;
    readonly organizationName: string;
  }[];
  readonly reviews: readonly {
    readonly reviewId: string;
    readonly productId: string;
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

export class PlatformError extends ApplicationError {
  constructor(status: number, code: string, message: string) {
    super(status, code, message);
    this.name = "PlatformError";
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
  return normalized;
}

function resourceId(value: unknown, field: string): string {
  const normalized = requiredText(value, field);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/.test(normalized)) {
    throw new PlatformError(
      400,
      "INVALID_IDENTIFIER",
      `${field} must be 2–64 characters using letters, numbers, dots, dashes, or underscores`,
    );
  }
  return normalized;
}

function grantCapability(value: unknown): GrantCapability {
  if (
    value !== "issue-purchase-credential" &&
    value !== "handle-support-cases"
  ) {
    throw new PlatformError(
      400,
      "INVALID_CAPABILITY",
      "Choose purchase issuing or support handling authority",
    );
  }
  return value;
}

function specialRole(value: unknown): SpecialRole {
  if (value !== "regulator") {
    throw new PlatformError(
      400,
      "INVALID_SPECIAL_ROLE",
      "The available special role is regulator",
    );
  }
  return value;
}

function approvalDecision(value: unknown): boolean {
  if (value === "approved") return true;
  if (value === "rejected") return false;
  throw new PlatformError(
    400,
    "INVALID_DECISION",
    "Choose approved or rejected",
  );
}

function optionalText(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  return requiredText(value, field);
}

function optionalFutureTimestamp(value: unknown, now: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  const normalized = requiredText(value, "Expiration");
  const milliseconds = Date.parse(normalized);
  if (!Number.isFinite(milliseconds) || normalized <= now) {
    throw new PlatformError(
      400,
      "INVALID_EXPIRATION",
      "Expiration must be a future ISO timestamp",
    );
  }
  return new Date(milliseconds).toISOString();
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

export interface InformationFlowPlatformOptions {
  readonly clock?: () => Date;
  readonly databasePath?: string;
  readonly encryptionKey?: Buffer;
  readonly sessionTtlMs?: number;
  readonly bootstrapAdministrator?: {
    readonly username: string;
    readonly displayName?: string;
    readonly password: string;
  };
}

export class InformationFlowPlatform {
  readonly #authority: SigningIdentity;
  readonly #system: BehaviorDerivedInformationFlowSystem;
  readonly #store: ApplicationStore;
  readonly #policy: AuthorizationPolicy;
  readonly #clock: () => Date;
  readonly #sessionTtlMs: number;
  readonly #accountsByUsername = new Map<string, StoredAccount>();
  readonly #accountsById = new Map<string, StoredAccount>();
  readonly #purchases = new Map<string, StoredPurchase>();
  readonly #reviews = new Map<string, PublicReview>();
  readonly #reviewReaders = new Map<string, Set<string>>();
  readonly #supportCases = new Map<string, StoredSupportCase>();
  readonly #regulatoryCases = new Map<string, StoredRegulatoryCase>();
  #purchaseSequence = 0;
  #reviewSequence = 0;
  #supportSequence = 0;
  #regulatorySequence = 0;
  constructor(options: InformationFlowPlatformOptions = {}) {
    this.#clock = options.clock ?? (() => new Date());
    this.#sessionTtlMs = options.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    const databasePath = options.databasePath ?? ":memory:";
    if (databasePath !== ":memory:" && options.encryptionKey === undefined) {
      throw new Error(
        "A 32-byte encryptionKey is required for a persistent database",
      );
    }
    this.#store = new ApplicationStore({
      databasePath,
      encryptionKey: options.encryptionKey ?? randomBytes(32),
    });
    this.#authority = this.#store.loadOrCreateSystemSigningIdentity(
      "platform-authority",
      this.#now(),
    );
    this.#system = new BehaviorDerivedInformationFlowSystem({
      trustedAuthorityId: "platform-authority",
      trustedAuthorityPublicKey: this.#authority.publicKey,
      regulatoryScopeId: REGULATORY_SCOPE,
    });
    this.#policy = new AuthorizationPolicy(this.#store, this.#clock);
    this.#hydrateFoundation();
    this.#ensureBootstrapAdministrator(
      options.bootstrapAdministrator ?? {
        username: DEFAULT_ADMIN_USERNAME,
        displayName: DEFAULT_ADMIN_DISPLAY_NAME,
        password: DEFAULT_ADMIN_PASSWORD,
      },
    );
  }

  close(): void {
    this.#store.close();
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
    if (password.length < 8 || password.length > 128) {
      throw new PlatformError(
        400,
        "INVALID_PASSWORD",
        "Password must be 8–128 characters",
      );
    }
    if (this.#accountsByUsername.has(normalizedUsername)) {
      throw new PlatformError(
        409,
        "USERNAME_TAKEN",
        "That username is already registered",
      );
    }
    return publicAccount(
      this.#createAccount(normalizedUsername, normalizedDisplayName, password),
    );
  }

  loginUser(input: {
    readonly username: unknown;
    readonly password: unknown;
  }): string {
    return this.#createSession(this.#authenticateAccount(input).userId);
  }

  loginAdministrator(input: {
    readonly username: unknown;
    readonly password: unknown;
  }): string {
    const account = this.#authenticateAccount(input);
    if (!this.#store.isSystemAdministrator(account.userId)) {
      throw new PlatformError(401, "LOGIN_FAILED", "Incorrect username or password");
    }
    return this.#createSession(account.userId);
  }

  #authenticateAccount(input: {
    readonly username: unknown;
    readonly password: unknown;
  }): StoredAccount {
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
    return account;
  }

  logout(token: string): void {
    this.#store.deleteSession(sessionTokenHash(token));
  }

  session(token: string | null): PlatformDashboard["account"] | null {
    if (token === null) return null;
    const userId = this.#store.sessionUserId(
      sessionTokenHash(token),
      this.#now(),
    );
    if (userId === null) return null;
    const account = this.#requireAccountById(userId);
    return {
      kind: "user",
      username: account.username,
      displayName: account.displayName,
      isAdministrator: this.#store.isSystemAdministrator(account.userId),
      specialRoles: this.#store.listSpecialRoles(account.userId),
    };
  }

  requestOrganization(
    token: string,
    input: { readonly organizationId: unknown; readonly name: unknown },
  ): PlatformDashboard {
    const account = this.#requireUser(token);
    if (this.#store.isSystemAdministrator(account.userId)) {
      throw new PlatformError(
        403,
        "ADMIN_ACCOUNT_RESTRICTED",
        "The system administrator cannot request an organization",
      );
    }
    const organizationId = resourceId(input.organizationId, "Organization ID");
    if (
      this.#store.getOrganization(organizationId) !== null ||
      this.#store
        .listPendingOrganizationRequests()
        .some((request) => request.proposedOrganizationId === organizationId)
    ) {
      throw new PlatformError(
        409,
        "ORGANIZATION_EXISTS",
        "That organization ID already exists or awaits approval",
      );
    }
    this.#store.createOrganizationRequest({
      requestId: `org-request-${randomUUID()}`,
      requesterUserId: account.userId,
      proposedOrganizationId: organizationId,
      proposedName: requiredText(input.name, "Organization name"),
      submittedAt: this.#now(),
    });
    return this.dashboard(token);
  }

  decideOrganizationRequest(
    token: string,
    input: {
      readonly requestId: unknown;
      readonly decision: unknown;
      readonly note?: unknown;
    },
  ): PlatformDashboard {
    const administrator = this.#requireUser(token);
    this.#policy.requireSystemAdministrator(administrator.userId);
    const requestId = requiredText(input.requestId, "Organization request");
    const request = this.#store.getOrganizationRequest(requestId);
    if (request === null) {
      throw new PlatformError(404, "REQUEST_NOT_FOUND", "Organization request not found");
    }
    if (request.status !== "pending") {
      throw new PlatformError(409, "REQUEST_DECIDED", "This request already has a decision");
    }
    const approved = approvalDecision(input.decision);
    if (
      approved &&
      this.#store.getOrganization(request.proposedOrganizationId) !== null
    ) {
      throw new PlatformError(409, "ORGANIZATION_EXISTS", "That organization ID already exists");
    }
    const decided = this.#store.decideOrganizationRequest({
      requestId,
      administratorUserId: administrator.userId,
      approved,
      decisionNote: optionalText(input.note, "Decision note"),
      reviewedAt: this.#now(),
    });
    if (approved) {
      this.#system.registerOrganization({
        organizationId: decided.proposedOrganizationId,
        name: decided.proposedName,
        registeredBy: decided.requesterUserId,
      });
    }
    return this.dashboard(token);
  }

  requestMembership(
    token: string,
    input: { readonly organizationId: unknown },
  ): PlatformDashboard {
    const account = this.#requireUser(token);
    if (this.#store.isSystemAdministrator(account.userId)) {
      throw new PlatformError(
        403,
        "ADMIN_ACCOUNT_RESTRICTED",
        "The system administrator cannot join an organization",
      );
    }
    const organizationId = resourceId(input.organizationId, "Organization ID");
    const organization = this.#store.getOrganization(organizationId);
    if (organization === null) {
      throw new PlatformError(404, "ORGANIZATION_NOT_FOUND", "Organization not found");
    }
    if (this.#store.isOrganizationMember(account.userId, organizationId)) {
      throw new PlatformError(409, "ALREADY_MEMBER", "You already belong to this organization");
    }
    if (
      this.#store
        .listMembershipRequestsForUser(account.userId)
        .some(
          (request) =>
            request.organizationId === organizationId && request.status === "pending",
        )
    ) {
      throw new PlatformError(409, "REQUEST_PENDING", "A membership request is already pending");
    }
    this.#store.createMembershipRequest({
      requestId: `membership-request-${randomUUID()}`,
      organizationId,
      requesterUserId: account.userId,
      submittedAt: this.#now(),
    });
    return this.dashboard(token);
  }

  decideMembershipRequest(
    token: string,
    input: {
      readonly requestId: unknown;
      readonly decision: unknown;
      readonly note?: unknown;
    },
  ): PlatformDashboard {
    const creator = this.#requireUser(token);
    const requestId = requiredText(input.requestId, "Membership request");
    const request = this.#store.getMembershipRequest(requestId);
    if (request === null) {
      throw new PlatformError(404, "REQUEST_NOT_FOUND", "Membership request not found");
    }
    this.#policy.requireOrganizationCreator(
      creator.userId,
      request.organizationId,
    );
    if (request.status !== "pending") {
      throw new PlatformError(409, "REQUEST_DECIDED", "This request already has a decision");
    }
    this.#store.decideMembershipRequest({
      requestId,
      reviewerUserId: creator.userId,
      approved: approvalDecision(input.decision),
      decisionNote: optionalText(input.note, "Decision note"),
      reviewedAt: this.#now(),
    });
    return this.dashboard(token);
  }

  requestSpecialRole(
    token: string,
    input: { readonly role: unknown; readonly justification: unknown },
  ): PlatformDashboard {
    const account = this.#requireUser(token);
    if (this.#store.isSystemAdministrator(account.userId)) {
      throw new PlatformError(
        403,
        "ADMIN_ACCOUNT_RESTRICTED",
        "The system administrator does not apply for user roles",
      );
    }
    const role = specialRole(input.role);
    if (this.#store.hasSpecialRole(account.userId, role)) {
      throw new PlatformError(409, "ROLE_ALREADY_GRANTED", `You are already a ${role}`);
    }
    if (
      this.#store
        .listSpecialRoleRequestsForUser(account.userId)
        .some((request) => request.role === role && request.status === "pending")
    ) {
      throw new PlatformError(409, "REQUEST_PENDING", "A role application is already pending");
    }
    this.#store.createSpecialRoleRequest({
      requestId: `role-request-${randomUUID()}`,
      requesterUserId: account.userId,
      role,
      justification: requiredText(input.justification, "Justification"),
      submittedAt: this.#now(),
    });
    return this.dashboard(token);
  }

  decideSpecialRoleRequest(
    token: string,
    input: {
      readonly requestId: unknown;
      readonly decision: unknown;
      readonly note?: unknown;
    },
  ): PlatformDashboard {
    const administrator = this.#requireUser(token);
    this.#policy.requireSystemAdministrator(administrator.userId);
    const requestId = requiredText(input.requestId, "Role request");
    const request = this.#store.getSpecialRoleRequest(requestId);
    if (request === null) {
      throw new PlatformError(404, "REQUEST_NOT_FOUND", "Role request not found");
    }
    if (request.status !== "pending") {
      throw new PlatformError(409, "REQUEST_DECIDED", "This request already has a decision");
    }
    this.#store.decideSpecialRoleRequest({
      requestId,
      administratorUserId: administrator.userId,
      approved: approvalDecision(input.decision),
      decisionNote: optionalText(input.note, "Decision note"),
      reviewedAt: this.#now(),
    });
    return this.dashboard(token);
  }

  createProduct(
    token: string,
    input: {
      readonly organizationId: unknown;
      readonly productId: unknown;
      readonly name: unknown;
    },
  ): PlatformDashboard {
    const account = this.#requireUser(token);
    const organizationId = resourceId(input.organizationId, "Organization ID");
    this.#policy.requireOrganizationControl(account.userId, organizationId);
    const productId = resourceId(input.productId, "Product ID");
    if (this.#store.getProduct(productId) !== null) {
      throw new PlatformError(409, "PRODUCT_EXISTS", "That product ID already exists");
    }
    const product = {
      productId,
      organizationId,
      name: requiredText(input.name, "Product name"),
      createdByUserId: account.userId,
      createdAt: this.#now(),
    };
    this.#store.createProduct(product);
    this.#system.registerProduct({
      productId,
      name: product.name,
      organizationId,
      registeredBy: account.userId,
    });
    const storedProduct = this.#store.getProduct(productId)!;
    this.#createAuthorityGrant(
      account,
      account,
      storedProduct,
      "issue-purchase-credential",
      null,
    );
    this.#createAuthorityGrant(
      account,
      account,
      storedProduct,
      "handle-support-cases",
      null,
    );
    return this.dashboard(token);
  }

  grantAuthority(
    token: string,
    input: {
      readonly productId: unknown;
      readonly granteeUsername: unknown;
      readonly capability: unknown;
      readonly expiresAt?: unknown;
    },
  ): PlatformDashboard {
    const controller = this.#requireUser(token);
    const productId = resourceId(input.productId, "Product ID");
    const product = this.#policy.requireProductControl(controller.userId, productId);
    const grantee = this.#requireAccountByUsername(input.granteeUsername);
    this.#policy.requireOrganizationMembership(
      grantee.userId,
      product.organizationId,
    );
    const capability = grantCapability(input.capability);
    const issuedAt = this.#now();
    const expiresAt = optionalFutureTimestamp(input.expiresAt, issuedAt);
    this.#createAuthorityGrant(
      controller,
      grantee,
      product,
      capability,
      expiresAt,
      issuedAt,
    );
    return this.dashboard(token);
  }

  #createAuthorityGrant(
    controller: StoredAccount,
    grantee: StoredAccount,
    product: ProductRecord,
    capability: GrantCapability,
    expiresAt: string | null,
    issuedAt = this.#now(),
  ): void {
    const unsigned = {
      grantId: `grant-${randomUUID()}`,
      authorityId: "platform-authority",
      granteeId: grantee.userId,
      capability,
      scopeId: product.productId,
      issuedAt,
    } as const satisfies Omit<SignedAuthorityGrant, "signature">;
    const signature = sign(
      authorityGrantSigningPayload(unsigned),
      this.#authority.privateKey,
    );
    this.#store.createAuthorityGrant({
      grantId: unsigned.grantId,
      organizationId: product.organizationId,
      productId: product.productId,
      grantedByUserId: controller.userId,
      granteeUserId: grantee.userId,
      capability,
      issuedAt,
      expiresAt,
      signature,
    });
    this.#system.grantAuthority({ ...unsigned, signature });
  }

  revokeAuthority(token: string, input: { readonly grantId: unknown }): PlatformDashboard {
    const controller = this.#requireUser(token);
    const grantId = requiredText(input.grantId, "Authority grant");
    this.#policy.requireGrantControl(controller.userId, grantId);
    if (
      !this.#store.revokeAuthorityGrant({
        grantId,
        revokedByUserId: controller.userId,
        revokedAt: this.#now(),
      })
    ) {
      throw new PlatformError(409, "GRANT_ALREADY_REVOKED", "Authority grant is already revoked");
    }
    return this.dashboard(token);
  }

  issuePurchase(
    token: string,
    input: {
      readonly productId: unknown;
      readonly buyerUsername: unknown;
      readonly orderId: unknown;
    },
  ): PlatformDashboard {
    const merchant = this.#requireUser(token);
    const productId = resourceId(input.productId, "Product ID");
    this.#policy.requireActiveGrant(
      merchant.userId,
      "issue-purchase-credential",
      productId,
    );
    const product = this.#store.getProduct(productId);
    if (product === null) {
      throw new PlatformError(404, "PRODUCT_NOT_FOUND", "Product not found");
    }
    const buyer = this.#requireAccountByUsername(input.buyerUsername);
    if (
      buyer.userId === merchant.userId ||
      this.#store.isSystemAdministrator(buyer.userId)
    ) {
      throw new PlatformError(400, "INVALID_BUYER", "Choose another registered customer");
    }
    this.#requireExternalBuyer(buyer, product);
    const orderId = requiredText(input.orderId, "Order number");
    this.#recordPurchase(merchant, buyer, product, orderId);
    return this.dashboard(token);
  }

  buyProduct(
    token: string,
    input: { readonly productId: unknown },
  ): PlatformDashboard {
    const buyer = this.#requireUser(token);
    if (this.#store.isSystemAdministrator(buyer.userId)) {
      throw new PlatformError(
        403,
        "ORDINARY_ACCOUNT_REQUIRED",
        "Products can be purchased with an ordinary account",
      );
    }
    const productId = resourceId(input.productId, "Product ID");
    const product = this.#store.getProduct(productId);
    if (product === null) {
      throw new PlatformError(404, "PRODUCT_NOT_FOUND", "Product not found");
    }
    this.#requireExternalBuyer(buyer, product);
    const issuerGrant = this.#store
      .listActiveAuthorityGrants(this.#now())
      .filter(
        (grant) =>
          grant.capability === "issue-purchase-credential" &&
          grant.productId === productId &&
          grant.granteeUserId !== buyer.userId,
      )
      .at(-1);
    let merchant: StoredAccount;
    if (issuerGrant === undefined) {
      merchant = this.#requireAccountById(product.createdByUserId);
      this.#createAuthorityGrant(
        merchant,
        merchant,
        product,
        "issue-purchase-credential",
        null,
      );
    } else {
      merchant = this.#requireAccountById(issuerGrant.granteeUserId);
    }
    const orderId = `ORD-${randomUUID().slice(0, 8).toUpperCase()}`;
    this.#recordPurchase(merchant, buyer, product, orderId);
    return this.dashboard(token);
  }

  #recordPurchase(
    merchant: StoredAccount,
    buyer: StoredAccount,
    product: ProductRecord,
    orderId: string,
  ): void {
    const productId = product.productId;
    if (
      [...this.#purchases.values()].some(
        (purchase) =>
          purchase.productId === productId && purchase.orderId === orderId,
      )
    ) {
      throw new PlatformError(409, "ORDER_EXISTS", "That order number already exists");
    }

    this.#purchaseSequence += 1;
    const credentialId = `purchase-${String(this.#purchaseSequence).padStart(3, "0")}`;
    const holderSecret = randomBytes(32).toString("base64url");
    const purchasedAt = this.#now();
    const credential = {
      credentialId,
      productId,
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
      productId,
      organizationId: product.organizationId,
      buyerId: buyer.userId,
      issuerId: merchant.userId,
      orderId,
      purchasedAt,
      holderSecret,
      reviewId: null,
      supportCaseId: null,
      regulatoryCaseId: null,
    });
    this.#addActivity(merchant.userId, `Order ${orderId} issued for ${product.name}`);
    this.#addActivity(buyer.userId, `${product.name} added to your purchases`);
  }

  #requireExternalBuyer(buyer: StoredAccount, product: ProductRecord): void {
    if (!this.#canPurchaseProduct(buyer, product)) {
      throw new PlatformError(
        403,
        "MERCHANT_ACCOUNT_CANNOT_BUY",
        "You cannot buy products from your own merchant",
      );
    }
  }

  #canPurchaseProduct(buyer: StoredAccount, product: ProductRecord): boolean {
    return (
      !this.#store.isSystemAdministrator(buyer.userId) &&
      !this.#store.isOrganizationMember(buyer.userId, product.organizationId) &&
      !this.#store.controlsOrganization(buyer.userId, product.organizationId)
    );
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
    const product = this.#store.getProduct(purchase.productId)!;
    this.#addActivity(account.userId, `Your ${product.name} review was published`);
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
    const now = this.#now();
    const supportGrant = this.#store
      .listAuthorityGrants()
      .filter(
        (grant) =>
          grant.productId === purchase.productId &&
          grant.capability === "handle-support-cases" &&
          authorityGrantStatus(grant, now) === "active",
      )
      .at(-1);
    if (supportGrant === undefined) {
      throw new PlatformError(
        409,
        "SUPPORT_HANDLER_UNAVAILABLE",
        "No active support handler is available for this product",
      );
    }
    this.#supportSequence += 1;
    const caseId = `CASE-${String(this.#supportSequence).padStart(3, "0")}`;
    const view = this.#system.requestSupport({
      caseId,
      actorId: buyer.userId,
      credentialId: purchase.credentialId,
      holderSecret: purchase.holderSecret,
      organizationId: purchase.organizationId,
      recipientId: supportGrant.granteeUserId,
      request: "replacement",
      requestedAt: this.#now(),
      policyVersion: "support-policy-1",
    });
    purchase.supportCaseId = caseId;
    this.#supportCases.set(caseId, {
      caseId,
      buyerId: buyer.userId,
      merchantId: supportGrant.granteeUserId,
      credentialId: purchase.credentialId,
      productId: purchase.productId,
      view,
      decisionId: null,
      outcome: "pending",
      reason: null,
    });
    this.#addActivity(buyer.userId, `Replacement request ${caseId} submitted`);
    this.#addActivity(supportGrant.granteeUserId, `New replacement request ${caseId}`);
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
    this.#policy.requireActiveGrant(
      merchant.userId,
      "handle-support-cases",
      supportCase.productId,
    );
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

  escalate(
    token: string,
    input: {
      readonly purchaseId: unknown;
      readonly reviewerUsername: unknown;
      readonly purpose?: unknown;
    },
  ): PlatformDashboard {
    const buyer = this.#requireUser(token);
    const purchase = this.#requireOwnedPurchase(buyer.userId, input.purchaseId);
    const reviewer = this.#requireAccountByUsername(input.reviewerUsername);
    this.#policy.requireSpecialRole(reviewer.userId, "regulator");
    if (reviewer.userId === buyer.userId) {
      throw new PlatformError(
        400,
        "INVALID_RECIPIENT",
        "Choose another account as the independent reviewer",
      );
    }
    const purpose =
      input.purpose === undefined || input.purpose === ""
        ? DEFAULT_DISCLOSURE_PURPOSE
        : requiredText(input.purpose, "Purpose");
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
    if (supportCase.decisionId === null) {
      throw new PlatformError(409, "EVIDENCE_INCOMPLETE", "A support decision is required first");
    }

    this.#regulatorySequence += 1;
    const caseId = `REG-${String(this.#regulatorySequence).padStart(3, "0")}`;
    this.#system.openRegulatoryCase({
      caseId,
      actorId: buyer.userId,
      credentialId: purchase.credentialId,
      holderSecret: purchase.holderSecret,
      respondentOrganizationId: purchase.organizationId,
      purpose,
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
      recipientId: reviewer.userId,
      purpose,
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
      recipientId: reviewer.userId,
      credentialId: purchase.credentialId,
      productId: purchase.productId,
      purpose,
      recordIds,
      verified: false,
      result: null,
    });
    this.#addActivity(buyer.userId, `Case ${caseId} submitted for independent review`);
    this.#addActivity(reviewer.userId, `New case ${caseId} disclosed to you`);
    return this.dashboard(token);
  }

  verifyCase(token: string, input: { readonly caseId: unknown }): PlatformDashboard {
    const reviewer = this.#requireUser(token);
    this.#policy.requireSpecialRole(reviewer.userId, "regulator");
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
        purpose: regulatoryCase.purpose,
        recordIds: regulatoryCase.recordIds,
      });
      regulatoryCase.verified = true;
      this.#addActivity(reviewer.userId, `${caseId} evidence verified`);
      this.#addActivity(regulatoryCase.buyerId, `${caseId} evidence verification completed`);
    }
    return this.dashboard(token);
  }

  dashboard(token: string): PlatformDashboard {
    const account = this.#requireUser(token);
    const now = this.#now();
    const isAdministrator = this.#store.isSystemAdministrator(account.userId);
    const specialRoles = this.#store.listSpecialRoles(account.userId);
    const products = this.#store.listProducts();
    const allOrganizations = this.#store.listOrganizations();
    const controlledOrganizations = this.#store.listControlledOrganizations(
      account.userId,
    );
    const organizations = controlledOrganizations.map((organization) => ({
      organizationId: organization.organizationId,
      name: organization.name,
      members: this.#store
        .listOrganizationMembers(organization.organizationId)
        .map((membership) =>
          publicAccount(this.#requireAccountById(membership.userId)),
        ),
      products: products
        .filter(
          (candidate) =>
            candidate.organizationId === organization.organizationId,
        )
        .map(({ productId, name }) => ({ productId, name })),
    }));
    const memberships = this.#store
      .listMembershipsForUser(account.userId)
      .map(({ organizationId, organizationName, joinedAt }) => ({
        organizationId,
        organizationName,
        joinedAt,
      }));
    const membershipOrganizationIds = new Set(
      memberships.map(({ organizationId }) => organizationId),
    );
    const membershipRequests = this.#store
      .listMembershipRequestsForUser(account.userId)
      .map((request) => ({
        requestId: request.requestId,
        organizationId: request.organizationId,
        organizationName: request.organizationName,
        status: request.status,
        submittedAt: request.submittedAt,
      }));
    const pendingMembershipOrganizationIds = new Set(
      membershipRequests
        .filter(({ status }) => status === "pending")
        .map(({ organizationId }) => organizationId),
    );
    const ordinaryAccounts = [...this.#accountsById.values()].filter(
      (candidate) => !this.#store.isSystemAdministrator(candidate.userId),
    );
    const issuableProducts = products
      .filter((candidate) =>
        this.#policy.hasActiveGrant(
          account.userId,
          "issue-purchase-credential",
          candidate.productId,
        ),
      )
      .map((candidate) => ({
        productId: candidate.productId,
        name: candidate.name,
        organizationName: candidate.organizationName,
      }));
    const authorityGrants = this.#store
      .listAuthorityGrantsForUser(account.userId)
      .map((grant) => ({
        grantId: grant.grantId,
        organizationName: grant.organizationName,
        productId: grant.productId,
        productName: grant.productName,
        granteeUsername: grant.granteeUsername,
        capability: grant.capability,
        status: authorityGrantStatus(grant, now),
        expiresAt: grant.expiresAt,
        receivedByYou: grant.granteeUserId === account.userId,
        canRevoke:
          grant.revokedAt === null &&
          this.#store.controlsOrganization(
            account.userId,
            grant.organizationId,
          ),
      }));
    const counts = {
      registeredUsers: this.#store.countOrdinaryAccounts(),
      publicReviews: this.#reviews.size,
      publicCommitments: this.#system.getPublicCommitmentRecords().length,
    };
    const firstProduct = products[0];
    const product =
      firstProduct === undefined
        ? null
        : {
            id: firstProduct.productId,
            name: firstProduct.name,
            organization: firstProduct.organizationName,
          };
    const purchases = [...this.#purchases.values()]
      .filter((purchase) => purchase.buyerId === account.userId)
      .map((purchase) => this.#purchaseCard(purchase));
    const supportInbox = [...this.#supportCases.values()]
      .filter(
        (supportCase) =>
          supportCase.merchantId === account.userId &&
          this.#policy.hasActiveGrant(
            account.userId,
            "handle-support-cases",
            supportCase.productId,
          ),
      )
      .map((supportCase) => ({
        caseId: supportCase.caseId,
        productName: this.#store.getProduct(supportCase.productId)!.name,
        customerReference: supportCase.view.contextSubjectId.slice(0, 12),
        purchasedWithinThirtyDays:
          supportCase.view.eligibility.purchasedWithinThirtyDays,
        replacementAvailable:
          supportCase.view.eligibility.replacementEntitlementUnused,
        outcome: supportCase.outcome,
        reason: supportCase.reason,
      }));
    const assignedCases = [...this.#regulatoryCases.values()]
      .filter(
        (regulatoryCase) =>
          regulatoryCase.recipientId === account.userId &&
          this.#store.hasSpecialRole(account.userId, "regulator"),
      )
      .map((regulatoryCase) => ({
        caseId: regulatoryCase.caseId,
        productName: this.#store.getProduct(regulatoryCase.productId)!.name,
        purpose: regulatoryCase.purpose,
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
        isAdministrator,
        specialRoles,
      },
      product,
      organizations,
      memberships,
      availableOrganizations: allOrganizations
        .filter(
          (organization) =>
            !membershipOrganizationIds.has(organization.organizationId) &&
            !pendingMembershipOrganizationIds.has(organization.organizationId),
        )
        .map(({ organizationId, name }) => ({ organizationId, name })),
      organizationRequests: this.#store
        .listOrganizationRequestsForUser(account.userId)
        .map((request) => ({
          requestId: request.requestId,
          organizationId: request.proposedOrganizationId,
          name: request.proposedName,
          status: request.status,
          submittedAt: request.submittedAt,
        })),
      membershipRequests,
      pendingMembershipApprovals: this.#store
        .listPendingMembershipRequestsForCreator(account.userId)
        .map((request) => ({
          requestId: request.requestId,
          organizationId: request.organizationId,
          organizationName: request.organizationName,
          requesterUsername: request.requesterUsername,
          requesterDisplayName: request.requesterDisplayName,
          submittedAt: request.submittedAt,
        })),
      specialRoleRequests: this.#store
        .listSpecialRoleRequestsForUser(account.userId)
        .map((request) => ({
          requestId: request.requestId,
          role: request.role,
          justification: request.justification,
          status: request.status,
          submittedAt: request.submittedAt,
        })),
      administratorApprovals: isAdministrator
        ? {
            organizationRequests: this.#store
              .listPendingOrganizationRequests()
              .map((request) => ({
                requestId: request.requestId,
                requesterUsername: request.requesterUsername,
                organizationId: request.proposedOrganizationId,
                name: request.proposedName,
                submittedAt: request.submittedAt,
              })),
            specialRoleRequests: this.#store
              .listPendingSpecialRoleRequests()
              .map((request) => ({
                requestId: request.requestId,
                requesterUsername: request.requesterUsername,
                requesterDisplayName: request.requesterDisplayName,
                role: request.role,
                justification: request.justification,
                submittedAt: request.submittedAt,
              })),
          }
        : { organizationRequests: [], specialRoleRequests: [] },
      products: products.map((candidate) => {
        const canPurchase = this.#canPurchaseProduct(account, candidate);
        return {
          productId: candidate.productId,
          name: candidate.name,
          organizationId: candidate.organizationId,
          organizationName: candidate.organizationName,
          belongsToAccountOrganization:
            this.#store.isOrganizationMember(
              account.userId,
              candidate.organizationId,
            ) ||
            this.#store.controlsOrganization(
              account.userId,
              candidate.organizationId,
            ),
          canPurchase,
          reviewCount: [...this.#reviews.values()].filter(
            (review) => review.productId === candidate.productId,
          ).length,
        };
      }),
      authorityGrants,
      availableAccounts: ordinaryAccounts
        .filter((candidate) => candidate.userId !== account.userId)
        .map(publicAccount),
      availableRegulators: this.#store
        .listActiveSpecialRoleUserIds("regulator")
        .filter((userId) => userId !== account.userId)
        .map((userId) => publicAccount(this.#requireAccountById(userId))),
      issuableProducts,
      reviews: this.#publicReviews(account.userId),
      purchases,
      canIssuePurchases: issuableProducts.length > 0,
      availableBuyers: issuableProducts.length > 0
        ? ordinaryAccounts
            .filter((candidate) => candidate.userId !== account.userId)
            .map(publicAccount)
        : [],
      supportInbox,
      assignedCases,
      activity: this.#store
        .listInboxEvents(account.userId)
        .map(({ message, createdAt }) => ({ message, at: createdAt })),
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

  publicReviews(): PlatformDashboard["reviews"] {
    return this.#publicReviews(null);
  }

  #createAccount(
    normalizedUsername: string,
    normalizedDisplayName: string,
    password: string,
  ): StoredAccount {
    const userId = `user-${randomUUID()}`;
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
    this.#store.createAccount(account);
    this.#system.registerActor({
      actorId: userId,
      signingPublicKey: signing.publicKey,
    });
    this.#accountsByUsername.set(normalizedUsername, account);
    this.#accountsById.set(userId, account);
    return account;
  }

  #ensureBootstrapAdministrator(input: {
    readonly username: string;
    readonly displayName?: string;
    readonly password: string;
  }): void {
    const normalizedUsername = username(input.username);
    const normalizedDisplayName = displayName(
      input.displayName,
      DEFAULT_ADMIN_DISPLAY_NAME,
    );
    const password = requiredText(input.password, "Administrator password");
    if (password.length < 8 || password.length > 128) {
      throw new Error("Administrator password must be 8–128 characters");
    }
    const existing = this.#accountsByUsername.get(normalizedUsername);
    const administratorIds = this.#store.listSystemAdministratorIds();
    if (existing !== undefined && !this.#store.isSystemAdministrator(existing.userId)) {
      throw new Error(
        `The bootstrap administrator username ${normalizedUsername} belongs to an ordinary account`,
      );
    }
    const administrator =
      existing ??
      (administratorIds.length === 1
        ? this.#accountsById.get(administratorIds[0]!)
        : undefined);
    if (administrator !== undefined) {
      if (!this.#store.isSystemAdministrator(administrator.userId)) {
        throw new Error(
          `The bootstrap administrator username ${normalizedUsername} belongs to an ordinary account`,
        );
      }
      const candidate = passwordHash(password, administrator.passwordSalt);
      if (
        administrator.username !== normalizedUsername ||
        administrator.displayName !== normalizedDisplayName ||
        !timingSafeEqual(candidate, administrator.passwordHash)
      ) {
        const salt = randomBytes(16);
        const updated: StoredAccount = {
          ...administrator,
          username: normalizedUsername,
          displayName: normalizedDisplayName,
          passwordSalt: salt,
          passwordHash: passwordHash(password, salt),
        };
        this.#store.updateAccountCredentials({
          userId: updated.userId,
          username: updated.username,
          displayName: updated.displayName,
          passwordSalt: updated.passwordSalt,
          passwordHash: updated.passwordHash,
          updatedAt: this.#now(),
        });
        this.#accountsByUsername.delete(administrator.username);
        this.#accountsByUsername.set(updated.username, updated);
        this.#accountsById.set(updated.userId, updated);
      }
      return;
    }
    if (administratorIds.length > 1) {
      throw new Error(
        "A bootstrap administrator cannot be selected because multiple administrator records exist",
      );
    }
    const createdAdministrator = this.#createAccount(
      normalizedUsername,
      normalizedDisplayName,
      password,
    );
    this.#store.appointSystemAdministrator(createdAdministrator.userId, this.#now());
  }

  #purchaseCard(purchase: StoredPurchase): PlatformDashboard["purchases"][number] {
    const product = this.#store.getProduct(purchase.productId)!;
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
      productName: product.name,
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
      productId: review.productId,
      productName: this.#store.getProduct(review.productId)?.name ?? review.productId,
      rating: review.rating,
      text: review.text,
      verifiedPurchase: review.verifiedPurchase,
      publishedAt: review.publishedAt,
      openedByYou:
        userId !== null &&
        Boolean(this.#reviewReaders.get(review.reviewId)?.has(userId)),
    }));
  }

  #createSession(userId: string): string {
    const token = randomBytes(32).toString("base64url");
    const createdAt = this.#clock();
    this.#store.createSession({
      tokenHash: sessionTokenHash(token),
      userId,
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + this.#sessionTtlMs).toISOString(),
    });
    return token;
  }

  #requireSession(token: string): string {
    const userId = this.#store.sessionUserId(
      sessionTokenHash(token),
      this.#now(),
    );
    if (userId === null) {
      throw new PlatformError(401, "AUTH_REQUIRED", "Please log in to continue");
    }
    return userId;
  }

  #requireUser(token: string): StoredAccount {
    return this.#requireAccountById(this.#requireSession(token));
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

  #addActivity(userId: string, message: string): void {
    this.#store.addInboxEvent({
      userId,
      eventType: "activity",
      message,
      resourceType: null,
      resourceId: null,
      createdAt: this.#now(),
    });
  }

  #hydrateFoundation(): void {
    for (const account of this.#store.listAccounts()) {
      this.#accountsByUsername.set(account.username, account);
      this.#accountsById.set(account.userId, account);
      this.#system.registerActor({
        actorId: account.userId,
        signingPublicKey: account.signing.publicKey,
      });
    }
    for (const organization of this.#store.listOrganizations()) {
      this.#system.registerOrganization({
        organizationId: organization.organizationId,
        name: organization.name,
        registeredBy: organization.createdByUserId,
      });
    }
    for (const product of this.#store.listProducts()) {
      this.#system.registerProduct({
        productId: product.productId,
        name: product.name,
        organizationId: product.organizationId,
        registeredBy: product.createdByUserId,
      });
    }
    for (const grant of this.#store.listActiveAuthorityGrants(this.#now())) {
      this.#system.grantAuthority({
        grantId: grant.grantId,
        authorityId: "platform-authority",
        granteeId: grant.granteeUserId,
        capability: grant.capability,
        scopeId: grant.productId,
        issuedAt: grant.issuedAt,
        signature: grant.signature,
      });
    }
    const recordedGrants = this.#store.listAuthorityGrants();
    for (const product of this.#store.listProducts()) {
      const owner = this.#requireAccountById(product.createdByUserId);
      for (const capability of [
        "issue-purchase-credential",
        "handle-support-cases",
      ] as const satisfies readonly GrantCapability[]) {
        const ownerGrantAlreadyRecorded = recordedGrants.some(
          (grant) =>
            grant.productId === product.productId &&
            grant.granteeUserId === owner.userId &&
            grant.capability === capability,
        );
        if (!ownerGrantAlreadyRecorded) {
          this.#createAuthorityGrant(
            owner,
            owner,
            product,
            capability,
            null,
          );
        }
      }
    }
  }

  #now(): string {
    return this.#clock().toISOString();
  }
}
