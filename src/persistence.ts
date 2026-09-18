import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

export type GrantCapability =
  | "issue-purchase-credential"
  | "handle-support-cases";
export type ApprovalStatus = "pending" | "approved" | "rejected";
export type SpecialRole = "regulator";

export interface SigningIdentityRecord {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

export interface AccountRecord {
  readonly userId: string;
  readonly username: string;
  readonly displayName: string;
  readonly passwordSalt: Buffer;
  readonly passwordHash: Buffer;
  readonly signing: SigningIdentityRecord;
  readonly createdAt: string;
}

export interface OrganizationRecord {
  readonly organizationId: string;
  readonly name: string;
  readonly createdByUserId: string;
  readonly createdAt: string;
}

export interface OrganizationCreationRequestRecord {
  readonly requestId: string;
  readonly requesterUserId: string;
  readonly requesterUsername: string;
  readonly proposedOrganizationId: string;
  readonly proposedName: string;
  readonly status: ApprovalStatus;
  readonly submittedAt: string;
  readonly reviewedByUserId: string | null;
  readonly reviewedAt: string | null;
  readonly decisionNote: string | null;
  readonly createdOrganizationId: string | null;
}

export interface OrganizationMembershipRecord {
  readonly organizationId: string;
  readonly organizationName: string;
  readonly userId: string;
  readonly username: string;
  readonly displayName: string;
  readonly joinedAt: string;
}

export interface OrganizationMembershipRequestRecord {
  readonly requestId: string;
  readonly organizationId: string;
  readonly organizationName: string;
  readonly requesterUserId: string;
  readonly requesterUsername: string;
  readonly requesterDisplayName: string;
  readonly status: ApprovalStatus;
  readonly submittedAt: string;
  readonly reviewedByUserId: string | null;
  readonly reviewedAt: string | null;
  readonly decisionNote: string | null;
}

export interface SpecialRoleRequestRecord {
  readonly requestId: string;
  readonly requesterUserId: string;
  readonly requesterUsername: string;
  readonly requesterDisplayName: string;
  readonly role: SpecialRole;
  readonly justification: string;
  readonly status: ApprovalStatus;
  readonly submittedAt: string;
  readonly reviewedByUserId: string | null;
  readonly reviewedAt: string | null;
  readonly decisionNote: string | null;
}

export interface ProductRecord {
  readonly productId: string;
  readonly organizationId: string;
  readonly organizationName: string;
  readonly name: string;
  readonly createdByUserId: string;
  readonly createdAt: string;
}

export interface AuthorityGrantRecord {
  readonly grantId: string;
  readonly organizationId: string;
  readonly organizationName: string;
  readonly productId: string;
  readonly productName: string;
  readonly grantedByUserId: string;
  readonly grantedByUsername: string;
  readonly granteeUserId: string;
  readonly granteeUsername: string;
  readonly capability: GrantCapability;
  readonly issuedAt: string;
  readonly expiresAt: string | null;
  readonly revokedAt: string | null;
  readonly signature: string;
}

export interface InboxEventRecord {
  readonly eventId: string;
  readonly eventType: string;
  readonly message: string;
  readonly resourceType: string | null;
  readonly resourceId: string | null;
  readonly createdAt: string;
  readonly readAt: string | null;
}

interface AccountRow {
  readonly user_id: string;
  readonly username: string;
  readonly display_name: string;
  readonly password_salt: Uint8Array;
  readonly password_hash: Uint8Array;
  readonly created_at: string;
  readonly identity_id: string;
  readonly public_key: string;
  readonly encrypted_private_key: Uint8Array;
  readonly encryption_nonce: Uint8Array;
  readonly authentication_tag: Uint8Array;
}

interface SigningIdentityRow {
  readonly identity_id: string;
  readonly public_key: string;
  readonly encrypted_private_key: Uint8Array;
  readonly encryption_nonce: Uint8Array;
  readonly authentication_tag: Uint8Array;
}

interface OrganizationRow {
  readonly organization_id: string;
  readonly name: string;
  readonly created_by_user_id: string;
  readonly created_at: string;
}

interface OrganizationCreationRequestRow {
  readonly request_id: string;
  readonly requester_user_id: string;
  readonly requester_username: string;
  readonly proposed_organization_id: string;
  readonly proposed_name: string;
  readonly status: ApprovalStatus;
  readonly submitted_at: string;
  readonly reviewed_by_user_id: string | null;
  readonly reviewed_at: string | null;
  readonly decision_note: string | null;
  readonly created_organization_id: string | null;
}

interface OrganizationMembershipRow {
  readonly organization_id: string;
  readonly organization_name: string;
  readonly user_id: string;
  readonly username: string;
  readonly display_name: string;
  readonly joined_at: string;
}

interface OrganizationMembershipRequestRow {
  readonly request_id: string;
  readonly organization_id: string;
  readonly organization_name: string;
  readonly requester_user_id: string;
  readonly requester_username: string;
  readonly requester_display_name: string;
  readonly status: ApprovalStatus;
  readonly submitted_at: string;
  readonly reviewed_by_user_id: string | null;
  readonly reviewed_at: string | null;
  readonly decision_note: string | null;
}

interface SpecialRoleRequestRow {
  readonly request_id: string;
  readonly requester_user_id: string;
  readonly requester_username: string;
  readonly requester_display_name: string;
  readonly role: SpecialRole;
  readonly justification: string;
  readonly status: ApprovalStatus;
  readonly submitted_at: string;
  readonly reviewed_by_user_id: string | null;
  readonly reviewed_at: string | null;
  readonly decision_note: string | null;
}

interface ProductRow {
  readonly product_id: string;
  readonly organization_id: string;
  readonly organization_name: string;
  readonly name: string;
  readonly created_by_user_id: string;
  readonly created_at: string;
}

interface AuthorityGrantRow {
  readonly grant_id: string;
  readonly organization_id: string;
  readonly organization_name: string;
  readonly product_id: string;
  readonly product_name: string;
  readonly granted_by_user_id: string;
  readonly granted_by_username: string;
  readonly grantee_user_id: string;
  readonly grantee_username: string;
  readonly capability: GrantCapability;
  readonly issued_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly signature: string;
}

interface InboxEventRow {
  readonly event_id: string;
  readonly event_type: string;
  readonly message: string;
  readonly resource_type: string | null;
  readonly resource_id: string | null;
  readonly created_at: string;
  readonly read_at: string | null;
}

const MIGRATIONS_DIRECTORY = fileURLToPath(
  new URL("../migrations/", import.meta.url),
);
const PRIVATE_KEY_ALGORITHM = "aes-256-gcm";
const PRIVATE_KEY_NONCE_BYTES = 12;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function copyBuffer(value: Uint8Array): Buffer {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function encryptionAdditionalData(identityId: string): Buffer {
  return Buffer.from(`information-flow/signing-identity/v1\0${identityId}`, "utf8");
}

function encryptPrivateKey(
  identityId: string,
  privateKey: KeyObject,
  encryptionKey: Buffer,
): {
  readonly encryptedPrivateKey: Buffer;
  readonly encryptionNonce: Buffer;
  readonly authenticationTag: Buffer;
} {
  const plaintext = privateKey.export({ format: "der", type: "pkcs8" });
  const encryptionNonce = randomBytes(PRIVATE_KEY_NONCE_BYTES);
  const cipher = createCipheriv(
    PRIVATE_KEY_ALGORITHM,
    encryptionKey,
    encryptionNonce,
  );
  cipher.setAAD(encryptionAdditionalData(identityId));
  const encryptedPrivateKey = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  return {
    encryptedPrivateKey,
    encryptionNonce,
    authenticationTag: cipher.getAuthTag(),
  };
}

function decryptPrivateKey(
  row: SigningIdentityRow,
  encryptionKey: Buffer,
): KeyObject {
  const decipher = createDecipheriv(
    PRIVATE_KEY_ALGORITHM,
    encryptionKey,
    copyBuffer(row.encryption_nonce),
  );
  decipher.setAAD(encryptionAdditionalData(row.identity_id));
  decipher.setAuthTag(copyBuffer(row.authentication_tag));
  const plaintext = Buffer.concat([
    decipher.update(copyBuffer(row.encrypted_private_key)),
    decipher.final(),
  ]);
  return createPrivateKey({ key: plaintext, format: "der", type: "pkcs8" });
}

function accountFromRow(row: AccountRow, encryptionKey: Buffer): AccountRecord {
  return {
    userId: row.user_id,
    username: row.username,
    displayName: row.display_name,
    passwordSalt: copyBuffer(row.password_salt),
    passwordHash: copyBuffer(row.password_hash),
    signing: {
      publicKey: row.public_key,
      privateKey: decryptPrivateKey(row, encryptionKey),
    },
    createdAt: row.created_at,
  };
}

function organizationFromRow(row: OrganizationRow): OrganizationRecord {
  return {
    organizationId: row.organization_id,
    name: row.name,
    createdByUserId: row.created_by_user_id,
    createdAt: row.created_at,
  };
}

function organizationRequestFromRow(
  row: OrganizationCreationRequestRow,
): OrganizationCreationRequestRecord {
  return {
    requestId: row.request_id,
    requesterUserId: row.requester_user_id,
    requesterUsername: row.requester_username,
    proposedOrganizationId: row.proposed_organization_id,
    proposedName: row.proposed_name,
    status: row.status,
    submittedAt: row.submitted_at,
    reviewedByUserId: row.reviewed_by_user_id,
    reviewedAt: row.reviewed_at,
    decisionNote: row.decision_note,
    createdOrganizationId: row.created_organization_id,
  };
}

function membershipFromRow(
  row: OrganizationMembershipRow,
): OrganizationMembershipRecord {
  return {
    organizationId: row.organization_id,
    organizationName: row.organization_name,
    userId: row.user_id,
    username: row.username,
    displayName: row.display_name,
    joinedAt: row.joined_at,
  };
}

function membershipRequestFromRow(
  row: OrganizationMembershipRequestRow,
): OrganizationMembershipRequestRecord {
  return {
    requestId: row.request_id,
    organizationId: row.organization_id,
    organizationName: row.organization_name,
    requesterUserId: row.requester_user_id,
    requesterUsername: row.requester_username,
    requesterDisplayName: row.requester_display_name,
    status: row.status,
    submittedAt: row.submitted_at,
    reviewedByUserId: row.reviewed_by_user_id,
    reviewedAt: row.reviewed_at,
    decisionNote: row.decision_note,
  };
}

function specialRoleRequestFromRow(
  row: SpecialRoleRequestRow,
): SpecialRoleRequestRecord {
  return {
    requestId: row.request_id,
    requesterUserId: row.requester_user_id,
    requesterUsername: row.requester_username,
    requesterDisplayName: row.requester_display_name,
    role: row.role,
    justification: row.justification,
    status: row.status,
    submittedAt: row.submitted_at,
    reviewedByUserId: row.reviewed_by_user_id,
    reviewedAt: row.reviewed_at,
    decisionNote: row.decision_note,
  };
}

function productFromRow(row: ProductRow): ProductRecord {
  return {
    productId: row.product_id,
    organizationId: row.organization_id,
    organizationName: row.organization_name,
    name: row.name,
    createdByUserId: row.created_by_user_id,
    createdAt: row.created_at,
  };
}

function grantFromRow(row: AuthorityGrantRow): AuthorityGrantRecord {
  return {
    grantId: row.grant_id,
    organizationId: row.organization_id,
    organizationName: row.organization_name,
    productId: row.product_id,
    productName: row.product_name,
    grantedByUserId: row.granted_by_user_id,
    grantedByUsername: row.granted_by_username,
    granteeUserId: row.grantee_user_id,
    granteeUsername: row.grantee_username,
    capability: row.capability,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    signature: row.signature,
  };
}

function inboxEventFromRow(row: InboxEventRow): InboxEventRecord {
  return {
    eventId: row.event_id,
    eventType: row.event_type,
    message: row.message,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    createdAt: row.created_at,
    readAt: row.read_at,
  };
}

export function decodeDataEncryptionKey(value: string): Buffer {
  const key = Buffer.from(value.trim(), "base64url");
  if (key.length !== 32) {
    throw new Error(
      "INFORMATION_FLOW_DATA_KEY must be a base64url-encoded 32-byte key",
    );
  }
  return key;
}

export function sessionTokenHash(token: string): string {
  return sha256(`information-flow/session/v1\0${token}`);
}

export class ApplicationStore {
  readonly #database: DatabaseSync;
  readonly #encryptionKey: Buffer;
  #closed = false;

  constructor(options: {
    readonly databasePath: string;
    readonly encryptionKey: Buffer;
    readonly migrationsDirectory?: string;
  }) {
    if (options.encryptionKey.length !== 32) {
      throw new Error("The application data encryption key must be 32 bytes");
    }
    this.#encryptionKey = Buffer.from(options.encryptionKey);
    if (options.databasePath !== ":memory:") {
      mkdirSync(path.dirname(path.resolve(options.databasePath)), {
        recursive: true,
      });
    }
    this.#database = new DatabaseSync(options.databasePath, {
      enableForeignKeyConstraints: true,
    });
    this.#database.exec("PRAGMA busy_timeout = 5000");
    if (options.databasePath !== ":memory:") {
      this.#database.exec("PRAGMA journal_mode = WAL");
      this.#database.exec("PRAGMA synchronous = FULL");
    }
    this.#applyMigrations(options.migrationsDirectory ?? MIGRATIONS_DIRECTORY);
  }

  close(): void {
    if (this.#closed) return;
    this.#database.close();
    this.#closed = true;
  }

  loadOrCreateSystemSigningIdentity(
    identityId: string,
    createdAt: string,
  ): SigningIdentityRecord {
    const existing = this.#database
      .prepare(
        `SELECT identity_id, public_key, encrypted_private_key,
                encryption_nonce, authentication_tag
           FROM signing_identities
          WHERE identity_id = ? AND purpose = 'system'`,
      )
      .get(identityId) as unknown as SigningIdentityRow | undefined;
    if (existing !== undefined) {
      return {
        publicKey: existing.public_key,
        privateKey: decryptPrivateKey(existing, this.#encryptionKey),
      };
    }

    const pair = generateKeyPairSync("ed25519");
    const publicKey = pair.publicKey
      .export({ type: "spki", format: "pem" })
      .toString();
    const encrypted = encryptPrivateKey(
      identityId,
      pair.privateKey,
      this.#encryptionKey,
    );
    this.#database
      .prepare(
        `INSERT INTO signing_identities (
           identity_id, owner_user_id, purpose, public_key,
           encrypted_private_key, encryption_nonce, authentication_tag, created_at
         ) VALUES (?, NULL, 'system', ?, ?, ?, ?, ?)`,
      )
      .run(
        identityId,
        publicKey,
        encrypted.encryptedPrivateKey,
        encrypted.encryptionNonce,
        encrypted.authenticationTag,
        createdAt,
      );
    return { publicKey, privateKey: pair.privateKey };
  }

  createAccount(account: AccountRecord): void {
    const identityId = `account:${account.userId}`;
    const encrypted = encryptPrivateKey(
      identityId,
      account.signing.privateKey,
      this.#encryptionKey,
    );
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO accounts (
             user_id, username, display_name, password_salt, password_hash, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(
          account.userId,
          account.username,
          account.displayName,
          account.passwordSalt,
          account.passwordHash,
          account.createdAt,
        );
      this.#database
        .prepare(
          `INSERT INTO signing_identities (
             identity_id, owner_user_id, purpose, public_key,
             encrypted_private_key, encryption_nonce, authentication_tag, created_at
           ) VALUES (?, ?, 'account', ?, ?, ?, ?, ?)`,
        )
        .run(
          identityId,
          account.userId,
          account.signing.publicKey,
          encrypted.encryptedPrivateKey,
          encrypted.encryptionNonce,
          encrypted.authenticationTag,
          account.createdAt,
        );
      this.#insertInboxEvent({
        userId: account.userId,
        eventType: "account.created",
        message: "Account created",
        resourceType: "account",
        resourceId: account.userId,
        createdAt: account.createdAt,
      });
      this.#insertAuditEvent({
        actorUserId: account.userId,
        eventType: "account.created",
        resourceType: "account",
        resourceId: account.userId,
        metadata: {},
        occurredAt: account.createdAt,
      });
    });
  }

  updateAccountCredentials(input: {
    readonly userId: string;
    readonly username: string;
    readonly displayName: string;
    readonly passwordSalt: Buffer;
    readonly passwordHash: Buffer;
    readonly updatedAt: string;
  }): void {
    this.#transaction(() => {
      const result = this.#database
        .prepare(
          `UPDATE accounts
              SET username = ?, display_name = ?, password_salt = ?, password_hash = ?
            WHERE user_id = ?`,
        )
        .run(
          input.username,
          input.displayName,
          input.passwordSalt,
          input.passwordHash,
          input.userId,
        );
      if (result.changes !== 1) throw new Error("Account not found");
      this.#database
        .prepare("DELETE FROM login_sessions WHERE user_id = ?")
        .run(input.userId);
      this.#insertInboxEvent({
        userId: input.userId,
        eventType: "account.credentials-updated",
        message: "Account login credentials updated",
        resourceType: "account",
        resourceId: input.userId,
        createdAt: input.updatedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.userId,
        eventType: "account.credentials-updated",
        resourceType: "account",
        resourceId: input.userId,
        metadata: { source: "bootstrap" },
        occurredAt: input.updatedAt,
      });
    });
  }

  getAccountByUsername(username: string): AccountRecord | null {
    const row = this.#database
      .prepare(
        `SELECT a.user_id, a.username, a.display_name, a.password_salt,
                a.password_hash, a.created_at, i.identity_id, i.public_key,
                i.encrypted_private_key, i.encryption_nonce, i.authentication_tag
           FROM accounts a
           JOIN signing_identities i ON i.owner_user_id = a.user_id
          WHERE a.username = ? COLLATE NOCASE`,
      )
      .get(username) as unknown as AccountRow | undefined;
    return row === undefined ? null : accountFromRow(row, this.#encryptionKey);
  }

  getAccountById(userId: string): AccountRecord | null {
    const row = this.#database
      .prepare(
        `SELECT a.user_id, a.username, a.display_name, a.password_salt,
                a.password_hash, a.created_at, i.identity_id, i.public_key,
                i.encrypted_private_key, i.encryption_nonce, i.authentication_tag
           FROM accounts a
           JOIN signing_identities i ON i.owner_user_id = a.user_id
          WHERE a.user_id = ?`,
      )
      .get(userId) as unknown as AccountRow | undefined;
    return row === undefined ? null : accountFromRow(row, this.#encryptionKey);
  }

  listAccounts(): readonly AccountRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT a.user_id, a.username, a.display_name, a.password_salt,
                a.password_hash, a.created_at, i.identity_id, i.public_key,
                i.encrypted_private_key, i.encryption_nonce, i.authentication_tag
           FROM accounts a
           JOIN signing_identities i ON i.owner_user_id = a.user_id
          ORDER BY a.created_at, a.user_id`,
      )
      .all() as unknown as AccountRow[];
    return rows.map((row) => accountFromRow(row, this.#encryptionKey));
  }

  countAccounts(): number {
    const row = this.#database
      .prepare("SELECT count(*) AS count FROM accounts")
      .get() as unknown as { readonly count: number };
    return row.count;
  }

  countOrdinaryAccounts(): number {
    const row = this.#database
      .prepare(
        `SELECT count(*) AS count
           FROM accounts a
           LEFT JOIN system_administrators administrator
             ON administrator.user_id = a.user_id
          WHERE administrator.user_id IS NULL`,
      )
      .get() as unknown as { readonly count: number };
    return row.count;
  }

  createSession(input: {
    readonly tokenHash: string;
    readonly userId: string;
    readonly createdAt: string;
    readonly expiresAt: string;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO login_sessions (token_hash, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      )
      .run(input.tokenHash, input.userId, input.createdAt, input.expiresAt);
  }

  sessionUserId(tokenHash: string, now: string): string | null {
    this.#database
      .prepare("DELETE FROM login_sessions WHERE expires_at <= ?")
      .run(now);
    const row = this.#database
      .prepare(
        `SELECT user_id
           FROM login_sessions
          WHERE token_hash = ? AND expires_at > ?`,
      )
      .get(tokenHash, now) as unknown as
      | { readonly user_id: string }
      | undefined;
    return row?.user_id ?? null;
  }

  deleteSession(tokenHash: string): void {
    this.#database
      .prepare("DELETE FROM login_sessions WHERE token_hash = ?")
      .run(tokenHash);
  }

  appointSystemAdministrator(userId: string, appointedAt: string): void {
    if (this.isSystemAdministrator(userId)) return;
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO system_administrators (user_id, appointed_at)
           VALUES (?, ?)`,
        )
        .run(userId, appointedAt);
      this.#insertInboxEvent({
        userId,
        eventType: "administrator.appointed",
        message: "System administration access enabled",
        resourceType: "account",
        resourceId: userId,
        createdAt: appointedAt,
      });
      this.#insertAuditEvent({
        actorUserId: userId,
        eventType: "administrator.appointed",
        resourceType: "account",
        resourceId: userId,
        metadata: { source: "bootstrap" },
        occurredAt: appointedAt,
      });
    });
  }

  isSystemAdministrator(userId: string): boolean {
    return (
      this.#database
        .prepare("SELECT 1 FROM system_administrators WHERE user_id = ?")
        .get(userId) !== undefined
    );
  }

  listSystemAdministratorIds(): readonly string[] {
    const rows = this.#database
      .prepare("SELECT user_id FROM system_administrators ORDER BY appointed_at")
      .all() as unknown as Array<{ readonly user_id: string }>;
    return rows.map(({ user_id }) => user_id);
  }

  createOrganizationRequest(input: {
    readonly requestId: string;
    readonly requesterUserId: string;
    readonly proposedOrganizationId: string;
    readonly proposedName: string;
    readonly submittedAt: string;
  }): OrganizationCreationRequestRecord {
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO organization_creation_requests (
             request_id, requester_user_id, proposed_organization_id,
             proposed_name, status, submitted_at, reviewed_by_user_id,
             reviewed_at, decision_note, created_organization_id
           ) VALUES (?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, NULL)`,
        )
        .run(
          input.requestId,
          input.requesterUserId,
          input.proposedOrganizationId,
          input.proposedName,
          input.submittedAt,
        );
      this.#insertInboxEvent({
        userId: input.requesterUserId,
        eventType: "organization.requested",
        message: `${input.proposedName} is awaiting administrator approval`,
        resourceType: "organization-request",
        resourceId: input.requestId,
        createdAt: input.submittedAt,
      });
      for (const administratorId of this.listSystemAdministratorIds()) {
        this.#insertInboxEvent({
          userId: administratorId,
          eventType: "organization.approval-required",
          message: `New organization request: ${input.proposedName}`,
          resourceType: "organization-request",
          resourceId: input.requestId,
          createdAt: input.submittedAt,
        });
      }
      this.#insertAuditEvent({
        actorUserId: input.requesterUserId,
        eventType: "organization.requested",
        resourceType: "organization-request",
        resourceId: input.requestId,
        metadata: {
          proposedOrganizationId: input.proposedOrganizationId,
          proposedName: input.proposedName,
        },
        occurredAt: input.submittedAt,
      });
    });
    return this.getOrganizationRequest(input.requestId)!;
  }

  getOrganizationRequest(
    requestId: string,
  ): OrganizationCreationRequestRecord | null {
    const row = this.#database
      .prepare(`${this.#organizationRequestSelect()} WHERE r.request_id = ?`)
      .get(requestId) as unknown as OrganizationCreationRequestRow | undefined;
    return row === undefined ? null : organizationRequestFromRow(row);
  }

  listOrganizationRequestsForUser(
    userId: string,
  ): readonly OrganizationCreationRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#organizationRequestSelect()}
          WHERE r.requester_user_id = ?
          ORDER BY r.submitted_at DESC, r.request_id`,
      )
      .all(userId) as unknown as OrganizationCreationRequestRow[];
    return rows.map(organizationRequestFromRow);
  }

  listPendingOrganizationRequests(): readonly OrganizationCreationRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#organizationRequestSelect()}
          WHERE r.status = 'pending'
          ORDER BY r.submitted_at, r.request_id`,
      )
      .all() as unknown as OrganizationCreationRequestRow[];
    return rows.map(organizationRequestFromRow);
  }

  decideOrganizationRequest(input: {
    readonly requestId: string;
    readonly administratorUserId: string;
    readonly approved: boolean;
    readonly decisionNote: string | null;
    readonly reviewedAt: string;
  }): OrganizationCreationRequestRecord {
    const request = this.getOrganizationRequest(input.requestId);
    if (request === null || request.status !== "pending") {
      throw new Error("Pending organization request not found");
    }
    const status = input.approved ? "approved" : "rejected";
    this.#transaction(() => {
      if (input.approved) {
        this.#database
          .prepare(
            `INSERT INTO organizations (
               organization_id, name, created_by_user_id, created_at
             ) VALUES (?, ?, ?, ?)`,
          )
          .run(
            request.proposedOrganizationId,
            request.proposedName,
            request.requesterUserId,
            input.reviewedAt,
          );
        this.#database
          .prepare(
            `INSERT INTO organization_controllers (
               organization_id, user_id, granted_at, revoked_at
             ) VALUES (?, ?, ?, NULL)`,
          )
          .run(
            request.proposedOrganizationId,
            request.requesterUserId,
            input.reviewedAt,
          );
        this.#database
          .prepare(
            `INSERT INTO organization_memberships (
               organization_id, user_id, approved_by_user_id, joined_at, revoked_at
             ) VALUES (?, ?, ?, ?, NULL)`,
          )
          .run(
            request.proposedOrganizationId,
            request.requesterUserId,
            input.administratorUserId,
            input.reviewedAt,
          );
      }
      this.#database
        .prepare(
          `UPDATE organization_creation_requests
              SET status = ?, reviewed_by_user_id = ?, reviewed_at = ?,
                  decision_note = ?, created_organization_id = ?
            WHERE request_id = ? AND status = 'pending'`,
        )
        .run(
          status,
          input.administratorUserId,
          input.reviewedAt,
          input.decisionNote,
          input.approved ? request.proposedOrganizationId : null,
          input.requestId,
        );
      this.#insertInboxEvent({
        userId: request.requesterUserId,
        eventType: `organization.${status}`,
        message: input.approved
          ? `${request.proposedName} was approved; you now control the organization`
          : `${request.proposedName} organization request was rejected`,
        resourceType: "organization-request",
        resourceId: request.requestId,
        createdAt: input.reviewedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.administratorUserId,
        eventType: `organization.${status}`,
        resourceType: "organization-request",
        resourceId: request.requestId,
        metadata: {
          proposedOrganizationId: request.proposedOrganizationId,
          requesterUserId: request.requesterUserId,
          decisionNote: input.decisionNote,
        },
        occurredAt: input.reviewedAt,
      });
    });
    return this.getOrganizationRequest(input.requestId)!;
  }

  createMembershipRequest(input: {
    readonly requestId: string;
    readonly organizationId: string;
    readonly requesterUserId: string;
    readonly submittedAt: string;
  }): OrganizationMembershipRequestRecord {
    const organization = this.getOrganization(input.organizationId);
    if (organization === null) throw new Error("Organization not found");
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO organization_membership_requests (
             request_id, organization_id, requester_user_id, status,
             submitted_at, reviewed_by_user_id, reviewed_at, decision_note
           ) VALUES (?, ?, ?, 'pending', ?, NULL, NULL, NULL)`,
        )
        .run(
          input.requestId,
          input.organizationId,
          input.requesterUserId,
          input.submittedAt,
        );
      this.#insertInboxEvent({
        userId: input.requesterUserId,
        eventType: "membership.requested",
        message: `Your request to join ${organization.name} is pending`,
        resourceType: "membership-request",
        resourceId: input.requestId,
        createdAt: input.submittedAt,
      });
      this.#insertInboxEvent({
        userId: organization.createdByUserId,
        eventType: "membership.approval-required",
        message: `A registered account requested to join ${organization.name}`,
        resourceType: "membership-request",
        resourceId: input.requestId,
        createdAt: input.submittedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.requesterUserId,
        eventType: "membership.requested",
        resourceType: "membership-request",
        resourceId: input.requestId,
        metadata: { organizationId: input.organizationId },
        occurredAt: input.submittedAt,
      });
    });
    return this.getMembershipRequest(input.requestId)!;
  }

  getMembershipRequest(
    requestId: string,
  ): OrganizationMembershipRequestRecord | null {
    const row = this.#database
      .prepare(`${this.#membershipRequestSelect()} WHERE r.request_id = ?`)
      .get(requestId) as unknown as OrganizationMembershipRequestRow | undefined;
    return row === undefined ? null : membershipRequestFromRow(row);
  }

  listMembershipRequestsForUser(
    userId: string,
  ): readonly OrganizationMembershipRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#membershipRequestSelect()}
          WHERE r.requester_user_id = ?
          ORDER BY r.submitted_at DESC, r.request_id`,
      )
      .all(userId) as unknown as OrganizationMembershipRequestRow[];
    return rows.map(membershipRequestFromRow);
  }

  listPendingMembershipRequestsForCreator(
    creatorUserId: string,
  ): readonly OrganizationMembershipRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#membershipRequestSelect()}
          WHERE r.status = 'pending' AND o.created_by_user_id = ?
          ORDER BY r.submitted_at, r.request_id`,
      )
      .all(creatorUserId) as unknown as OrganizationMembershipRequestRow[];
    return rows.map(membershipRequestFromRow);
  }

  decideMembershipRequest(input: {
    readonly requestId: string;
    readonly reviewerUserId: string;
    readonly approved: boolean;
    readonly decisionNote: string | null;
    readonly reviewedAt: string;
  }): OrganizationMembershipRequestRecord {
    const request = this.getMembershipRequest(input.requestId);
    if (request === null || request.status !== "pending") {
      throw new Error("Pending membership request not found");
    }
    const status = input.approved ? "approved" : "rejected";
    this.#transaction(() => {
      if (input.approved) {
        this.#database
          .prepare(
            `INSERT INTO organization_memberships (
               organization_id, user_id, approved_by_user_id, joined_at, revoked_at
             ) VALUES (?, ?, ?, ?, NULL)`,
          )
          .run(
            request.organizationId,
            request.requesterUserId,
            input.reviewerUserId,
            input.reviewedAt,
          );
      }
      this.#database
        .prepare(
          `UPDATE organization_membership_requests
              SET status = ?, reviewed_by_user_id = ?, reviewed_at = ?,
                  decision_note = ?
            WHERE request_id = ? AND status = 'pending'`,
        )
        .run(
          status,
          input.reviewerUserId,
          input.reviewedAt,
          input.decisionNote,
          input.requestId,
        );
      this.#insertInboxEvent({
        userId: request.requesterUserId,
        eventType: `membership.${status}`,
        message: input.approved
          ? `You joined ${request.organizationName}`
          : `Your request to join ${request.organizationName} was rejected`,
        resourceType: "membership-request",
        resourceId: request.requestId,
        createdAt: input.reviewedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.reviewerUserId,
        eventType: `membership.${status}`,
        resourceType: "membership-request",
        resourceId: request.requestId,
        metadata: {
          organizationId: request.organizationId,
          requesterUserId: request.requesterUserId,
          decisionNote: input.decisionNote,
        },
        occurredAt: input.reviewedAt,
      });
    });
    return this.getMembershipRequest(input.requestId)!;
  }

  isOrganizationMember(userId: string, organizationId: string): boolean {
    return (
      this.#database
        .prepare(
          `SELECT 1 FROM organization_memberships
            WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL`,
        )
        .get(organizationId, userId) !== undefined
    );
  }

  listMembershipsForUser(
    userId: string,
  ): readonly OrganizationMembershipRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT m.organization_id, o.name AS organization_name,
                m.user_id, a.username, a.display_name, m.joined_at
           FROM organization_memberships m
           JOIN organizations o ON o.organization_id = m.organization_id
           JOIN accounts a ON a.user_id = m.user_id
          WHERE m.user_id = ? AND m.revoked_at IS NULL
          ORDER BY m.joined_at, m.organization_id`,
      )
      .all(userId) as unknown as OrganizationMembershipRow[];
    return rows.map(membershipFromRow);
  }

  listOrganizationMembers(
    organizationId: string,
  ): readonly OrganizationMembershipRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT m.organization_id, o.name AS organization_name,
                m.user_id, a.username, a.display_name, m.joined_at
           FROM organization_memberships m
           JOIN organizations o ON o.organization_id = m.organization_id
           JOIN accounts a ON a.user_id = m.user_id
          WHERE m.organization_id = ? AND m.revoked_at IS NULL
          ORDER BY m.joined_at, m.user_id`,
      )
      .all(organizationId) as unknown as OrganizationMembershipRow[];
    return rows.map(membershipFromRow);
  }

  createSpecialRoleRequest(input: {
    readonly requestId: string;
    readonly requesterUserId: string;
    readonly role: SpecialRole;
    readonly justification: string;
    readonly submittedAt: string;
  }): SpecialRoleRequestRecord {
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO special_role_requests (
             request_id, requester_user_id, role, justification, status,
             submitted_at, reviewed_by_user_id, reviewed_at, decision_note
           ) VALUES (?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL)`,
        )
        .run(
          input.requestId,
          input.requesterUserId,
          input.role,
          input.justification,
          input.submittedAt,
        );
      this.#insertInboxEvent({
        userId: input.requesterUserId,
        eventType: "role.requested",
        message: `Your ${input.role} application is awaiting administrator approval`,
        resourceType: "role-request",
        resourceId: input.requestId,
        createdAt: input.submittedAt,
      });
      for (const administratorId of this.listSystemAdministratorIds()) {
        this.#insertInboxEvent({
          userId: administratorId,
          eventType: "role.approval-required",
          message: `New ${input.role} application`,
          resourceType: "role-request",
          resourceId: input.requestId,
          createdAt: input.submittedAt,
        });
      }
      this.#insertAuditEvent({
        actorUserId: input.requesterUserId,
        eventType: "role.requested",
        resourceType: "role-request",
        resourceId: input.requestId,
        metadata: { role: input.role },
        occurredAt: input.submittedAt,
      });
    });
    return this.getSpecialRoleRequest(input.requestId)!;
  }

  getSpecialRoleRequest(requestId: string): SpecialRoleRequestRecord | null {
    const row = this.#database
      .prepare(`${this.#specialRoleRequestSelect()} WHERE r.request_id = ?`)
      .get(requestId) as unknown as SpecialRoleRequestRow | undefined;
    return row === undefined ? null : specialRoleRequestFromRow(row);
  }

  listSpecialRoleRequestsForUser(
    userId: string,
  ): readonly SpecialRoleRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#specialRoleRequestSelect()}
          WHERE r.requester_user_id = ?
          ORDER BY r.submitted_at DESC, r.request_id`,
      )
      .all(userId) as unknown as SpecialRoleRequestRow[];
    return rows.map(specialRoleRequestFromRow);
  }

  listPendingSpecialRoleRequests(): readonly SpecialRoleRequestRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#specialRoleRequestSelect()}
          WHERE r.status = 'pending'
          ORDER BY r.submitted_at, r.request_id`,
      )
      .all() as unknown as SpecialRoleRequestRow[];
    return rows.map(specialRoleRequestFromRow);
  }

  decideSpecialRoleRequest(input: {
    readonly requestId: string;
    readonly administratorUserId: string;
    readonly approved: boolean;
    readonly decisionNote: string | null;
    readonly reviewedAt: string;
  }): SpecialRoleRequestRecord {
    const request = this.getSpecialRoleRequest(input.requestId);
    if (request === null || request.status !== "pending") {
      throw new Error("Pending special-role request not found");
    }
    const status = input.approved ? "approved" : "rejected";
    this.#transaction(() => {
      if (input.approved) {
        this.#database
          .prepare(
            `INSERT INTO account_special_roles (
               user_id, role, granted_by_user_id, granted_at, revoked_at
             ) VALUES (?, ?, ?, ?, NULL)
             ON CONFLICT (user_id, role) DO UPDATE SET
               granted_by_user_id = excluded.granted_by_user_id,
               granted_at = excluded.granted_at,
               revoked_at = NULL`,
          )
          .run(
            request.requesterUserId,
            request.role,
            input.administratorUserId,
            input.reviewedAt,
          );
      }
      this.#database
        .prepare(
          `UPDATE special_role_requests
              SET status = ?, reviewed_by_user_id = ?, reviewed_at = ?,
                  decision_note = ?
            WHERE request_id = ? AND status = 'pending'`,
        )
        .run(
          status,
          input.administratorUserId,
          input.reviewedAt,
          input.decisionNote,
          input.requestId,
        );
      this.#insertInboxEvent({
        userId: request.requesterUserId,
        eventType: `role.${status}`,
        message: input.approved
          ? `Your ${request.role} application was approved`
          : `Your ${request.role} application was rejected`,
        resourceType: "role-request",
        resourceId: request.requestId,
        createdAt: input.reviewedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.administratorUserId,
        eventType: `role.${status}`,
        resourceType: "role-request",
        resourceId: request.requestId,
        metadata: {
          role: request.role,
          requesterUserId: request.requesterUserId,
          decisionNote: input.decisionNote,
        },
        occurredAt: input.reviewedAt,
      });
    });
    return this.getSpecialRoleRequest(input.requestId)!;
  }

  hasSpecialRole(userId: string, role: SpecialRole): boolean {
    return (
      this.#database
        .prepare(
          `SELECT 1 FROM account_special_roles
            WHERE user_id = ? AND role = ? AND revoked_at IS NULL`,
        )
        .get(userId, role) !== undefined
    );
  }

  listSpecialRoles(userId: string): readonly SpecialRole[] {
    const rows = this.#database
      .prepare(
        `SELECT role FROM account_special_roles
          WHERE user_id = ? AND revoked_at IS NULL
          ORDER BY role`,
      )
      .all(userId) as unknown as Array<{ readonly role: SpecialRole }>;
    return rows.map(({ role }) => role);
  }

  listActiveSpecialRoleUserIds(role: SpecialRole): readonly string[] {
    const rows = this.#database
      .prepare(
        `SELECT user_id FROM account_special_roles
          WHERE role = ? AND revoked_at IS NULL
          ORDER BY granted_at, user_id`,
      )
      .all(role) as unknown as Array<{ readonly user_id: string }>;
    return rows.map(({ user_id }) => user_id);
  }

  getOrganization(organizationId: string): OrganizationRecord | null {
    const row = this.#database
      .prepare(
        `SELECT organization_id, name, created_by_user_id, created_at
           FROM organizations
          WHERE organization_id = ?`,
      )
      .get(organizationId) as unknown as OrganizationRow | undefined;
    return row === undefined ? null : organizationFromRow(row);
  }

  listOrganizations(): readonly OrganizationRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT organization_id, name, created_by_user_id, created_at
           FROM organizations
          ORDER BY created_at, organization_id`,
      )
      .all() as unknown as OrganizationRow[];
    return rows.map(organizationFromRow);
  }

  listControlledOrganizations(userId: string): readonly OrganizationRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT o.organization_id, o.name, o.created_by_user_id, o.created_at
           FROM organizations o
           JOIN organization_controllers c
             ON c.organization_id = o.organization_id
          WHERE c.user_id = ? AND c.revoked_at IS NULL
          ORDER BY o.created_at, o.organization_id`,
      )
      .all(userId) as unknown as OrganizationRow[];
    return rows.map(organizationFromRow);
  }

  controlsOrganization(userId: string, organizationId: string): boolean {
    return (
      this.#database
        .prepare(
          `SELECT 1 AS allowed
             FROM organization_controllers
            WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL`,
        )
        .get(organizationId, userId) !== undefined
    );
  }

  createProduct(input: Omit<ProductRecord, "organizationName">): void {
    const organization = this.getOrganization(input.organizationId);
    if (organization === null) throw new Error("Organization not found");
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO products (
             product_id, organization_id, name, created_by_user_id, created_at
           ) VALUES (?, ?, ?, ?, ?)`,
        )
        .run(
          input.productId,
          input.organizationId,
          input.name,
          input.createdByUserId,
          input.createdAt,
        );
      this.#insertInboxEvent({
        userId: input.createdByUserId,
        eventType: "product.created",
        message: `${input.name} added to ${organization.name}`,
        resourceType: "product",
        resourceId: input.productId,
        createdAt: input.createdAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.createdByUserId,
        eventType: "product.created",
        resourceType: "product",
        resourceId: input.productId,
        metadata: { organizationId: input.organizationId, name: input.name },
        occurredAt: input.createdAt,
      });
    });
  }

  getProduct(productId: string): ProductRecord | null {
    const row = this.#database
      .prepare(
        `SELECT p.product_id, p.organization_id, o.name AS organization_name,
                p.name, p.created_by_user_id, p.created_at
           FROM products p
           JOIN organizations o ON o.organization_id = p.organization_id
          WHERE p.product_id = ?`,
      )
      .get(productId) as unknown as ProductRow | undefined;
    return row === undefined ? null : productFromRow(row);
  }

  listProducts(): readonly ProductRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT p.product_id, p.organization_id, o.name AS organization_name,
                p.name, p.created_by_user_id, p.created_at
           FROM products p
           JOIN organizations o ON o.organization_id = p.organization_id
          ORDER BY p.created_at, p.product_id`,
      )
      .all() as unknown as ProductRow[];
    return rows.map(productFromRow);
  }

  createAuthorityGrant(input: {
    readonly grantId: string;
    readonly organizationId: string;
    readonly productId: string;
    readonly grantedByUserId: string;
    readonly granteeUserId: string;
    readonly capability: GrantCapability;
    readonly issuedAt: string;
    readonly expiresAt: string | null;
    readonly signature: string;
  }): void {
    const product = this.getProduct(input.productId);
    const grantee = this.getAccountById(input.granteeUserId);
    if (product === null || grantee === null) {
      throw new Error("Grant dependencies not found");
    }
    this.#transaction(() => {
      this.#database
        .prepare(
          `INSERT INTO authority_grants (
             grant_id, organization_id, product_id, granted_by_user_id,
             grantee_user_id, capability, issued_at, expires_at, revoked_at,
             signature
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
        )
        .run(
          input.grantId,
          input.organizationId,
          input.productId,
          input.grantedByUserId,
          input.granteeUserId,
          input.capability,
          input.issuedAt,
          input.expiresAt,
          input.signature,
        );
      const capabilityMessage =
        input.capability === "issue-purchase-credential"
          ? `record ${product.name} purchases`
          : `handle ${product.name} support cases`;
      this.#insertInboxEvent({
        userId: input.granteeUserId,
        eventType: "authority.granted",
        message: `${product.organizationName} authorized you to ${capabilityMessage}`,
        resourceType: "authority-grant",
        resourceId: input.grantId,
        createdAt: input.issuedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.grantedByUserId,
        eventType: "authority.granted",
        resourceType: "authority-grant",
        resourceId: input.grantId,
        metadata: {
          capability: input.capability,
          productId: input.productId,
          granteeUserId: input.granteeUserId,
          expiresAt: input.expiresAt,
        },
        occurredAt: input.issuedAt,
      });
    });
  }

  revokeAuthorityGrant(input: {
    readonly grantId: string;
    readonly revokedByUserId: string;
    readonly revokedAt: string;
  }): boolean {
    const grant = this.getAuthorityGrant(input.grantId);
    if (grant === null || grant.revokedAt !== null) return false;
    this.#transaction(() => {
      this.#database
        .prepare(
          `UPDATE authority_grants
              SET revoked_at = ?
            WHERE grant_id = ? AND revoked_at IS NULL`,
        )
        .run(input.revokedAt, input.grantId);
      this.#insertInboxEvent({
        userId: grant.granteeUserId,
        eventType: "authority.revoked",
        message: `${grant.organizationName} revoked your authority to ${
          grant.capability === "issue-purchase-credential"
            ? `record ${grant.productName} purchases`
            : `handle ${grant.productName} support cases`
        }`,
        resourceType: "authority-grant",
        resourceId: grant.grantId,
        createdAt: input.revokedAt,
      });
      this.#insertAuditEvent({
        actorUserId: input.revokedByUserId,
        eventType: "authority.revoked",
        resourceType: "authority-grant",
        resourceId: grant.grantId,
        metadata: {},
        occurredAt: input.revokedAt,
      });
    });
    return true;
  }

  getAuthorityGrant(grantId: string): AuthorityGrantRecord | null {
    const row = this.#database
      .prepare(`${this.#grantSelect()} WHERE g.grant_id = ?`)
      .get(grantId) as unknown as AuthorityGrantRow | undefined;
    return row === undefined ? null : grantFromRow(row);
  }

  listAuthorityGrants(): readonly AuthorityGrantRecord[] {
    const rows = this.#database
      .prepare(`${this.#grantSelect()} ORDER BY g.issued_at, g.grant_id`)
      .all() as unknown as AuthorityGrantRow[];
    return rows.map(grantFromRow);
  }

  listAuthorityGrantsForUser(userId: string): readonly AuthorityGrantRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#grantSelect()}
          WHERE g.grantee_user_id = ? OR g.granted_by_user_id = ?
          ORDER BY g.issued_at DESC, g.grant_id`,
      )
      .all(userId, userId) as unknown as AuthorityGrantRow[];
    return rows.map(grantFromRow);
  }

  findActiveAuthorityGrant(
    userId: string,
    capability: GrantCapability,
    productId: string,
    now: string,
  ): AuthorityGrantRecord | null {
    const row = this.#database
      .prepare(
        `${this.#grantSelect()}
          WHERE g.grantee_user_id = ?
            AND g.capability = ?
            AND g.product_id = ?
            AND g.issued_at <= ?
            AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > ?)
          ORDER BY g.issued_at DESC, g.grant_id
          LIMIT 1`,
      )
      .get(userId, capability, productId, now, now) as unknown as
      | AuthorityGrantRow
      | undefined;
    return row === undefined ? null : grantFromRow(row);
  }

  listActiveAuthorityGrants(now: string): readonly AuthorityGrantRecord[] {
    const rows = this.#database
      .prepare(
        `${this.#grantSelect()}
          WHERE g.issued_at <= ?
            AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > ?)
          ORDER BY g.issued_at, g.grant_id`,
      )
      .all(now, now) as unknown as AuthorityGrantRow[];
    return rows.map(grantFromRow);
  }

  addInboxEvent(input: {
    readonly userId: string;
    readonly eventType: string;
    readonly message: string;
    readonly resourceType: string | null;
    readonly resourceId: string | null;
    readonly createdAt: string;
  }): void {
    this.#insertInboxEvent(input);
  }

  listInboxEvents(userId: string): readonly InboxEventRecord[] {
    const rows = this.#database
      .prepare(
        `SELECT event_id, event_type, message, resource_type, resource_id,
                created_at, read_at
           FROM inbox_events
          WHERE user_id = ?
          ORDER BY created_at DESC, event_id DESC`,
      )
      .all(userId) as unknown as InboxEventRow[];
    return rows.map(inboxEventFromRow);
  }

  #organizationRequestSelect(): string {
    return `SELECT r.request_id, r.requester_user_id,
                   requester.username AS requester_username,
                   r.proposed_organization_id, r.proposed_name, r.status,
                   r.submitted_at, r.reviewed_by_user_id, r.reviewed_at,
                   r.decision_note, r.created_organization_id
              FROM organization_creation_requests r
              JOIN accounts requester ON requester.user_id = r.requester_user_id`;
  }

  #membershipRequestSelect(): string {
    return `SELECT r.request_id, r.organization_id,
                   o.name AS organization_name, r.requester_user_id,
                   requester.username AS requester_username,
                   requester.display_name AS requester_display_name,
                   r.status, r.submitted_at, r.reviewed_by_user_id,
                   r.reviewed_at, r.decision_note
              FROM organization_membership_requests r
              JOIN organizations o ON o.organization_id = r.organization_id
              JOIN accounts requester ON requester.user_id = r.requester_user_id`;
  }

  #specialRoleRequestSelect(): string {
    return `SELECT r.request_id, r.requester_user_id,
                   requester.username AS requester_username,
                   requester.display_name AS requester_display_name,
                   r.role, r.justification, r.status, r.submitted_at,
                   r.reviewed_by_user_id, r.reviewed_at, r.decision_note
              FROM special_role_requests r
              JOIN accounts requester ON requester.user_id = r.requester_user_id`;
  }

  #grantSelect(): string {
    return `SELECT g.grant_id, g.organization_id, o.name AS organization_name,
                   g.product_id, p.name AS product_name,
                   g.granted_by_user_id, grantor.username AS granted_by_username,
                   g.grantee_user_id, grantee.username AS grantee_username,
                   g.capability, g.issued_at, g.expires_at, g.revoked_at,
                   g.signature
              FROM authority_grants g
              JOIN organizations o ON o.organization_id = g.organization_id
              JOIN products p ON p.product_id = g.product_id
              JOIN accounts grantor ON grantor.user_id = g.granted_by_user_id
              JOIN accounts grantee ON grantee.user_id = g.grantee_user_id`;
  }

  #insertInboxEvent(input: {
    readonly userId: string;
    readonly eventType: string;
    readonly message: string;
    readonly resourceType: string | null;
    readonly resourceId: string | null;
    readonly createdAt: string;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO inbox_events (
           event_id, user_id, event_type, message, resource_type, resource_id,
           created_at, read_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        `inbox-${randomUUID()}`,
        input.userId,
        input.eventType,
        input.message,
        input.resourceType,
        input.resourceId,
        input.createdAt,
      );
  }

  #insertAuditEvent(input: {
    readonly actorUserId: string | null;
    readonly eventType: string;
    readonly resourceType: string;
    readonly resourceId: string;
    readonly metadata: Record<string, unknown>;
    readonly occurredAt: string;
  }): void {
    this.#database
      .prepare(
        `INSERT INTO audit_events (
           event_id, actor_user_id, event_type, resource_type, resource_id,
           metadata_json, occurred_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        `audit-${randomUUID()}`,
        input.actorUserId,
        input.eventType,
        input.resourceType,
        input.resourceId,
        JSON.stringify(input.metadata),
        input.occurredAt,
      );
  }

  #applyMigrations(migrationsDirectory: string): void {
    this.#database.exec(
      `CREATE TABLE IF NOT EXISTS schema_migrations (
         name TEXT PRIMARY KEY,
         applied_at TEXT NOT NULL
       ) STRICT`,
    );
    const appliedRows = this.#database
      .prepare("SELECT name FROM schema_migrations")
      .all() as unknown as Array<{ readonly name: string }>;
    const applied = new Set(appliedRows.map(({ name }) => name));
    const migrationNames = readdirSync(migrationsDirectory)
      .filter((name) => /^\d+.*\.sql$/.test(name))
      .sort();
    for (const name of migrationNames) {
      if (applied.has(name)) continue;
      const sql = readFileSync(path.join(migrationsDirectory, name), "utf8");
      this.#transaction(() => {
        this.#database.exec(sql);
        this.#database
          .prepare(
            "INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)",
          )
          .run(name, new Date().toISOString());
      });
    }
  }

  #transaction<T>(operation: () => T): T {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      this.#database.exec("ROLLBACK");
      throw error;
    }
  }
}
