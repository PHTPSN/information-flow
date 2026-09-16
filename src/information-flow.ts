import { createHash, randomBytes } from "node:crypto";

export const INFORMATION_FLOW_SCHEMA_VERSION = 2 as const;
export const FLOW_NONCE_BYTES = 32;
export const FLOW_COMMITMENT_DOMAIN =
  "midnight-buildathon:information-flow:v1";

export const CONTEXT_KINDS = [
  "reputation",
  "support",
  "regulatory",
] as const;

export type ContextKind = (typeof CONTEXT_KINDS)[number];

export interface ActorRef {
  readonly id: string;
}

export type RecipientRef =
  | { readonly kind: "public" }
  | { readonly kind: "actor"; readonly actorId: string };

export interface RecordRef {
  readonly id: string;
  readonly digest: string;
}

export interface Claim {
  readonly id: string;
  readonly type: string;
  readonly value: string;
  readonly issuerId: string;
}

export interface RecipientView {
  readonly recipient: RecipientRef;
  readonly visibleClaimIds: readonly string[];
}

export interface InformationFlow {
  readonly schemaVersion: typeof INFORMATION_FLOW_SCHEMA_VERSION;
  readonly flowId: string;
  readonly context: {
    readonly kind: ContextKind;
    readonly policyVersion: string;
  };
  readonly actors: readonly ActorRef[];
  readonly senderId: string;
  readonly records: readonly RecordRef[];
  readonly claims: readonly Claim[];
  readonly view: RecipientView;
}

type UnknownObject = Record<string, unknown>;

function invalid(path: string, message: string): never {
  throw new TypeError(`${path}: ${message}`);
}

function expectObject(value: unknown, path: string): UnknownObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid(path, "expected an object");
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return invalid(path, "expected a plain object");
  }

  return value as UnknownObject;
}

function expectExactKeys(
  value: UnknownObject,
  expectedKeys: readonly string[],
  path: string,
): void {
  const actualKeys = Object.keys(value);
  const missing = expectedKeys.filter((key) => !(key in value));
  const unexpected = actualKeys.filter((key) => !expectedKeys.includes(key));

  if (missing.length > 0 || unexpected.length > 0) {
    const details = [
      missing.length > 0 ? `missing ${missing.join(", ")}` : "",
      unexpected.length > 0 ? `unexpected ${unexpected.join(", ")}` : "",
    ]
      .filter(Boolean)
      .join("; ");

    invalid(path, details);
  }
}

function expectArray(value: unknown, path: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    return invalid(path, "expected an array");
  }
  return value;
}

function expectText(value: unknown, path: string): string {
  if (typeof value !== "string") {
    return invalid(path, "expected text");
  }

  const normalized = value.normalize("NFC");
  if (normalized.trim().length === 0) {
    return invalid(path, "must not be empty");
  }

  return normalized;
}

function expectChoice<const T extends readonly string[]>(
  value: unknown,
  choices: T,
  path: string,
): T[number] {
  const text = expectText(value, path);
  if (!(choices as readonly string[]).includes(text)) {
    return invalid(path, `expected one of ${choices.join(", ")}`);
  }
  return text as T[number];
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function expectUnique(
  values: readonly string[],
  path: string,
  description: string,
): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      invalid(path, `duplicate ${description}: ${value}`);
    }
    seen.add(value);
  }
}

function readActor(value: unknown, index: number): ActorRef {
  const path = `InformationFlow.actors[${index}]`;
  const actor = expectObject(value, path);
  expectExactKeys(actor, ["id"], path);

  return {
    id: expectText(actor.id, `${path}.id`),
  };
}

function readRecipient(value: unknown): RecipientRef {
  const path = "InformationFlow.view.recipient";
  const recipient = expectObject(value, path);
  const kind = expectChoice(
    recipient.kind,
    ["public", "actor"] as const,
    `${path}.kind`,
  );

  if (kind === "public") {
    expectExactKeys(recipient, ["kind"], path);
    return { kind };
  }

  expectExactKeys(recipient, ["kind", "actorId"], path);
  return {
    kind,
    actorId: expectText(recipient.actorId, `${path}.actorId`),
  };
}

function readRecord(value: unknown, index: number): RecordRef {
  const path = `InformationFlow.records[${index}]`;
  const record = expectObject(value, path);
  expectExactKeys(record, ["id", "digest"], path);

  return {
    id: expectText(record.id, `${path}.id`),
    digest: expectText(record.digest, `${path}.digest`),
  };
}

function readClaim(value: unknown, index: number): Claim {
  const path = `InformationFlow.claims[${index}]`;
  const claim = expectObject(value, path);
  expectExactKeys(claim, ["id", "type", "value", "issuerId"], path);

  return {
    id: expectText(claim.id, `${path}.id`),
    type: expectText(claim.type, `${path}.type`),
    value: expectText(claim.value, `${path}.value`),
    issuerId: expectText(claim.issuerId, `${path}.issuerId`),
  };
}

function canonicalInformationFlow(input: unknown): InformationFlow {
  const flow = expectObject(input, "InformationFlow");
  expectExactKeys(
    flow,
    [
      "schemaVersion",
      "flowId",
      "context",
      "actors",
      "senderId",
      "records",
      "claims",
      "view",
    ],
    "InformationFlow",
  );

  if (flow.schemaVersion !== INFORMATION_FLOW_SCHEMA_VERSION) {
    invalid(
      "InformationFlow.schemaVersion",
      `expected ${INFORMATION_FLOW_SCHEMA_VERSION}`,
    );
  }

  const context = expectObject(flow.context, "InformationFlow.context");
  expectExactKeys(context, ["kind", "policyVersion"], "InformationFlow.context");

  const actors = expectArray(flow.actors, "InformationFlow.actors")
    .map(readActor)
    .sort((left, right) => compareText(left.id, right.id));

  const records = expectArray(flow.records, "InformationFlow.records")
    .map(readRecord)
    .sort((left, right) => compareText(left.id, right.id));

  const claims = expectArray(flow.claims, "InformationFlow.claims")
    .map(readClaim)
    .sort((left, right) => compareText(left.id, right.id));

  const view = expectObject(flow.view, "InformationFlow.view");
  expectExactKeys(
    view,
    ["recipient", "visibleClaimIds"],
    "InformationFlow.view",
  );
  const recipient = readRecipient(view.recipient);

  const visibleClaimIds = expectArray(
    view.visibleClaimIds,
    "InformationFlow.view.visibleClaimIds",
  )
    .map((value, index) =>
      expectText(value, `InformationFlow.view.visibleClaimIds[${index}]`),
    )
    .sort(compareText);

  expectUnique(
    actors.map((actor) => actor.id),
    "InformationFlow.actors",
    "actor id",
  );
  expectUnique(
    records.map((record) => record.id),
    "InformationFlow.records",
    "record id",
  );
  expectUnique(
    claims.map((claim) => claim.id),
    "InformationFlow.claims",
    "claim id",
  );
  expectUnique(
    visibleClaimIds,
    "InformationFlow.view.visibleClaimIds",
    "claim id",
  );

  const actorIds = new Set(actors.map((actor) => actor.id));
  const senderId = expectText(flow.senderId, "InformationFlow.senderId");
  if (!actorIds.has(senderId)) {
    invalid(
      "InformationFlow.senderId",
      `no actor exists with id ${senderId}`,
    );
  }

  for (const claim of claims) {
    if (!actorIds.has(claim.issuerId)) {
      invalid(
        `InformationFlow.claims.${claim.id}.issuerId`,
        `no actor exists with id ${claim.issuerId}`,
      );
    }
  }

  if (recipient.kind === "actor" && !actorIds.has(recipient.actorId)) {
    invalid(
      "InformationFlow.view.recipient.actorId",
      `no actor exists with id ${recipient.actorId}`,
    );
  }

  const claimIds = new Set(claims.map((claim) => claim.id));
  for (const claimId of visibleClaimIds) {
    if (!claimIds.has(claimId)) {
      invalid(
        "InformationFlow.view.visibleClaimIds",
        `unknown claim id ${claimId}`,
      );
    }
  }

  return {
    schemaVersion: INFORMATION_FLOW_SCHEMA_VERSION,
    flowId: expectText(flow.flowId, "InformationFlow.flowId"),
    context: {
      kind: expectChoice(
        context.kind,
        CONTEXT_KINDS,
        "InformationFlow.context.kind",
      ),
      policyVersion: expectText(
        context.policyVersion,
        "InformationFlow.context.policyVersion",
      ),
    },
    actors,
    senderId,
    records,
    claims,
    view: {
      recipient,
      visibleClaimIds,
    },
  };
}

export function canonicalizeInformationFlow(input: unknown): string {
  return JSON.stringify(canonicalInformationFlow(input));
}

function encodePartLength(length: number): Buffer {
  const encoded = Buffer.allocUnsafe(4);
  encoded.writeUInt32BE(length);
  return encoded;
}

export function generateFlowNonce(): Uint8Array {
  return randomBytes(FLOW_NONCE_BYTES);
}

export function commitInformationFlow(
  input: unknown,
  nonce: Uint8Array,
): string {
  if (!(nonce instanceof Uint8Array)) {
    invalid("nonce", "expected a Uint8Array");
  }
  if (nonce.byteLength !== FLOW_NONCE_BYTES) {
    invalid("nonce", `expected exactly ${FLOW_NONCE_BYTES} bytes`);
  }

  const parts = [
    Buffer.from(FLOW_COMMITMENT_DOMAIN, "utf8"),
    Buffer.from(nonce),
    Buffer.from(canonicalizeInformationFlow(input), "utf8"),
  ];

  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(encodePartLength(part.byteLength));
    hash.update(part);
  }

  return hash.digest("hex");
}
