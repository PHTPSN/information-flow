CREATE TABLE accounts (
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_salt BLOB NOT NULL,
  password_hash BLOB NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE signing_identities (
  identity_id TEXT PRIMARY KEY,
  owner_user_id TEXT UNIQUE REFERENCES accounts(user_id) ON DELETE RESTRICT,
  purpose TEXT NOT NULL CHECK (purpose IN ('account', 'system')),
  public_key TEXT NOT NULL,
  encrypted_private_key BLOB NOT NULL,
  encryption_nonce BLOB NOT NULL,
  authentication_tag BLOB NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (
    (purpose = 'account' AND owner_user_id IS NOT NULL) OR
    (purpose = 'system' AND owner_user_id IS NULL)
  )
) STRICT;

CREATE TABLE login_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX login_sessions_user_id_idx ON login_sessions(user_id);
CREATE INDEX login_sessions_expires_at_idx ON login_sessions(expires_at);

CREATE TABLE organizations (
  organization_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE organization_controllers (
  organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  granted_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (organization_id, user_id)
) STRICT;
CREATE INDEX organization_controllers_user_id_idx ON organization_controllers(user_id);

CREATE TABLE products (
  product_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  created_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  UNIQUE (organization_id, name)
) STRICT;
CREATE INDEX products_organization_id_idx ON products(organization_id);

CREATE TABLE authority_grants (
  grant_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
  product_id TEXT NOT NULL REFERENCES products(product_id) ON DELETE RESTRICT,
  granted_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  grantee_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  capability TEXT NOT NULL CHECK (
    capability IN ('issue-purchase-credential', 'handle-support-cases')
  ),
  issued_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  signature TEXT NOT NULL,
  UNIQUE (grantee_user_id, capability, product_id, issued_at)
) STRICT;
CREATE INDEX authority_grants_grantee_idx
  ON authority_grants(grantee_user_id, capability, product_id);
CREATE INDEX authority_grants_organization_idx ON authority_grants(organization_id);

CREATE TABLE purchases (
  purchase_id TEXT PRIMARY KEY,
  product_id TEXT NOT NULL REFERENCES products(product_id) ON DELETE RESTRICT,
  buyer_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  issuer_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  order_reference TEXT NOT NULL,
  purchased_at TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('recorded', 'credential_issued', 'revoked')),
  created_at TEXT NOT NULL,
  UNIQUE (product_id, order_reference)
) STRICT;

CREATE TABLE purchase_credentials (
  credential_id TEXT PRIMARY KEY,
  purchase_id TEXT NOT NULL UNIQUE REFERENCES purchases(purchase_id) ON DELETE RESTRICT,
  holder_secret_hash TEXT NOT NULL,
  encrypted_credential BLOB NOT NULL,
  encryption_nonce BLOB NOT NULL,
  authentication_tag BLOB NOT NULL,
  signature TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  revoked_at TEXT
) STRICT;

CREATE TABLE review_drafts (
  draft_id TEXT PRIMARY KEY,
  purchase_id TEXT NOT NULL REFERENCES purchases(purchase_id) ON DELETE RESTRICT,
  author_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  review_text TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('draft', 'commitment_pending', 'confirmed', 'published')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE review_revisions (
  revision_id TEXT PRIMARY KEY,
  draft_id TEXT NOT NULL REFERENCES review_drafts(draft_id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  review_text TEXT NOT NULL,
  visibility TEXT NOT NULL CHECK (visibility IN ('private', 'public')),
  published_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (draft_id, revision_number)
) STRICT;

CREATE TABLE support_cases (
  case_id TEXT PRIMARY KEY,
  purchase_id TEXT NOT NULL REFERENCES purchases(purchase_id) ON DELETE RESTRICT,
  opened_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  assigned_handler_user_id TEXT REFERENCES accounts(user_id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN ('open', 'responding', 'decided', 'closed', 'escalated')),
  opened_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE support_case_messages (
  message_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES support_cases(case_id) ON DELETE RESTRICT,
  author_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE support_decisions (
  decision_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL UNIQUE REFERENCES support_cases(case_id) ON DELETE RESTRICT,
  issuer_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  outcome TEXT NOT NULL CHECK (outcome IN ('approved', 'rejected')),
  reason TEXT NOT NULL,
  signature TEXT NOT NULL,
  decided_at TEXT NOT NULL
) STRICT;

CREATE TABLE support_case_status_history (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES support_cases(case_id) ON DELETE RESTRICT,
  from_state TEXT,
  to_state TEXT NOT NULL,
  changed_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  changed_at TEXT NOT NULL
) STRICT;

CREATE TABLE disclosure_grants (
  disclosure_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES support_cases(case_id) ON DELETE RESTRICT,
  authorizer_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  recipient_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  purpose TEXT NOT NULL,
  record_ids_json TEXT NOT NULL CHECK (json_valid(record_ids_json)),
  state TEXT NOT NULL CHECK (state IN ('prepared', 'authorized', 'viewed', 'expired', 'revoked')),
  signature TEXT,
  prepared_at TEXT NOT NULL,
  authorized_at TEXT,
  expires_at TEXT,
  revoked_at TEXT
) STRICT;

CREATE TABLE disclosure_access_receipts (
  receipt_id TEXT PRIMARY KEY,
  disclosure_id TEXT NOT NULL REFERENCES disclosure_grants(disclosure_id) ON DELETE RESTRICT,
  recipient_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  accessed_at TEXT NOT NULL,
  record_ids_json TEXT NOT NULL CHECK (json_valid(record_ids_json))
) STRICT;

CREATE TABLE midnight_contracts (
  contract_id TEXT PRIMARY KEY,
  network_id TEXT NOT NULL,
  public_address TEXT NOT NULL,
  deployed_at TEXT NOT NULL,
  active INTEGER NOT NULL CHECK (active IN (0, 1)),
  UNIQUE (network_id, public_address)
) STRICT;

CREATE TABLE commitment_submissions (
  submission_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  local_action_type TEXT NOT NULL,
  local_action_id TEXT NOT NULL,
  commitment TEXT NOT NULL CHECK (length(commitment) = 64),
  contract_id TEXT REFERENCES midnight_contracts(contract_id) ON DELETE RESTRICT,
  state TEXT NOT NULL CHECK (state IN ('prepared', 'submitted', 'confirmed', 'failed')),
  transaction_id TEXT,
  expected_ledger_position INTEGER,
  confirmed_ledger_position INTEGER,
  failure_code TEXT,
  failure_message TEXT,
  prepared_at TEXT NOT NULL,
  submitted_at TEXT,
  confirmed_at TEXT,
  failed_at TEXT,
  UNIQUE (local_action_type, local_action_id)
) STRICT;

CREATE TABLE inbox_events (
  event_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  created_at TEXT NOT NULL,
  read_at TEXT
) STRICT;
CREATE INDEX inbox_events_user_created_idx ON inbox_events(user_id, created_at DESC);

CREATE TABLE audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  actor_user_id TEXT REFERENCES accounts(user_id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
  occurred_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit events are immutable');
END;
