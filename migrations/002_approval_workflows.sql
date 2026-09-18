CREATE TABLE system_administrators (
  user_id TEXT PRIMARY KEY REFERENCES accounts(user_id) ON DELETE RESTRICT,
  appointed_at TEXT NOT NULL
) STRICT;

CREATE TABLE organization_creation_requests (
  request_id TEXT PRIMARY KEY,
  requester_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  proposed_organization_id TEXT NOT NULL,
  proposed_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  submitted_at TEXT NOT NULL,
  reviewed_by_user_id TEXT REFERENCES accounts(user_id) ON DELETE RESTRICT,
  reviewed_at TEXT,
  decision_note TEXT,
  created_organization_id TEXT REFERENCES organizations(organization_id) ON DELETE RESTRICT,
  CHECK (
    (status = 'pending' AND reviewed_by_user_id IS NULL AND reviewed_at IS NULL AND
      decision_note IS NULL AND created_organization_id IS NULL) OR
    (status = 'approved' AND reviewed_by_user_id IS NOT NULL AND reviewed_at IS NOT NULL AND
      created_organization_id IS NOT NULL) OR
    (status = 'rejected' AND reviewed_by_user_id IS NOT NULL AND reviewed_at IS NOT NULL AND
      created_organization_id IS NULL)
  )
) STRICT;
CREATE UNIQUE INDEX organization_creation_requests_pending_id_idx
  ON organization_creation_requests(proposed_organization_id)
  WHERE status = 'pending';
CREATE INDEX organization_creation_requests_requester_idx
  ON organization_creation_requests(requester_user_id, submitted_at);
CREATE INDEX organization_creation_requests_status_idx
  ON organization_creation_requests(status, submitted_at);

CREATE TABLE organization_memberships (
  organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  approved_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  joined_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (organization_id, user_id)
) STRICT;
CREATE INDEX organization_memberships_user_idx
  ON organization_memberships(user_id, revoked_at);

INSERT INTO organization_memberships (
  organization_id, user_id, approved_by_user_id, joined_at, revoked_at
)
SELECT organization_id, created_by_user_id, created_by_user_id, created_at, NULL
  FROM organizations;

CREATE TABLE organization_membership_requests (
  request_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
  requester_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  submitted_at TEXT NOT NULL,
  reviewed_by_user_id TEXT REFERENCES accounts(user_id) ON DELETE RESTRICT,
  reviewed_at TEXT,
  decision_note TEXT,
  CHECK (
    (status = 'pending' AND reviewed_by_user_id IS NULL AND reviewed_at IS NULL AND
      decision_note IS NULL) OR
    (status IN ('approved', 'rejected') AND reviewed_by_user_id IS NOT NULL AND
      reviewed_at IS NOT NULL)
  )
) STRICT;
CREATE UNIQUE INDEX organization_membership_requests_pending_idx
  ON organization_membership_requests(organization_id, requester_user_id)
  WHERE status = 'pending';
CREATE INDEX organization_membership_requests_requester_idx
  ON organization_membership_requests(requester_user_id, submitted_at);
CREATE INDEX organization_membership_requests_status_idx
  ON organization_membership_requests(status, submitted_at);

CREATE TABLE special_role_requests (
  request_id TEXT PRIMARY KEY,
  requester_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  role TEXT NOT NULL CHECK (role IN ('regulator')),
  justification TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  submitted_at TEXT NOT NULL,
  reviewed_by_user_id TEXT REFERENCES accounts(user_id) ON DELETE RESTRICT,
  reviewed_at TEXT,
  decision_note TEXT,
  CHECK (
    (status = 'pending' AND reviewed_by_user_id IS NULL AND reviewed_at IS NULL AND
      decision_note IS NULL) OR
    (status IN ('approved', 'rejected') AND reviewed_by_user_id IS NOT NULL AND
      reviewed_at IS NOT NULL)
  )
) STRICT;
CREATE UNIQUE INDEX special_role_requests_pending_idx
  ON special_role_requests(requester_user_id, role)
  WHERE status = 'pending';
CREATE INDEX special_role_requests_status_idx
  ON special_role_requests(status, submitted_at);

CREATE TABLE account_special_roles (
  user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  role TEXT NOT NULL CHECK (role IN ('regulator')),
  granted_by_user_id TEXT NOT NULL REFERENCES accounts(user_id) ON DELETE RESTRICT,
  granted_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (user_id, role)
) STRICT;
CREATE INDEX account_special_roles_active_idx
  ON account_special_roles(role, revoked_at);
