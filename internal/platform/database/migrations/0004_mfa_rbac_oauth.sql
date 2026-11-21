-- TopChoiceBank v2 MFA, RBAC index, and OAuth PKCE schema

-- identity.mfa_factors
CREATE TABLE IF NOT EXISTS identity.mfa_factors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  factor_type text NOT NULL CHECK (factor_type IN ('TOTP')),
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
  encrypted_secret bytea NOT NULL,
  key_version integer NOT NULL CHECK (key_version > 0),
  status text NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING','ACTIVE','REVOKED')),
  verified_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (user_id, label),
  CHECK ((status = 'ACTIVE' AND verified_at IS NOT NULL) OR status <> 'ACTIVE'),
  CHECK ((status = 'REVOKED' AND revoked_at IS NOT NULL) OR status <> 'REVOKED')
);

CREATE UNIQUE INDEX IF NOT EXISTS mfa_one_active_totp_idx
  ON identity.mfa_factors (user_id, factor_type) WHERE status = 'ACTIVE';

-- identity.mfa_backup_codes
CREATE TABLE IF NOT EXISTS identity.mfa_backup_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  factor_id uuid NOT NULL REFERENCES identity.mfa_factors(id) ON DELETE CASCADE,
  code_hash bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  consumed_at timestamptz,
  UNIQUE (factor_id, code_hash)
);

CREATE INDEX IF NOT EXISTS mfa_backup_unused_idx ON identity.mfa_backup_codes (factor_id)
  WHERE consumed_at IS NULL;

-- identity.oauth_clients
CREATE TABLE IF NOT EXISTS identity.oauth_clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE,
  client_name text NOT NULL,
  client_type text NOT NULL CHECK (client_type IN ('PUBLIC','CONFIDENTIAL')),
  secret_hash bytea,
  redirect_uris text[] NOT NULL CHECK (cardinality(redirect_uris) > 0),
  allowed_scopes text[] NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((client_type = 'PUBLIC' AND secret_hash IS NULL) OR
         (client_type = 'CONFIDENTIAL' AND secret_hash IS NOT NULL))
);

-- identity.oauth_authorization_codes
CREATE TABLE IF NOT EXISTS identity.oauth_authorization_codes (
  code_hash bytea PRIMARY KEY,
  client_id uuid NOT NULL REFERENCES identity.oauth_clients(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  pkce_challenge text NOT NULL,
  pkce_method text NOT NULL CHECK (pkce_method = 'S256'),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS oauth_codes_expiry_idx ON identity.oauth_authorization_codes (expires_at)
  WHERE used_at IS NULL;

-- Covering index on active user roles
CREATE INDEX IF NOT EXISTS user_roles_active_role_idx ON identity.user_roles (role_id, user_id)
  WHERE revoked_at IS NULL;

-- Seed event schema registry for identity MFA and password events
INSERT INTO events.event_schema_registry (event_type, schema_version, json_schema, schema_sha256)
VALUES (
  'identity.mfa_enrolled.v1',
  1,
  '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"factor_id":{"type":"string"},"factor_type":{"type":"string"}},"required":["user_id","factor_id","factor_type"]}'::jsonb,
  sha256('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"factor_id":{"type":"string"},"factor_type":{"type":"string"}},"required":["user_id","factor_id","factor_type"]}'::bytea)
),
(
  'identity.password_changed.v1',
  1,
  '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"}},"required":["user_id"]}'::jsonb,
  sha256('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"}},"required":["user_id"]}'::bytea)
) ON CONFLICT (event_type, schema_version) DO NOTHING;
