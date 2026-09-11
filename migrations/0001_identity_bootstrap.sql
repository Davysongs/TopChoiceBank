-- TopChoiceBank v2 identity foundation bootstrap.
-- Includes shared extensions, schema setup, authn/authz core tables, and
-- rotating refresh-token family tracking.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS platform;
CREATE SCHEMA IF NOT EXISTS identity;

CREATE OR REPLACE FUNCTION platform.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS identity.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL,
  password_hash text NOT NULL,
  password_hash_algorithm text NOT NULL DEFAULT 'argon2id',
  status text NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'ACTIVE', 'LOCKED', 'DISABLED')),
  email_verified_at timestamptz,
  failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
  failed_login_window_started_at timestamptz,
  locked_until timestamptz,
  password_changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT users_email_unique UNIQUE (email),
  CONSTRAINT users_lock_consistent CHECK (
    (status = 'LOCKED' AND locked_until IS NOT NULL) OR
    (status <> 'LOCKED' AND locked_until IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS identity.roles (
  id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL UNIQUE
    CHECK (name IN ('customer', 'admin', 'risk_analyst', 'readonly')),
  description text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS identity.user_roles (
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  role_id smallint NOT NULL REFERENCES identity.roles(id) ON DELETE RESTRICT,
  granted_by uuid REFERENCES identity.users(id) ON DELETE SET NULL,
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  PRIMARY KEY (user_id, role_id),
  CONSTRAINT user_roles_time_order CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

CREATE TABLE IF NOT EXISTS identity.devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  fingerprint_hash bytea NOT NULL,
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  trust_state text NOT NULL DEFAULT 'UNTRUSTED'
    CHECK (trust_state IN ('UNTRUSTED', 'TRUSTED', 'BLOCKED')),
  trusted_until timestamptz,
  first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_ip inet,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  UNIQUE (user_id, fingerprint_hash),
  CONSTRAINT devices_user_composite_pk UNIQUE (user_id, id),
  CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE IF NOT EXISTS identity.refresh_families (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  reason text NOT NULL DEFAULT 'created',
  revoked_at timestamptz,
  revoked_reason text,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((revoked_at IS NULL AND revoked_reason IS NULL) OR
         (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)),
  CONSTRAINT refresh_families_user_composite_pk UNIQUE (user_id, id)
);

CREATE TABLE IF NOT EXISTS identity.sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  device_id uuid REFERENCES identity.devices(id) ON DELETE SET NULL,
  refresh_family_id uuid NOT NULL REFERENCES identity.refresh_families(id) ON DELETE CASCADE,
  access_token_jti text NOT NULL,
  refresh_token_hash bytea NOT NULL UNIQUE,
  rotated_from_session_id uuid REFERENCES identity.sessions(id) ON DELETE SET NULL,
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text,
  created_ip inet NOT NULL,
  user_agent text NOT NULL CHECK (length(user_agent) <= 512),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT sessions_user_device_fk
  FOREIGN KEY (user_id, device_id) REFERENCES identity.devices (user_id, id),
  CONSTRAINT sessions_user_refresh_family_fk
  FOREIGN KEY (user_id, refresh_family_id) REFERENCES identity.refresh_families (user_id, id),
  CONSTRAINT sessions_user_rotated_from_session_fk
  FOREIGN KEY (user_id, rotated_from_session_id) REFERENCES identity.sessions (user_id, id),
  CONSTRAINT sessions_user_composite_pk UNIQUE (user_id, id),
  CHECK (expires_at > issued_at),
  CHECK (
    (revoked_at IS NULL AND revoke_reason IS NULL) OR
    (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS identity.security_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  user_id uuid REFERENCES identity.users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
  request_id text,
  source_ip inet,
  device_id uuid REFERENCES identity.devices(id) ON DELETE SET NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(metadata) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS users_status_created_idx ON identity.users (status, created_at);
CREATE INDEX IF NOT EXISTS user_roles_active_role_idx ON identity.user_roles (role_id, user_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS devices_user_last_seen_idx ON identity.devices (user_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS refresh_families_user_last_used_idx ON identity.refresh_families (user_id, last_used_at DESC);
CREATE INDEX IF NOT EXISTS refresh_families_active_idx ON identity.refresh_families (user_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS sessions_user_active_idx ON identity.sessions (user_id, expires_at DESC)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS sessions_family_active_idx ON identity.sessions (refresh_family_id)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS security_events_user_time_idx
  ON identity.security_events (user_id, occurred_at DESC);

DROP TRIGGER IF EXISTS users_updated_at ON identity.users;

CREATE TRIGGER users_updated_at
BEFORE UPDATE ON identity.users
FOR EACH ROW EXECUTE FUNCTION platform.touch_updated_at();

DROP TRIGGER IF EXISTS devices_updated_at ON identity.devices;

CREATE TRIGGER devices_updated_at
BEFORE UPDATE ON identity.devices
FOR EACH ROW EXECUTE FUNCTION platform.touch_updated_at();

INSERT INTO identity.roles (name, description)
VALUES
  ('customer', 'standard identity role'),
  ('admin', 'administrative identity role'),
  ('risk_analyst', 'risk review identity role'),
  ('readonly', 'read-only identity role')
ON CONFLICT (name) DO NOTHING;
