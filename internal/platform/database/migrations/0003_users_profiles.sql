-- TopChoiceBank v2 users schema and profile tables

CREATE SCHEMA IF NOT EXISTS users;

CREATE TABLE IF NOT EXISTS users.user_profiles (
  user_id uuid PRIMARY KEY REFERENCES identity.users(id) ON DELETE CASCADE,
  legal_given_name text NOT NULL CHECK (length(legal_given_name) BETWEEN 1 AND 100),
  legal_family_name text NOT NULL CHECK (length(legal_family_name) BETWEEN 1 AND 100),
  date_of_birth date NOT NULL CHECK (date_of_birth >= DATE '1900-01-01'),
  phone_e164 text NOT NULL UNIQUE CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  address_line1 text NOT NULL,
  address_line2 text,
  city text NOT NULL,
  region text,
  postal_code text,
  country_code char(2) NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
  onboarding_state text NOT NULL DEFAULT 'PENDING'
    CHECK (onboarding_state IN ('PENDING','UNDER_REVIEW','APPROVED','REJECTED')),
  onboarding_submitted_at timestamptz,
  onboarding_decided_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (date_of_birth <= CURRENT_DATE),
  CHECK (onboarding_decided_at IS NULL OR onboarding_submitted_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS profiles_onboarding_queue_idx
  ON users.user_profiles (onboarding_state, onboarding_submitted_at)
  WHERE onboarding_state IN ('PENDING','UNDER_REVIEW');

DROP TRIGGER IF EXISTS user_profiles_updated_at ON users.user_profiles;
CREATE TRIGGER user_profiles_updated_at
BEFORE UPDATE ON users.user_profiles
FOR EACH ROW EXECUTE FUNCTION platform.touch_updated_at();

-- Seed event schema registry for users profile events
INSERT INTO events.event_schema_registry (event_type, schema_version, json_schema, schema_sha256)
VALUES (
  'users.profile_created.v1',
  1,
  '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"legal_given_name":{"type":"string"},"legal_family_name":{"type":"string"},"date_of_birth":{"type":"string"},"phone_e164":{"type":"string"},"onboarding_state":{"type":"string"},"version":{"type":"integer"}},"required":["user_id","legal_given_name","legal_family_name","date_of_birth","phone_e164","onboarding_state","version"]}'::jsonb,
  sha256('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"legal_given_name":{"type":"string"},"legal_family_name":{"type":"string"},"date_of_birth":{"type":"string"},"phone_e164":{"type":"string"},"onboarding_state":{"type":"string"},"version":{"type":"integer"}},"required":["user_id","legal_given_name","legal_family_name","date_of_birth","phone_e164","onboarding_state","version"]}'::bytea)
),
(
  'users.profile_updated.v1',
  1,
  '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"version":{"type":"integer"}},"required":["user_id","version"]}'::jsonb,
  sha256('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"version":{"type":"integer"}},"required":["user_id","version"]}'::bytea)
) ON CONFLICT (event_type, schema_version) DO NOTHING;

