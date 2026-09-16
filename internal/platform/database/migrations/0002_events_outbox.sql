-- TopChoiceBank v2 events schema and outbox tables

CREATE SCHEMA IF NOT EXISTS events;

CREATE TABLE IF NOT EXISTS events.event_schema_registry (
  event_type text NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version > 0),
  json_schema jsonb NOT NULL CHECK (jsonb_typeof(json_schema) = 'object'),
  schema_sha256 bytea NOT NULL CHECK (octet_length(schema_sha256) = 32),
  compatibility text NOT NULL DEFAULT 'BACKWARD' CHECK (compatibility IN ('BACKWARD','FULL')),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DEPRECATED')),
  registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (event_type, schema_version),
  CONSTRAINT event_schema_registry_sha256_unique UNIQUE (schema_sha256)
);

CREATE TABLE IF NOT EXISTS events.outbox_events (
  sequence_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  aggregate_type text NOT NULL,
  aggregate_id uuid NOT NULL,
  aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
  event_type text NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version > 0),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  headers jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(headers) = 'object'),
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  claimed_by text,
  claimed_until timestamptz,
  publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
  published_at timestamptz,
  broker_message_id text,
  last_error_code text,
  CONSTRAINT outbox_aggregate_version_unique UNIQUE (aggregate_type, aggregate_id, aggregate_version, event_type),
  FOREIGN KEY (event_type, schema_version)
    REFERENCES events.event_schema_registry(event_type, schema_version) ON DELETE RESTRICT,
  CHECK ((published_at IS NULL AND broker_message_id IS NULL) OR
         (published_at IS NOT NULL AND broker_message_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS outbox_claim_idx ON events.outbox_events (available_at, sequence_id)
  WHERE published_at IS NULL;
CREATE INDEX IF NOT EXISTS outbox_stale_claim_idx ON events.outbox_events (claimed_until)
  WHERE published_at IS NULL AND claimed_until IS NOT NULL;

-- Seed event schema registry for identity.user_registered.v1
INSERT INTO events.event_schema_registry (event_type, schema_version, json_schema, schema_sha256)
VALUES (
  'identity.user_registered.v1',
  1,
  '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"email":{"type":"string"},"status":{"type":"string"}},"required":["user_id","email","status"]}'::jsonb,
  sha256('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"email":{"type":"string"},"status":{"type":"string"}},"required":["user_id","email","status"]}'::bytea)
  digest('{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"user_id":{"type":"string"},"email":{"type":"string"},"status":{"type":"string"}},"required":["user_id","email","status"]}'::bytea, 'sha256')
) ON CONFLICT (event_type, schema_version) DO NOTHING;

