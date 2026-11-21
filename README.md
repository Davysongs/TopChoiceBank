# TopChoiceBank v2

TopChoiceBank v2 is a Go-based rewrite and modular-monolith baseline for a simulated retail banking platform. It provides production-grade infrastructure, strict domain validation, multi-factor authentication (MFA), role-based access control (RBAC), customer profile management with optimistic concurrency, and a constrained OAuth 2.0 + S256 PKCE authorization server for third-party partners.

> [!NOTE]
> This codebase is an engineering demonstration and architecture benchmark. It is **not** real banking software.

---

## Architecture & Subsystems

The application follows a modular monolith design with clearly defined domain boundaries and transactional guarantees:

### 1. Platform Foundations (`internal/platform`)
- **`config`**: Strongly-typed environment configuration.
- **`database`**: PostgreSQL connection pooling with health lifecycle hooks and transactional outbox utilities.
- **`http`**: Standard library HTTP router with middleware composition, correlation IDs (`X-Request-ID`), structured request logging, and strict [RFC 9457 Problem Details](https://datatracker.ietf.org/doc/html/rfc9457) error formatting.
- **`logging`**: Structured JSON logging abstraction.
- **`security`**: Cryptographic primitives including Argon2id password hashing, constant-time comparisons, token hashing, and JWT signing/verification.

### 2. Identity & Authentication (`internal/identity`)
- **Registration & Credentials**: Secure registration using Argon2id with terms-of-service versioning.
- **Session Management**: Monotonically rotating refresh-token families with automatic replay detection, family revocation, and device fingerprinting.
- **Audit Logging**: Structured security event recording in `identity.security_events` with port-stripped IP addressing.
- **TOTP MFA**: Vault Transit key port integration (`AESGCMTransitEncryptor`), RFC 6238 time-step validation with drift tolerance, and time-step replay prevention.
- **Single-Use Backup Codes**: Formatted 128-bit entropy recovery codes stored as SHA-256 hashes and consumed atomically.
- **Lockout Protection**: Automatic account lockout across consecutive failed credential or MFA submissions.
- **Password Rotation**: Concurrent password updates guarded by user version checks, session revocation, and recent-MFA or step-up verification.

### 3. Role-Based Access Control (RBAC) & Authorization
- **Four System Roles**: `customer`, `admin`, `risk_analyst`, and `readonly`.
- **Scope Bundles**: Fine-grained endpoint permissions (`profile:read`, `profile:write`, `accounts:read`, `transfers:write`, etc.) mapped to system roles.
- **Route Middleware**:
  - `RequireAuth`: Authenticates Bearer JWTs and partner OAuth access tokens.
  - `RequireRoles`: Deny-by-default role authorization.
  - `RequireScopes`: Mandatory scope validation.
  - `RequireRecentMFA`: Elevated action gating behind recent MFA verification claims (`amr`, `auth_time`).
- **Resource Ownership**: Application-layer subject ownership verification (`CheckResourceOwnership`).
- **Offline Role Seeding CLI**: Administrative command in `cmd/seed-roles` supporting role grants and automated customer default role backfill.

### 4. Users & Customer Profiles (`internal/users`)
- **Decoupled Data Model**: Customer profile data (`users.user_profiles`) linked via foreign key to `identity.users`.
- **Value Objects**:
  - `LegalName`: Unicode-aware given and family names.
  - `DateOfBirth`: Calendar date strictly validated in the past.
  - `Phone`: Strict E.164 international phone formatting.
  - `Address`: ISO 3166-1 alpha-2 country codes and address length bounds.
- **Data Protection**: PII masking in API responses (`phone_masked`, `email_masked`).
- **Optimistic Concurrency Control (OCC)**: Version tracking via `ETag` and required `If-Match: "<version>"` headers on updates.
- **Immutable Legal Fields**: Protection against legal identity tampering outside formal KYC workflows.
- **Onboarding State Machine**: Lifecycle state tracking (`PENDING` $\rightarrow$ `UNDER_REVIEW` $\rightarrow$ `APPROVED` | `REJECTED`).
- **Transactional Outbox Events**: Atomic event emission (`users.profile_created.v1`, `users.profile_updated.v1`).

### 5. Partner OAuth 2.0 with S256 PKCE (`internal/identity/adapters/oauth`)
- **Authorization Code Flow**: Powered by [Ory Fosite](https://github.com/ory/fosite).
- **Mandatory S256 PKCE**: Required code challenge verification on all partner token exchanges.
- **Loopback Support**: Exact redirect matching supporting dynamic ports for native loopback clients (`http://127.0.0.1` and `http://[::1]`).
- **Single-Use Consent Tokens**: Ephemeral consent tokens recorded in `identity.oauth_consumed_consents` to prevent replay attacks.
- **Distributed Token Persistence**: Multi-instance access token storage in `identity.oauth_access_tokens` ensuring tokens survive process restarts and instance failover.

---

## Process Entry Points

| Command | Path | Description |
|---|---|---|
| **API** | `cmd/api` | Primary HTTP/REST server exposing auth, profile, and OAuth routes. |
| **Worker** | `cmd/worker` | Transactional outbox event processor and background task dispatcher. |
| **Scheduler** | `cmd/scheduler` | Periodic maintenance and cron tasks runner. |
| **Seed Roles** | `cmd/seed-roles` | Offline CLI for role assignments and default customer role backfills. |

---

## API Endpoints

### System & Health
- `GET /health` — Service readiness check
- `GET /healthz` — Kubernetes liveness probe

### Authentication & Multi-Factor Auth
- `POST /v1/auth/register` — Register a customer account
- `POST /v1/auth/login` — Credential-based login (returns tokens or MFA challenge)
- `POST /v1/auth/refresh` — Rotate refresh-token and issue fresh session
- `POST /v1/auth/mfa/enrol` — Initiate TOTP factor enrollment
- `POST /v1/auth/mfa/verify` — Verify and activate TOTP factor
- `POST /v1/auth/password/change` — Rotate password with step-up MFA verification

### Users & Profiles
- `GET /v1/users/me` — Retrieve authenticated user profile (requires `profile:read`)
- `PATCH /v1/users/me` — Update profile contact/address fields with `If-Match` (requires `profile:write`)

### Partner OAuth 2.0 PKCE
- `GET /v1/oauth/authorize` — Validate partner authorization parameters and return consent prompt
- `POST /v1/oauth/authorize` — Submit user consent and issue authorization code
- `POST /v1/oauth/token` — Exchange authorization code + S256 PKCE verifier for access token

---

## Local Setup

### 1. Requirements
- Go 1.22+
- PostgreSQL 15+
- Node.js & npm (for OpenAPI tooling)

### 2. Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```

### 3. Database Migrations
Migrations are located in `internal/platform/database/migrations/`:
- `0001_initial_schema.sql` — Outbox & event registry
- `0002_identity_auth.sql` — Users, sessions, refresh families, devices, and security events
- `0003_user_profiles.sql` — Customer profiles and onboarding queue
- `0004_mfa_rbac_oauth.sql` — MFA factors, backup codes, OAuth clients, codes, and access tokens

---

## Development & Makefile Commands

```bash
# Compile all binaries
make build

# Run complete test suite
make test

# Run static analysis
make vet

# Format code
make fmt

# CI formatting check
make fmt-check

# Generate bundled OpenAPI spec and Postman collection
make postman-collection

# Run application processes
make run-api
make run-worker
make run-scheduler
```

### Seeding Roles CLI
```bash
# Assign a role to a specific user
go run ./cmd/seed-roles -email customer@example.com -role admin

# Ensure all users without active roles receive the default customer role
go run ./cmd/seed-roles -ensure-customer-defaults
```

---

## API Specification & Postman Collection

- **OpenAPI 3.0 Specification**: [`api/openapi/openapi.yaml`](file:///Users/hp/TopChoiceBank/api/openapi/openapi.yaml)
- **Bundled Schema**: [`api/openapi/generated/openapi.bundle.yaml`](file:///Users/hp/TopChoiceBank/api/openapi/generated/openapi.bundle.yaml)
- **Postman Collection**: [`test/postman/topchoicebank.postman_collection.json`](file:///Users/hp/TopChoiceBank/test/postman/topchoicebank.postman_collection.json)
