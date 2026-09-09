TopChoiceBank v2
=================

TopChoiceBank v2 is a Go-based rewrite foundation for a simulated retail banking platform.
It is intentionally limited to infrastructure today: a modular-monolith process baseline with REST/HTTP, lifecycle management, and clean observability entry points.

This codebase is an engineering demonstration and is **not** real banking software.

## Current scope

- API process bootstrap (`cmd/api`)
- Worker process bootstrap (`cmd/worker`)
- Scheduler process bootstrap (`cmd/scheduler`)
- Shared platform foundations in `internal/platform`:
  - `config` for environment-driven settings
  - `logging` structured log abstraction
  - `http` router, middleware, health endpoint, graceful shutdown
  - `database` connection configuration and lifecycle hooks
  - `security` small cryptographic utility primitive
- Repository tooling and operations:
  - `Makefile`
  - `Dockerfile`
  - `compose.yaml`
  - GitHub Actions CI workflow
  - OpenAPI placeholder
  - architecture and ADR documentation

## Local setup

1. Copy environment file: `cp .env.example .env`
2. Build all process binaries: `make build`
3. Run process:
   - API: `make run-api`
   - Worker: `make run-worker`
   - Scheduler: `make run-scheduler`

## Development commands

- `make build`: `go build ./...`
- `make test`: `go test ./...`
- `make vet`: `go vet ./...`
- `make fmt`: `gofmt -w` on all Go files
- `make fmt-check`: CI-friendly formatting check

## Technology direction

- Go application services
- PostgreSQL-oriented data access foundation
- REST/OpenAPI layout
- Modular monolith with separate runtime roles
- Containerized deployment baseline
- Integration and e2e testing structure prepared for future expansion

## Implementation status

- ✅ Foundation scaffold in place
- ✅ CI and local developer tooling in place
- ⏳ No domain modules yet (accounts, ledger, transfers, etc.)
- ⏳ No authentication, jobs, observability stack, or cloud deployment yet

