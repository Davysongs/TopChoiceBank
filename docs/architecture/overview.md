# TopChoiceBank v2 Architecture Overview

## Intent

TopChoiceBank v2 starts as a modular monolith to keep the first iteration pragmatic while preserving a
clear path to future decomposition.

## Runtime model

- `cmd/api`: handles synchronous HTTP request/response traffic and external integration surfaces.
- `cmd/worker`: owns long-lived background execution for asynchronous jobs.
- `cmd/scheduler`: owns scheduling orchestration and maintenance tasks.

## Platform layers

- `internal/platform/config`: validates and exposes environment-driven configuration.
- `internal/platform/logging`: shared structured logging contract.
- `internal/platform/http`: router, middleware, health checks, and lifecycle.
- `internal/platform/database`: database configuration and pool lifecycle hooks.
- `internal/platform/security`: shared security primitives used across process boundaries.

## Data and external systems

The initial release keeps persistence intent as PostgreSQL-oriented but does not yet define a banking schema.
Future stages will add repository packages and domain services in the same module before extracting boundaries.

