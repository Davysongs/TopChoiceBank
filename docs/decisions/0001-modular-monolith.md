# ADR 0001: Start as a modular monolith

## Status

Accepted

## Context

TopChoiceBank v2 is being rebuilt from scratch as a production-leaning simulation platform.
Early implementation risk is highest in process orchestration, observability, and deployment consistency.

## Decision

We will begin with a modular monolith, split by runtime responsibility (`api`, `worker`, `scheduler`) and common internal platform packages, and defer microservice extraction until domain complexity and ownership boundaries justify it.

## Consequences

- Faster delivery for foundational infrastructure.
- Lower coupling and simpler local operation in the first stage.
- Clear module boundaries that can be split later into services with minimal rewrite risk.

## Future migration

- If team size grows or non-functional load requires, APIs can be extracted behind stable internal interfaces.

