# Contributing to TopChoiceBank v2

Welcome! This repository is currently in foundation stage.

Please follow these rules for now:

1. Keep changes within the bootstrap scope until explicit domain tasks are assigned.
2. Reuse platform packages under `internal/platform` for cross-process concerns.
3. Keep commits focused and small.
4. Prefer `make test`, `make vet`, and `make fmt-check` before opening a pull request.
5. Do not add domain modules (accounts, ledger, transfers, etc.) in foundation tasks.

## Commit style

Use clear, imperative commit messages, for example:

- `chore: bootstrap api process lifecycle`
- `feat: add environment config loader`

## Reporting issues

Report architectural concerns with one clear summary plus expected behavior.

