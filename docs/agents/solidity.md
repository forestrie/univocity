# Solidity conventions (Univocity)

Canonical import/comment rules: **`.cursorrules`**. Run `forge fmt` last.

## Source layout

- `src/<name>/lib/` — libraries; `src/<name>/interfaces/` — interfaces/events
- `src/contracts/` — deployable compositions
- One library per file; type-first library params
- Tests: `test/<name>/`, `test/shared/`, `test/deploy/`

## Modules

- **checkpoints** — crypto-sensitive verification; libs under `src/checkpoints/lib/`
- **cose** — CBOR/COSE; keep parsing small and composable

## Comments

- NatSpec on all public functions and events
- Explain non-obvious invariants; avoid repeating mechanical descriptions

## Commits

See `.cursor/rules/commit-conventions.mdc`.
