# Agent context for univocity

This document gives AI agents the context needed to work effectively in this
repository. **Read it first** before making code or doc changes.

## Project summary

- **Purpose:** On-chain split view protection for
  [forestrie](https://github.com/forestrie/) transparency logs. Contracts
  verify that checkpoints can only be published if consistent with previously
  published checkpoints (see
  [draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html)).
- **Authorization:** Every checkpoint requires (1) a **grant** (inclusion
  proof in the target log’s owner) and (2) a **consistency receipt** signed
  by the target log’s signer. Caller identity is not part of the model. See
  [ARC-0017 auth overview](docs/arc/arc-0017-auth-overview.md).
- **Priorities:** Preserve security properties of checkpoint verification;
  keep crypto code small, well-commented, and auditable; favour clarity and
  testability over micro-optimisation.

## Repository rules (always apply)

- **`.cursorrules`** — Solidity: explicit named imports only; comment
  wrapping (soft 79, hard 100 chars); run `forge fmt` last. Apply in
  `src/**/*.sol`, `script/**/*.sol`, `test/**/*.sol`.
- **`.cursor/rules/commit-conventions.mdc`** — Commit titles ≤ 79 chars;
  body lines ≤ 72 chars; no Co-Authored-By; use repo git user only.
- **`.cursor/rules/docs-workflow.mdc`** — Numbered docs in `docs/`: arc-NNNN,
  adr-NNNN, plan-NNNN; YAML header (Status, Date, Related); cross-reference
  with markdown links.

## Source layout

- **Modules** (`src/<name>/`): `lib/` = libraries; `interfaces/` = interfaces,
  events, external types. One library per file; type-first library params;
  shared types in `src/<name>/<Type>.sol`; events in `src/<name>/interfaces/`.
- **Deployables:** `src/contracts/` — contracts composing one or more modules.
- **Modules:** `checkpoints` (verification, crypto-sensitive),
  `cose` (CBOR/COSE). Keep checkpoint representation minimal; isolate
  crypto in `src/checkpoints/lib/`; keep COSE/CBOR small and composable.
- **Tests:** `test/<name>/` per module; `test/shared/` shared infra;
  `test/deploy/` for deployment scripts and integration-style tests.

## Tooling and CI

- **Build:** `forge build` (remappings in `foundry.toml`, `@univocity/=src/`).
- **Test:** `forge test`; invariant tests: `forge test --match-contract
  UnivocityInvariantTest`.
- **Format:** `forge fmt` (line length 79 in `foundry.toml`). Run after edits;
  do not re-wrap after fmt.
- **CI** (`.github/workflows/test.yml`): `forge fmt --check`, `forge build
  --sizes`, `forge test -vvv`, then `mise run slither-check`. Use
  `FOUNDRY_PROFILE=ci` in CI.

## Documentation

- **`docs/arc/`** — Architecture (e.g. ARC-0017 log hierarchy and auth).
- **`docs/adr/`** — Architecture decision records.
- **`docs/plans/`** — Implementation plans; historical in `docs/history/plans/`.
- When adding or changing design, create or update arc/adr/plan docs per
  docs-workflow; use the next free NNNN for that type.

## Deployment

- Scripts in `script/` (e.g. `script/Deploy.s.sol`). Env: `BOOTSTRAP_AUTHORITY`,
  `AUTHORITY_LOG_ID`, `KS256_SIGNER` or `ES256_X`/`ES256_Y`.
- Reusable deploy scripts live under `script/deploy/` for integration tests.

## More detail

- **README.md** — Overview, auth model, contract architecture, deployment, usage.
- **WARP.md** — Extended conventions and agent guidance (defers to this file
  as the primary agent context).
