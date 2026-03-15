# Agents

## Project summary

- **Purpose:** On-chain split view protection for
  [forestrie](https://github.com/forestrie/) transparency logs.
  Contracts verify that checkpoints can only be published if
  consistent with previously published checkpoints (see
  [draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html)).
- **Authorization:** Every checkpoint requires (1) a **grant**
  (inclusion proof in the target log's owner) and (2) a
  **consistency receipt** signed by the target log's signer. Caller
  identity is not part of the model. See
  [ARC-0017 auth overview](docs/arc/arc-0017-auth-overview.md).
- **Priorities:** Preserve security properties of checkpoint
  verification; keep crypto code small, well-commented, and
  auditable; favour clarity and testability over micro-optimisation.

## Repository rules (always apply)

- **`.cursorrules`** — Solidity: explicit named imports only; comment
  wrapping (soft 79, hard 100 chars); run `forge fmt` last. Apply in
  `src/**/*.sol`, `script/**/*.sol`, `test/**/*.sol`.

## Source layout

- **Modules** (`src/<name>/`): `lib/` = libraries;
  `interfaces/` = interfaces, events, external types. One library
  per file; type-first library params; shared types in
  `src/<name>/<Type>.sol`; events in `src/<name>/interfaces/`.
- **Deployables:** `src/contracts/` — contracts composing one or
  more modules.
- **Modules:** `checkpoints` (verification, crypto-sensitive),
  `cose` (CBOR/COSE). Keep checkpoint representation minimal;
  isolate crypto in `src/checkpoints/lib/`; keep COSE/CBOR small
  and composable.
- **Tests:** `test/<name>/` per module; `test/shared/` shared infra;
  `test/deploy/` for deployment scripts and integration-style tests.

## Tooling and CI

- **Build:** `forge build` (remappings in `foundry.toml`,
  `@univocity/=src/`).
- **Test:** `forge test`; invariant tests:
  `forge test --match-contract UnivocityInvariantTest`.
- **Format:** `forge fmt` (line length 79 in `foundry.toml`). Run
  after edits; do not re-wrap after fmt.
- **CI** (`.github/workflows/test.yml`): `forge fmt --check`,
  `forge build --sizes`, `forge test -vvv`, then
  `mise run slither-check`. CI uses `FOUNDRY_PROFILE=ci`.

## Documentation

- **`docs/arc/`** — Architecture (e.g. ARC-0017 log hierarchy and
  auth).
- **`docs/adr/`** — Architecture decision records.
- **`docs/plans/`** — Implementation plans; historical in
  `docs/history/plans/`.
- When adding or changing design, create or update arc/adr/plan docs;
  use the next free NNNN for that type.

## Deployment

- Scripts in `script/` (e.g. `script/Deploy.s.sol`,
  `script/DeployProxyUUPSUnivocity.s.sol`). Env:
  `BOOTSTRAP_AUTHORITY`, `AUTHORITY_LOG_ID`, `KS256_SIGNER` or
  `ES256_X`/`ES256_Y`; for CREATE3 UUPS: `UPGRADE_ADMIN`,
  `RPC_URL`, `PRIVATE_KEY`.
- **Secrets:** Deploy tasks use **Doppler** (no `.env`/`.secret.env`);
  Doppler CLI version pinned in `mise.toml`.
- **CREATE3 stable address:** UUPSUnivocity deploys to a
  deterministic address via the shared Arachnid CREATE3 factory.
  Config in `deployment.json`; taskfile `taskfiles/deploy.yml`.
- Reusable deploy scripts live under `script/deploy/` for
  integration tests.

## Deeper context — read on demand

The files below contain detailed conventions and guidance. Read them
when the trigger conditions apply rather than on every task.

| File | Read when |
|------|-----------|
| `WARP.md` | Modifying or adding Solidity source (`src/`, `script/`, `test/`). Contains detailed module/library naming conventions, commit message rules, NatSpec and comment requirements, and module-specific agent guidance for `checkpoints` and `cose`. |
| `docs/arc/arc-0017-auth-overview.md` | Working on authorization, grant verification, or checkpoint signing logic. |
| `docs/arc/arc-0017-log-hierarchy-and-authority.md` | Working on log hierarchy, authority log relationships, or multi-log features. |
| `README.md` | Deployment workflows, contract architecture overview, or security model. |

## Cursor Cloud specific instructions

This is a Foundry-based Solidity smart contract project. There is no
web server or backend service to run — all development tasks are
`forge` commands.

### Key commands

| Task | Command |
|------|---------|
| Build | `forge build` |
| Test | `forge test -vvv` |
| Invariant tests only | `forge test --match-contract UnivocityInvariantTest` |
| Format check | `forge fmt --check` |
| Auto-format | `forge fmt` |
| Build with sizes | `forge build --sizes` |

### Environment notes

- **Foundry v1.5.1** is pinned (must match CI). Install via
  `foundryup --install v1.5.1`. The binaries live in
  `~/.foundry/bin`; ensure this is on `PATH`.
- **Git submodules** supply all Solidity library dependencies
  (`lib/forge-std`, `lib/openzeppelin-contracts`, `lib/solmate`,
  `lib/witnet-solidity-bridge`). Submodules are managed exclusively
  by Foundry — any `forge build` or `forge test` invocation will
  resolve and update them automatically. Do not run
  `git submodule update` manually.
- The build uses `via_ir = true` and optimizer (200 runs), so initial
  compilation takes ~40 s. Incremental builds are fast.
- `forge fmt` is authoritative — never re-wrap output after running
  it.
- No database, Docker, or external service is needed for build/test.
  Deployment-only tooling (Doppler, Anvil, go-task) is optional.
