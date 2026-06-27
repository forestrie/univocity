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

- **`.cursorrules`** — Solidity imports and comment wrapping; see
  [docs/agents/solidity.md](docs/agents/solidity.md) for layout.
- **`.cursor/rules/`** — [branch-naming](.cursor/rules/branch-naming.mdc),
  [solidity-comments](.cursor/rules/solidity-comments.mdc) (cross-repo NatSpec;
  wrapping stays in `.cursorrules`), [types-single-responsibility](.cursor/rules/types-single-responsibility.mdc).

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
- **CI** (`.github/workflows/ci.yml`, invoked by `test.yml`): `forge fmt
  --check`, CREATE3 factory build, protocol `forge build --sizes`,
  `forge test -vvv`, `mise run slither-check`. Uses `FOUNDRY_PROFILE=ci`.
- **Contracts release** (`release.yml` on `v*` tags): gated on the same CI
  job, then `task contract-artefacts-release:release` publishes
  `univocity-<release-id>.tar.gz` and `create3-factory-<release-id>.tar.gz`.
  See [ADR-0007](docs/adr/adr-0007-contract-release-build-archives.md) and
  [CONTEXT.md](CONTEXT.md).

## Documentation

- **`docs/arc/`** — Contract architecture (ARC-0016, ARC-0017, etc.).
- **`docs/adr/`** — Contract decision records.
- **`docs/plans/`** — Implementation plans; historical in `docs/history/plans/`.
- **Platform** ADRs/ARCs/glossary: [devdocs](../../devdocs/), [glossary.md](../../devdocs/glossary.md).
- **Agent index**: [docs/agents/README.md](docs/agents/README.md).
- When adding design docs, use next free NNNN; see `.cursor/rules/docs-workflow.mdc`.

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
| `docs/agents/solidity.md` | Modifying Solidity (`src/`, `script/`, `test/`). |
| `docs/arc/arc-0017-auth-overview.md` | Authorization, grant verification, checkpoint signing. |
| `docs/arc/arc-0017-log-hierarchy-and-authority.md` | Log hierarchy and multi-log features. |
| `README.md` | Deployment, contract architecture, security model. |

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
| ES256 Imutable deploy + bootstrap | `doppler run --project univocity --config dev -- task deploy:imutable:es256` |
| Contracts release dry-run | `UNIVOCITY_TOOLS_VERSION=v0.4.0 task contract-artefacts-release:release` |

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
