# univocity

On-chain split view protection for [forestrie](https://github.com/forestrie/)
transparency logs.

## Overview

univocity provides Solidity contracts that verify transparency log checkpoints
can only be published on-chain if they are consistent with previously
published checkpoints. This prevents log operators from presenting different
views of the log to different parties.

The verification logic implements the consistency proof format described in
[draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html).

## Authorization model

Every checkpoint is authorized by two checks; caller identity is not part of
the model. See [ARC-0017 auth overview](docs/arc/arc-0017-auth-overview.md) for
the full description and diagrams.

1. **Grant (inclusion proof)**  
   The publish supplies a **grant**: an inclusion proof in the target log’s
   **owner** (the log against which the grant is verified). For the root’s
   first checkpoint there is no prior owner, so the grant is self-inclusion
   (index 0). For any other log, the owner is that log’s `authLogId` (root →
   self; child authority → parent; data log → owning authority). The grant
   leaf encodes bounds (minGrowth, maxHeight) and flags (e.g. GF_CREATE,
   GF_EXTEND). First checkpoint to a new log requires `ownerLogId` in the
   grant and inclusion verified against that owner.

2. **Consistency receipt (signed)**  
   The consistency receipt is signed by the target log’s **signer**. For the
   root’s first checkpoint the signer must be the **bootstrap key** (set at
   deployment). For any other first checkpoint the signer is supplied in
   **grantData** and stored as that log’s root key. For later checkpoints the
   receipt must verify against the log’s stored root key (or a valid
   delegation). The contract does not recover keys on-chain (verify-only).

**Permissionless submission.** Any address may call `publishCheckpoint` with a
valid grant and validly signed consistency receipt. The contract never checks
`msg.sender` for authorization. The submitter is recorded in
`CheckpointPublished` for attribution only.

**No on-chain ownership.** The checkpoint signing key is the effective owner
of the log; there is no separate ownership state or bootstrap
re-initialization.

## Contract architecture

- **Univocity.sol** — Main contract: multi-log checkpoint state, bootstrap
  access control, grant verification (inclusion in owner + bounds), and
  consistency receipt verification (signature and proof chain).
- **consistencyReceipt** — Verifies the MMR consistency receipt chain (decode
  CBOR proofs, run `consistentRoots` / `consistentRootsMemory`, build
  detached payload commitment). Used by Univocity; no storage references.
- **cosecbor** — COSE_Sign1 Sig_structure and verify (ES256, KS256); CBOR
  extractAlgorithm from protected header (constants and free functions).

## Deployment

### Consumer deploy (no Foundry required)

Independent operators can deploy **ImutableUnivocity** from a published release
using the prebuilt [univocity-tools deployer](https://github.com/forestrie/univocity-tools/releases)
binary — no `forge`, `cast`, or clone of this repo.

1. Download `deployer-linux-x64` or `deployer-darwin-arm64` (+ `.sha256`) from
   an [univocity-tools release](https://github.com/forestrie/univocity-tools/releases).
2. One-shot EOA deploy (uses `deploy-manifest-<tag>.json` when present):

```shell
./deployer-darwin-arm64 deploy imutable \
  --from-release v0.4.0 \
  --bootstrap-alg ks256 \
  --bootstrap-ks256-signer 0xYourSigner \
  --deploy-key "$DEPLOY_KEY" \
  --rpc-url "$RPC_URL"
```

Multi-step flows (`deploy propose imutable --from-manifest`, `--release-root`,
`deploy execute`) are documented in
[univocity-tools CLI docs](https://github.com/forestrie/univocity-tools/blob/main/docs/agents/cli.md).

Foundry remains required for **contract development** and for producing release
archives in CI.

### Developer deploy (from source)

**ImutableUnivocity (non-upgradeable):** Set `KS256_SIGNER` or `ES256_X`/`ES256_Y`,
then `forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast`.

**UUPSUnivocity (CREATE3 stable address):** Deploys the UUPS proxy to a
deterministic address using the shared Arachnid CREATE3 factory. Config in
`deployment.json`. Secrets via **Doppler** (or `.env`): `RPC_URL`, `PRIVATE_KEY`,
`UPGRADE_ADMIN`, `BOOTSTRAP_ALG`, `BOOTSTRAP_PUB`. Steps are idempotent (no-op
when factory or proxy already deployed).

```shell
task deploy                 # one-shot: factory (if missing), prepare, execute
task deploy:uups            # same as deploy (ensure factory, prepare, execute)
task deploy:uups:prepare    # dry-run only
task deploy:uups:execute    # broadcast (no-op if proxy already deployed)
task deploy:uups:predict    # print predicted proxy address
task deploy:verify          # verify implementation on explorer (ETHERSCAN_API_KEY)
```

Verification: set `ETHERSCAN_API_KEY` (or `EXPLORER_API_KEY`); for Basescan/Blockscout
set `VERIFIER_URL` if needed. No-op if proxy is not deployed.

Doppler CLI is pinned in `mise.toml`; run `mise install` to get it. **Getting
doppler on your PATH:** mise only adds tools to PATH when it is activated. (1)
In this repo, `.envrc` runs `use mise` — run `direnv allow` and `cd` into the
repo so `doppler` and other tools are on PATH. (2) Or add
`eval "$(mise activate bash)"` (or `zsh`) to your shell profile so mise tools
are available in any directory. (3) Or run via mise:
`mise exec -- doppler run -- task deploy:uups:prepare`.

## Contracts release

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml).
Release is gated on the shared CI check (same steps as PR CI via
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)): fmt, both forge
builds, tests, and slither.

Published **build archives** (see [ADR-0007](docs/adr/adr-0007-contract-release-build-archives.md)).
`<release-id>` is `vX.Y.Z+YYMMDD-shortCommit` (e.g.
`v0.1.3+260613-04279cb`):

| Asset | Forge project |
|-------|---------------|
| `univocity-<release-id>.tar.gz` | Protocol build (repo root) |
| `create3-factory-<release-id>.tar.gz` | CREATE3 factory build (`script/create3-factory/`) |

Each archive is round-trip validated with `contract-artefacts archive-extract`
and `archive-validate` before publish. Requires
[univocity-tools](https://github.com/forestrie/univocity-tools) `v0.4.0+`
(`contract-artefacts` binary).

Local dry-run (downloads Linux `contract-artefacts` on CI; on macOS use a local
Cart build or `workflow_dispatch`):

```shell
UNIVOCITY_TOOLS_VERSION=v0.4.0 task contract-artefacts-release:release
ls -la .work/univocity-*.tar.gz .work/create3-factory-*.tar.gz
```

## Usage

```shell
forge build   # build
forge test    # test
forge test --match-contract UnivocityInvariantTest   # invariant tests
forge fmt     # format
```

## Security model

- **Signing key = ownership** — Only the holder of the checkpoint signing
  key can produce valid checkpoints; there is no on-chain ownership to
  override this.
- **Bootstrap immutable** — The bootstrap authority and signing keys are set
  at deployment and cannot be changed.
- **Event sourcing** — All state-changing operations that affect
  transparency and verifiability emit events.

## Reference implementation

The MMR algorithms are ported from the reference Python implementation:
[merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)

## License

MIT
