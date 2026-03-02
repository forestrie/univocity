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

Set environment variables and run:

```shell
export BOOTSTRAP_AUTHORITY=0x...
export AUTHORITY_LOG_ID=0x...   # 32-byte hex
export KS256_SIGNER=0x...       # optional; at least one of KS256_SIGNER or ES256_X/Y
# optional: ES256_X=0x... ES256_Y=0x...
forge script script/Deploy.s.sol --rpc-url <RPC> --broadcast
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
