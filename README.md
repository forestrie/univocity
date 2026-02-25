# univocity

On-chain split view protection for [forestrie](https://github.com/forestrie/)
transparency logs.

## Overview

univocity provides Solidity contracts that verify transparency log checkpoints
can only be published on-chain if they are consistent with previously published
checkpoints. This prevents log operators from presenting different views of the
log to different parties.

The verification logic implements the consistency proof format described in
[draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html).

## Authorization Model (R5 / SCITT pattern)

- **Signing authority**: Checkpoint content is authorized by a signature that chains from the previous checkpoint (SCITT issuer model).
- **Publishing authority**: R5 payment receipts (SCITT COSE_Sign1 format) authorize the economic cost of publishing; the contract verifies receipt signature and bounds (checkpoint count, max height).
- **Permissionless submission**: Given a validly signed checkpoint and valid payment receipt, any party may submit. The contract does not restrict `msg.sender` to the payer or signer.
- **No on-chain ownership**: The checkpoint signing key is the effective “owner” of the log; there is no separate ownership state or bootstrap re-initialization.

## Contract Architecture

- **Univocity.sol**: Main contract; multi-log checkpoint state, bootstrap access control, R5 receipt verification, consistency proof verification.
- **LibAuthorityVerifier**: Verifies SCITT-format payment receipts (COSE_Sign1 + CBOR claims) and inclusion in the authority log.
- **consistencyReceipt**: Verifies MMR consistency receipt chain (decode CBOR proofs,
  run `consistentRoots`/`consistentRootsMemory`, build detached payload commitment).
- **cosecbor**: COSE_Sign1 Sig_structure and verify (ES256, KS256); CBOR
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

## Security Model

- **Signing key = ownership**: Only the holder of the checkpoint signing key can produce valid checkpoints; there is no on-chain ownership to override this.
- **Bootstrap immutable**: The bootstrap authority and signing keys are set at deployment and cannot be changed.
- **Event sourcing**: All state-changing operations that affect transparency and verifiability emit events.

## Reference Implementation

The MMR algorithms are ported from the reference Python implementation:
[merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)

## License

MIT
