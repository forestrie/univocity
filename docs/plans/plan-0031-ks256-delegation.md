# Plan 0031: KS256 root delegation to ES256 checkpoint signers

**Status:** DRAFT  
**Date:** 2026-06-06  
**Related:** [ADR-0006](../adr/adr-0006-cose-shaped-delegation-proof.md),
[plan-0029](plan-0029-eip-compatible-ks256-signers.md),
[plan-0028](plan-0028-cose-shaped-delegation-proof.md)

## 1. Goal

Allow logs whose root key is KS256 (20-byte Ethereum address) to authorize
ES256 checkpoint signers via COSE-shaped delegation proofs, while keeping
KS256 consistency receipts non-delegatable.

## 2. Workstream A (contract)

### 2.1 `delegationVerifier.sol`

- Add `verifyDelegationProofKS256` mirroring `verifyDelegationProofES256`:
  - Require `protectedHeader` alg `ALG_KS256`.
  - Same canonical payload:
    `domain || logId || mmrStart || mmrEnd || delegatedKeyX || delegatedKeyY`.
  - Verify COSE Sign1 Sig_structure with `keccak256` via `verifyKS256Raw`.
  - Root is `address storedRoot`; delegate remains ES256 (64-byte x || y).

### 2.2 `_Univocity.sol` — `_checkpointSignersES256`

- Return opaque `rootKey` bytes (20-byte KS256 or 64-byte ES256) plus ES256
  verifier coordinates.
- When `config.rootKey.length == 20` and delegation present: verify KS256
  delegation, return stored root key and ES256 delegate as verifier.
- When first checkpoint (`rootX/rootY` zero), `grantData.length == 20`, and
  delegation present: same KS256 delegation path using root from `grantData`.
- Without delegation, ES256 receipt on KS256 root still reverts
  `InconsistentReceiptSignature(ALG_ES256, ALG_KS256)`.

### 2.3 `_verifyCheckpointSignatureES256` — first checkpoint persistence

- When `grantData.length == 20`: match bootstrap via `_bootstrapKS256Signer()`,
  persist `abi.encodePacked(ksRoot)`; do not call `_es256KeyMatchesBootstrap`.
- When `grantData.length == 64`: existing ES256 bootstrap path unchanged.

### 2.4 Tests

- `test/checkpoints/UnivocityDelegationKS256.t.sol`: EOA KS256 root with ES256
  delegated first and extend checkpoints.

## 3. Out of scope (later workstreams)

- KS256 consistency receipt delegation.
- Arbor / Canopy proof production for KS256 delegation certificates.
- ERC-1271 KS256 root delegation tests (EOA minimum in Workstream A).

## 4. Deploy (Workstream A gate for e2e)

Fresh deploy required — existing `0x611dd70B…` is immutable and lacks
`verifyDelegationProofKS256`.

**Deployed (Base Sepolia Safe KS256 bootstrap):**
`0x7A4E8ad88D6Df29FEBEc0d546d148Ed4bea8Cb94` (ImutableUnivocity). Root Safe:
`0x1528b86ff561f617602356efdbD05908a07AA788`. Authority logId:
`keccak256("authority-log")`.

Set **`E2E_UNIVOCITY_ADDRESS_KS256_BOOTSTRAP`** in Doppler **`canopy/dev`** and
GitHub CI vars. ES256 deployment: **`E2E_UNIVOCITY_ADDRESS_ES256_BOOTSTRAP`**
(see [plan-0032](plan-0032-es256-immutable-deploy.md)).
**`univocity/dev`** (sync to GitHub **`dev`** vars for CI). Canopy e2e static
forest log id: `7a4e8ad8-8d6d-429f-8bec-0d546d148edb` (see
`canopy/packages/tests/canopy-api/tests/utils/e2e-static-log-ids.ts`).

## 5. Verification

```sh
forge test
```
