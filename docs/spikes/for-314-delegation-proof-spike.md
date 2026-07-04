# FOR-314 spike: delegation proof provenance

**Status:** COMPLETE (Outcome **B**)  
**Date:** 2026-07-04  
**Linear:** [FOR-314](https://linear.app/forestrie/issue/FOR-314/delegation-proof-and-multi-seal-spike)  
**Plan:** [plan-0033 Phase 0](https://github.com/forestrie/devdocs/blob/main/plans/plan-0033-checkpoint-publisher.md#phase-0--spike-delegation-proof-provenance)

## Question

Can the sealer-embedded COSE delegation certificate (checkpoint unprotected label
**1000**) be reused directly as the on-chain `DelegationProof` calldata field
in `publishCheckpoint`?

## Outcome: **B — wire separate `onchainProof`**

The label-1000 certificate is **not** signature-compatible with on-chain
`DelegationProof` verification. The publisher (and sibling proof document) must
carry **pre-decoded** `DelegationProof` material from the issuer response
(`onchainProof` in [arbor plan-0003](https://github.com/forestrie/arbor/blob/main/docs/plan-0003-non-custodial-checkpoint-support.md)),
not extract it from the checkpoint COSE cert bytes alone.

## Comparison

| Aspect | Sealer / `delegationcert` (label 1000) | On-chain `delegationVerifier` |
|--------|----------------------------------------|-------------------------------|
| **Document** | Full COSE_Sign1 array (protected, unprotected, payload map, signature) | Typed ABI fields only |
| **Sig_structure payload** | CBOR map (keys 1,3,4,5,6,7,8,9,10 per forestrie.delegation profile) | Raw concat: `"forestrie.univocity.delegation.v1" ‖ logId ‖ mmrStart ‖ mmrEnd ‖ keyX ‖ keyY` (33 + 32 + 8 + 8 + 32 + 32 bytes) |
| **Protected header** | `{1: alg, 3: cty, 4: kid}` (deterministic int-key map) | Minimal e.g. `a10126` (ES256) or KS256 header; must match proof branch |
| **Signature semantics** | COSE Sign1 over cert payload map | COSE Sign1 over **contract-derived** payload (ADR-0006) |
| **log_id encoding** | Payload key **1**: hex string in CBOR map | `bytes32 logId` in concat payload |
| **Delegated key** | COSE_Key map at payload key **5** | 64-byte `delegationKey` (x‖y) in concat payload |

### Code references

- On-chain domain + payload: `src/checkpoints/lib/delegationVerifier.sol`
  (`DELEGATION_DOMAIN`, `abi.encodePacked` payload before `buildSigStructure`).
- Cert builder: `arbor/services/pkgs/delegationcert/build_certificate.go`
  (`BuildDelegationToBeSigned` — CBOR payload map in Sig_structure).
- Test helper for on-chain shape: `test/checkpoints/UnivocityTestHelper.sol`
  (`_buildDelegationPayloadES256`).
- Wire shape for issuer: `arbor/docs/plan-0003-non-custodial-checkpoint-support.md`
  (`OnchainDelegationProof` / `onchainProof`).

### Why Outcome A fails

Reusing the cert signature would require the root key to have signed the **CBOR
map** payload, but the contract verifies a signature over the **concat** payload.
Those byte strings differ for the same logical delegation (different length,
encoding, and field layout). Changing the contract to verify cert payload maps
would contradict ADR-0006 (no on-chain cert parse) and expand consensus surface.

## Implications for downstream issues

| Issue | Action |
|-------|--------|
| FOR-316 (sibling proof doc) | Include `onchainProof` fields (or equivalent pre-decoded tuple), not raw label-1000 cert alone |
| FOR-315 (`publishproof`) | Map sibling doc → `DelegationProof` ABI; do not re-sign cert payload |
| Custodian / issuer | Populate `onchainProof` using `_buildDelegationPayloadES256` semantics (or KS256 branch) at issue time |

## Multi-seal consistency proof chain (FOR-314 test)

Integration test `test_multiSealProofChain_singlePublish_advancesTargetLogTwice`
in `test/integration/CheckpointFlow.t.sol` pins **`ConsistencyProof[]` length 2**
for catching up on-chain size 0 → 2 in one `publishCheckpoint`:

1. `{ treeSize1: 0, treeSize2: 1, paths: [], rightPeaks: [leaf1] }`
2. `{ treeSize1: 1, treeSize2: 2, paths: [[leaf2]], rightPeaks: [leaf2] }`

Receipt signature uses `buildDetachedPayloadCommitment` over the accumulator
after `verifyConsistencyProofChain`. Sequential per-seal publishes use a
**single** proof each (see `test_fullFlow_sameReceiptDifferentSubmitters`).
