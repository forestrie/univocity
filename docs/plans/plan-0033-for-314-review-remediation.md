# Plan 0033 — FOR-314 review remediation

**Status:** DRAFT  
**Date:** 2026-07-04  
**Related:** [FOR-314](https://linear.app/forestrie/issue/FOR-314/delegation-proof-and-multi-seal-spike), [PR #28](https://github.com/forestrie/univocity/pull/28), [devdocs plan-0033](https://github.com/forestrie/devdocs/blob/main/plans/plan-0033-checkpoint-publisher.md)

## Scope

Review of `robin/for-314-delegation-proof-spike` (single branch, 1 commit).
Spike doc + multi-seal integration test; no production publisher code.

## Remediation items

### R1 — Remove Co-Authored-By from commit (Low)

**Finding:** Commit `9ec6525` includes `Co-Authored-By: Cursor` — violates Forestrie
commit conventions.

**Acceptance:** Squash or amend before merge; commit message body ≤72 cols, no
Co-Authored-By lines.

**Branch:** current PR (pre-merge housekeeping).

### R2 — Fix harness mutability (Low)

**Finding:** `MultiSealReceiptHarness.buildSignedReceipt` is `pure` but uses
`vm.sign`.

**Acceptance:** Drop `pure` (or move signing to test contract that inherits
`Test` without incorrect mutability).

**Branch:** current PR or follow-up nit on same branch.

### R3 — Index spike doc (Low)

**Finding:** `docs/spikes/for-314-delegation-proof-spike.md` not linked from
`docs/plans/README.md`.

**Acceptance:** README entry under a **Spikes** or **FOR-314** pointer to spike
artefact.

**Branch:** current PR or FOR-320 docs pass.

### R4 — Document batched publish idtimestamp semantics (Medium)

**Finding:** `test_multiSealProofChain_singlePublish_advancesTargetLogTwice`
builds `targetLeaf2` with `idtimestamp=2` but calls `publishCheckpoint` with
`IDTIMESTAMP_1` only. Contract accepts this today; publisher must know whether
real seals use **one publish per seal** vs **catch-up chain** and which
idtimestamp binds the grant.

**Acceptance:** Spike doc or FOR-315 plan note: production publisher path is
**one checkpoint key → one grant idtimestamp** (sequential publishes); batched
0→N test is contract-capability pin only.

**Branch:** devdocs plan-0033 amendment or FOR-315 issue description (no code
change required for FOR-314 merge).

### R5 — KS256-root onchainProof vector (Medium, deferred)

**Finding:** Spike doc references KS256 delegation branch; test uses empty
`DelegationProof` only. Custodian/sealer must emit `onchainProof` per Outcome B.

**Acceptance:** Foundry or Go test in arbor/univocity when issuer wiring lands
(FOR-316 / custodian slice); cross-link from spike doc.

**Branch:** new issue or FOR-316 stack (not blocking FOR-314).

## Deferred (Low)

- Deduplicate `MultiSealReceiptHarness` with `UnivocityTestHelper` receipt
  builders when `publishproof` package adds shared Go vectors.
- `foundry.lock` solmate pin: confirm intentional; revert if unrelated to forge
  build on CI agent.

## Branch assignment summary

| Item | Where |
|------|-------|
| R1, R2, R3 | Merge blockers / same PR |
| R4 | FOR-315 planning note |
| R5 | FOR-316 / arbor custodian |
