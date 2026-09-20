# Univocity checkpoint tests

Plan 0022 Phase 0 refactored the test layout. The suite is split into
functionally grouped contracts:

- **UnivocityTestHelper.sol** — Shared setup, constants, and helpers (deployment,
  PublishGrant, leaf commitment, consistency receipts, inclusion proofs, paths,
  ES256 helpers, `_publishBootstrapAndSecondCheckpoint`). All test contracts
  that need these inherit `UnivocityTestHelper`.

- **Univocity.t.sol** — Main integration suite (UnivocityTest). Uses the helper;
  setUp deploys Univocity and publishes bootstrap + second checkpoint. Holds
  first-checkpoint behaviour, validation, consistency proof reverts, receipt/
  grant decode, ES256 recovery, delegation, and rule3 tests.

- **UnivocityBootstrap.t.sol** — Bootstrap and first-checkpoint tests
  (UnivocityBootstrapTest). Add bootstrap first-checkpoint tests here
  (Plan 0022 Phase 4).

- **UnivocityGrantRequirements.t.sol** — Grant flag and code requirement tests
  (GF_*, GC_*).

- **UnivocityExtend.t.sol** — Second checkpoint and extend tests (size-two
  flow, bootstrap publish, invalid grant does not extend, idtimestamps).

- **UnivocityBounds.t.sol** — maxHeight, minGrowth, and grant-exhausted tests.

- **UnivocityStateAndEvents.t.sol** — getLogState, isLogInitialized, events,
  checkpoint count.

- **UnivocityMisc.t.sol** — Error coverage matrix and similar.

- **UnivocityConsistencyProof.t.sol** — Consistency proof chain shape: every
  proof must start at the anchored size (FOR-567), grow, declare complete MMR
  sizes, and carry paths of the length the draft's `inclusion_proof_path`
  implies. Holds the regression routes for the base-0 / aliased-base /
  chain-break / shrinking-chain / empty-path / peak-count cases plus an
  1→3→4→7 chain.

Fixtures use valid MMR geometry only: valid sizes are 1, 3, 4, 7, 8, 10, 11,
15 … (`indexHeight(size) == 0`); size 2 is not an MMR and the contract rejects
it. The authority log after `_publishBootstrapAndSecondCheckpoint` is at size
3 with accumulator `[hashPosPair64(3, leaf0, leaf1)]`.

Optional future splits (when adding tests or reducing Univocity.t.sol further):
- Receipt/grant decode → `UnivocityReceiptDecode.t.sol`
- Delegation / ES256 recovery → `UnivocityDelegation.t.sol`
