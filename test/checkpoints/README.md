# Univocity checkpoint tests

Plan 0022 Phase 0 refactored the test layout. The suite is split into
functionally grouped contracts:

- **UnivocityTestHelper.sol** — Shared setup, constants, and helpers (deployment,
  PaymentGrant, leaf commitment, consistency receipts, inclusion proofs, paths,
  ES256 helpers, `_publishBootstrapAndSecondCheckpoint`). All test contracts
  that need these inherit `UnivocityTestHelper`.

- **Univocity.t.sol** — Main integration suite (UnivocityTest). Uses the helper;
  setUp deploys Univocity and publishes bootstrap + second checkpoint. Holds
  first-checkpoint behaviour, validation, consistency proof reverts, receipt/
  grant decode, ES256 recovery, delegation, and rule3 tests.

- **UnivocityBootstrap.t.sol** — Bootstrap and first-checkpoint tests
  (UnivocityBootstrapTest). Add GF_REQUIRE_SIGNER bootstrap tests here
  (Plan 0022 Phase 4).

- **UnivocityGrantRequirements.t.sol** — Grant flag and code requirement tests
  (GF_*, GC_*).

- **UnivocityExtend.t.sol** — Second checkpoint and extend tests (size-two
  flow, bootstrap publish, invalid grant does not extend, idtimestamps).

- **UnivocityBounds.t.sol** — maxHeight, minGrowth, and grant-exhausted tests.

- **UnivocityStateAndEvents.t.sol** — getLogState, isLogInitialized, events,
  checkpoint count.

- **UnivocityMisc.t.sol** — Error coverage matrix and similar.

Optional future splits (when adding tests or reducing Univocity.t.sol further):
- Consistency proof chain and receipt/grant decode → `UnivocityConsistencyProof.t.sol`
- Delegation / ES256 recovery → `UnivocityDelegation.t.sol`
