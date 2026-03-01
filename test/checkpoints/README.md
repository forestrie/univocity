# Univocity checkpoint tests

Plan 0022 Phase 0 refactored the test layout:

- **UnivocityTestHelper.sol** — Shared setup, constants, and helpers (deployment,
  PaymentGrant, leaf commitment, consistency receipts, inclusion proofs, paths,
  ES256 helpers). All test contracts that need these should inherit
  `UnivocityTestHelper`. Add new helper methods here.

- **Univocity.t.sol** — Main integration suite (UnivocityTest). Uses the helper;
  setUp deploys Univocity and publishes bootstrap + second checkpoint. Most
  tests live here; more can be split out over time.

- **UnivocityBootstrap.t.sol** — Bootstrap and first-checkpoint tests
  (UnivocityBootstrapTest). Add GF_REQUIRE_SIGNER bootstrap tests here
  (Plan 0022 Phase 4).

Future split targets (when adding tests or reducing Univocity.t.sol size):
- Grant requirements → `UnivocityGrantRequirements.t.sol`
- Extend / second checkpoint → `UnivocityExtend.t.sol`
- Consistency proof chain → `UnivocityConsistencyProof.t.sol`
- Bounds (maxHeight, minGrowth) → `UnivocityBounds.t.sol`
- Delegation / ES256 → `UnivocityDelegation.t.sol`
- State and events → `UnivocityStateAndEvents.t.sol`
