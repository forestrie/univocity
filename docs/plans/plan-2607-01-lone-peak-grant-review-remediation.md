# Plan 2607-01 — lone-peak grant inclusion: review remediation

**Status:** DRAFT
**Date:** 2026-07-17
**Related:** [FOR-393](https://linear.app/forestrie/issue/FOR-393),
branch `robin/for-393-lone-peak-grant-leaf`,
[ARC-0017 auth overview](../arc/arc-0017-auth-overview.md) (rules 1–5),
[demo repo](https://github.com/forestrie/demo) `README.md` "Slide 7 is
order-dependent: the lone-peak grant leaf",
arbor `services/publisher/src/publish.go` (`ShouldAck`),
arbor `services/pkgs/publishproof/inclusion.go` (`BuildInclusionProof`).

## Scope

Review of `robin/univocity-lone-peak-grant-leaf` — single branch (Graphite
reports the branch as untracked, so §2.1 single-branch fallback applies), no
commits yet, working tree only:

| File | Change |
|------|--------|
| `src/contracts/_Univocity.sol` | remove the over-strict empty-path guard in `_applyInclusionGrant`; document why an empty path is always safe |
| `src/interfaces/types.sol` | correct the `InclusionProof` NatSpec ("empty path means no payment proof" was wrong); document `index` as an MMR node index |
| `test/checkpoints/UnivocityGrantLonePeak.t.sol` | new — 6 tests (1 regression + 5 fail-closed) |

Gates: `forge fmt --check` clean, `forge test` 250 passed / 0 failed / 1
skipped, `mise run slither-check` 0 results.

### The defect (verified in production, lane-A Base Sepolia)

`_applyInclusionGrant` accepted an empty grant inclusion path only when
`ownerLog.size == 1`. An empty path is not "no proof" — it is the proof that
the grant leaf **is** an accumulator peak, which is the normal shape whenever
the grant leaf is the owner's last leaf and the owner's leaf count is odd. A
child log's create grant is by construction the owner's most recent leaf, so
child creation failed on a leaf-count-parity coin flip.

Reproduced end-to-end: with the root at 103 leaves (odd — 103 = 64+32+4+2+**1**)
the auth log's first publish reverted `InvalidPaymentReceipt` (`0xf2d20499`,
tx `0x5908f076…`, trace shows `LogRegistered` emitted then revert — i.e. the
failure is at the post-registration guard, not the grant checks). The arbor
publisher then logged `unpublishable checkpoint terminally acked` and never
retried, so the data log beneath it retried `owner_not_anchored` forever.
Confirmed by prediction: re-running with the grant at leaf 104 (even) published
on the first attempt.

### Invariants checked

| Invariant | Requires | Diff |
|-----------|----------|------|
| ARC-0017 Rule 2 | "Grant = inclusion proof in target log's owner (authLogId)" | **Upholds.** Inclusion is still cryptographically required; the removed guard rejected *valid* inclusion proofs on an owner-**size** predicate rather than on whether inclusion held — it contradicted Rule 2. |
| ARC-0017 Rule 3 | first checkpoint to a new log needs `ownerLogId` + inclusion in that owner | Unchanged (`:305` still reverts on zero `ownerLogId`). |
| ARC-0017 §5 | submission is permissionless; `msg.sender` is not authorization | Unchanged — and therefore the relaxation must be sound against a hostile submitter. It is: with an empty path the check degrades to `leaf == owner's height-0 peak`, and the leaf is `sha256(idts ‖ sha256(grant fields))`, so matching a real peak is a preimage problem. |
| Fail-closed | an absent/forged proof must not pass | **Upholds**, and now proven: 5 negative tests (leaf-not-the-peak, owner-has-no-height-0-peak, escalated grant, wrong idtimestamp) pass against **both** the old and new contract. |

The relaxation also fixes the same latent bug for root self-extension
(`else` branch, `authLogId == self`): a root whose own `GF_EXTEND` grant leaf
is the lone peak was equally unpublishable.

## Findings

| ID | Sev | Dim | Location | Finding | Invariant/Rule |
|----|-----|-----|----------|---------|----------------|
| F1 | High | Liveness | `_Univocity.sol:363-367` (removed) | Over-strict empty-path guard permanently strands child logs (publisher terminally acks the mined revert). **Fixed by this diff.** | ARC-0017 Rule 2 |
| F2 | Medium | Correctness / observability | `_Univocity.sol` `_applyInclusionGrant` → `_updateLogState` | With an empty path, `index` is unconstrained: `peakIndex` keys off `proof.length`, and `includedRoot`'s loop never runs, so any `index` verifies and is emitted as `CheckpointPublished.grantIndex`. The old `size == 1 && index == 0` branch at least pinned it. A permissionless submitter can now feed indexers an arbitrary `grantIndex`. Not a safety issue (inclusion is still proven). | ARC-0017 §5 (permissionless submission) |
| F3 | Medium | Correctness | `_validateCheckpointAccumulatorLength` vs `proofLengthRootStorage` | Two disagreeing peak notions: the validator uses `peaks(size-1).length`, peak *selection* uses `peakIndex(peaksBitmap(size), d)`. They agree on canonical MMR sizes but not otherwise (size 2 → 2 vs 1). Nothing rejects a non-canonical `claimedSize`, so a log can be published into a state where height-based peak selection is ill-defined. Requires a cooperating owner key, so no known exploit — hardening. | MMR profile |
| F4 | Medium | Liveness | arbor `publisher/src/publish.go` `ShouldAck` | `StatusReverted` is terminally acked on the rationale "self-heals via the next seal's catch-up (adr-0008)". That assumption fails for a **quiescent** log (an auth log holding a single create grant never re-seals). This diff removes the known trigger; the class remains — any future deterministic revert silently strands a log. | adr-0008 |
| F5 | Low | Best practice | `IUnivocityErrors.InvalidPaymentReceipt` | One error for four distinct conditions (`:266` root index≠0, `:305` missing ownerLogId, the removed guard, `:377` inclusion failure), named for "payment" in a model with no payment. Localising the live failure needed a `cast run` trace. | operability |
| F6 | Low | Test coverage | `test/checkpoints/UnivocityTestHelper.sol` | The shared harness publishes non-canonical MMR states (size 2 with a 2-entry accumulator; `acc[0]` is `parent(l0,l1)`), so tests built on it cannot express real peak algebra. The new suite therefore seeds its own canonical states. Harness states diverging from go-merklelog output weakens every test built on them. | F3 |

### Design holes & non-obvious details

- **An empty inclusion path is overloaded.** `types.sol` documented it as "no
  payment proof" while the verifier treats it as a peak assertion. The contract
  guard encoded the doc's reading, the algorithms encoded the other. The diff
  makes the doc match the algorithms (the sound reading). Any future
  "is a proof present?" check must not key off `path.length`.
- **`peakIndex(lc, d)` assumes at most one peak per height**, which holds only
  for canonical MMRs (F3).
- **Contract reverts are not self-healing for quiescent logs** (F4). The
  auth→data topology guarantees quiescent auth logs: an auth log created for a
  single data log receives exactly one leaf, ever.
- **The publisher already satisfies the F2 remediation**:
  `BuildInclusionProof` returns `InclusionProof{Index: nodeIndex, …}`, and for
  a lone peak `nodeIndex == mmrSize-1`. So R2 is safe to land.

## Remediation items

### R0 — Linear issue and branch naming (High, pre-merge) — **DONE**

**Finding:** the defect was found while rehearsing the IETF 126 demo, not from
a tracked issue, so the branch initially violated
`.cursor/rules/branch-naming.mdc` (`<user>/for-<issue-no>-<short-desc>`).

**Resolved:** [FOR-393](https://linear.app/forestrie/issue/FOR-393) filed;
branch renamed `robin/for-393-lone-peak-grant-leaf`.

### R1 — Constrain `index` when the path is empty (Medium)

**Finding:** F2.

**Change:** in `_applyInclusionGrant`, when `grantInclusionProof.path.length
== 0`, require `grantInclusionProof.index == ownerLog.size - 1`. A height-0
peak is always the MMR's last node, so this is exactly the general form of the
old `size == 1 && index == 0` rule, and it keeps `CheckpointPublished.grantIndex`
truthful. Guard `ownerLog.size != 0` first (`verifyInclusionStorage` already
rejects size 0, but the subtraction must not underflow).

**Acceptance:** a lone-peak grant with the correct node index publishes; the
same grant with any other index reverts; `grantIndex` in the event equals the
peak's node index. Arbor publisher unaffected (`BuildInclusionProof` already
sends `nodeIndex`) — assert this with an integration test or a cross-repo note
before merging.

**Branch:** current branch (small, same code path, same review).

**Deliberately not in this diff:** the fix for F1 must be the minimal, provably
sound change; F2 is a separate (non-security) constraint and is sequenced after
the demo.

### R2 — Reject non-canonical MMR sizes (Medium)

**Finding:** F3.

**Change:** in `publishCheckpoint`, validate that `claimedSize` is a canonical
MMR size — i.e. `peaks(claimedSize-1).length == popcount64(peaksBitmap(claimedSize))`
— or replace `_validateCheckpointAccumulatorLength`'s `peaks(size-1).length`
with the `peaksBitmap` form so a single notion of "peaks" governs both
validation and selection. Prefer the latter (one algebra, less gas) if the
KATs agree.

**Acceptance:** a checkpoint at a non-canonical size (e.g. 2) reverts with a
named error; all existing canonical KATs still pass; `test/checkpoints/`
harness updated to emit canonical states (see R4).

**Branch:** new branch, after this one — it will churn the shared test harness.

### R3 — Publisher: do not silently strand a terminally-reverted log (Medium)

**Finding:** F4. **Repo:** arbor (sibling) — Linear issue, not this stack.

**Change:** keep the terminal ack (retrying a deterministic revert burns gas
with no progress — correct as-is), but make the outcome recoverable and
visible: emit a metric + alert keyed by logId, and record the stranded
checkpoint in a dead-letter the operator can replay once the owner advances.
Optionally re-enqueue with backoff **only** when the owner's on-chain size has
advanced since the failed attempt — that is the only state change that can turn
this class of revert into a success.

**Acceptance:** a reverted publish on a log that never re-seals raises an alert
and appears in the dead-letter; no unbounded retry loop.

### R4 — Canonical MMR fixtures for the checkpoint test harness (Low)

**Finding:** F6. Fold into R2 — the harness must produce canonical states, or
`UnivocityTestHelper` states will keep contradicting the peak algebra.

### R5 — Split `InvalidPaymentReceipt` (Low, deferred)

**Finding:** F5.

**Change:** distinct errors per condition (e.g. `RootGrantIndexNonZero`,
`MissingOwnerLogId`, `GrantInclusionFailed`). **Breaking:** arbor
`publisher/src/chainwriter.go` maps the 4-byte selector (`f2d20499`) to a name;
`chainwriter_test.go` pins it. Coordinate with a contracts release and an arbor
bump. Defer past the demo.

## Deferred (Low)

- R5 (error taxonomy) — post-demo, needs a coordinated arbor bump.
- R4 folded into R2.

## Demo-day note (not a contracts item)

The IETF 126 demo does **not** need this fix to land: with the deck run in
presentation order the root reaches 103 leaves (odd) before the auth grant, so
slide 7 fails. Either release this contract fix, or keep the root's leaf count
even at that point. Do **not** "fix" it by making the publisher retry — the
demo's root never grows after slide 6, so a retry would revert identically,
forever. See the demo repo README.
