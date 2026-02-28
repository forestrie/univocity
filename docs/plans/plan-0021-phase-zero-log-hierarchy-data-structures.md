# Plan 0021: Phase 0 — Log hierarchy data structures (agent execution guide)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md),
[ARC-0017](../arc/arc-0017-log-hierarchy-and-authority.md),
[ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md),
[plan-0012](plan-0012-arc-0016-implementation-review.md)

**Design summary.** Phase 0 of [ARC-0017](../arc/arc-0017-log-hierarchy-and-authority.md): data structures for the log hierarchy. **Authorization:** ARC-0017 §2 — rootKey at first checkpoint (direct or **recovered rootKey** in delegation); grant = inclusion against owner; **ownerLogId** in grant for log creation; bootstrap only for **first checkpoint ever**; root has authLogId = self ([ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md)). **Grant bounds:** growth-based only (max_size/maxHeight, min_range/minGrowth); effective cap (max_size − current_size) / min_range. No checkpoint counter (Phase E). **Phase F (optional):** Create new authority logs via grant (ownerLogId + createAsAuthority; extend leaf commitment) so tests cover root→child→data hierarchy.

---

## 1. Goal and scope

**Goal:** Add on-chain **data structures** for the log hierarchy (ARC-0017 Phase 0): LogKind, authLogId (owning for data, parent for authority), separate LogConfig mapping, key/inclusion routing per ARC-0017 §2. Grant bounds via size only (no checkpointCount).

**Out of scope (until Phase F):** Multiple authority logs (beyond root + one child for testing); per-log bootstrap; explicit revocation. Phase F adds **creation of new authority logs via a grant** so tests can cover the hierarchical model (root → child authority → data under child).

**Decisions (fixed):** Log kind 0 / Authority=1 / Data=2; single authLogId (owning for data, parent for authority); rootKey at first checkpoint (recovered rootKey in delegation); grant = inclusion against owner; ownerLogId in grant for log creation. Full rules: **ARC-0017 §2** and plan §3.3.

---

## 2. Task dependency graph

```
Phase A (types and interface)
  A.1  Add LogKind enum/constants + extend LogState in IUnivocity.sol
  A.2  (Optional) Add IUnivocityErrors for invalid kind if needed later

Phase B (storage and initialization)
  B.1  Extend LogState in Univocity.sol to match interface (storage layout)
  B.2  In _updateLogState: set kind and authLogId on first checkpoint
       (isNewLog)
  B.3  Pass “authority log id used” into _updateLogState so new data logs
       get correct authLogId (owning)

Phase C (inclusion proof routing)
  C.1  In publishCheckpoint: compute authorityLogIdForInclusion (see below)
  C.2  Use authorityLogIdForInclusion instead of authorityLogId when
       loading authority log for inclusion verification for data logs
  C.3  Pass authorityLogIdForInclusion into _updateLogState

Phase D (tests and views)
  D.1  Unit/integration: first bootstrap sets kind=Authority, authLogId=0
  D.2  Unit/integration: first checkpoint to data log sets kind=Data,
       authLogId=authorityLogId
  D.3  Unit/integration: subsequent checkpoint to data log uses
       log.authLogId for inclusion (same result while single auth)
  D.4  getLogState returns new fields; existing tests that assert on
       LogState may need to allow new fields

Phase E (remove checkpointCount from current implementation)
  E.1  Remove checkpointCount from LogState (interface and contract);
       enforce grant bounds using size only (maxHeight, minGrowth).
  E.2  Remove _checkPaymentGrantBoundsCheckpointRange; drop checkpoint
       range check (checkpointStart/checkpointEnd) from publishCheckpoint.
  E.3  Update CheckpointPublished event (drop checkpointCount); emit size
       only (observers use size as progression index).
  E.4  Update tests and invariants that assert on checkpointCount.
```

Phase F (authority log creation) — optional extension so hierarchy is testable:
  F.1  Add ownerLogId and createAsAuthority to PaymentGrant; extend leaf
       commitment (inner hash) to include both when used for log creation.
  F.2  First checkpoint to new log: if createAsAuthority, verify inclusion
       against ownerLogId (parent), set kind=Authority, authLogId=parent.
  F.3  Extend existing log: when config.kind==Authority and authLogId!=rootLogId (child)
       (child), verify inclusion against parent (_logs[config.authLogId]);
       no OnlyBootstrapAuthority.
  F.4  _updateLogState: when isNewLog and not root, set kind from grant
       (Authority if createAsAuthority else Data), authLogId=ownerLogId.
  F.5  Tests D.5–D.8: create child authority; extend child; create data
       under child; extend data under child (inclusion against child).

Execute A → B → C → D (optionally F after D). Phase E can be done before or as part of the same
work as A–D; if done first, LogState in the codebase already has no
checkpointCount when adding LogConfig/LogKind. B.2 and B.3 depend on C.1–C.3 (we need to pass
authority log id into _updateLogState); so implement C.1–C.3 before
finalising B.2–B.3, or implement B.2–B.3 to accept the parameter that C.3
will supply. Phase F depends on C (authForInclusion and ownerLogId already used for data logs).

---

## 2.1 Complexity: adding authority log creation (Phase F)

**Why add it:** Without the ability to create a child authority, tests cannot cover the full hierarchical model (grant from parent, inclusion against parent, data logs owned by child). Phase 0 would only exercise root + data logs.

**Additional complexity:**

| Area | Change | Impact |
|------|--------|--------|
| **PaymentGrant** | Add `ownerLogId` (already planned for data log creation), add `createAsAuthority bool`. | One extra field; both needed so first checkpoint sets kind correctly (Authority vs Data). |
| **Leaf commitment** | Extend inner hash to include `ownerLogId` and `createAsAuthority` when present. | Breaks existing receipt format; new deployments use extended format. Document or version. |
| **publishCheckpoint** | New branch: existing log with kind==Authority and authLogId!=rootLogId (child) → verify inclusion against parent, consistency against child’s rootKey; no bootstrap. First checkpoint to new log with createAsAuthority → verify inclusion against ownerLogId, set kind=Authority, authLogId=ownerLogId. | Reuse existing authForInclusion logic; Only first checkpoint ever uses OnlyBootstrapAuthority; root extension requires grant in root (ADR-0004). |
| **_updateLogState** | When isNewLog and not root: set kind from grant (Authority if createAsAuthority else Data), authLogId=ownerLogId. | Single extra parameter or derive from grant. |
| **Tests** | D.5–D.8: create child authority (first checkpoint, createAsAuthority, inclusion in root); extend child; create data under child; extend data under child. | Four test cases; reuses same publishCheckpoint path. |

**Recommendation:** Include Phase F in Phase 0 so that a single implementation delivers testable hierarchy (root → child authority → data under child). The extra work is bounded: one grant field, one branch for “extend child authority,” one branch for “first checkpoint = new authority,” and leaf commitment extension. **Must have:** Hierarchy tests D.5–D.8 and grant expiry tests (including cascading effect on child logs) are required; include Phase F and a grant-expiry test phase.

---

## 3. Target types and state

### 3.1 LogKind

Add to the codebase (in `IUnivocity.sol` or a shared constants file).
Values start at 1 so that 0 (storage default) means undefined/not set:

```solidity
/// @notice Log role in the hierarchy (ARC-0017 Phase 0).
///    Zero = undefined/not set (uninitialized log state).
enum LogKind {
    Undefined,      // 0 = not set (uninitialized)
    Authority = 1,  // authority log (root or future child)
    Data = 2        // data log (owned by an authority log)
}
```

If the project avoids enums in storage for gas/serialization, use `uint8`
with named constants: `uint8 constant LOG_KIND_AUTHORITY = 1; uint8
constant LOG_KIND_DATA = 2;` (0 remains “not set”). Store `uint8 kind` in
LogState.

### 3.2 LogConfig and LogState (separate mappings, association by logId)

Parameters that do not change after the log is created are grouped in
**LogConfig**. **LogState** holds only mutable state. The two are stored in
**separate mappings** and associated by **logId** (same key for both).

In `IUnivocity.sol`, add `LogConfig` and define `LogState` as:

```solidity
/// @notice Immutable per-log parameters (set at first checkpoint).
/// Stored in a separate mapping from LogState; use same logId to look up both.
struct LogConfig {
    LogKind kind;           // 0 = not set; Authority = 1; Data = 2.
    bytes32 authLogId;      // If kind==Data: owning. If kind==Authority: parent (root = self = rootLogId).
    bytes rootKey;          // P-256 root key (64 bytes); established at first checkpoint (ARC §2 rule 1).
    uint256 initializedAt;  // Block number of first checkpoint.
}

struct LogState {
    bytes32[] accumulator;
    uint64 size;
}
```

**Grant bounds (growth-based):** Grants are strictly limited by **maxHeight** (max_size) and **minGrowth** (min_range). Effective cap on checkpoints under a grant = (maxHeight − currentSize) / minGrowth. No checkpoint counter; size-only checks (see Phase E).

**Storage:** Two mappings keyed by logId:

- `mapping(bytes32 logId => LogState) _logs` — mutable state only.
- `mapping(bytes32 logId => LogConfig) _logConfigs` — immutable config; set at first checkpoint.

Reference by association: for a given `logId`, use `_logs[logId]` for state and
`_logConfigs[logId]` for config. No nesting; both structs are top-level in their
mappings.

Storage layout: replacing the previous flat `LogState` (accumulator, size,
checkpointCount, initializedAt, rootKey, kind, authLogId) with two mappings and
dropping checkpointCount changes the layout. Existing deployments cannot be migrated without a storage
migration; new deployments use this layout. Contract and test code that
previously used `log.initializedAt`, `log.rootKey`, `log.kind`, `log.authLogId`
now use `_logConfigs[logId].initializedAt`, `_logConfigs[logId].rootKey`,
`_logConfigs[logId].kind`, `_logConfigs[logId].authLogId`. Views such as
`getLogState(logId)` return state; add `getLogConfig(logId)` (or equivalent) to
expose config.

### 3.3 Authority model (ARC-0017 §2)

The four canonical rules and how they govern log extension are in **ARC-0017 §2 (Authorization rules)**. Summary: (1) RootKey at first checkpoint — direct key or **recovered rootKey** in delegation; (2) Grant = inclusion against owner (parent for authority, auth log for data); (3) First checkpoint establishes kind and authLogId; (4) Bootstrap only for first checkpoint ever (grant against self, index 0,
    path up to MAX_HEIGHT; receipt signer must match bootstrap key); (5) Log-creation grants must include **ownerLogId**.

**Derived: key for consistency receipt**

- **First checkpoint, bootstrap:** Receipt signer must match bootstrap key;
    store as rootKey (prevents front-running).
- **First checkpoint, other log (direct):** Signing key from receipt; verify, then store as rootKey.
- **First checkpoint, other log (delegation):** Verify delegation; store the **recovered rootKey** (the key that signed the delegation) as rootKey. Grant/receipt may need to supply both delegation and public root key.
- **Later checkpoint, any log:** That log's established rootKey (or delegation from it).

So after the first checkpoint, **every** log uses **its own** rootKey for the
consistency receipt. Only the first uses bootstrap keys (bootstrap log) or
a key from the owner (other logs).

**Derived: inclusion (grant) routing — owner in grant for log creation**

When the grant type **allows log creation** (first checkpoint to a new data
log or new authority log), the grant **must include the owner log**: for
**data log** creation the owner is its associated auth log; for **authority
log** creation the owner is its parent. So the grant carries an **owner
logId** (or equivalent) whenever it is used to create a log; the contract
verifies the inclusion proof against that owner log and sets
authLogId = owner logId when applying the first checkpoint.

- **First checkpoint ever (bootstrap):** Grant against self (index 0, path
    length up to MAX_HEIGHT); OnlyBootstrapAuthority; receipt signer must
    match bootstrap key; creates root with authLogId = rootLogId (self). No
    owner field (N/A). See [ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md) §2.2, §3.1.
- **Root extension (after creation):** Grant in root; ownerLogId == rootLogId; verify inclusion against root’s accumulator; permissionless (no bootstrap check).
- **Data log:** Inclusion proof against owning authority (`_logConfigs[logId].authLogId`). First checkpoint: **owner logId from grant** = associated auth log; set authLogId from that.
- **Child authority:** Inclusion proof against **parent** log. First checkpoint: **owner logId from grant** = parent logId; set kind = Authority, authLogId = parentLogId.

`authorityLogIdForInclusion = (paymentGrant.logId == authorityLogId) ?
bytes32(0) : (initializedAt == 0 ? paymentGrant.ownerLogId :
_logConfigs[paymentGrant.logId].authLogId)`. For log creation the grant
supplies `ownerLogId` (associated auth log for data, parent for authority).
When non-zero, use `_logs[authorityLogIdForInclusion]` for `verifyInclusion`.

---

**A. Key for consistency receipt (implementation)**

- **First checkpoint** (log not yet initialized): Bootstrap log → verify
  with bootstrap keys. Any other log: **direct** signature → verify and
  **store** the signing key as `_logConfigs[logId].rootKey`; **delegation**
  → verify delegation and **store the recovered rootKey** (the key that
  signed the delegation) as `_logConfigs[logId].rootKey`. The grant/receipt
  may need to supply both the delegation proof and the public root key when
  using delegation for first checkpoint.
- **Later checkpoint:** Verify consistency receipt against
  `_decodeLogRootKey` for the **target** log (every log uses its own
  established rootKey).


---

## 4. Execution steps (agent checklist)

### Phase A: Types and interface

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| A.1 | `src/checkpoints/interfaces/IUnivocity.sol` | Add `enum LogKind { Authority = 1, Data = 2 }`. Add `struct LogConfig` (initializedAt, rootKey, kind, authLogId). Replace flat LogState with `struct LogState { bytes32[] accumulator; uint64 size }` (no nested config, no checkpointCount). Add or extend interface for `getLogConfig(logId)`. | Interface compiles; `getLogState(logId)` returns LogState; config via `getLogConfig(logId)`. |
| A.2 | (Optional) `IUnivocityErrors.sol` | Skip unless a revert for “invalid kind” is required later. Phase 0 does not need it. | — |

### Phase B: Storage and initialization

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| B.1 | `src/contracts/Univocity.sol` | Use `IUnivocity.LogState` and `IUnivocity.LogConfig`. Add second mapping `_logConfigs(bytes32 => LogConfig)`. Move config fields out of `_logs` into `_logConfigs[logId]`. Keep `_logs[logId]` for accumulator and size only (no checkpointCount). | Contract compiles; storage uses separate mappings; association by logId. |
| B.2 | `Univocity.sol` — `_updateLogState` | When `isNewLog` is true, set `_logConfigs[logId].initializedAt`, `_logConfigs[logId].rootKey` (from the key that signed the first checkpoint — rule 1), `_logConfigs[logId].kind`, and `_logConfigs[logId].authLogId`. For the **root** (when `logId == rootLogId`), set kind = Authority, authLogId = logId (self). For a **data** log, set kind = Data, authLogId = &lt;param&gt;. For a **child authority**, set kind = Authority, authLogId = parentLogId. | First bootstrap: Authority, authLogId=rootLogId (self), rootKey from bootstrap or stored. First data/child: kind and authLogId set; rootKey from first-checkpoint signer. |
| B.3 | `Univocity.sol` — `_updateLogState` | Add parameter `bytes32 authorityLogIdUsed`. When `isNewLog` and root log, set `_logConfigs[logId].authLogId = logId` (self). When isNewLog and data/child log, set `_logConfigs[logId].authLogId = authorityLogIdUsed`. When !isNewLog, do not overwrite _logConfigs[logId]. | _updateLogState receives authority log id; new data logs get correct _logConfigs[logId].authLogId (owning); root gets authLogId = self. |

### Phase C: Inclusion proof routing

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| C.1 | `Univocity.sol` — `publishCheckpoint`, `IUnivocity.sol` | When grant allows log creation (first checkpoint to target log), grant must include **ownerLogId** (auth log for data log, parent for authority log). For **root extension**, ownerLogId == rootLogId and verify inclusion against root. Compute `authForInclusion` from config.authLogId (root = self, so rootLogId) or ownerLogId for first checkpoint. Add `ownerLogId` to PaymentGrant (or equivalent) for log-creation use. | ownerLogId in grant; authForInclusion uses it for first checkpoint; root extension uses rootLogId. |
| C.2 | `Univocity.sol` — `publishCheckpoint` | Verify inclusion against `_logs[authForInclusion]` where authForInclusion is the log’s authLogId (for root extension = rootLogId; for data = owning; for child = parent). No separate “root = bytes32(0)” branch for extension. | Inclusion proof verified against the log’s owner (root = self). |
| C.3 | `Univocity.sol` — `publishCheckpoint` and `_updateLogState` | When calling `_updateLogState`, pass authForInclusion (root: rootLogId; first checkpoint ever: bytes32(0) for “root created”; data/child: owner or authLogId). In _updateLogState when isNewLog: if logId == rootLogId set kind=Authority, authLogId=logId (self); else set kind from grant (Phase F: createAsAuthority → Authority, else Data), authLogId=ownerLogId/authorityLogIdUsed. Set initializedAt, rootKey per rule 1. | Root gets authLogId=self; data logs and (Phase F) child authority get correct config. |
| C.4 | `Univocity.sol` — `publishCheckpoint` (consistency receipt) | Key for consistency receipt per §3.3: **first checkpoint** — bootstrap log → bootstrap keys; other log → verify key from receipt (direct or owner delegation) and store as rootKey. **Later checkpoint** — verify against _decodeLogRootKey(target log). | First: bootstrap keys or verify+store; later: target's rootKey. |

**Note:** Detecting “is this the authority log?” in _updateLogState: pass
`logId` and compare `logId == authorityLogId` (state var). So when
isNewLog && logId == rootLogId → _logConfigs[logId].kind=Authority,
_logConfigs[logId].authLogId=logId (self); when isNewLog && logId != rootLogId →
_logConfigs[logId].kind=Data, _logConfigs[logId].authLogId=authorityLogIdUsed.

### Phase D: Tests and views

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| D.1 | `test/` (e.g. Univocity.t.sol or CheckpointFlow) | After first bootstrap checkpoint, read getLogConfig(rootLogId): kind == Authority, authLogId == rootLogId (self). | Test passes. |
| D.2 | `test/` | Publish first checkpoint to a **data** log (inclusion proof against authority log). Read getLogConfig(dataLogId): kind == Data, authLogId == authorityLogId. | Test passes. |
| D.3 | `test/` | Publish second checkpoint to the same data log. Verify inclusion is still checked (e.g. wrong proof reverts). Optionally assert getLogConfig(dataLogId).authLogId unchanged. | Test passes. |
| D.4 | `test/` | Tests that need config use getLogConfig(logId) (initializedAt, rootKey, kind, authLogId). Tests that need mutable state use getLogState(logId). For Foundry/invariants, ensure both mappings are covered where appropriate. | All existing tests pass; no regression. |
| D.5–D.8 | (Phase F) | See Phase F table. Create child authority; extend child; create data under child; extend data under child. | Hierarchy tests pass. |

### Phase F (optional): Authority log creation

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| F.1 | `IUnivocity.sol`, `Univocity.sol` | Add `ownerLogId` and `createAsAuthority` to PaymentGrant. Extend _leafCommitment inner hash to include both (document as new receipt format). | Grant struct and leaf binding support log-creation semantics. |
| F.2 | `Univocity.sol` — `publishCheckpoint` | First checkpoint to new log: when createAsAuthority, verify inclusion against ownerLogId (parent); set kind=Authority, authLogId=ownerLogId via _updateLogState. | New authority log created with parent link. |
| F.3 | `Univocity.sol` — `publishCheckpoint` | When target log exists and _logConfigs[logId].kind==Authority and _logConfigs[logId].authLogId!=0: verify inclusion against _logs[_logConfigs[logId].authLogId]; consistency against child's rootKey; no OnlyBootstrapAuthority. | Child authority extend path works. |
| F.4 | `Univocity.sol` — `_updateLogState` | When isNewLog and logId != authorityLogId: set kind = Authority if createAsAuthority else Data; set authLogId = ownerLogId. | Config set correctly for new data and new authority. |
| F.5 | `test/` | D.5: First checkpoint with createAsAuthority=true, ownerLogId=root, inclusion in root → getLogConfig(childId): kind==Authority, authLogId==root. D.6: Second checkpoint to child (inclusion in root). D.7: First checkpoint to data log with ownerLogId=childId → getLogConfig(dataId): kind==Data, authLogId==childId. D.8: Second checkpoint to that data log (inclusion in child). | Full root→child→data hierarchy covered. |

### Phase E: Remove checkpointCount from current implementation

| Step | Location | Action | Acceptance |
|------|----------|--------|------------|
| E.1 | `IUnivocity.sol`, `Univocity.sol` | Remove `checkpointCount` from `LogState` struct and from `_logs` storage. Grant bounds are enforced only via size: `_checkPaymentGrantBoundsMaxHeight(size, paymentGrant)` and `size >= currentSize + paymentGrant.minGrowth`. | LogState has accumulator and size only; no counter in state. |
| E.2 | `Univocity.sol` — `publishCheckpoint` | Remove call to `_checkPaymentGrantBoundsCheckpointRange`. Remove or repurpose `_checkPaymentGrantBoundsCheckpointRange`; grant no longer uses checkpointStart/checkpointEnd for bounds (max checkpoints implied by (maxHeight − currentSize) / minGrowth). | No checkpoint-range check; size and maxHeight/minGrowth define allowed publishes. |
| E.3 | `IUnivocityEvents.sol`, `Univocity.sol` | Remove `checkpointCount` parameter from `CheckpointPublished` event. Emit `size` only (observers use size as progression index). | Event signature and emit updated; no checkpointCount in events. |
| E.4 | `test/`, invariants | Update tests that assert on `getLogState(...).checkpointCount` to use `size` (or remove assertion). Update `invariant_checkpointCountMonotonic` to a size-monotonic invariant or remove. | All tests and invariants pass. |

**Note (Phase E):** PaymentGrant may retain `checkpointStart` and `checkpointEnd` in the struct and in the leaf commitment for receipt binding; they are simply not used for on-chain bounds. Alternatively, grant can be refactored to size-based fields in a follow-up.

---

## 5. File and symbol reference

| File | Symbols / lines to touch |
|------|---------------------------|
| `src/checkpoints/interfaces/IUnivocity.sol` | Add `enum LogKind`, `struct LogConfig` (initializedAt, rootKey, kind, authLogId), and `struct LogState` (accumulator, size only; no checkpointCount). Add `getLogConfig(logId)`. Add **ownerLogId** to PaymentGrant for log-creation; (Phase F) add **createAsAuthority** and extend leaf commitment. |
| `src/contracts/Univocity.sol` | Add mapping `_logConfigs(bytes32 => LogConfig)`. Use `_logs[logId]` for state, `_logConfigs[logId]` for config. `publishCheckpoint`: authForInclusion from _logConfigs; key for consistency receipt per §3.3 A (C.4); pass to _updateLogState. `_updateLogState`: when isNewLog set _logConfigs[logId] (initializedAt, kind, authLogId; rootKey set by setLogRoot). |
| `test/checkpoints/Univocity.t.sol` or equivalent | Add or extend tests for first bootstrap (getLogConfig: kind==Authority, authLogId==0), first data log (getLogConfig: kind==Data, authLogId==authorityLogId), and optionally second data checkpoint. |
| `test/integration/CheckpointFlow.t.sol` | If it asserts on LogState or getLogState/getLogConfig, update assertions to use getLogConfig(logId) for config and getLogState(logId) for state. |
| `test/invariants/Univocity.invariants.sol` | If invariants read log state or config, extend to use both mappings / getLogState and getLogConfig where appropriate. |
| (Phase E) `IUnivocity.sol`, `IUnivocityEvents.sol`, `Univocity.sol`, tests | Remove checkpointCount from LogState and from CheckpointPublished; remove _checkPaymentGrantBoundsCheckpointRange; grant bounds via size (maxHeight, minGrowth) only. |

---

## 6. Revert behaviour and edge cases

- **Existing logs (upgrade / no migration):** New deployment uses separate
  mappings `_logs` and `_logConfigs`. If upgrading an existing contract to
  the new layout, storage migration is required. To support legacy data logs
  after a layout change: when
  `_logConfigs[logId].authLogId == 0` and `_logConfigs[logId].initializedAt != 0` and
  `logId != authorityLogId`, treat as “legacy data log” and use
  `authorityLogId` for inclusion. Document in code comments.
- **Authority log:** Never use _logConfigs[logId].authLogId for inclusion
  when the log is the authority log (we only use authForInclusion in the data-log
  branch).
- **_logConfigs[logId].kind == 0:** Treat as undefined/not set (uninitialized
  or legacy log). When routing inclusion, if we ever read kind and need to
  branch, 0 should not match Authority or Data.

### 6.5 Security assessment and gaps (after four canonical rules)

The four rules in §3.3 address the previously raised gaps as follows.

**Addressed by the rules:**

1. **RootKey establishment:** Rule 1 — rootKey is established by the first checkpoint (stored from the signer/delegated key). No separate setLogRoot for initial setup; setLogRoot is for key rotation or later phases if needed.

2. **Grant = inclusion against owner:** Rule 2 — the grant is always an inclusion proof against the log's owner (parent for authority, authority for data). For first checkpoint we need the owner logId (authorityLogId for new data log; parent logId for new child authority — see remaining choice below).

3. **First checkpoint signature:** Rule 3 — for the first checkpoint, **direct** signature → store signing key as rootKey; **delegation** → store the **recovered rootKey** (the key that signed the delegation) as rootKey. Bootstrap uses bootstrap keys (rule 4).

4. **Bootstrap special case:** Rule 4 — grant against self, size > 1, bootstrap key signature, OnlyBootstrapAuthority. No other log has grant against self.

5. **OnlyBootstrapAuthority for child authority:** Child authority checkpoints are gated by inclusion proof in the parent and consistency signature from the child's rootKey (or key that becomes it). Any caller can submit with grant and valid signature; no OnlyBootstrapAuthority for child authority.

**Resolved: owner in grant for log creation**

When the grant **allows log creation** (first checkpoint to a new data log or
new authority log), the grant **must include the owner log**: for **data
log** creation the owner is its associated auth log; for **authority log**
creation the owner is its parent. So the grant carries an **ownerLogId**
(or equivalent) whenever it is used to create a log. The contract uses
`ownerLogId` from the grant as the log to verify the inclusion proof against
and sets `authLogId = ownerLogId` when applying the first checkpoint. No
separate design choice — owner is required in the grant for log-creation
grants.

---

## 7. Acceptance criteria (summary)

- [ ] `LogConfig` in `_logConfigs`; `LogState` has accumulator and size only in `_logs` (no checkpointCount); association by logId.
- [ ] First checkpoint that sets `authorityLogId` also sets _logConfigs[authorityLogId].kind = Authority, _logConfigs[authorityLogId].authLogId = 0.
- [ ] First checkpoint to any other log sets _logConfigs[logId].kind = Data (or Authority when Phase F createAsAuthority), _logConfigs[logId].authLogId from grant ownerLogId.
- [ ] Subsequent checkpoints to a data log use `_logConfigs[logId].authLogId` for inclusion verification; (Phase F) subsequent checkpoints to a child authority use parent (config.authLogId) for inclusion.
- [ ] Consistency receipt key selection per §3.3: first checkpoint → bootstrap keys (bootstrap) or verify and store **recovered rootKey** in delegation case (other logs); later → target's rootKey. Grant for log creation includes **ownerLogId**; delegation first-checkpoint grant may include both delegation and public root key (C.1, C.4).
- [ ] Grant bounds use size only (maxHeight, minGrowth); checkpointCount removed from state and events (Phase E). `getLogState(logId)` and `getLogConfig(logId)`; all existing tests pass.
- [ ] (Without Phase F) No change to proof format or leaf commitment. (Phase F) Leaf commitment extended for ownerLogId and createAsAuthority; permissionless submission unchanged.
- [ ] `forge build` and `forge test` pass. (Phase F) Hierarchy tests D.5–D.8 pass.

---

## 8. Related

- [ARC-0017 Phase 0](../arc/arc-0017-log-hierarchy-and-authority.md) — data structures and semantics.
- [ARC-0017 Appendix A](../arc/arc-0017-log-hierarchy-and-authority.md#appendix-a-features-we-cannot-implement-yet-due-to-current-choices) — features not implementable until after Phase 0 or later phases.
