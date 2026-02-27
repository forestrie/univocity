# ARC-0017: Log hierarchy and authority (revised for current implementation)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md),
[ARC-0016](arc-0016-checkpoint-incentivisation-implementation.md),
[ARC-0001](arc-0001-grant-minimum-range.md),
[plan-0012](../plans/plan-0012-arc-0016-implementation-review.md),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md)

This document describes the **log hierarchy and authority model** revised to be
consistent with the choices made in the current univocity implementation. It
defines how authority logs and data logs relate, how creation and extension
are gated by grants, and how the bootstrap authority works. An **initial
phase** focuses on the **data structures** required for the hierarchy. An
**appendix** lists features that cannot be implemented yet due to current
choices.

### Terminology

- **Root log / rootLogId:** The very first log, the root authority log.
  State variable `rootLogId`; set on the first successful
  `publishCheckpoint` from the bootstrap authority.
- **Auth log:** Any authority log (root or child). Extension is gated by a
  grant from the log’s **authLogId** (root: self; child: parent). Bootstrap
  is used only for the first checkpoint ever (creation of the root).
- **Data log:** Any log that is not an authority log. Extension is gated by
  a grant from its owning auth log. There is no explicit hierarchy of data
  logs; only the right to extend is hierarchical (based on auth logs).

---

## 1. Purpose

We need a clear model for:

- **Distinguishing** authority logs from data logs.
- **Ownership:** which data logs are owned by which authority log.
- **Creating** an authority log: requiring a specific grant from a parent
  log and maintaining that relationship.
- **Bootstrap authority:** how the right to establish and extend an authority
  log works.
- **Extending data logs:** how the right to publish checkpoints to a data
  log is tied to a grant from its owning authority log.

The current implementation has a **single** authority log and no explicit
hierarchy in the data model. This ARC aligns the target hierarchy with
current behaviour and specifies the minimal data structures (Phase 0) needed
to support it and any future multi-authority design.

---

## 2. Authorization rules

1. **RootKey** for every log is established by the **first checkpoint** for that log (not set beforehand). Direct signature → that key is stored as rootKey. Delegation → the **recovered rootKey** (the key that signed the delegation) is stored; the grant may need to supply both delegation and public root key.
2. **Grant** = inclusion proof against the log’s **owner** (authLogId): data
   log → owning authority log; authority log → parent log; **root** → self
   (authLogId = rootLogId, so grant is in the root log itself).
3. **First checkpoint** establishes the log’s **kind** and **authLogId**
   (owner). Any checkpoint’s signature or delegation must verify against that
   log’s established rootKey — or it is the first checkpoint, in which case
   the key (or recovered rootKey) is stored as rootKey.
4. **Bootstrap** is used only for the **first checkpoint ever** (no log
   exists yet): grant is self-inclusion (index 0, empty path) in the new
   tree, signature must verify with bootstrap keys (OnlyBootstrapAuthority).
   After that, the root has authLogId = rootLogId; root extension requires a
   grant (inclusion proof) in the root, like any other log.
5. **Log creation:** when a grant allows creating a log (first checkpoint to
   a new data or authority log), the grant must include the **owner logId**
   (auth log for data, parent for authority).

**How this governs log extension.** To extend a log (publish a checkpoint),
the caller must supply (a) a **grant** evidenced by an inclusion proof in
the **owner’s** log (config.authLogId: for the root, the root itself; for a
child authority, the parent; for a data log, the owning authority), and (b)
a **consistency receipt** whose signature or delegation verifies against
that log’s **established rootKey** (or, for the first checkpoint, establishes
it). The **root** is extended with a grant in the root (self-issued); a
child authority with a grant in the parent; a data log with a grant in its
owning authority. No log can be extended without both the owner’s grant and
the correct key for the target log. See [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md).

---

## 3. Current implementation constraints

The following choices are fixed in the current codebase and shape what we can
do without breaking changes:

| Constraint | Current state |
|------------|----------------|
| **Root log** | One. `rootLogId` is a single `bytes32`; set on first bootstrap
  checkpoint; no list of “auth logs.” |
| **Log type** | LogConfig.kind (Authority or Data). Root has kind Authority,
  authLogId = rootLogId (self). |
| **Ownership** | LogConfig.authLogId: for data logs = owning auth log; for
  auth logs = parent (root has self = rootLogId). |
| **Bootstrap authority** | One address, immutable (`bootstrapAuthority`).
  Only it may publish the **first checkpoint ever** (creates root). Root
  extension thereafter requires a grant in the root (permissionless).
  `setLogRoot` is **internal**; see [§ Root key rollover](#root-key-rollover). |
| **Grant evidence** | Pre-decoded inclusion proof (index, path) against the
  owner’s accumulator. No COSE Receipt of Inclusion. |

So today: **one root log**, **one bootstrap authority**. Non-root logs use
`config.authLogId` (owning or parent) for grant verification.

### Root key rollover

Key rollover is **not** implemented by exposing `setLogRoot` externally.
If we add rollover, it will be **PaymentGrant-based**: the checkpoint to be
published is signed by the **old** key; the PaymentGrant (or equivalent)
carries the **new** public key; if the publish succeeds (signature, grant,
bounds), the contract calls internal `_setLogRoot(logId, newKey)` once. There
is no requirement for `setLogRoot` to be externally callable for rollover.

---

## 4. Initial phase (Phase 0): Data structures for the hierarchy

Phase 0 defines the **on-chain data structures** needed to express the
hierarchy and to support future phases (e.g. multiple authority logs,
sub-authorities). No change to grant semantics or proof format in this phase;
only how we **identify** and **relate** logs.

### 4.1 Distinguishing authority logs from data logs

**Goal:** The contract must be able to tell “this log is an authority log”
from “this log is a data log” without relying only on `logId == rootLogId`.

**Proposed:**

- **Option A (minimal):** Keep a single `rootLogId` and treat “root log” as
  “the log whose id equals rootLogId.” All other logs are data logs or child
  auth logs. No new type field. (Current behaviour.)
- **Option B (extensible):** Introduce a **log kind** (e.g. enum or flag) on
  log state: `Authority` vs `Data`. When a log is created (first checkpoint),
  it is marked as Authority or Data depending on who created it and whether
  it was created via a “create authority” grant (see below). Then “is this an
  authority log?” is `log.config.kind == Authority` and we can later support
  multiple authority logs by having multiple logs with `kind == Authority`.

**Phase 0 recommendation:** Add a **log kind** to the stored state for each
log (e.g. in `LogState` or in a parallel structure keyed by logId). Values
**start at 1** so that 0 (storage default) means undefined/not set:
`Authority = 1` | `Data = 2`. The **root** authority log (today’s single
authority) is created by bootstrap and has kind `Authority`. Any log created
later via a grant from an authority log is either `Authority` (if the grant
is an “create child authority” grant) or `Data` (if the grant is a “publish
checkpoints” grant). This allows future multi-authority without a second
phase that retrofits a type, and distinguishes uninitialized state (0).

See §5 for LogConfig/LogState. Kind is set at first checkpoint:
    Authority for root or child; Data for data logs.

### 4.2 Single authLogId: owning (Data) or parent (Authority)

**Goal:** For every log we store one **authLogId** field. Its meaning
depends on **kind**: if kind is Data, authLogId is the **owning** authority
log (whose grants gate checkpoint publishing); if kind is Authority,
authLogId is the **parent** authority log (root has self = rootLogId).

**Proposed:**

- Add a single **authLogId** field per log. Interpretation:
  - **kind == Data:** authLogId = owning authority log (the authority log
    whose accumulator was used to verify the inclusion proof at log creation).
  - **kind == Authority:** authLogId = parent (root has self = rootLogId;
    for a future child authority, the log that issued the “create authority”
    grant).

**Concrete:**

- In **LogConfig** (and thus in `LogState.config`), include `bytes32
  authLogId`. Semantics:
  - For an **authority** log: config.authLogId = parent (root has self =
    rootLogId).
  - For a **data** log: config.authLogId = owning authority; set at first
    checkpoint to the authority logId used for the inclusion proof.
- When verifying a checkpoint for a data log, the contract uses
  `log.config.authLogId` (interpreted as owning) to select which authority
  log’s accumulator and size to use for the inclusion proof.

### 4.3 Creating an authority log: grant from parent and permanent relation

**Goal:** Creating a **new** authority log (child) must require a **specific
grant** from a parent log (today: the root authority log). The new authority
log **remains related** to that parent (e.g. for lifecycle or governance).

**Current limitation:** We do not yet support “create a new authority log.”
Only one authority log exists, created implicitly by the first bootstrap
checkpoint. So “creating an authority log” is out of scope for the current
implementation; Phase 0 only **defines the data structures** that would
support it.

**Proposed (for the data model):**

- **Parent authority:** For an **authority** log, the single **authLogId**
  field is interpreted as **parent**: the authority log that issued the
  “create child authority” grant. Root has authLogId = rootLogId (self). (For data logs, authLogId is
  owning; see 4.2.)
- **Grant type in leaf:** The authority log’s leaf commitment schema must
  support a **grant type** (or equivalent) so that a leaf can mean “you may
  create a new authority log” vs “you may publish checkpoints to data log X.”
  Today the leaf binds (logId, payer, range, bounds); for “create authority”
  we might bind (parentLogId, “new_authority”, delegatee or new log id, …).
  Phase 0 can restrict to **data structures** only: store authLogId on logs;
  the actual grant format and verification for “create authority” is a later
  phase.
- **Permanent relation:** Once an authority log is created, its authLogId
  (as parent) never changes. So the hierarchy is immutable from the
  contract’s perspective.

### 4.4 How the auth log and bootstrap authority work

**Goal:** Clarify how the **right to extend** the root and other authority
logs is determined.

**Unified model (per [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md)):**

- **First checkpoint ever:** Only `bootstrapAuthority` may publish. No log
  exists yet; grant is self-inclusion (index 0, empty path) in the new tree.
  This creates the root with `authLogId = rootLogId` (self).
- **Root extension (after creation):** Extension of the root requires a
  **grant** (inclusion proof) in the root log itself. `paymentGrant.ownerLogId
  == rootLogId` and the contract verifies inclusion against the root's
  accumulator. **No** `msg.sender == bootstrapAuthority` check; submission
  is permissionless (anyone with a valid grant in the root may extend).
- **Child authority extension (future):** Governed by §2: grant in the
  **parent** log; receipt verifiable against the child's rootKey. Phase 0
  adds authLogId (as parent); child authority creation is a later phase.
- **Root key updates:** Via rollover (internal `setLogRoot`), not by
  exposing setLogRoot externally.

**Summary:** Bootstrap is used only for **creating** the root. Every other
extension (root and non-root) is grant-based: inclusion proof against the
log's authLogId (root = self, others = parent or owner).

---

### 4.5 How the right to extend data logs is tied to a grant from the owning auth log

**Goal:** The right to publish checkpoints to a **data** log must be
**granted** by the log’s **owning** authority log (evidence = inclusion proof
in that authority log).

**Current behaviour:**

- There is one authority log. Every non-authority log is implicitly
  “owned” by it. The right to extend a data log is evidenced by an
  **inclusion proof** (index, path) against that authority log’s
  accumulator: the leaf in the proof is the commitment (paymentGrant +
  paymentIDTimestampBe). So “grant from the authority log” = “leaf
  committed in the authority log”; the contract verifies inclusion and
  bounds (checkpoint range, min_growth, max_height).

**Proposed (consistent and extensible):**

- **Ownership:** Each data log stores `authLogId` (interpreted as owning;
  see 4.2). The right to extend that data log is **always** evidenced by an
  inclusion proof against **that** authority log’s accumulator (and size).
  So “grant from owning auth log” = “inclusion proof against authLogId’s
  MMR.”
- **No change to proof format:** We keep pre-decoded inclusion proof (index,
  path) and the same leaf commitment formula. The contract uses
  `_logs[log.config.authLogId]` for grant verification (owning for data logs;
  for the root, authLogId is the root itself).
- **Authority log extension:** Root and child authority are both gated by a
  **grant** (inclusion proof) from the log’s authLogId (root: self; child:
  parent). So the hierarchy is: (1) root is extended by anyone with a valid
  grant in the root; (2) child authority (future) by anyone with a valid
  grant in the parent; (3) data logs by anyone with a valid grant from the
  owning authority log.

**Phase 0 concrete:**

- LogConfig and authLogId as in §5. For a data log first checkpoint, set
  authLogId from the grant ownerLogId (today the single rootLogId). Use the
  log authLogId when verifying inclusion for that log's checkpoints (owning
  for data logs).

---

## 5. Phase 0 summary: state additions

**LogConfig** — parameters that do not change after the log is created:

| Field | Meaning |
|-------|--------|
| **initializedAt** | Block number of first checkpoint. |
| **rootKey** | Root public key (e.g. 64-byte P-256). **Established at first checkpoint** (§2 rule 1): direct signature → that key; delegation → recovered rootKey. setLogRoot may be used for rotation later. |
| **kind** | 0 = undefined/not set; Authority = 1; Data = 2. Set at first checkpoint. |
| **authLogId** | If kind == Data: **owning** authority log. If kind == Authority: **parent**
  (root has **self** = rootLogId). Set at first checkpoint from grant
  **ownerLogId** when grant allows log creation (§2 rule 5). |

**LogState** — holds mutable state (accumulator, size). Immutable-per-log fields live in **LogConfig** (nested or in a separate mapping keyed by logId; see plan-0021). Grant bounds are enforced via size only (max_size, min_range); no separate checkpoint counter.

Global `rootLogId` identifies the root authority log. When we introduce
multiple auth logs, we use `config.kind` to find all authority logs.

---

## 6. Critical ambiguities

- **Storage layout:** This ARC and plan-0021 describe LogConfig as either nested in LogState or in a **separate mapping** keyed by logId. Implementations must be consistent; plan-0021 uses separate mappings. Any reference to `log.config` in this ARC should be read as "config for that logId" (same key in the config mapping).
- **Grant bounds:** Grants are strictly limited by **state growth**: max_size (max log size under the grant) and min_range (minimum size increase per checkpoint). The effective cap on checkpoints under a grant is (max_size − current_size) / min_range. No separate checkpoint counter; size alone governs.
- **Grant payload for log creation:** The exact shape of ownerLogId in the grant (e.g. new field on PaymentGrant, or in the leaf commitment) is left to the implementation; §2 rule 5 requires that the owner log be identified when the grant allows creating a log.

---

## 7. Security model (holistic assessment)

**Trust root:** The bootstrap authority (one address) and bootstrap keys.
The root is created by the bootstrap (first checkpoint ever); thereafter,
root extension is gated by a **grant in the root** (self-issued), not by
identity. So every extension (including root) has on-chain grant evidence.

**Two gates for extension:** To extend any non-bootstrap log, a caller must satisfy **both** (a) **Grant:** an inclusion proof in the **owner's** log (parent for authority, owning authority for data), and (b) **Consistency receipt:** a signature or delegation verifiable against that log's **established rootKey** (or, on first checkpoint, a key that is then stored as rootKey). An attacker who holds a grant but not the log's key cannot extend the log; an attacker who holds the key but has no grant cannot pass the inclusion check. The hierarchy is enforced by key selection: child authority's rootKey is set at creation (from parent's delegation or recovered rootKey); data log's rootKey is set at creation (from signer or owner's delegation).

**Limitations:** There is **no revocation list** in the current design: once a grant (leaf) is in an authority log's MMR, it is valid until **consumed**. Grants are **growth-bounded** (max_size, min_range): they allow only a limited amount of log growth; after that, a new grant is required. Revocation (explicit invalidation) would require a later phase (see §9). The root authority is a single point of trust: compromise of the bootstrap authority or keys allows full control of the root log and thus of all grants issued from it.

---

## 8. Incentivisation and value flow

**Structured incentivisation:** The model supports structured value flow. Grants are evidenced by leaves in an authority log; the leaf commitment binds (logId, payer, bounds, …), so **who paid** is on-chain. Value flows to whoever controls inclusion in the authority log: they decide which grants (payments) to include. So (1) **Root authority** can issue grants for data logs (and, in a later phase, for child authorities); payers pay the root (or its operator) for those grants. (2) **Child authority** (when implemented) can issue grants for its own data logs; payers pay that child's operator. (3) **Extension of a child authority** requires a grant from the parent — so the parent can charge or gate the child's growth. The hierarchy therefore allows **tiered incentivisation**: root earns from grants it issues; child authorities earn from grants they issue for their data logs; parent can require payment or policy for child extension. **Value flow** is clear: payment → grant (leaf in authority log) → right to publish checkpoints to a specific log (or create a log). The design does **not** by itself define who receives the payment (that is an off-chain or separate contract choice); it does ensure that the **grant** is the on-chain proof of the right to publish and that the owner of the log (authority) is the one whose tree must contain that grant.

---

## 9. Revocation and grant consumption: expiring misbehaving authority and their data logs

**Grant bounds are growth-based, not time-based.** Grants are strictly limited by **state growth**: **max_size** (maximum log size under the grant) and **min_range** (minimum size increase per checkpoint). A grant allows a **bounded amount of log growth**; the effective cap on checkpoints under that grant is (max_size − current_size) / min_range. After that growth is consumed, a **new grant** (new leaf in the owner's log) is required. There is **no time-bound expiry**; grants are consumed by use.

**Current state:** There is **no revocation list**: once a leaf is in an authority log's MMR, it remains valid until **consumed** (until the bounded growth is used). We cannot today explicitly revoke a grant on-chain (Appendix A.6).

**Expiring a misbehaving authority log (child):** An authority log (child) is extended only when someone presents a **grant in the parent's** log. So the **parent** controls whether the child can grow: if the parent **stops issuing new grants** that allow extending the child, the child cannot receive further checkpoints. The child's tree is then frozen (no new leaves). So **yes**, the model allows the parent to **expire a misbehaving child authority** by no longer issuing extension grants. No additional "expiry" mechanism is required for this.

**Expiring all data logs that authority created:** Data logs owned by that authority need **grants that are leaves in that authority's log**. Each grant allows only **bounded growth** (up to max_size, with min_range per checkpoint). So each grant is **consumed** as the data log grows. When a data log has consumed its grant (reached the size bound), it needs a **new** grant — i.e. a new leaf in the authority's tree. If the parent has stopped issuing extension grants to that authority, the **authority's tree cannot grow**, so the authority **cannot add new leaves** (new grants) for its data logs. Therefore: (1) Existing grants in the authority's tree remain valid until **consumed** (until each data log grows to its grant's max_size). (2) Once those grants are consumed, those data logs need new grants — but the authority cannot issue them (its tree is frozen). (3) So **all data logs owned by that authority ultimately become unextendable**: first they consume their current grants, then they cannot obtain new ones. **Expiry of the misbehaving authority (parent stops extension grants) therefore ultimately expires all data logs that authority has created**, via grant consumption. No time-based expiry is required; the growth-bounded nature of grants plus the frozen authority tree is sufficient.

**Summary:** Grants are **growth-bounded** (max_size, min_range), not time-bound. The current design does **not** implement an explicit revocation list. The model **already** supports expiring a misbehaving child authority (parent stops extension grants) and, as a consequence, **all data logs owned by that authority** become unextendable once they have consumed their existing grants, because the frozen authority cannot issue new ones.

---

## 10. Later phases (out of scope for this ARC)

- **Multiple authority logs:** Creating a new authority log via a “create
  authority” grant from a parent; storing per–authority log bootstrap
  address.
- **Grant type / schema:** Extending the leaf commitment or proof format to
  distinguish “create authority” vs “publish to data log” grants.
- **Lifecycle / revocation:** Explicit revocation of grants (grants are
  already growth-bounded; see §9 for consumption and freezing authority).

---

## Appendix A: Features we cannot implement yet due to current choices

The following features are **not** implementable without breaking or
significant changes, given the current implementation choices. This list
should be used when prioritising Phase 0 vs later work or when updating
devdocs.

1. **Multiple authority logs**  
   Current: single `rootLogId`. We cannot add a second auth log without new
   state and logic to choose which auth log to use for a given data log.
   Phase 0’s `authLogId` and `kind` prepare for this but do not implement it.

2. **Creating an authority log via a grant**  
   Current: the only authority log is created by the bootstrap authority’s
   first checkpoint; there is no “create child authority” grant or flow. We
   cannot implement “create a new authority log by proving a grant from
   parent” until we have (a) a grant type or leaf schema for “create
   authority,” (b) state for parent/child relation (authLogId when kind is
   Authority), and (c) a per–auth log bootstrap authority if child
   authorities have their own bootstrap.

3. **Explicit “auth log vs data log” in the API**  
   Current: callers pass any logId; the contract uses config.kind and
   config.authLogId. “List auth logs” or “list data logs under authority X”
   requires iterating or an index (Phase 0 adds the fields).

4. **Per–authority log bootstrap authority**  
   Current: one global `bootstrapAuthority`. We cannot assign different
   bootstrap addresses to different authority logs without new state (e.g.
   mapping logId → bootstrap address) and logic to resolve “who may extend
   this authority log.”

5. **Ownership-based routing of grants**  
   Current: every data log’s grant is verified against the single
   authority log. We cannot “route” a data log’s inclusion proof to the
   correct authority log without storing `authLogId` (as owning) and using
   it in verification (Phase 0 adds the field for this).

6. **Revoking grants**  
   Current: grants are evidenced by inclusion in the authority MMR; once a
   leaf is in the tree, it is valid until **consumed** (grants are
   growth-bounded by max_size and min_range, not time). We cannot
   **explicitly revoke** a grant without a separate revocation structure
   (not in scope for Phase 0). See **§9** for how growth-bounded consumption
   plus the parent stopping extension grants ultimately makes all data logs
   owned by a misbehaving child authority unextendable.

7. **Query: “which data logs belong to authority X?”**  
   By design, enumerating logs by owner is an **off-chain concern**. The
   event-sourced model (CheckpointPublished, LogRegistered, etc.) enables
   indexers to build and maintain such mappings efficiently. The contract
   stores `config.authLogId` per log (Phase 0) but does not maintain an
   on-chain index; the design reflects this.

8. **Hierarchy visualization or governance**  
   Current: no parent/child. We cannot support “parent chain” or
   governance over a subtree without `authLogId` (as parent for authority
   logs, owning for data logs) as in Phase 0.

Phase 0 (data structures: kind + single authLogId) addresses the foundation
for 1, 2 (partial), 3, 5, 7 (partial), and 8 (partial). It does not by
itself implement multiple authority logs, create-authority grants, per-log
bootstrap, or revocation.
