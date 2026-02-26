# ARC-0017: Log hierarchy and authority (revised for current implementation)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ARC-0016](arc-0016-checkpoint-incentivisation-implementation.md),
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
2. **Grant** = inclusion proof against the log’s **owner**: data log → owning authority log; authority log → parent log; bootstrap → special case (grant against self).
3. **First checkpoint** establishes the log’s **kind** and **authLogId** (owner). Any checkpoint’s signature or delegation must verify against that log’s established rootKey — or it is the first checkpoint, in which case the key (or recovered rootKey) is stored as rootKey.
4. **Bootstrap** is the only special case: grant is inclusion against itself (first leaf in the new tree), first checkpoint must have size > 1, signature must verify with bootstrap keys (OnlyBootstrapAuthority).
5. **Log creation:** when a grant allows creating a log (first checkpoint to a new data or authority log), the grant must include the **owner logId** (auth log for data, parent for authority).

**How this governs log extension.** To extend a log (publish a checkpoint), the caller must supply (a) a **grant** evidenced by an inclusion proof in the **owner’s** log (so the owner has authorized this publish), and (b) a **consistency receipt** whose signature or delegation verifies against that log’s **established rootKey** (or, for the first checkpoint, establishes it). The bootstrap log is extended only by the bootstrap authority with a self-referential grant and bootstrap-key signature. A child authority is extended only with a grant in the parent and a receipt verifiable against the child’s rootKey (set at creation from the parent’s delegation). A data log is extended only with a grant in its owning authority and a receipt verifiable against the data log’s rootKey. No log can be extended without both the owner’s grant and the correct key for the target log.

---

## 3. Current implementation constraints

The following choices are fixed in the current codebase and shape what we can
do without breaking changes:

| Constraint | Current state |
|------------|----------------|
| **Authority log count** | One. `authorityLogId` is a single `bytes32`; set on first bootstrap checkpoint; no list of “auth logs.” |
| **Log type** | No explicit type. Every log has the same `LogState` (accumulator, size, and a config struct). The only distinction is “is this logId == authorityLogId?” |
| **Ownership** | None. There is no field linking a data log to an authority log. Grants are evidenced by an inclusion proof against **the** authority log. |
| **Parent for auth log** | N/A. The single authority log has no parent; it is created by the contract’s bootstrap authority in the first checkpoint. |
| **Bootstrap authority** | One address, immutable (`bootstrapAuthority`). Only it may publish to the authority log and call `setLogRoot`. |
| **Grant evidence** | Pre-decoded inclusion proof (index, path) against the authority log accumulator. No COSE Receipt of Inclusion. |

So today: **one authority log**, **one bootstrap authority**, **no stored
ownership or parent-child relation**. “Which logs belong to which authority”
is implicit: all non-authority logs use the single `authorityLogId` for
grant verification.

---

## 4. Initial phase (Phase 0): Data structures for the hierarchy

Phase 0 defines the **on-chain data structures** needed to express the
hierarchy and to support future phases (e.g. multiple authority logs,
sub-authorities). No change to grant semantics or proof format in this phase;
only how we **identify** and **relate** logs.

### 4.1 Distinguishing authority logs from data logs

**Goal:** The contract must be able to tell “this log is an authority log”
from “this log is a data log” without relying only on `logId ==
authorityLogId`.

**Proposed:**

- **Option A (minimal):** Keep a single `authorityLogId` and treat “authority
  log” as “the log whose id equals authorityLogId.” All other logs are data
  logs. No new type field. (Current behaviour.)
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
authLogId is the **parent** authority log (zero for root).

**Proposed:**

- Add a single **authLogId** field per log. Interpretation:
  - **kind == Data:** authLogId = owning authority log (the authority log
    whose accumulator was used to verify the inclusion proof at log creation).
  - **kind == Authority:** authLogId = parent authority log (zero for root;
    for a future child authority, the log that issued the “create authority”
    grant).

**Concrete:**

- In **LogConfig** (and thus in `LogState.config`), include `bytes32
  authLogId`. Semantics:
  - For an **authority** log: config.authLogId = parent (root has 0).
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
  “create child authority” grant. Root authority has `authLogId ==
  bytes32(0)`. (For data logs, authLogId is owning; see 4.2.)
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

### 4.4 How the auth log bootstrap authority works

**Goal:** Clarify how the **right to extend the authority log** and to
perform bootstrap-only actions is determined.

**Current behaviour:**

- **Single bootstrap authority:** One address, `bootstrapAuthority`, set at
  deployment. It is the only address that may:
  - Publish the first checkpoint (which sets `authorityLogId`), and
  - Publish any subsequent checkpoint to the authority log (when
    `paymentGrant.logId == authorityLogId`).
- **No grant for authority log:** The authority log does not require an
  inclusion proof; the contract checks `msg.sender == bootstrapAuthority`
  instead. So “bootstrap authority” = identity-based right to extend the
  authority log and to call `setLogRoot` for any log.

**Proposed (consistent with current implementation):**

- The **root** authority log has no grant-based gate: only the contract’s
  bootstrap authority may extend it. This remains the rule.
- - For a **future child** authority log, extension is governed by §2: the
  caller must supply (a) a **grant** (inclusion proof in the **parent**
  log) and (b) a **consistency receipt** verifiable against the **child's**
  established rootKey. There is no separate "per-log bootstrap address" for
  the child — anyone with a valid grant in the parent and the child's key
  (or delegation) may extend the child. Phase 0 only adds authLogId (as
  parent); child authority creation is a later phase.

**Summary for Phase 0:** The **root** authority log's bootstrap authority
is the single `bootstrapAuthority` immutable. No change to that. Add state
so that a **future** authority log can have authLogId as parent.

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
  path) and the same leaf commitment formula. The only change is that the
  contract uses `_logs[log.config.authLogId]` (owning) instead of
  `_logs[authorityLogId]` when the log is a data log (redundant while there
  is only one authority log).
- **Authority log extension:** Still gated by bootstrap authority only (no
  inclusion proof). So the hierarchy is: (1) authority logs are extended
  by their bootstrap authority; (2) data logs are extended by anyone who
  holds a valid grant (inclusion proof) from the owning authority log.

**Phase 0 concrete:**

- LogConfig and authLogId as in §5. For a data log first checkpoint, set authLogId from the grant ownerLogId (today the single authorityLogId). Use the log authLogId when verifying inclusion for that log's checkpoints (owning for data logs).

---

## 5. Phase 0 summary: state additions

**LogConfig** — parameters that do not change after the log is created:

| Field | Meaning |
|-------|--------|
| **initializedAt** | Block number of first checkpoint. |
| **rootKey** | Root public key (e.g. 64-byte P-256). **Established at first checkpoint** (§2 rule 1): direct signature → that key; delegation → recovered rootKey. setLogRoot may be used for rotation later. |
| **kind** | 0 = undefined/not set; Authority = 1; Data = 2. Set at first checkpoint. |
| **authLogId** | If kind == Data: **owning** authority log. If kind == Authority: **parent** (zero for root). Set at first checkpoint from grant **ownerLogId** when grant allows log creation (§2 rule 5). |

**LogState** — holds mutable state (accumulator, size). Immutable-per-log fields live in **LogConfig** (nested or in a separate mapping keyed by logId; see plan-0021). Grant bounds are enforced via size only (max_size, min_range); no separate checkpoint counter.

Global `authorityLogId` can remain for “root” authority until we introduce
multiple authority logs; then we may treat it as “root authority log id”
and use `config.kind` to find all authority logs.

---

## 6. Critical ambiguities

- **Storage layout:** This ARC and plan-0021 describe LogConfig as either nested in LogState or in a **separate mapping** keyed by logId. Implementations must be consistent; plan-0021 uses separate mappings. Any reference to `log.config` in this ARC should be read as "config for that logId" (same key in the config mapping).
- **Grant bounds:** Grants are strictly limited by **state growth**: max_size (max log size under the grant) and min_range (minimum size increase per checkpoint). The effective cap on checkpoints under a grant is (max_size − current_size) / min_range. No separate checkpoint counter; size alone governs.
- **Grant payload for log creation:** The exact shape of ownerLogId in the grant (e.g. new field on PaymentGrant, or in the leaf commitment) is left to the implementation; §2 rule 5 requires that the owner log be identified when the grant allows creating a log.

---

## 7. Security model (holistic assessment)

**Trust root:** The bootstrap authority (one address) and bootstrap keys. The root authority log is the only log that does not require a grant from another log; extension is gated by identity (OnlyBootstrapAuthority) and a self-referential grant (first leaf in the tree).

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
   Current: single `authorityLogId`. We cannot add a second authority log
   without new state (e.g. a set or list of authority logIds, or the `kind`
   + `authLogId` model above) and new logic to choose which authority log to
   use for a given data log. Phase 0’s `authLogId` and `kind` prepare for
   this but do not implement it.

2. **Creating an authority log via a grant**  
   Current: the only authority log is created by the bootstrap authority’s
   first checkpoint; there is no “create child authority” grant or flow. We
   cannot implement “create a new authority log by proving a grant from
   parent” until we have (a) a grant type or leaf schema for “create
   authority,” (b) state for parent/child relation (authLogId when kind is
   Authority), and (c) a per–auth log bootstrap authority if child
   authorities have their own bootstrap.

3. **Explicit “auth log vs data log” in the API**  
   Current: no type is exposed; callers pass any logId and the contract
   treats “authority log” as logId == authorityLogId. We cannot expose
   “list authority logs” or “list data logs under authority X” without
   storing kind and ownership (Phase 0).

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
   Current: no stored ownership. We cannot answer this without storing
   `authLogId` (Phase 0, as owning for data logs) and either iterating logs
   or maintaining an index (e.g. mapping authLogId → list of data logIds),
   which is a further enhancement.

8. **Hierarchy visualization or governance**  
   Current: no parent/child. We cannot support “parent chain” or
   governance over a subtree without `authLogId` (as parent for authority
   logs, owning for data logs) as in Phase 0.

Phase 0 (data structures: kind + single authLogId) addresses the foundation
for 1, 2 (partial), 3, 5, 7 (partial), and 8 (partial). It does not by
itself implement multiple authority logs, create-authority grants, per-log
bootstrap, or revocation.
