# ARC-0017: Log hierarchy and authority (revised for current implementation)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Overview:** [ARC-0017 authorization model (diagrams)](arc-0017-auth-overview.md)  
**Related:** [Canopy — Grants (off-chain Forestrie-_grant, verification vs ingestion)](https://github.com/forestrie/canopy/blob/main/docs/grants.md),
[ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md),
[ARC-0016](arc-0016-checkpoint-incentivisation-implementation.md),
[ARC-0001](arc-0001-grant-minimum-range.md),
[plan-0012](../history/plans/plan-0012-arc-0016-implementation-review.md) (historical),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md)

This document describes the **log hierarchy and authority model** revised to be
consistent with the choices made in the current univocity implementation. It
defines how authority logs and data logs relate, how creation and extension
are gated by grants, and how the bootstrap (key-signed first checkpoint) works. An **initial
phase** focuses on the **data structures** required for the hierarchy. An
**appendix** lists features that cannot be implemented yet due to current
choices.

### Terminology

- **Root log / rootLogId:** The very first log, the root authority log.
  State variable `rootLogId`; set on the first successful
  `publishCheckpoint` signed by the bootstrap key.
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

The contract keeps a **unique bootstrap root** (`rootLogId`). The hierarchy is
explicit in **LogConfig**: each log has **kind** (`Authority` | `Data`) and
**authLogId** (parent for authority logs, owning authority for data logs). **Child
authority logs** (new `logId` with `kind = Authority`, parent issued the create
grant) are supported; see §4.3 and Appendix A. This ARC aligns naming and rules
with that model and records Phase 0 state plus later work.

---

## 2. Authorization rules

1. **RootKey** for every log is established by the **first checkpoint** for that log (not set beforehand). The signer key is supplied in **grantData** (verify-only; no on-chain key recovery). The contract verifies the receipt (and, with delegation, the delegation proof) against that key and stores it as rootKey.
2. **Grant** = inclusion proof against the log’s **owner** (authLogId): data
   log → owning authority log; authority log → parent log; **root** → self
   (authLogId = rootLogId, so grant is in the root log itself).
3. **First checkpoint** establishes the log’s **kind** and **authLogId**
   (owner). Kind is set from the grant’s **request** (GC_AUTH_LOG or
   GC_DATA_LOG); request must be allowed by the grant flags. Any checkpoint’s
   signature or delegation must verify against that log’s established rootKey
   — or it is the first checkpoint, in which case the key from grantData is
   verified and stored as rootKey.
4. **Bootstrap** is used only for the **first checkpoint ever** (no log
   exists yet): grant is self-inclusion (index 0; path length up to
   MAX_HEIGHT) in the new tree; receipt signer must match bootstrap key
   (prevents front-running). After that, the root
   has authLogId = rootLogId; root extension requires a grant (inclusion
   proof) in the root, like any other log.
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
  checkpoint. Enumerating authority logs is an off-chain indexer concern
  (see [§ Enumerating authority logs](#enumerating-authority-logs-off-chain-indexer-concern)). |
| **Log type** | LogConfig.kind (Authority or Data). Root has kind Authority,
  authLogId = rootLogId (self). |
| **Ownership** | LogConfig.authLogId: for data logs = owning auth log; for
  auth logs = parent (root has self = rootLogId). |
| **Bootstrap** | The **first checkpoint ever** (creates root) is accepted only if
  the **receipt signer** matches the bootstrap key (constructor key). The
  **caller** (msg.sender) is not checked — submission is permissionless.
  Root extension thereafter requires a grant in the root (permissionless).
  `setLogRoot` is **internal**; see [§ Root key rollover](#root-key-rollover). |
| **Grant evidence** | Pre-decoded inclusion proof (index, path) against the
  owner’s accumulator. No COSE Receipt of Inclusion. |

So today: **one root log**; bootstrap is key-only (no address). Non-root logs use
`config.authLogId` (owning or parent) for grant verification.

### Enumerating authority logs: off-chain indexer concern

The contract does **not** maintain a list of authority log ids. Discovering
which logIds are authority logs is an **off-chain indexer concern**. Any
indexer that processes `CheckpointPublished` (and, for new logs,
`LogRegistered`) can derive the set of authority logs: for each logId that
appears in those events, the indexer may call `getLogConfig(logId)` and treat
`config.kind == Authority` as an authority log. The root is identified by
`rootLogId`. No on-chain enumeration is required.

### Root key rollover

Key rollover is **not** implemented by exposing `setLogRoot` externally.
If we add rollover, it will be **PublishGrant-based**: the checkpoint to be
published is signed by the **old** key; the PublishGrant (or equivalent)
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

**Implemented:** Creating a **child** authority log via a grant from a parent
is supported: the first checkpoint to the new `logId` carries an inclusion proof
in the **parent** authority log, **request** selects `GC_AUTH_LOG`, and
**grantData** supplies the child’s initial **rootKey** (see [auth overview §7.5](arc-0017-auth-overview.md#75-subsequent-log-operator-first-checkpoint-create-log)).
The root remains the only log whose **first checkpoint ever** uses the
**bootstrap** key.

**Data model (parent relation):**

- **Parent authority:** For an **authority** log, the single **authLogId**
  field is interpreted as **parent**: the authority log that issued the
  “create child authority” grant. Root has authLogId = rootLogId (self). (For data logs, authLogId is
  owning; see 4.2.)
- **Leaf / grant shape:** **GF\_\*** / **GC\_\*** (and **ownerLogId**) distinguish
  “create child authority” vs “create / extend data log” at the **first**
  checkpoint; see §2 and [auth overview §6](arc-0017-auth-overview.md#6-grant-vs-request-first-checkpoint-log-kind).
- **Permanent relation:** Once an authority log is created, its authLogId
  (as parent) never changes. So the hierarchy is immutable from the
  contract’s perspective.

### 4.4 How the auth log and bootstrap work

**Goal:** Clarify how the **right to extend** the root and other authority
logs is determined.

**Unified model (per [ADR-0004](../adr/adr-0004-root-log-self-grant-extension.md)).**
For payment evidence (path length, bootstrap signer) see
[ARC-0016](arc-0016-checkpoint-incentivisation-implementation.md) §2.2, §3.1.

- **First checkpoint ever:** No log exists yet; grant is self-inclusion
  (index 0; path length up to MAX_HEIGHT); receipt signer must match
  bootstrap key (signer key from grantData; verify-only; grantData must equal
  bootstrap key bytes). Submission is permissionless. This creates the root
  with `authLogId = rootLogId` (self).
- **Root extension (after creation):** Extension of the root requires a
  **grant** (inclusion proof) in the root log itself. `publishGrant.ownerLogId
  == rootLogId` and the contract verifies inclusion against the root's
  accumulator. **No** caller check; submission
  is permissionless (anyone with a valid grant in the root may extend).
- **Child authority extension:** Governed by §2: grant (inclusion proof) in the
  **parent** log; consistency receipt verifiable against the child’s stored
  **rootKey** (or delegate).
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

- Each log’s **config.authLogId** selects the accumulator used for **grant**
  verification: for a **data** log, the **owning** authority log; for an
  **authority** log (including the root), the **parent** (root uses **self**).
  The right to extend a data log is an **inclusion proof** against **that**
  authority log’s accumulator. Deployments may have only **root + data** logs,
  or **root + child authorities + data** under them; the same rule applies per
  `authLogId`.

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
| **rootKey** | Root public key (e.g. 64-byte P-256). **Established at first checkpoint** (§2 rule 1): key from grantData (verify-only) verified and stored. setLogRoot may be used for rotation later. |
| **kind** | 0 = undefined/not set; Authority = 1; Data = 2. Set at first checkpoint. |
| **authLogId** | If kind == Data: **owning** authority log. If kind == Authority: **parent**
  (root has **self** = rootLogId). Set at first checkpoint from grant
  **ownerLogId** when grant allows log creation (§2 rule 5). |

**LogState** — holds mutable state (accumulator, size). Immutable-per-log fields live in **LogConfig** (nested or in a separate mapping keyed by logId; see plan-0021). Grant bounds are enforced via size only (max_size, min_range); no separate checkpoint counter.

Global `rootLogId` identifies the root authority log. Enumerating authority
logs is an off-chain indexer concern (see
[§ Enumerating authority logs](#enumerating-authority-logs-off-chain-indexer-concern)).

---

## 6. Critical ambiguities

- **Storage layout:** This ARC and plan-0021 describe LogConfig as either nested in LogState or in a **separate mapping** keyed by logId. Implementations must be consistent; plan-0021 uses separate mappings. Any reference to `log.config` in this ARC should be read as "config for that logId" (same key in the config mapping).
- **Grant bounds:** Grants are strictly limited by **state growth**: max_size (max log size under the grant) and min_range (minimum size increase per checkpoint). The effective cap on checkpoints under a grant is (max_size − current_size) / min_range. No separate checkpoint counter; size alone governs.
- **Grant payload for log creation:** The exact shape of ownerLogId in the grant (e.g. new field on PublishGrant, or in the leaf commitment) is left to the implementation; §2 rule 5 requires that the owner log be identified when the grant allows creating a log.

---

## 7. Security model (holistic assessment)

**Trust root:** The bootstrap key (constructor key).
The root is created by the bootstrap (first checkpoint ever); thereafter,
root extension is gated by a **grant in the root** (self-issued), not by
identity. So every extension (including root) has on-chain grant evidence.

**Two gates for extension:** To extend any non-bootstrap log, a caller must satisfy **both** (a) **Grant:** an inclusion proof in the **owner's** log (parent for authority, owning authority for data), and (b) **Consistency receipt:** a signature or delegation verifiable against that log's **established rootKey** (or, on first checkpoint, a key that is then stored as rootKey). An attacker who holds a grant but not the log's key cannot extend the log; an attacker who holds the key but has no grant cannot pass the inclusion check. The hierarchy is enforced by key selection: child authority's rootKey is set at creation (from grantData, verify-only); data log's rootKey is set at creation (from grantData, verify-only).

**Limitations:** There is **no revocation list** in the current design: once a grant (leaf) is in an authority log's MMR, it is valid until **consumed**. Grants are **growth-bounded** (max_size, min_range): they allow only a limited amount of log growth; after that, a new grant is required. The absence of a revocation list is a **deliberate design choice**, not a missing feature — see the design-rationale note in §9 for why forward non-renewal plus monitoring is preferred over a CRL/OCSP-style revocation list. The root authority is a single point of trust: compromise of the bootstrap key allows full control of the root log and thus of all grants issued from it. The bootstrap key may itself be an **ERC-1271 smart-account signer (e.g. a multisig)** rather than a single EOA — validated on-chain via `isValidSignature` (see [auth overview §3](arc-0017-auth-overview.md#3-checkpoint-signers-who-signs-the-receipt)) — so the M-of-N threshold protecting the root is a deployment/config choice, not pinned by the contract.

---

## 8. Incentivisation and value flow

**Structured incentivisation:** The model supports structured value flow. Grants are evidenced by leaves in an authority log; the leaf commitment binds (logId, payer, bounds, …), so **who paid** is on-chain. Value flows to whoever controls inclusion in the authority log: they decide which grants (payments) to include. So (1) **Root authority** can issue grants for data logs (and, in a later phase, for child authorities); payers pay the root (or its operator) for those grants. (2) **Child authority** (when implemented) can issue grants for its own data logs; payers pay that child's operator. (3) **Extension of a child authority** requires a grant from the parent — so the parent can charge or gate the child's growth. The hierarchy therefore allows **tiered incentivisation**: root earns from grants it issues; child authorities earn from grants they issue for their data logs; parent can require payment or policy for child extension. **Value flow** is clear: payment → grant (leaf in authority log) → right to publish checkpoints to a specific log (or create a log). The design does **not** by itself define who receives the payment (that is an off-chain or separate contract choice); it does ensure that the **grant** is the on-chain proof of the right to publish and that the owner of the log (authority) is the one whose tree must contain that grant.

**Forward design (aim) — extending operator incentivisation to monitor incentivisation.** The value flow above incentivises **operators** (who publish checkpoints and issue grants). The **aim** — forward design, not implemented — is to extend the same structured, per-log value flow to **monitors**: the independent parties who watch the public log for signer self-equivocation, divergence across roots, and withheld data. This matters because, under a detection-based (rather than gatekeeping) model, the honest residual trust is the **monitor ecosystem** (see §9), not the trust model itself. **No incentivised monitor set exists today**, and this is a known-hard problem: classic transparency systems such as Certificate Transparency — despite large operator backing — have struggled to durably incentivise independent monitoring. The bet is that **agentic use cases change the economics**: an agent verifying a counterparty already reads the log, so agents are natural monitors, and monitoring can be funded as a **flywheel between monitors ↔ statement-makers ↔ operators** rather than appointed and subsidised. Mechanically this is the same **permissionless, bonded participation** that would decentralise the operator set — operators and monitors admitted by objective stake/slashing rather than gatekeeper discretion (validator-set-grade *participation*, though this is a staked attestation/monitoring network, not a BFT consensus set). Its one structural bound is **objective adjudication**: integrity faults (equivocation, broken consistency, an invalid signature) are objectively provable and so slashable permissionlessly, whereas **data-availability faults need a DA scheme** (sampling / erasure coding) to adjudicate — absent that, DA-monitoring stays reputational. There is no structural reason monitor incentivisation cannot be done neutrally on the same value-flow mechanism; designing it is future work. This note records the intent only; nothing here is enforced on-chain today.

---

## 9. Revocation and grant consumption: expiring misbehaving authority and their data logs

**Grant bounds are growth-based, not time-based.** Grants are strictly limited by **state growth**: **max_size** (maximum log size under the grant) and **min_range** (minimum size increase per checkpoint). A grant allows a **bounded amount of log growth**; the effective cap on checkpoints under that grant is (max_size − current_size) / min_range. After that growth is consumed, a **new grant** (new leaf in the owner's log) is required. There is **no time-bound expiry**; grants are consumed by use.

**Current state:** There is **no revocation list**: once a leaf is in an authority log's MMR, it remains valid until **consumed** (until the bounded growth is used). We cannot today explicitly revoke a grant on-chain (Appendix A.6).

**Expiring a misbehaving authority log (child):** An authority log (child) is extended only when someone presents a **grant in the parent's** log. So the **parent** controls whether the child can grow: if the parent **stops issuing new grants** that allow extending the child, the child cannot receive further checkpoints. The child's tree is then frozen (no new leaves). So **yes**, the model allows the parent to **expire a misbehaving child authority** by no longer issuing extension grants. No additional "expiry" mechanism is required for this.

**Expiring all data logs that authority created:** Data logs owned by that authority need **grants that are leaves in that authority's log**. Each grant allows only **bounded growth** (up to max_size, with min_range per checkpoint). So each grant is **consumed** as the data log grows. When a data log has consumed its grant (reached the size bound), it needs a **new** grant — i.e. a new leaf in the authority's tree. If the parent has stopped issuing extension grants to that authority, the **authority's tree cannot grow**, so the authority **cannot add new leaves** (new grants) for its data logs. Therefore: (1) Existing grants in the authority's tree remain valid until **consumed** (until each data log grows to its grant's max_size). (2) Once those grants are consumed, those data logs need new grants — but the authority cannot issue them (its tree is frozen). (3) So **all data logs owned by that authority ultimately become unextendable**: first they consume their current grants, then they cannot obtain new ones. **Expiry of the misbehaving authority (parent stops extension grants) therefore ultimately expires all data logs that authority has created**, via grant consumption. No time-based expiry is required; the growth-bounded nature of grants plus the frozen authority tree is sufficient.

**Summary:** Grants are **growth-bounded** (max_size, min_range), not time-bound. The current design does **not** implement an explicit revocation list. The model **already** supports expiring a misbehaving child authority (parent stops extension grants) and, as a consequence, **all data logs owned by that authority** become unextendable once they have consumed their existing grants, because the frozen authority cannot issue new ones.

### 9.1 Design rationale: forward non-renewal and monitoring, not a revocation list

The absence of a revocation list is a **deliberate design choice**, not a missing feature. Two distinct notions of "revocation" must be separated:

- **Revoking history** (un-making or invalidating an already-committed entry): **correctly forbidden.** Append-only, point-in-time finality is the core integrity property the contract exists to enforce; a consistency-verified, signature-bound checkpoint is final, and conceding the ability to retract it would defeat the purpose of the log.
- **Revoking authority going forward** (preventing future growth under a compromised or misbehaving authority): **handled by grant non-renewal** (the owner declines to issue further growth grants → the child freezes once its current grants are consumed; §9 above) **plus forward attestation by monitors/auditors** observing the public log.

Forward non-renewal plus monitoring is preferred over a CRL/OCSP-style revocation list for spec-level reasons. A revocation list reintroduces an **online oracle** (verifiers must consult it), a **liveness dependency** (the list must be reachable to verify), a **withholding vector** (whoever serves the list can selectively withhold or delay entries), and a **timing window** (the gap between revocation and its propagation) — and it **relocates trust** to whoever controls the list. None of these is neutral. More fundamentally, the question most trust, audit, liability, and compliance use cases turn on is *"did the relying party act honestly on the information available at the time?"* — and **retrospective revocation cannot un-make a reliance that already happened.** Replacing per-verifier revocation-checking with **forward monitor/auditor attestation** over the public log is more scalable, composable, and neutral (the CT/SCITT model); the honest residual is the **monitor ecosystem** (§8), not the trust model.

Relatedly, the `max_size` bound on a grant is itself an **active choice about the ability to withhold authority going forward** (see [auth-overview §7.4](arc-0017-auth-overview.md#74-refreshing-gf_extend-grants)): an effectively-unbounded grant **relinquishes** that forward lever in favour of maximal finality and liveness, while a **bounded** grant **retains** a forward soft-sunset (decline-to-renew) at the cost of refresh overhead.

---

## 10. Later phases (out of scope for this ARC)

- **Multiple global roots / disjoint forests in one contract:** Today a single
  `rootLogId` anchors the deployment; child authorities extend **that** tree.
- **Grant type / schema:** Further refinement of leaf commitment or proof format
  beyond current **GF\_\*** / **GC\_\*** / **PublishGrant** (e.g. richer grant types).
- **Lifecycle / revocation:** Explicit revocation of grants (grants are
  already growth-bounded; see §9 for consumption and freezing authority).

---

## Appendix A: Implementation status (post–Phase 0)

Phase 0 is **implemented**: LogConfig (kind, authLogId, rootKey,
initializedAt), grant verification against the owner (**authLogId** /
**ownerLogId** for first checkpoint), root key from first checkpoint
(including bootstrap signer check for the **root’s** first checkpoint only).

**Implemented — hierarchy**

- **Child authority logs:** A “create authority” grant from a parent, with the
  appropriate **GF\_\*** / **GC\_\*** pairing, sets `kind = Authority` and
  `authLogId = parent`; the first checkpoint’s signer (from **grantData**)
  becomes the child’s **rootKey**. No per-authority bootstrap key — only the
  deployment root uses the constructor bootstrap key once.
- **Ownership-based routing:** Inclusion proofs for extending a log are verified
  against the accumulator for that log’s **authLogId** (owning vs parent per
  §4.2). **Kind** and **authLogId** are exposed via `getLogConfig`; enumerating
  “all authority logs” remains an **off-chain indexer** concern (§3).

**Not implemented (or deferred)**

1. **Multiple disjoint bootstrap roots** in one contract (second `rootLogId` / forest).
2. **On-chain COSE / rich receipt objects** as grant evidence — **grant evidence**
   today uses pre-decoded inclusion proof (index, path); see §3 table.
3. **Explicit revocation list** for grants — growth-bounded consumption only; see **§9**.

**By design:** **msg.sender** is not used for checkpoint authorization; valid
grant + valid receipt signature suffice ([auth overview §5](arc-0017-auth-overview.md#5-what-is-not-in-the-model)).
Off-chain Forestrie workers may ingest by **logId** and content hash only; the
**contract remains the verifier** for what extends shared history (see
[Canopy grants — Takeaways](https://github.com/forestrie/canopy/blob/main/docs/grants.md#takeaways) — verification vs ingestion).
