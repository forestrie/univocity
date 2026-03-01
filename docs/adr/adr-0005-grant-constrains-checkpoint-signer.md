# ADR-0005: Grant-constrains allowed checkpoint signer (root key)

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [ARC-0017](../arc/arc-0017-auth-overview.md),
[ARC-0017 (hierarchy)](../arc/arc-0017-log-hierarchy-and-authority.md),
[ADR-0004](adr-0004-root-log-self-grant-extension.md),
[ADR-0003](adr-0003-bootstrap-keys-opaque-constructor.md),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md)

## Question

What is the simplest way, given the current implementation, to update
PaymentGrant so that it **constrains the allowed checkpoint signer** to a
particular key? It must support delegation, account for the bootstrap case,
and avoid undoing the refactoring that achieved maximum commonality in
processing grants and proofs. The expected outcome is that **a single grant**
sets the allowed signer for the created log(s), and that signer is used to
establish the root key for the log. For root creation, the grant should
reference itself (self-included) and match the bootstrap key — because even
as the grant references itself, it is self-included and otherwise not
constrained.

## Context

### Current behaviour

- **Grant:** Inclusion proof in the target log’s owner (root = self;
  child/data = parent or owning authority). Grant is in the leaf commitment;
  request (GC_* for log kind) is not.
- **Receipt signer:** For every checkpoint, the consistency receipt must be
  signed by the target log’s signer. On **first checkpoint** to a log, the
  recovered signer (or delegate) is stored as that log’s **root key**.
- **Bootstrap:** Root’s first checkpoint has no prior owner; grant is
  self-inclusion (index 0). The receipt signer is required to match the
  **bootstrap key** (prevents front-running). No grant field currently
  expresses “allowed signer”; the bootstrap check is hardcoded.

So today the “allowed signer” is implicit: whoever signs the receipt becomes
the log’s root key (and for root we require that to be the bootstrap key).
We want to make it **explicit in the grant** so that the owner's committed
leaf binds the allowed signer, with a single common code path.

### Request is not part of the grant

The request field is **not** part of the grant. Putting an "allowed signer"
in the request would only express a **publisher restriction**: the submitter
saying "I am willing to publish only if the checkpoint is signed by this key."
Any key can be placed in the request; it is a requirement by the publisher,
not a constraint committed by the grant's owner. The signer would need the
private key corresponding to what the publisher put in the request, but the
publisher could check that for themselves before submission. **No additional
security is offered** — the owner's tree does not bind the signer. So the
allowed signer must be part of the **grant** (the committed leaf), not the
request.

### Refactoring to preserve

- Grant vs request: grant in commitment (hash unchanged); request carries
  GC_* and other non-commitment data.
- Single rule for “first checkpoint to a log”: grant valid for create;
  request valid for kind; then update log state. Root is the case where
  owner is self and signer must match bootstrap.
- Delegation: already supported for ES256; delegate signs the receipt; root
  key authorises the delegate. Any “allowed signer” design must still allow
  the delegate to be the one who signs while the grant specifies the root
  (or a key that authorises that delegate).

## Re-evaluation: request vs grant

**Putting allowed signer in the request (rejected).** The request is not
part of the grant. A value in the request only expresses a **publisher
restriction**: "I (the submitter) am willing to publish only if the
checkpoint signer matches this key." Any key can be placed there; it is a
constraint chosen by the publisher, not by the owner who committed the
grant. The signer must hold the private key corresponding to whatever the
publisher put in the request, but the publisher could verify that off-chain
before submitting. No additional security is offered; the owner's tree does
not bind who may sign. So the allowed signer must be part of the **grant**
(the committed leaf), so that the **owner** binds the initial signer.

## Decision (proposed)

**Update the grant format for the create (GF_CREATE) case so that it can
optionally bind the initial signer to a specific key.** The binding is part
of the grant (in the leaf commitment); delegation proofs to that key are
allowed. When present, the contract requires the receipt signer (or the root
recovered from the delegation proof) to match the key in the grant before
setting it as the log's root key.

### Grant format change

- Introduce **GF_REQUIRE_SIGNER**: when set with GF_CREATE, **grantData** is
  the allowed signer: its length must equal the expected public key length for
  the algorithm (e.g. 20 bytes KS256, 64 bytes ES256), and those exact bytes
  are the key (no sentinel). Otherwise grantData keeps current semantics.
- For leaves that **create** a log (grant has GF_CREATE), the grant may
  bind the allowed signer by setting GF_REQUIRE_SIGNER and using grantData
  as the key bytes. This is part of the leaf commitment (grantData is already
  in the hash).
- **Absence of signer commitment:** Should always mean the initial signer was
  allowed to be **open and implicit** (whoever signs becomes root key). That
  is valid only for non-root creates. For the bootstrap checkpoint it is
  never the case — the root's first checkpoint always has a required signer
  (the bootstrap key). So the **bootstrap grant must always** commit to the
  bootstrap key; no optional/absent for root.
- **Bootstrap:** Require the signer commitment to be exactly the bootstrap
  key. No extra security (contract already enforces bootstrap key), but
  **auditing is consistent**: the tree always shows the allowed signer
  explicitly for root.
- **Backward compatibility:** Non-root grants without the binding retain
  current semantics (any signer). Existing root leaves created before this
  change may have no signer commitment; validation can keep the current
  hardcoded bootstrap check for those legacy cases. New root creation
  requires the grant to commit to the bootstrap key.

### Root (bootstrap) case

- Grant references itself: self-inclusion at index 0 (unchanged).
- The grant **must** set GF_REQUIRE_SIGNER and **grantData** to the bootstrap
  key bytes (length = expected public key length for the alg). The contract
  requires the receipt signer to match the bootstrap key; the requirement is
  expressed in the tree for consistent auditing. Absence of GF_REQUIRE_SIGNER
  is not allowed for bootstrap (absence means open signer, which never
  applies to root).

### Non-root (new log) case

- Grant proves inclusion in the owner and has GF_CREATE and the appropriate
  GF_AUTH_LOG or GF_DATA_LOG.
- If the grant sets GF_REQUIRE_SIGNER, grantData is the allowed signer (key
  bytes); the receipt must be signed by that key (or by a delegate authorised
  by it). The recovered signer (or root from delegation) is stored as the new
  log's root key only if it matches grantData. If the grant does not set
  GF_REQUIRE_SIGNER, current behaviour: whoever signs becomes the root key.

### Delegation

- Delegation remains supported: the **receipt** is signed by the delegate;
  the **root** (or authorised key) signs the delegation proof. The grant's
  allowed signer designates that root — the key that must have authorised the
  delegate. The contract recovers the root from the delegation signature and
  checks that it matches the allowed signer in the grant; then stores it as
  the log's root key. So the grant binds "which root key this log will have,"
  and that key may sign directly or via a delegate.

### Implementation sketch

1. **Add GF_REQUIRE_SIGNER:** New grant flag (e.g. next bit after GF_EXTEND).
   When set with GF_CREATE, the **grantData** carries the allowed signer:
   require `grantData.length` to be the expected public key length for the
   algorithm (e.g. 20 bytes for KS256, 64 bytes for ES256), and use those
   exact bytes as the allowed signer. No sentinel or reserved value — the
   bytes are the key. Bootstrap grant: GF_CREATE | GF_REQUIRE_SIGNER and
   `grantData = bootstrapKey` (same length rule). Non-root create with
   binding: GF_CREATE | GF_REQUIRE_SIGNER and `grantData =` public key bytes.
   When GF_REQUIRE_SIGNER is not set, grantData keeps current semantics;
   for create, signer is open (non-root only; root must set GF_REQUIRE_SIGNER
   and grantData = bootstrap key).
   **Scope:** GF_REQUIRE_SIGNER is ignored for any checkpoint other than the
   first to a log. Once the requirement is met at the log's establishing
   checkpoint, normal consistency-proof verification (receipt must be signed
   by the log's root key or its delegate) enforces the signer for the rest of
   the log's life.
2. **Contract:** First checkpoint to a log: if grant has GF_REQUIRE_SIGNER,
   require `grantData.length == expectedPublicKeyLength(alg)` (e.g. 20 or 64),
   then require recovered signer (or root from delegation) to equal `grantData`
   before setting `config.rootKey`. For root, require GF_REQUIRE_SIGNER and
   grantData equal to contract's bootstrap key (reject if absent or wrong
   length). For non-root, GF_REQUIRE_SIGNER optional; if absent, any signer.
   Legacy root leaves without GF_REQUIRE_SIGNER: keep hardcoded bootstrap
   check for backward compatibility.
3. **Common path:** Same grant/request/receipt flow. Root: grant must have
   GF_REQUIRE_SIGNER and grantData = bootstrap key bytes. Non-root:
   optional GF_REQUIRE_SIGNER; if set, grantData = allowed key bytes; if
   absent, open signer.

## Options (reference)

| Option | Description |
|--------|-------------|
| **A. Allowed signer in request** | Rejected. Request is not part of the grant; only a publisher restriction; no additional security. |
| **B. Optional allowed signer in grant** | For GF_CREATE, grant may optionally bind initial signer (in commitment); bootstrap grant must always commit to bootstrap key. Delegation to that key allowed. **Proposed.** |
| **C. Mandatory allowed signer in grant** | Same as B but required for all new creates. Simpler contract logic but breaks compatibility with existing leaves that lack it. |
| **D. No change** | Keep current behaviour. Does not meet the goal. |

## Consequences

- **Owner binds signer:** The committed grant (leaf) can specify the allowed
  signer for the created log; the publisher cannot relax that constraint.
- **Single grant:** One grant leaf both proves inclusion and, when the
  optional binding is present, binds the log's root key to a specific key
  (with delegation to that key allowed).
- **Root:** Grant references itself; grant **must** commit to the bootstrap
  key (required for bootstrap). Auditing consistent; no optional/absent for
  root (absence means open signer, which never applies to bootstrap).
- **Delegation:** Unchanged: delegate signs receipt; grant's allowed signer
  is the root that must have authorised the delegate; contract verifies
  recovered root matches grant and stores it.
- **Commitment change:** New leaves that use the binding have a different
  hash shape; existing leaves without the field remain valid (no binding).
- **Docs and plans:** ARC-0017 and plan-0021 would describe the optional
  grant binding; implementation plan would define the grant encoding and the
  signer-match check for the create path.

## Update (plan-0026)

**Verify-only, no recovery.** [Plan 0026](../plans/plan-0026-verify-only-no-recovery.md)
implements verify-only: the contract no longer recovers the signer from the
receipt or delegation signature. For the **first checkpoint** to a log,
**grantData** must be the signer (root) public key (20 bytes KS256, 64 bytes
ES256); the contract verifies the receipt (or delegation) with that key and
reverts on failure. **GF_REQUIRE_SIGNER** is retained for leaf-hash
compatibility but is **no longer branched on** in logic; all first checkpoints
effectively require the key in grantData.