# ADR-0004: Root log self-grant extension (unified auth model)

**Status:** ACCEPTED  
**Date:** 2026-02-27  
**Related:** [ARC-0017](../arc/arc-0017-log-hierarchy-and-authority.md),
[ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md)

## Decision

**Option A (Adopt) is accepted.** The root log’s `authLogId` is set to its
own `logId` (self). Extension of the root requires a grant (inclusion
proof) in the root itself (self-issued). The **first checkpoint ever**
(creation of the root) must be signed by the bootstrap key. There are
**no existing deployments**; the project is in design and development
phase, so we adopt this model comprehensively in ARC, plans, and
implementation with no migration constraints.

## Context

Today the **root authority log** is extended under different rules than other
logs:

- **Root extension (historical):** Previously an address was used; the contract
  now has no address check. Root extension requires a grant (inclusion proof)
  in the root.
- **Other logs:** Extension requires a **grant** — an inclusion proof against
  the log’s **owner** (data log → owning auth log; child authority → parent
  log). No identity check; submission is permissionless once the grant exists.

So root extension is identity-gated and grant-free; every other extension is
grant-gated and permissionless. That split complicates both the authorization
logic and auditability: root growth has no on-chain grant evidence.

This ADR evaluates making root extension **grant-based** by treating the root
as its own “parent”: set the root log’s `authLogId` to its own `logId`, and
require that extension of the root also be backed by a grant — a **self-issued**
grant (inclusion proof against the root log itself).

## Proposal

1. **Root’s authLogId = self.** When the root log is created (first checkpoint
   ever), set `config.authLogId = logId` (i.e. `rootLogId`) instead of
   `bytes32(0)`. So the root has a parent in the same sense as other auth
   logs; that parent is itself.

2. **Root extension requires a grant in the root.** For any checkpoint that
   extends the root (`logId == rootLogId` and root already exists), require
   the same rule as for other logs: `publishGrant.ownerLogId == config.authLogId`
   (so `ownerLogId == rootLogId`) and verify inclusion of the grant leaf
   against the root log’s accumulator (and size). No caller check for extension.

3. **Single special case: first checkpoint ever.** The only remaining
   special case is the **creation** of the root (no log exists yet). That
   still requires the bootstrap key (receipt signer) and a self-inclusion proof
   (index 0; path length up to MAX_HEIGHT, new tree). After that, the root exists with
   `authLogId = rootLogId`, and all further extensions (root and non-root)
   use the same rule: grant from the log’s authLogId.

4. **Bootstrap only for creation.** The **first** checkpoint (which creates the
   root) must be signed by the bootstrap key. Every
   subsequent root extension would be permissionless for whoever holds a
   valid grant (inclusion proof) in the root — consistent with
   [ADR-0001](adr-0001-payer-attribution-permissionless-submission.md).

5. **Root content.** The root log would then contain leaves that are grants
   both for **extending the root** (self-issued) and for **creating or
   extending child logs**. That is special: the root is the only log that
   can issue grants for itself. Indexers and tooling may still treat “grant
   in root with ownerLogId == rootLogId” as “root self-extension” and “grant
   in root with ownerLogId == rootLogId and logId != rootLogId” as “child
   creation/extension,” but the on-chain rule is uniform.

## Assessment

### Simplification and generalisation of authorization

- **Single rule for all extensions after bootstrap:** “To extend log L, supply
  a valid inclusion proof against `L.config.authLogId`.” For the root,
  authLogId is the root itself; for others, it is the parent or owner. No
  separate branch for “if root then check bootstrap and ignore grant.”
- **Code path:** `_verifyInclusionGrant` could treat root like any other log
  once the root exists: require `publishGrant.ownerLogId == rootLogId`, verify
  inclusion against `_logs[rootLogId]`. The only special branch remains “first
  checkpoint ever” (create root, bootstrap only, self-inclusion). So yes, the
  checks simplify and generalise.

### Auditability

- **Every extension has grant evidence.** Root extension would leave an
  on-chain trail: each new checkpoint is justified by an inclusion proof
  (grant) in the root. Auditors and indexers can always answer “who
  authorised this extension?” by the grant leaf in the root (and its
  bounds, payer, etc.). Today, root extension has no such evidence.
- **Consistent story:** “Log L grew because a grant in L’s owner (authLogId)
  was proven.” Holds for data logs, child auth logs, and the root.

### Remaining special behaviour

- **First checkpoint ever:** Still bootstrap-only; no prior log to hold a
  grant. Unavoidable.
- **Root is the only self-issuing log.** Only the root has `authLogId ==
  logId`. So “grant from authLogId” for the root means “grant from the root
  (self).” No other log can have self-issued grants. Tooling that lists
  “grants issued by log X” may still treat root self-grants as a distinct
  category (e.g. “root extension” vs “child grant”).
- **Root contains mixed grant types.** The root’s leaves can be both
  self-extension grants (same logId / ownerLogId semantics as used today for
  “extend root”) and child-creation/extension grants. Schema and indexing
  already distinguish by PublishGrant fields (logId, ownerLogId,
  createAsAuthority); no new ambiguity, but docs and UX should spell out that
  the root log is the only one that holds both self- and child-grants.

### Behavioural change

- **Who can extend the root:** Under this design, **anyone** who can supply a
  valid inclusion proof for a grant in the root can extend the root
  (permissionless submission). So after the first checkpoint (which creates
  the root), the **second** and later checkpoints can be submitted by any
  address that proves inclusion of a grant leaf in the root. This aligns
  root with the rest of the model (grant-based, permissionless submitter).
- **No deployments:** There are no existing deployments. The project is in
  design and development phase, so we adopt this model comprehensively
  with no migration or backward-compatibility constraints.

## Options (reference)

| Option | Description |
|--------|-------------|
| **A. Adopt** | Implement root authLogId = self and grant-based root extension.
  Single special case = first checkpoint ever. **Accepted.** |
| **B. Reject** | Keep root extension bootstrap-only, no grant. Not chosen. |
| **C. Adopt in new deployments only** | Not applicable; no existing
  deployments. |

## Consequences

- **ARC-0017 and plan-0021** would be updated: root’s authLogId = rootLogId;
  root extension requires grant in root (inclusion proof); bootstrap only for
  first checkpoint ever.
- **Contract:** `_verifyInclusionGrant` would drop the “if root, check
  bootstrap and require index 0 (path length up to MAX_HEIGHT)” branch for extension; add root to the
  “grant from authLogId” path with authLogId == rootLogId. Set
  `config.authLogId = logId` when creating the root in `_initializeAuthorityLog`.
- **Tests and docs:** Root extension tests would use inclusion proofs against
  the root; bootstrap-only tests would apply only to the first checkpoint
  ever.
- **Indexers:** Root log can be queried for “all grants”; a subset are
  self-extension (ownerLogId == rootLogId, logId == rootLogId) and the rest
  are for children. No change to event shape; only to when root extension
  is allowed (grant required).
