# Implementation Plans

Implementation plans describe detailed work breakdown for significant
features or changes to the univocity contracts. They reference ADRs
and ARCs from the [forestrie/devdocs](https://github.com/forestrie/devdocs)
repository.

## Index

[plan-0012-arc-0016-implementation-review.md](plan-0012-arc-0016-implementation-review.md)
ARC-0016 implementation review: current state and appendix of
divergences/gaps for holistic reflection (e.g. before ARC-0017).

[plan-0021-phase-zero-log-hierarchy-data-structures.md](plan-0021-phase-zero-log-hierarchy-data-structures.md)
Phase 0 log hierarchy (ARC-0017): data structures — LogKind, authLogId, separate LogConfig; authorization per ARC-0017 §2 (rootKey at first checkpoint, recovered rootKey in delegation; ownerLogId in grant for log creation). Grant bounds growth-based only (maxHeight, minGrowth; no checkpointCount). Agent execution guide and dependency graph.

[plan-0001-r5-authority.md](plan-0001-r5-authority.md)
Implementation plan for adding R5 payment-bounded authority to the
univocity contracts. Covers multi-log support, authority log
infrastructure, receipt verification, hybrid coverage model
(checkpoint_end + max_height), and comprehensive event sourcing.

## Related Documentation

This repo also has:

- **[../adr/](../adr/)** — Architecture Decision Records (decisions with
  context and rationale). E.g. ADR-0001 (payer attribution), ADR-0002
  (CoseVerifierKeys caller dispatch), ADR-0003 (bootstrap keys opaque
  constructor).
- **[../arc/](../arc/)** — Architecture Reference Content (specs and
  reference). E.g. ARC-0001 (grant minimum range), ARC-0002 (delegation cert
  label alignment), ARC-0016 (incentivisation implementation reflection),
  ARC-0017 (log hierarchy and authority).

Design documents and architecture decisions are also maintained in the
[forestrie/devdocs](https://github.com/forestrie/devdocs) repository:

- **ADR** (Architecture Decision Records): Document specific technical
  decisions with context, options considered, and rationale.
- **ARC** (Architecture Reference Content): Detailed specifications
  and reference material for system components.
- **Plans**: Implementation plans for significant features.
