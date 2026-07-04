# Implementation Plans

> **Plan numbering.** Plans `plan-0001…` (created on or before 2026-07) are
> frozen legacy absolute ids — do not renumber them. New plans use **date
> cohorts**: `plan-YYMM-NN-<slug>.md` (e.g. `plan-2607-01-…` = 1st plan of
> July 2026); larger multi-part plans use a `plan-YYMM-NN-<slug>/` directory.
> Forward-only.

Implementation plans describe detailed work breakdown for significant
features or changes to the univocity contracts. They reference ADRs
and ARCs in this repo and in [forestrie/devdocs](https://github.com/forestrie/devdocs).

## Index

[plan-0013-adr-0032-delegated-checkpoint-verification.md](plan-0013-adr-0032-delegated-checkpoint-verification.md)  
ADR-0032 delegated checkpoint verification (ES256 delegation, root from first
checkpoint). **Implemented.**

[plan-0016-minimal-cose-cbor-api-predecode.md](plan-0016-minimal-cose-cbor-api-predecode.md)  
Pre-decoded consistency receipt and inclusion proof API; minimal COSE/CBOR
on-chain. **Implemented.**

[plan-0021-phase-zero-log-hierarchy-data-structures.md](plan-0021-phase-zero-log-hierarchy-data-structures.md)  
Phase 0 log hierarchy (ARC-0017): LogKind, authLogId, LogConfig; grant =
inclusion against owner; rootKey at first checkpoint. **Implemented.**

[plan-0020-algorithms-test-coverage-parity.md](plan-0020-algorithms-test-coverage-parity.md)  
Algorithms test coverage parity.

[plan-0014-gas-metrics.md](plan-0014-gas-metrics.md)  
Gas metrics (if present).

## Historical plans

Superseded or point-in-time plans are in [../history/plans/](../history/plans/).

## Related documentation

- **[../adr/](../adr/)** — Architecture Decision Records.
- **[../arc/](../arc/)** — Architecture Reference Content (ARC-0016,
  ARC-0017, [auth overview](../arc/arc-0017-auth-overview.md)).
