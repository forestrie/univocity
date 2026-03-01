# ARC-0001: Grant minimum range and permissionless submission

**Status:** ACCEPTED  
**Date:** 2026-02-23  
**Related:** [plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md),
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md).
Historical: [plan-0001](../history/plans/plan-0001-r5-authority.md),
[plan-0015](../history/plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md).

## 1. Purpose

This document records why the grant model includes a **minimum range** (expressed
on-chain as `min_growth`: minimum growth in MMR size per checkpoint) and how it
fits the permissionless submission model.

## 2. Incentive alignment

Under permissionless submission, **any** sender may call `publishCheckpoint`
once a grant is committed in the authority log. Submitters have no obligation
to extend the log by more than the minimum that satisfies the contract. In
practice, financial incentives (e.g. gas or per-checkpoint rewards) can
encourage **minimally extending** checkpoints: many small submissions instead of
fewer larger ones. That can increase overhead (more transactions, more proofs)
and may be undesirable for the authority or the system.

## 3. Authority-controlled minimum

The grant issued by the authority log includes a **min_growth** (and optionally
max_height and checkpoint range). The contract enforces:

- `(new MMR size) - (current log size) >= paymentGrant.minGrowth`

So the **authority**, not the submitter, controls the **minimum** amount by
which the log must grow for any checkpoint published under that grant. The
authority can set a larger `min_growth` to discourage minimal submissions and
align incentives (e.g. one checkpoint covering a useful range instead of many
tiny ones). This is an important aspect of the permissionless submission
model: submission is open to anyone, but the **shape** of what is accepted
(minimum extension, max height, checkpoint count range) is defined by the
grant in the authority log.

## 4. Summary

- **Permissionless submission:** Any sender may publish once the grant is in
  the authority log.
- **Grant minimum range (min_growth):** The authority log controls the
  minimum range (minimum growth) of any checkpoint under that grant, so
  submitters cannot always choose minimally extending checkpoints for
  financial gain; the authority sets the floor.

Plans that define the API or bounds checks should reference this concept. See
[plan-0021](../plans/plan-0021-phase-zero-log-hierarchy-data-structures.md) and
[ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md) for
`PaymentGrant.minGrowth` and bounds checks.
