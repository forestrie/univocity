# ADR-0001: Payer attribution and permissionless submission

**Status:** ACCEPTED  
**Date:** 2026-02-23  
**Related:** [ARC-0001](../arc/arc-0001-grant-minimum-range.md),
[plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md).
Historical: [plan-0001](../history/plans/plan-0001-r5-authority.md),
[plan-0015](../history/plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md),
[plan-0014](../history/plans/plan-0014-feasibility-consistency-receipt-calldata-memory.md).

## Decision

**After the grant is made to any payer, any sender may publish the checkpoint.**

The owner’s log (root or auth log) commits to a leaf that includes the grant
and bounds (including min_growth; see
[ARC-0001](../arc/arc-0001-grant-minimum-range.md)). The contract does not
restrict who may submit. The grant struct was renamed to PublishGrant and the
**payer field was removed**; any sender may submit; submission is
permissionless. In `CheckpointPublished`, **sender** is a non-indexed
parameter; **grantLogId** and **rootKey** are indexed. See [plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md)
and historical plans (payment receipt, R5) in [history/plans](../history/plans/).

## Context

The `address payer` field (formerly in the grant struct, now PublishGrant) was
assessed for purpose and
consistency with the original design (permissionless submission; “who paid”
vs “who may submit”).

- **Plans (0001, 0015, 0013):** Payer is “who paid”; part of leaf commitment
  and events for attribution. No check of `msg.sender` against payer;
  submission is permissionless.
- **Implementation:** Aligned: no sender-vs-payer check; payer was later
  removed from the grant struct (PublishGrant);
  The events
  `CheckpointAuthorized` and `PaymentReceiptRegistered` were removed (implied
  by successful publish); authorization failures revert with custom errors
  (see [ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md#authorization-failure-revert-codes)).

## Consequences

- Payer was removed from the grant; leaf commitment no longer includes it
  and leaf binding.
- Submission stays permissionless; no access control on `msg.sender`.
- Events attribute sender (who submitted) and grant/log data for indexers.
