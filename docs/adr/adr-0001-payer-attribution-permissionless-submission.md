# ADR-0001: Payer attribution and permissionless submission

**Status:** ACCEPTED  
**Date:** 2026-02-23  
**Related:** [ARC-0001](../arc/arc-0001-grant-minimum-range.md),
[plan-0001](../plans/plan-0001-r5-authority.md),
[plan-0015](../plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md),
[plan-0014](../plans/plan-0014-feasibility-consistency-receipt-calldata-memory.md),
[plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md)

## Decision

**After the grant is made to any payer, any sender may publish the checkpoint.**

The owner’s log (root or auth log) commits to a leaf that includes the payer
(who paid) and bounds (including min_growth; see
[ARC-0001](../arc/arc-0001-grant-minimum-range.md)). The contract does not check
`msg.sender` against `paymentGrant.payer`. Payer is for attribution only (who
paid for the grant); submission is permissionless. In `CheckpointPublished`,
both **sender** and **payer** are attributed and are **indexed** parameters
(filterable by indexers). See
[plan-0015](../plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md)
and [plan-0001](../plans/plan-0001-r5-authority.md).

## Context

The `address payer` field in `PaymentGrant` was assessed for purpose and
consistency with the original design (permissionless submission; “who paid”
vs “who may submit”).

- **Plans (0001, 0015, 0013):** Payer is “who paid”; part of leaf commitment
  and events for attribution. No check of `msg.sender` against payer;
  submission is permissionless.
- **Implementation:** Aligned: no `msg.sender == paymentGrant.payer` check;
  payer used only in leaf commitment and in `CheckpointPublished`. The events
  `CheckpointAuthorized` and `PaymentReceiptRegistered` were removed (implied
  by successful publish); authorization failures revert with custom errors
  (see [ARC-0016](../arc/arc-0016-checkpoint-incentivisation-implementation.md#authorization-failure-revert-codes)).

## Consequences

- Payer remains in `PaymentGrant` and in the leaf commitment for attribution
  and leaf binding.
- Submission stays permissionless; no access control on `msg.sender`.
- Events that include payer (when emitted) attribute “who paid” for indexers.
