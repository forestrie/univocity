# Plan 0017: Assessment — payer in PaymentGrant

**Status:** DRAFT  
**Date:** 2026-02-23  
**Related:** [plan-0001](plan-0001-r5-authority.md), [plan-0015](plan-0015-publishCheckpoint-payment-receipt-as-roi.md), [plan-0014](plan-0014-feasibility-consistency-receipt-calldata-memory.md), [plan-0013](plan-0013-adr-0032-delegated-checkpoint-verification.md)

## 1. Purpose of this document

Review the ARC and plan documents to assess the **purpose and value of the
`address payer` field** in `PaymentGrant`, and to identify **inconsistencies**
between the original design (permissionless submission, “who paid” vs “who may
submit”) and the current implementation, so a way forward can be decided.

---

## 2. Stated purpose of payer in the plans

### 2.1 Plan 0001 (R5 authority)

- **Claim -1:** `payer` is a 20-byte address; described as **“who paid”**.
- **Explicit:** “The payer claim identifies who **PAID**, not who may
  **SUBMIT**.”
- **Submission model:** “msg.sender is NOT checked against claims.payer”;
  “Submission is permissionless given valid signature + receipt”; “Anyone can
  be the courier.”
- **Authority model:** “Signer, Payer, Submitter are independent roles”;
  “Contract does NOT verify `msg.sender`.”
- **Events:** `CheckpointAuthorized` and `AuthorizationFailed` include
  `payer` for attribution (“who paid, not msg.sender”).

So in plan-0001, **payer is purely attribution/accounting**: it identifies who
paid for the grant. It is **not** used for access control. Permissionless
submission is a non-negotiable design point.

### 2.2 Plan 0015 (payment receipt as RoI)

- **PaymentGrant** includes `address payer` and it is part of the **leaf
  commitment**:  
  `inner = SHA256(logId || payer || checkpointStart || ...)`.
- The doc does **not** say that the submitter must equal payer or that payer
  restricts who may call `publishCheckpoint`.
- The contract “derives leaf commitment from this + paymentIDTimestampBe” and
  uses it to verify the Receipt of Inclusion and bounds. So payer is part of
  **what the authority log commits to**, not who is allowed to submit.

### 2.3 Plan 0014 (feasibility)

- “The **payment receipt** proves that the **payment receipt signer** (payer)
  is allowed to publish the log checkpoint.”
- **Wording note:** The *signer* of the payment receipt is the **bootstrap
  authority** (verified with bootstrap keys). The **payer** is a **claim**
  inside the receipt. So “payment receipt signer (payer)” is ambiguous; the
  intended meaning is that the receipt (signed by the authority) proves that
  the **grant** (including the payer claim) is authorized to publish. So
  plan-0014 does not redefine payer as “who may submit”; it is still the
  payer claim in the receipt.

### 2.4 Plan 0013 (ADR-0032)

- Leaf formula includes payer:  
  `SHA256(logId‖payer‖checkpointStart‖checkpointEnd‖maxHeight‖minGrowth)`.
- “Same receipt different submitters” is called out as desired behaviour
  (permissionless submission).
- No requirement that `msg.sender == payer`.

**Summary (docs):** Payer is consistently “who paid.” It is part of the
authority log’s commitment (leaf formula) and events for attribution. It is
**not** used to restrict who may submit; submission remains permissionless.

---

## 3. Where the current implementation lies

### 3.1 What is implemented

- **PaymentGrant** includes `address payer` (see [IUnivocity.sol](../../src/checkpoints/interfaces/IUnivocity.sol)).
- **Leaf commitment** uses payer:  
  `inner = SHA256(logId || payer || checkpointStart || ...)` in
  `Univocity._leafCommitment`.
- **No** check `msg.sender == paymentGrant.payer` anywhere. Submission is
  permissionless: any address can call `publishCheckpoint` with a valid
  consistency receipt and payment inclusion proof.
- **Events:** The interface defines `CheckpointAuthorized`, `AuthorizationFailed`,
  and `PaymentReceiptRegistered` (all include `payer`), but the current
  `Univocity.sol` **does not emit** these events. It only emits
  `Initialized`, `LogRegistered`, and `CheckpointPublished`.

So the implementation **aligns with permissionless submission** and **does
not** use payer for access control. Payer is used only in the leaf commitment
and in the event *definitions* (which are not currently emitted).

### 3.2 Inconsistencies

| Aspect | Plan / ARC | Current implementation |
|--------|------------|-------------------------|
| Payer = who paid, not who may submit | Explicit in plan-0001 | Aligned: no `msg.sender == payer` check |
| Payer in leaf commitment | plan-0015, plan-0013 | Aligned: `_leafCommitment` includes `g.payer` |
| CheckpointAuthorized / AuthorizationFailed | Emitted in plan-0001 pseudocode | Not emitted; events exist in interface only |
| PaymentReceiptRegistered | In IUnivocityEvents | Not emitted |

So the only real inconsistency is **event emission**: the plans describe
emitting payer for attribution and debugging, but the current code path
(pre-decoded API, plan-0016) does not emit those events. That is a
documentation/observability gap, not a change in the security model.

---

## 4. Alternative reading: “auth log endorses a specific submitter”

You noted that payer “seems to align better with a model where the authority
log **endorses a specific msg.sender** to publish the checkpoint.”

- **In the docs:** That model is **rejected**. Plan-0001 and the authority
  model explicitly say the receipt authorizes the **checkpoint** (and the
  grant), not the **submitter**; “Anyone can be the courier.”
- **In the implementation:** There is no endorsement of `msg.sender`; payer
  is not compared to the caller. So the implementation does **not** implement
  “only payer may submit”; it implements “anyone may submit with a valid
  receipt.”
- **Why payer is in the leaf:** So that the **authority log entry** is bound
  to a specific (logId, payer, range, …). That supports **attribution** (“this
  grant was paid for by this address”) and **uniqueness** of the leaf (different
  payers ⇒ different leaves for the same range). It does **not** mean “only
  this address may submit this grant.”

So if the goal were “authority log endorses a specific msg.sender,” the
design would need to **add** a check `msg.sender == paymentGrant.payer` and
would **contradict** the stated permissionless-submission design. The current
design and implementation keep submission permissionless and use payer for
attribution and leaf binding only.

---

## 5. If payer were removed

### 5.1 What would change

- **Leaf formula:** Would drop payer from the inner hash. New formula would
  be something like:  
  `inner = SHA256(logId || checkpointStart || checkpointEnd || maxHeight ||
  minGrowth)`.
- **PaymentGrant:** Would no longer have a `payer` field.
- **Compatibility:** Any **existing** authority log that already has leaves
  committed with the current formula (including payer) would **no longer**
  match the new formula. So removing payer is a **breaking change** for
  existing authority log state unless we version the formula or only apply
  the new formula to new logs.

### 5.2 What would be lost

- **Attribution in the commitment:** The authority log would no longer
  bind “who paid” into the leaf. Indexing or analytics that today derive
  “who paid” from the leaf or from events would lose that dimension unless
  we added it elsewhere (e.g. a new event or off-chain only).
- **Event semantics:** The defined-but-unemitted events
  (`CheckpointAuthorized`, `PaymentReceiptRegistered`, `AuthorizationFailed`)
  currently include `payer`; if we ever start emitting them, we would either
  drop the payer argument or define a separate attribution mechanism.

### 5.3 What would not be lost (security / permissionless model)

- **Permissionless submission:** We do not enforce `msg.sender == payer`, so
  removing payer does not change who may submit. Security of the
  permissionless model is unchanged.
- **Receipt and bounds checks:** Authorization is still “valid receipt +
  inclusion in authority log + bounds”; that does not depend on payer.

So removing payer would **not** weaken the permissionless design; it would
mainly affect **attribution** and **leaf compatibility** with existing logs.

---

## 6. Inconsistencies summary (original arc/plan vs implementation)

| Topic | Original arc/plan | Current implementation | Consistent? |
|-------|-------------------|------------------------|------------|
| Payer = who paid | Yes | Used only in leaf + event types | Yes |
| No msg.sender vs payer check | Yes | No check | Yes |
| Payer in leaf commitment | Yes (plan-0015, 0013) | Yes | Yes |
| Emit CheckpointAuthorized etc. | Yes (plan-0001) | Not emitted | No (events missing) |
| Permissionless submission | Yes | Yes | Yes |

The only identified inconsistency is **missing emission** of
CheckpointAuthorized, PaymentReceiptRegistered, and AuthorizationFailed. The
**semantics** of payer (who paid, not who may submit) are consistent between
docs and implementation.

---

## 7. Ways forward

1. **Keep payer, fix observability (optional)**  
   Keep `PaymentGrant.payer` and the leaf formula as-is. Optionally add
   emission of `CheckpointAuthorized` (and related events) so that
   attribution (“who paid”) is visible on-chain and aligns with plan-0001.

2. **Keep payer, document only**  
   Keep payer and the current behaviour. Explicitly document in an ADR/plan
   that payer is for attribution and leaf binding only, and that
  “permissionless submission” means no check of `msg.sender` against payer.
  Resolve the plan-0014 “payment receipt signer (payer)” wording to avoid
  implying payer = submitter.

3. **Remove payer**  
   If attribution is not needed in the commitment (e.g. handled off-chain or
   via a future event-only design), remove payer from PaymentGrant and from
   the leaf formula. Accept breaking change for existing authority logs or
   define a versioned/migration path.

4. **Restrict to payer-as-submitter (design change)**  
   If the product goal is “authority log endorses a specific submitter,” add
   `msg.sender == paymentGrant.payer` and document this as a **change** from
  “permissionless submission” in a new ADR/plan, with clear security and
  product implications.

---

## 8. Recommendation

The arc and plan documents are **consistent** with each other and with the
implementation on the role of payer: **attribution (“who paid”), not access
control**. The main gap is that events that would expose payer for
observability are defined but not emitted.

- If the product still wants **on-chain attribution** of “who paid,” **keep
  payer** and consider adding the missing events.
- If attribution is not required in the commitment and you want to simplify
  the API and leaf formula, **removing payer** is consistent with the
  permissionless model; the main cost is breaking existing authority log
  leaves and losing payer in the commitment unless you add another mechanism.

I can turn this into a short ADR or add a “Decision” section to an existing
plan if you want it captured as a formal decision.
