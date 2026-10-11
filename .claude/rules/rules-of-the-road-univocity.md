# Rules of the road — univocity (on-chain)

Solidity contracts for on-chain split-view protection. Load with
[platform.md](https://github.com/forestrie/forestrie-agents/blob/main/rules-of-the-road/platform.md). `⤷` = specialises a platform rule. The contract is
the ground truth — an invariant that is not enforced on-chain is not enforced.

Glossary/links: [`arc-univocity` skill](https://github.com/forestrie/forestrie-agents/blob/main/arc-context/arc-univocity/SKILL.md).

---

### U1 — publishCheckpoint verifies both sealing and authority on-chain
`publishCheckpoint` MUST verify (a) the checkpoint is signed by the log's root
key **or a valid delegation** of it, and (b) the presented grant's **inclusion**
in the parent log against the parent's on-chain accumulator, within the grant's
size bounds — link by link to the bootstrap key bound at deploy. **Why:** this
publish-time discharge is what lets any chain read stand in for the sealing and
authority questions.
⤷ specialises P4/P10. [ADR-0032](https://github.com/forestrie/devdocs/blob/main/archive/2602/adr/adr-0032-delegated-checkpoint-signature-verification.md) · [receipt trust model, question 3](https://github.com/forestrie/devdocs/blob/main/protocol/receipt-trust-model.md#3-authority--is-this-log-authorised-back-to-the-genesis--bootstrap-key).

### U2 — publishCheckpoint is permissionless
Never gate on `msg.sender`. Anyone holding a valid grant + signed checkpoint may
pay gas to publish; payer ≠ issuer ≠ submitter. **Why:** a sender check would
hand an operator a censorship lever the model exists to remove.
⤷ specialises P6. [ARC-0016 §6.2](https://github.com/forestrie/devdocs/blob/main/archive/2602/arc/arc-0016-checkpoint-incentivisation-model.md).

### U3 — maxHeight is a ceiling, not a balance
Enforce `size ≤ maxHeight` (an entry-count high-water mark) and any
`minGrowth ≤ delta`; do NOT store or decrement a per-grant balance/counter. Two
grants over one log do not sum — either bound may apply; the isolation unit is
the log. **Why:** a decrementing balance would make grants spendable/refundable,
breaking irrevocability.
⤷ specialises P8. [ARC-0028 §2](https://github.com/forestrie/devdocs/blob/main/arc/arc-0028-grant-funded-task-escrow.md).

### U4 — One root per instance, set once, immutable
`rootLogId` / bootstrap key is set at construction and never reassigned; it is
the account, authority, and fee boundary. **Why:** every downstream guarantee
resolves to this single enforced root — a reassignable root voids all of them.
⤷ specialises P14. [ADR-0059](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0059-instance-root-fee-accounts.md) · [ADR-0034](https://github.com/forestrie/devdocs/blob/main/archive/2606/adr/adr-0034-forest-genesis-chain-binding-required.md).

### U5 — Emit CheckpointPublished as the meter
Emit one `CheckpointPublished` per checkpoint carrying `logId`, kind, and size;
the contract keeps no billing counter — indexers count events. **Why:** metering
is off-chain by counting events, keeping the contract minimal and the meter
publicly reconstructible.
[ARC-0026](https://github.com/forestrie/devdocs/blob/main/archive/2607/arc/arc-0026-onboard-grant-apis-and-fee-tracing.md).

### U6 — Genesis uses the explicit v1 schema
Accept genesis with an explicit `(chainId, contract)` v1 schema; reject the
legacy `uint32[]` array. **Why:** the curator-attested chain-binding tuple is
what sealer/publisher verify against without env vars.
[ADR-0034](https://github.com/forestrie/devdocs/blob/main/archive/2606/adr/adr-0034-forest-genesis-chain-binding-required.md).

### U7 — On-chain COSE/CBOR must match the canonical wire bytes
`LibCose` / `LibCbor` verification MUST match the exact canonical bytes the
sealer signs (RFC 8949 §4.2). **Why:** the contract is the arbiter of
"conformant" — any decode divergence rejects valid receipts or, worse, accepts
malformed ones.
⤷ specialises P16. [ADR-0046](https://github.com/forestrie/devdocs/blob/main/archive/2607/adr/adr-0046-checkpoint-is-consistency-receipt.md).

### U8 — Base contract stays policy-agnostic; derived flags are external
`GF_DERIVED` flag space is reserved for external-protocol reuse; native
validation ignores unknown bits. Policy on derived flags is enforced by a
*composing* contract, not the base one. **Why:** keeping the base contract
policy-free is what lets other protocols build on it without forking it.
[ARC-0029](https://github.com/forestrie/devdocs/blob/main/arc/arc-0029-derived-grant-policy-and-sender-bound-enforcement.md).
