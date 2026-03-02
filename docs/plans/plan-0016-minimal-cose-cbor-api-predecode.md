# Plan 0016: Minimal COSE/CBOR API and pre-decode (agent execution guide)

**Status:** Implemented  
**Date:** 2025-02-23  
**Related:** [plan-0014 feasibility](../history/plans/plan-0014-feasibility-consistency-receipt-calldata-memory.md),
[plan-0015](../history/plans/plan-0015-publishCheckpoint-payment-receipt-as-roi.md),
[draft-bryce-cose-receipts-mmr-profile](https://raw.githubusercontent.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/refs/heads/main/draft-bryce-cose-receipts-mmr-profile.md)

## 1. Goal and decisions

**Goal:** Replace the current `publishCheckpoint` with a **single pre-decoded
entry point** and radically simplify the codebase: no full COSE_Sign1 receipt
parsing on-chain, no Receipt of Inclusion for payment, no delegation cert
decode. Raw proof data is calldata at the edge; first consistency proof uses
storage for the initial accumulator (no copy).

**Design intents (current implementation reflects all COSE/CBOR we need):**

- Without breaking the cryptographic guarantees of COSE_Sign1, we accept
  **pre-decoded COSE envelopes and supplemental material** to significantly
  reduce the need for COSE/CBOR on-chain handling.
- The remaining COSE/CBOR needs are **explicitly in support of the MMR
  profile** and the aspects of SCITT that are unavoidably on-chain (e.g.
  signature verification, algorithm extraction, Sig_structure).
- We make **no attempt at generalised COSE/CBOR handling**; only the
  minimal surface required for consistency receipt verification and
  delegation proof.
- Future algorithm support or extended COSE use would require **contract
  upgrade or new deployment**, not in-contract generality.

**Decisions (fixed):**

- **Consistency receipt:** Pre-decoded only. Caller supplies
  (protectedHeader, signature, consistencyProofs, delegationProof). Binding
  is assured by verification (derive payload from proofs → verify signature);
  see Appendix A.1.
- **Payment proof:** Plain inclusion proof only (index + path against
  authority log). No COSE, no Receipt of Inclusion, no signature verification
  for payment. See Appendix A.7.
- **Delegation:** Minimal proof only (delegatedKey, mmrStart, mmrEnd, alg,
  signature). No delegation cert (COSE) decode. Root is set by bootstrap
  (e.g. setLogRoot); never derived from a cert. See Appendix A.4–A.5.
- **Backwards compatibility:** None required.

## 2. Target API and types

**Types (add / use):**

```solidity
struct ConsistencyReceipt {
    bytes protectedHeader;
    bytes signature;
    bytes[] consistencyProofs;  // each = bstr .cbor [tree-size-1, tree-size-2,
                                 // paths, right-peaks]; decoded on-chain
    DelegationProof delegationProof;
}

struct DelegationProof {
    bytes32 delegatedKeyX;
    bytes32 delegatedKeyY;
    uint64 mmrStart;
    uint64 mmrEnd;
    uint64 alg;       // COSE-style; initially require P-256 (e.g. 1)
    bytes signature;  // P-256: 64 bytes (r || s)
}
```

Payment: raw inclusion proof = `bytes calldata` (bstr .cbor [index, path]).
Decode with `decodeInclusionProofPayload`; verify with `verifyInclusion`. No
signature.

**Single entry point (replaces existing):**

```solidity
function publishCheckpoint(
    ConsistencyReceipt calldata consistencyParts,
    bytes calldata paymentInclusionProof,  // empty when not required
    bytes8 paymentIDTimestampBe,
    IUnivocity.PublishGrant calldata publishGrant
) external;
```

**Bootstrap-only:** `setLogRoot(logId, rootKeyX, rootKeyY)` so the log root is
never derived from a cert.

## 3. Execution phases (complete guide)

Execute in order. Each phase leaves the tree buildable and testable where
possible.

---

### Phase 1 — Minimal delegation and root bootstrap

1. **Add `setLogRoot(logId, rootKeyX, rootKeyY)`** in Univocity (or
   equivalent), callable only by bootstrap. Ensures root is never taken from
   a cert.
2. **Add minimal `verifyDelegationProof`** (in delegationVerifier or
   inline): args (delegatedKeyX, delegatedKeyY, mmrStart, mmrEnd, alg,
   signature, logId, mmrIndex, storedRootX, storedRootY). Require alg
   indicates P-256; require signature.length == 64; r = signature[0:32],
   s = signature[32:64]; build canonical message (logId, mmrStart, mmrEnd,
   delegatedKeyX, delegatedKeyY), hash with sha256; P256.verify(hash, r, s,
   storedRootX, storedRootY); check logId and mmrIndex in [mmrStart, mmrEnd].
3. **Remove delegation cert decode path:** LibCose.decodeDelegationCert,
   DelegationCertDecoded; LibCbor.decodeDelegationPayload, DelegationPayload,
   readMapExtractDelegationUnprotected, readMapLookupBstr,
   readMapExtractCoseKeyEc2; delegationVerifier.verifyDelegationCert
   (current), _establishRoot, _parseUncompressedPoint. No other call sites
   should remain for these after removal.
4. **Tests:** Add tests for verifyDelegationProof and setLogRoot; remove or
   refactor tests for decodeDelegationCert / decodeDelegationPayload /
   verifyDelegationCert (old).

---

### Phase 2 — Calldata and storage for consistency proofs

**Revision (A.6a):** We use the memory path only: caller copies
consistencyProofs from calldata to memory; verifyConsistencyProofChain takes
bytes[] memory; decodeConsistencyProofPayload(bytes memory) is the single
decoder. The following steps 5–8 are superseded and left for reference only.

5. **LibCbor — calldata decoder:** *(Superseded: removed; memory path only.)* Add
   `decodeConsistencyProofPayload(bytes calldata data)` returning
   `ConsistencyProofPayload memory`. Raw bytes must not be copied wholesale;
   use a cursor-over-calldata (or calldata buffer) and only allocate memory
   for decoded paths and rightPeaks. Match existing decoder’s revert behaviour
   (UnexpectedMajorType, InvalidCborStructure). Test with same fixtures as
   memory decoder.
6. **consistentRoots — no copy from storage:** Done. `consistentRoots` takes
   `bytes32[] storage accumulatorFrom` and reads in place in the loop.
7. **consistencyReceipt:** *(Superseded: chain takes bytes[] memory; no
   calldata overload.)*
8. **Cleanup:** *(Superseded: single decoder is decodeConsistencyProofPayload(bytes
   memory); no calldata decoder to remove.)*
9. **Tests:** Consistency chain with calldata inputs; regression that first
   proof does not copy initial accumulator; full flow with pre-decoded
   receipt.

---

### Phase 3 — Removals (receipt envelopes and payment RoI)

10. **Delete whole files:** `src/cose/lib/LibCoseReceipt.sol`,
    `src/checkpoints/lib/LibInclusionReceipt.sol`,
    `src/checkpoints/lib/LibAuthorityVerifier.sol`.
11. **LibCose:** Remove decodeCoseSign1, decodeCoseSign1WithUnprotected,
    _readValueToBytes (and any other callers of these). Retain:
    buildSigStructure, verifySignatureDetachedPayload, fromDelegatedEs256,
    CoseSign1 (for verify path), _readBytes, _readLength, _skipValue,
    _encodeBstr, algorithm verification.
12. **LibCbor:** Remove readUnprotectedMapConsistencyProofs,
    readUnprotectedMapConsistencyProofsAndDelegation,
    readUnprotectedMapInclusionProofs, _readBstrOrArrayOfBstr;
    VDP_VERIFIABLE_PROOFS, CONSISTENCY_PROOF_LABEL, INCLUSION_PROOF_LABEL;
    decodePaymentClaims, PaymentClaims. Retain: extractAlgorithm,
    decodeConsistencyProofPayload (memory), decodeInclusionProofPayload,
    ConsistencyProofPayload, InclusionProofPayload, and internal helpers used
    only by those.
13. **Tests:** Remove or repurpose LibCoseReceipt.t.sol,
    LibAuthorityVerifier.t.sol; adjust LibCose.t.sol and LibCbor.t.sol (drop
    tests for removed functions; keep buildSigStructure, verifySignature*,
    decodeConsistencyProofPayload, decodeInclusionProofPayload).

---

### Phase 4 — Univocity: single entry point and payment path

14. **Replace publishCheckpoint** with the single pre-decoded signature:
    `ConsistencyReceipt calldata consistencyParts`, `bytes calldata
    paymentInclusionProof`, paymentIDTimestampBe, publishGrant. Remove the
    old overload that accepted raw receipt bytes.
15. **Consistency path:** Call
    `verifyConsistencyProofChain(log.accumulator, consistencyParts.consistencyProofs)`.
    Build detached payload from returned accumulator; verify consistency
    receipt signature with delegated key (when delegation) or stored root
    (otherwise). For delegation, call verifyDelegationProof then verify
    signature with (delegatedKeyX, delegatedKeyY).
16. **Payment path:** When paymentInclusionProof.length > 0, decode with
    decodeInclusionProofPayload, then verifyInclusion(index, leafCommitment,
    path, authorityLog.accumulator, authorityLog.size). No signature
    verification for payment.
17. **Imports:** Remove LibCoseReceipt, LibInclusionReceipt (and
    LibAuthorityVerifier if still referenced).

---

### Phase 5 — Quality

18. **Tests:** Full publishCheckpoint flow with ConsistencyReceipt calldata
    and calldata paymentInclusionProof; delegation via minimal proof;
    setLogRoot then delegated checkpoint. Ensure no regression on state
    updates and signature verification.
19. **Lint and format:** Run `forge fmt`; fix comment line length per
    project rules (79/100, tag continuation); resolve warnings.
20. **NatSpec:** Document that verifyConsistencyProofChain takes
    bytes[] memory (caller copies from calldata at entry point); that
    consistentRoots reads storage in place and does not copy the accumulator.
    Keep comments implementation-focused.

**Done criteria:** Single entry point live; payment plain inclusion only;
delegation minimal proof only; all listed code removed; raw proof bytes
calldata and first proof uses storage; tests pass; format and lint clean.

### Implementation status (as of plan revision)

- **Phase 1:** Steps 1–2 done (setLogRoot, verifyDelegationProof in place and
  used from publishCheckpoint). Step 3–4 not done: delegation cert decode
  path (decodeDelegationCert, verifyDelegationCert, _establishRoot,
  _parseUncompressedPoint, decodeDelegationPayload, etc.) still present;
  removal is part of Phase 3.
- **Phase 2:** Revised per Appendix A.6a. We do **not** use a calldata
  decoder; we use the memory path only. Caller copies
  consistencyParts.consistencyProofs from calldata to memory, then calls
  verifyConsistencyProofChain(bytes[] memory). Steps 5–8 (add calldata
  decoder, switch chain to calldata, remove memory decoder) are superseded.
  Step 6 (consistentRoots no copy from storage) is done: consistentRoots
  already takes storage and reads in place.
- **Phase 3:** Not done. LibCoseReceipt, LibInclusionReceipt,
  LibAuthorityVerifier still exist. Tests use LibCoseReceipt for
  _toConsistencyReceipt (decode raw receipt → struct for publishCheckpoint).
  LibCose/LibCbor/delegationVerifier still contain the receipt/cert/decode
  code listed in §4.
- **Phase 4:** Done. Single publishCheckpoint(ConsistencyReceipt calldata,
  paymentInclusionProof, paymentIDTimestampBe, publishGrant); consistency
  path copies proofs and uses verifyConsistencyProofChain; payment path uses
  decodeInclusionProofPayload + verifyInclusion; delegation uses
  verifyDelegationProof. Univocity does not import LibCoseReceipt,
  LibInclusionReceipt, or LibAuthorityVerifier.
- **Phase 5:** Partial. NatSpec for verifyConsistencyProofChain should say it
  takes memory (caller copies from calldata); step 20 referred to calldata
  and is obsolete.

**Next steps (recommended order):**

1. **Align plan text with decisions:** In §5 "What to retain", change
   "decodeConsistencyProofPayload (calldata path)" to "(memory path)". Add a
   one-line note under Phase 2 that it was revised per A.6a (memory path,
   copy at boundary).
2. **Phase 3 — removals:** Delete LibCoseReceipt.sol, LibInclusionReceipt.sol,
   LibAuthorityVerifier.sol. Strip LibCose (decodeCoseSign1,
   decodeCoseSign1WithUnprotected, _readValueToBytes, decodeDelegationCert,
   DelegationCertDecoded), LibCbor (readUnprotectedMap*,
   decodePaymentClaims, PaymentClaims, decodeDelegationPayload,
   DelegationPayload, readMapExtractDelegationUnprotected, readMapLookupBstr,
   readMapExtractCoseKeyEc2, constants), delegationVerifier
   (verifyDelegationCert, _establishRoot, _parseUncompressedPoint). Retain
   only what §5 lists.
3. **Tests without LibCoseReceipt:** Tests currently use
   _toConsistencyReceipt(raw) → LibCoseReceipt.decodeConsistencyReceiptCoseSign1FromMemory.
   Either (a) add a test-only helper (e.g. in test/ or a test helper contract)
   that decodes raw COSE receipt bytes to ConsistencyReceipt so tests keep
   passing without LibCoseReceipt in src, or (b) refactor tests to build
   ConsistencyReceipt (protectedHeader, signature, consistencyProofs,
   delegationProof) directly from test data and remove the raw-receipt
   decode path entirely. Option (b) is cleaner long-term but requires more
   test refactor.
4. **Phase 5 — quality:** Update NatSpec (verifyConsistencyProofChain takes
   memory; caller copies from calldata). Run full test suite, forge fmt, fix
   comment line length per project rules. Fix or remove Univocity.sol
   comment that references LibAuthorityVerifier (e.g. ks256Signer "Used by
   LibAuthorityVerifier").

## 4. Code to remove (consolidated)

**Files to delete:**

| File | Reason |
|------|--------|
| `src/cose/lib/LibCoseReceipt.sol` | Consistency and RoI decode removed; pre-decoded path only. |
| `src/checkpoints/lib/LibInclusionReceipt.sol` | Payment = plain inclusion; no RoI verify. |
| `src/checkpoints/lib/LibAuthorityVerifier.sol` | Not used; CWT payment claims path removed. |

**LibCose:** decodeCoseSign1, decodeCoseSign1WithUnprotected, _readValueToBytes,
decodeDelegationCert, DelegationCertDecoded.

**LibCbor:** readUnprotectedMapConsistencyProofs,
readUnprotectedMapConsistencyProofsAndDelegation,
readUnprotectedMapInclusionProofs, _readBstrOrArrayOfBstr;
VDP_VERIFIABLE_PROOFS, CONSISTENCY_PROOF_LABEL, INCLUSION_PROOF_LABEL;
decodePaymentClaims, PaymentClaims; decodeDelegationPayload,
DelegationPayload, readMapExtractDelegationUnprotected, readMapLookupBstr,
readMapExtractCoseKeyEc2.

**delegationVerifier:** verifyDelegationCert (current implementation),
_establishRoot, _parseUncompressedPoint. Replace with verifyDelegationProof
(Phase 1).

**Optional after Phase 2:** decodeConsistencyProofPayload(bytes memory) and
any helpers that become dead, unless kept as test-only.

## 5. What to retain

- **Consistency:** decodeConsistencyProofPayload (memory path; caller copies
  from calldata at entry point), ConsistencyProofPayload;
  verifyConsistencyProofChain,
  buildDetachedPayloadCommitment; consistentRoots (storage, no copy),
  consistentRootsMemory, peaks, includedRoot.
- **Inclusion (payment):** decodeInclusionProofPayload, InclusionProofPayload,
  verifyInclusion.
- **COSE (signature only):** buildSigStructure, verifySignatureDetachedPayload,
  fromDelegatedEs256, CoseSign1, algorithm verification; no receipt decode.
- **Delegation:** verifyDelegationProof (minimal), setLogRoot (bootstrap).

---

# Appendix A. Supporting reasoning and discussion

This appendix holds the rationale and extended discussion for the decisions
in §1. It is not part of the execution checklist.

## A.1 Security invariant: what binds proofs to the signature

COSE Sign1 signs Sig_structure = ["Signature1", protected, external_aad,
payload]. For Receipt of Consistency (MMR profile), the payload is
**detached**: the verifier recomputes it from (initial peaks, consistency
proofs). The verifier runs the consistency algorithm to get the new
accumulator, builds the detached payload (e.g. commitment to that
accumulator), then verifies the signature over (protected, that payload).
The signature verifies only if the payload derived from the provided proofs
equals what the signer signed. So **verification itself** binds the proofs
to the signature; the contract does not need to parse a full COSE_Sign1
envelope to establish that (protected, signature, proofs) belong together.
Pre-decoding off-chain and passing (protectedHeader, signature,
consistencyProofs) is therefore **safe** as long as the contract (1) runs
verifyConsistencyProofChain, (2) builds detached payload from the result,
(3) verifies the signature over (protectedHeader, that payload).

## A.2 What can be minimised on-chain

Single-purpose decoders instead of generic decodeCoseSign1; no reassembly of
receipts; consistency proof payloads already minimal (decodeConsistencyProofPayload
+ algorithms). For payment, switching to plain inclusion removes all COSE
handling for payment. For delegation, minimal proof removes all COSE/CBOR
for delegation. Target layered API is summarised in A.3.

## A.3 Minimal layered API (target shape)

**CBOR:** Decode consistency-proof payload only (array(4) → treeSize1,
treeSize2, paths, rightPeaks); decode inclusion-proof payload when payment
non-empty. No generic map iteration; no delegation cert decode.

**COSE:** buildSigStructure(protectedHeader, payload);
verifySignatureDetachedPayload(cose, detachedPayload, keys); fromDelegatedEs256.
No decodeCoseSign1 / decodeCoseSign1WithUnprotected; no decodeDelegationCert.

**MMR:** verifyConsistencyProofChain, buildDetachedPayloadCommitment,
consistentRoots, consistentRootsMemory, peaks, includedRoot,
decodeInclusionProofPayload, verifyInclusion.

## A.4 Delegation: off-chain handling and stored root only

We cannot accept a caller-supplied root and delegated key without
on-chain verification that the root authorized the delegated key; otherwise
an attacker could supply (root′, delegated′) and sign with delegated′. So
verification of “root authorized this delegated key” must happen on-chain.
We must **not** use a caller-supplied root for that verification; we use
only the **stored** root (log.rootKeyX, log.rootKeyY). The root is
established by bootstrap (e.g. setLogRoot) before any delegated checkpoint;
we do not establish root from a cert. Minimal delegation proof: caller
supplies (delegatedKeyX, delegatedKeyY, mmrStart, mmrEnd, alg, signature);
contract verifies one P-256 signature from the stored root over a canonical
message binding those values, then verifies the consistency receipt
signature with the delegated key.

## A.5 Minimal cryptographic binding: delegated key ↔ root

What must be assured: the delegated key that signed the consistency receipt
was **authorized by the root**. Minimal approach: (1) Stored root only. (2)
Caller supplies delegation proof (delegatedKey, mmrStart, mmrEnd, alg,
signature). (3) Canonical message: deterministic encoding of (logId, mmrStart,
mmrEnd, delegatedKeyX, delegatedKeyY). (4) For P-256: require signature.length
== 64, r = signature[0:32], s = signature[32:64]; hash = sha256(canonicalMessage);
P256.verify(hash, r, s, storedRootX, storedRootY). (5) Check logId and
mmrIndex in [mmrStart, mmrEnd]. (6) Verify consistency receipt signature with
delegated key (existing COSE path). No COSE/CBOR for delegation; only
P256.verify, sha256, canonical message encoding, and alg-specific signature
unpacking.

### A.5a. Assessment: key format vs alg; one alg or two?

**1. Should the delegated key format be contingent on alg?**

Yes. The delegated key representation should be defined by the algorithm.

- **Today (P-256 only):** We use `(delegatedKeyX, delegatedKeyY)` — uncompressed
  P-256 point. That matches `alg` indicating ES256/P-256.
- **Future algs:** Other algorithms use different key formats (e.g. Ed25519:
  single 32-byte public key; compressed EC: 33 bytes). So key layout is
  alg-specific.
- **Recommendation:** Keep the current struct for the initial P-256-only
  design. Document that `alg` defines both the delegation-signature algorithm
  and the delegated-key format. If a second algorithm family is added later,
  either (a) extend the struct with alg-specific key fields (e.g. optional
  `bytes delegatedKeyRaw` for non-P-256), or (b) use a single `bytes
  delegatedKeyMaterial` plus `alg` and decode in an alg-specific way. No
  change required for the current single-alg design; just document the
  dependency.

**2. Do we need distinct algs for the delegation signature and the delegated
key?**

No, for the current design. One `alg` in DelegationProof is enough.

- **What the single `alg` is used for today:**
  - (a) **Delegation proof signature:** The *root* signs the canonical message
    with this algorithm. We require alg = ES256, unpack (r, s), and call
    P256.verify. So `alg` identifies the algorithm used for the delegation
    signature.
  - (b) **Delegated key type:** We pass `(delegatedKeyX, delegatedKeyY)` to
    `fromDelegatedEs256` when verifying the consistency receipt. So we
    implicitly assume the delegated key is a P-256 key. That matches the same
    alg.
- **Consistency receipt algorithm:** The algorithm used to *sign the
  consistency receipt* is **not** in DelegationProof; it is in the receipt’s
  protected header. The contract reads it via
  `extractAlgorithm(consistencyParts.protectedHeader)` and uses it in
  `verifySignatureDetachedPayload`. So the receipt can in principle declare
  ES256 or KS256; for the delegation path we currently supply a P-256 key
  (fromDelegatedEs256), so the receipt must use ES256 for that key to be
  valid. No second alg field is needed for “receipt signature alg” because
  that is carried by the receipt.
- **When would two algs be useful?** Only if we ever support a split such as:
  “root signs the delegation message with algorithm A (e.g. P-256), and the
  delegated key is of type B (e.g. Ed25519).” Then we’d want one identifier
  for the delegation-signature algorithm (and signature layout) and one for
  the delegated-key type (and key format). For P-256-only, A and B are the
  same, so one `alg` suffices.
- **Decision (applied):** Keep a single `alg` in DelegationProof. Document that
  it specifies (1) the root's delegation-signature algorithm and (2) the
  delegated key's type/format. Add a second field (e.g. `delegatedKeyAlg`)
  only if you introduce another key/signature family later.

## A.6 Calldata and storage (proof data and accumulatorFrom)

**Proof data:** The entry point receives ConsistencyReceipt calldata, so
consistencyProofs is bytes[] calldata. We can change
verifyConsistencyProofChain to take bytes[] calldata rawProofPayloads and
decodeConsistencyProofPayload(bytes calldata data) so raw proof bytes are
never copied at the edge. The decoder must use a calldata-capable cursor or
buffer; only decoded paths and rightPeaks are allocated in memory. Algorithm
functions continue to take decoded data in memory.

**accumulatorFrom:** For the **first** proof (idx == 0), the input is
initialAccumulator (storage). We can avoid copying by implementing
consistentRoots so it reads accumulatorFrom[i] from storage in the loop and
calls includedRoot(fromPeaks[i], accumulatorFrom[i], proofs[i]). For
**subsequent** proofs (idx >= 1), the input is the previous step’s result
(accMem), which is necessarily in memory; consistentRootsMemory remains the
path for chained steps.

### A.6a. Assessment: calldata vs memory consistency-proof decoder

We previously had two decoders: `decodeConsistencyProofPayload(bytes memory)`
(WitnetBuffer-based) and `decodeConsistencyProofPayloadFromCalldata(bytes
calldata)` (cursor over calldata). The calldata path produced signature
verification failures in practice. The contract copies
`consistencyParts.consistencyProofs` into memory and uses the single memory
path; the calldata decoder and verifyConsistencyProofChainCalldata have been
removed.

**Efficiency.** The calldata decoder avoids copying the raw proof bytes from
calldata to memory before decoding; only the decoded outputs (paths,
rightPeaks, sizes) are allocated in memory. So when the source is calldata,
the calldata path is more gas- and memory-efficient at the boundary. When
the source is already memory (e.g. tests building payloads in memory), there
is no efficiency gain from a calldata decoder.

**Simplicity and robustness.** The memory decoder shares the same helpers
(`_readLength`, `_readUint`, `_readBytes`, `_readArrayOfBstr32`,
`_readArrayOfArrayOfBstr32`) with the rest of LibCbor (payment claims,
delegation payload, inclusion proof, COSE map reading). One code path, one
mental model, one set of edge cases. WitnetBuffer is audited (Trail of Bits)
and used consistently. The calldata decoder duplicates CBOR reading logic
with cursor-based, calldata-specific helpers; we have two implementations
to maintain and have already seen a failure (wrong decoded accumulator →
detached payload mismatch → ConsistencyReceiptSignatureInvalid) when using the
calldata path, which suggests higher risk of off-by-one or layout bugs.

**Complexity of implementation.** Memory: single decoder plus shared helpers;
dependency on WitnetBuffer is consistent with the rest of the library.
Calldata: a second, parallel implementation (length decoding, uint decoding,
bstr32 and array-of-bstr32 reading) with assembly for calldataload in
`_readBstr32Calldata`. More code, more surface area, and no reuse of the
audited buffer logic.

**WitnetBuffer and eliminability.** The consistency-proof decoder is only one
of several LibCbor entry points. `decodePaymentClaims`, `decodeDelegationPayload`,
`decodeInclusionProofPayload`, and COSE map reading (e.g. for protected
header, inclusion proofs, EC2 key) all use WitnetBuffer. Adopting the
calldata decoder for consistency proofs alone does **not** allow removing the
WitnetBuffer dependency; we would still need it for every other decoder. To
eliminate WitnetBuffer we would have to reimplement or duplicate all of those
paths with calldata- or custom-memory cursors, which would be a large,
risky change and would lose the benefit of the audited dependency. So the
calldata consistency decoder does not materially move the needle on
dependency reduction, and eliminating WitnetBuffer is not a good trade for
this use case.

**Reality of "proofs as calldata".** The original goal of having low-level
algorithms work exclusively on proofs as calldata cannot be met. The
algorithms (`consistentRoots`, `consistentRootsMemory`, `includedRoot`) take
decoded data: `bytes32[][] memory` paths, `bytes32[] memory` peaks/accumulator.
Those structures are built and passed in memory. So at best we keep the *raw*
proof bytes in calldata until the moment we decode; after that, everything
is in memory. The only benefit of the calldata decoder is avoiding the copy
of those raw bytes from calldata to memory before decoding. That is a
bounded saving (one copy per proof payload), not a structural guarantee that
"proofs stay in calldata."

**Recommendation.** Prefer the **memory-based `decodeConsistencyProofPayload`**
and treat it as the single path for consistency-proof decoding. The calldata
decoder and `verifyConsistencyProofChainCalldata` have been removed. The contract should continue to copy
`consistencyParts.consistencyProofs` from calldata into a `bytes[] memory`
and call `verifyConsistencyProofChain` (memory). Reasons: (1) One
implementation, one set of helpers, one dependency (WitnetBuffer) shared with
all other CBOR decoding. (2) Proven, audited buffer behaviour; no duplicate
cursor logic. (3) The "proofs only in calldata" goal is unattainable for the
algorithms anyway; we only gain avoiding one copy per payload, at the cost of
duplicate code and observed bugs. (4) WitnetBuffer cannot be removed by this
choice alone, so the calldata path does not simplify the dependency graph.
Accepting the copy at the boundary is the simpler and more robust choice.

## A.6b Pre-decode consistency (and inclusion) proof elements

**Question.** The decoding of `bytes[] consistencyProofs` on-chain (each
element = bstr .cbor [ tree-size-1, tree-size-2, consistency-paths,
right-peaks ]) is redundant if the client can decode CBOR off-chain. Can we
pre-decode those elements and pass decoded data so the contract never runs
`decodeConsistencyProofPayload`, and thus remove more CBOR support?

**Assessment: yes.** We can change the receipt and entry point so that
consistency proof *payloads* are supplied already decoded.

**Proposed change (consistency only):**

- Replace `bytes[] consistencyProofs` in `ConsistencyReceipt` with an array
  of decoded payloads, e.g. a struct matching the current
  `ConsistencyProofPayload` (treeSize1, treeSize2, paths, rightPeaks).
- Contract then never calls `decodeConsistencyProofPayload`; it passes the
  decoded array directly into the consistency chain (e.g.
  `verifyConsistencyProofChain(initialAccumulator, decodedProofs)` where
  `decodedProofs` is `ConsistencyProofPayload[]`).
- **Removable from LibCbor:** `decodeConsistencyProofPayload`,
  `_readArrayOfArrayOfBstr32`, and (if only used there) `_readArrayOfBstr32`
  for the consistency path. Note: `_readArrayOfBstr32` is also used by
  `decodeInclusionProofPayload`; see below.

**Inclusion proof.** The same idea applies to the payment inclusion proof:
today the contract receives `bytes paymentInclusionProof` (bstr .cbor [
index, path ]) and decodes it with `decodeInclusionProofPayload`. If we
pre-decode, the entry point can take (e.g.) optional `(uint64 index,
bytes32[] path)` or a small struct instead of raw bytes. Then the contract
never calls `decodeInclusionProofPayload`.

**If both are pre-decoded:**

- **Removable from LibCbor:** `decodeConsistencyProofPayload`,
  `decodeInclusionProofPayload`, `_readArrayOfBstr32`,
  `_readArrayOfArrayOfBstr32`, `_readUint`, `_readBytes`, `_bytesToBytes32`,
  and the structs `ConsistencyProofPayload` / `InclusionProofPayload` (move
  to interface or shared types as the pre-decoded shapes).
- **Remaining in LibCbor:** Only what is needed for the protected header:
  `extractAlgorithm` and its helpers: `_readLength`, `_readIntegerKey`,
  `_readInteger`, `_skipValue`. No WitnetBuffer use for proof decoding; only
  for the small protected-header map read.

**ABI / calldata.** Passing decoded consistency proofs means
`ConsistencyProofPayload[]` (or equivalent) in the receipt. Each element has
`uint64 treeSize1`, `uint64 treeSize2`, `bytes32[][] paths`, `bytes32[]
rightPeaks`. Solidity and the ABI support nested dynamic arrays in structs
in calldata. So the receipt can be e.g.
`ConsistencyProofPayload[] decodedConsistencyProofs` instead of
`bytes[] consistencyProofs`. Same for payment: instead of
`bytes paymentInclusionProof`, use e.g. `InclusionProofPayload calldata` (or
two args `uint64 index`, `bytes32[] path`) when non-empty.

**Recommendation.** Pre-decoding the referenced elements (consistency proof
payloads and, optionally, the payment inclusion proof) is feasible and
reduces on-chain CBOR to the minimum: only the protected header map for
`extractAlgorithm`. That eliminates the “redundant” decoding described in
the diff (decodeConsistencyProofPayload and the right-peaks/paths decoding).
Implement as a follow-on to the current plan: (1) Add
`ConsistencyProofPayload[]` (or a type alias) to the receipt and
`verifyConsistencyProofChain(..., ConsistencyProofPayload[] memory)`; remove
on-chain consistency proof decoding. (2) Optionally add pre-decoded
inclusion proof to the entry point and remove
`decodeInclusionProofPayload`.

## A.7 Payment by plain inclusion: why safe and advantageous

**Decision:** Payment proof is plain inclusion proof only (no COSE RoI, no
signature verification for payment).

**Why safe:** The authority log’s state (accumulator, size) is already trusted
on-chain (from verified checkpoints). A valid MMR inclusion proof (index +
path) proves the leaf is in that tree. The attestation is inclusion itself;
forging would require a preimage for the leaf hash or control of the
authority log. So plain inclusion enforces the same “grant from auth log”
guarantee as a signed receipt.

**Why advantageous:** Simpler (no COSE for payment, no payment signature);
less code (LibInclusionReceipt and RoI paths removed); lower gas; matches
the invariant that the grant is enforceable with plain inclusion. Encoding:
bstr .cbor [ index, inclusion-path ] per MMR profile.
