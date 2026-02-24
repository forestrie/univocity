# Plan 0016: Minimal COSE/CBOR API and pre-decode (agent execution guide)

**Status:** DRAFT  
**Date:** 2025-02-23  
**Related:** [plan-0014](plan-0014-feasibility-consistency-receipt-calldata-memory.md),
[plan-0015](plan-0015-publishCheckpoint-payment-receipt-as-roi.md),
[draft-bryce-cose-receipts-mmr-profile](https://raw.githubusercontent.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/refs/heads/main/draft-bryce-cose-receipts-mmr-profile.md)

## 1. Goal and decisions

**Goal:** Replace the current `publishCheckpoint` with a **single pre-decoded
entry point** and radically simplify the codebase: no full COSE_Sign1 receipt
parsing on-chain, no Receipt of Inclusion for payment, no delegation cert
decode. Raw proof data is calldata at the edge; first consistency proof uses
storage for the initial accumulator (no copy).

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
    IUnivocity.PaymentGrant calldata paymentGrant
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
2. **Add minimal `verifyDelegationProof`** (in LibDelegationVerifier or
   inline): args (delegatedKeyX, delegatedKeyY, mmrStart, mmrEnd, alg,
   signature, logId, mmrIndex, storedRootX, storedRootY). Require alg
   indicates P-256; require signature.length == 64; r = signature[0:32],
   s = signature[32:64]; build canonical message (logId, mmrStart, mmrEnd,
   delegatedKeyX, delegatedKeyY), hash with sha256; P256.verify(hash, r, s,
   storedRootX, storedRootY); check logId and mmrIndex in [mmrStart, mmrEnd].
3. **Remove delegation cert decode path:** LibCose.decodeDelegationCert,
   DelegationCertDecoded; LibCbor.decodeDelegationPayload, DelegationPayload,
   readMapExtractDelegationUnprotected, readMapLookupBstr,
   readMapExtractCoseKeyEc2; LibDelegationVerifier.verifyDelegationCert
   (current), _establishRoot, _parseUncompressedPoint. No other call sites
   should remain for these after removal.
4. **Tests:** Add tests for verifyDelegationProof and setLogRoot; remove or
   refactor tests for decodeDelegationCert / decodeDelegationPayload /
   verifyDelegationCert (old).

---

### Phase 2 — Calldata and storage for consistency proofs

5. **LibCbor — calldata decoder:** Add
   `decodeConsistencyProofPayload(bytes calldata data)` returning
   `ConsistencyProofPayload memory`. Raw bytes must not be copied wholesale;
   use a cursor-over-calldata (or calldata buffer) and only allocate memory
   for decoded paths and rightPeaks. Match existing decoder’s revert behaviour
   (UnexpectedMajorType, InvalidCborStructure). Test with same fixtures as
   memory decoder.
6. **consistentRoots — no copy from storage:** In
   `src/algorithms/consistentRoots.sol`, refactor `consistentRoots` so it
   does **not** copy `accumulatorFrom` to memory. Implement the same loop as
   `consistentRootsMemory` in place: `fromPeaks = peaks(ifrom)`, then for each
   i call `includedRoot(fromPeaks[i], accumulatorFrom[i], proofs[i])` with
   duplicate collapsing. Leave `consistentRootsMemory` unchanged (used for
   chained steps).
7. **LibConsistencyReceipt:** Change
   `verifyConsistencyProofChain(bytes32[] storage initialAccumulator, bytes[] memory rawProofPayloads)`
   to
   `verifyConsistencyProofChain(bytes32[] storage initialAccumulator, bytes[] calldata rawProofPayloads)`.
   In the loop call `decodeConsistencyProofPayload(rawProofPayloads[idx])`
   (calldata overload). Keep idx==0 using `consistentRoots(..., initialAccumulator, p.paths)` and idx>=1 using `consistentRootsMemory(..., accumulatorFrom, p.paths)`.
8. **Cleanup:** Once all call sites use calldata, remove
   `decodeConsistencyProofPayload(bytes memory)` (and any helpers that become
   dead) unless tests still need it; then prefer a test-only helper.
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
    decodeConsistencyProofPayload (calldata path), decodeInclusionProofPayload,
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
    paymentInclusionProof`, paymentIDTimestampBe, paymentGrant. Remove the
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
20. **NatSpec:** Document that verifyConsistencyProofChain takes calldata
    and does not copy raw proof bytes; that consistentRoots reads storage in
    place and does not copy the accumulator. Keep comments
    implementation-focused.

**Done criteria:** Single entry point live; payment plain inclusion only;
delegation minimal proof only; all listed code removed; raw proof bytes
calldata and first proof uses storage; tests pass; format and lint clean.

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

**LibDelegationVerifier:** verifyDelegationCert (current implementation),
_establishRoot, _parseUncompressedPoint. Replace with verifyDelegationProof
(Phase 1).

**Optional after Phase 2:** decodeConsistencyProofPayload(bytes memory) and
any helpers that become dead, unless kept as test-only.

## 5. What to retain

- **Consistency:** decodeConsistencyProofPayload (calldata path),
  ConsistencyProofPayload; verifyConsistencyProofChain,
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
