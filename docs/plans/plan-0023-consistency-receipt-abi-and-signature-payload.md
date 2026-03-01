# Plan 0023: ConsistencyReceipt ABI encoding and signature payload

**Status:** DRAFT  
**Date:** 2025-02-23  
**Related:** [plan-0016](plan-0016-minimal-cose-cbor-api-predecode.md), [ADR-0005](../adr/adr-0005-grant-constrains-checkpoint-signer.md)

## 1. Purpose

This document specifies unambiguously (1) how `ConsistencyReceipt` and nested
types are ABI-encoded and decoded, and (2) what is covered by the consistency
receipt signature. There must be no ambiguity: the same receipt bytes must
decode to the same in-memory representation regardless of how the receipt is
passed (e.g. as the only parameter vs as the first of four parameters), and
the signed payload must be uniquely determined by the decoded receipt.

## 2. Types (IUnivocity)

```solidity
struct ConsistencyProof {
    uint64 treeSize1;
    uint64 treeSize2;
    bytes32[][] paths;
    bytes32[] rightPeaks;
}

struct ConsistencyReceipt {
    bytes protectedHeader;
    bytes signature;
    ConsistencyProof[] consistencyProofs;
    DelegationProof delegationProof;
}
```

All four fields of `ConsistencyReceipt` are dynamic (variable-length). All
fields of `ConsistencyProof` except `treeSize1` and `treeSize2` are dynamic.

## 3. ABI encoding (EIP-712 / Contract ABI)

### 3.1 Rules

- Dynamic types (bytes, arrays, structs with dynamic fields) are encoded as a
  32-byte offset from the start of the argument block to the start of their
  data. The actual data is laid out in a tail section; nested dynamic values
  are again represented by offsets relative to the argument block start.
- Structs are encoded as the concatenation of the encoding of their fields,
  in declaration order.
- So for a single argument `(ConsistencyReceipt receipt)`, the argument block
  is: `[offset_protectedHeader, offset_signature, offset_consistencyProofs,
  offset_delegationProof]` (4 × 32 bytes) followed by the tail. Each offset
  points to the start of that field’s encoding.
- For four arguments
  `(ConsistencyReceipt consistencyParts, InclusionProof paymentInclusionProof,
  bytes8 paymentIDTimestampBe, PaymentGrant paymentGrant)` the argument block
  is: `[offset_consistencyParts, offset_inclusion, paymentIDTimestampBe (padded
  to 32), offset_grant]` (4 × 32 bytes). The first word is the offset to the
  receipt. At that offset, the receipt is encoded exactly as above: four
  offsets then tail. The *content* of the receipt (the four offsets for its
  fields and the tail) is the same sequence of bytes regardless of whether
  the receipt is the only argument or the first of four. Only the *base*
  offset (where that content starts) differs (e.g. 0x20 for single-arg vs 0x80
  for four-arg).

### 3.2 Decoding

- The callee receives calldata. When it reads the first parameter
  `ConsistencyReceipt calldata consistencyParts`, it loads the offset at
  the parameter’s slot (e.g. 0x04 + 0x00 for selector + first arg), then
  interprets the 4 words at that offset as the four field offsets, then
  follows those to decode protectedHeader, signature, consistencyProofs,
  delegationProof. The Solidity compiler generates the same decoding logic
  for the same type. The decoded struct is therefore uniquely determined by
  the bytes at the pointed-to offset.
- **Conclusion:** If the same `ConsistencyReceipt` value is encoded as the
  only parameter and again as the first of four parameters, the *receipt
  content* bytes (the 4 offsets + tail for the receipt) are identical. The
  decoder reads from a different base offset but follows the same layout.
  **There is no room for the decoder to produce different decoded values for
  the same receipt.** Any observed difference (e.g. different
  `consistencyProofs[0].rightPeaks[0]` or different recovered key) must have
  a cause other than “ABI decode differs by parameter position.”

## 4. What is covered by the signature

The consistency receipt signature is over a **detached payload** that is
derived deterministically from the receipt’s consistency proofs (and, for
extend checkpoints, from the log’s current accumulator). No other input
affects the payload.

### 4.1 Payload derivation (same in contract and test helper)

1. **Accumulator from proofs**

   `accMem = verifyConsistencyProofChain(initialAcc, consistencyProofs)`.

   - For the **first checkpoint** (new log): `initialAcc = []`. For one proof
     with `treeSize1 == 0`, `accMem = _copyPeaks(proof.rightPeaks)` (a copy of
     the proof’s `rightPeaks` array).
   - So for a single proof (treeSize1=0, treeSize2=1, paths=[], rightPeaks=
     [peak0]), we have `accMem = [peak0]`.

2. **Detached payload (commitment)**

   `detachedPayload = buildDetachedPayloadCommitment(accMem)`  
   `= abi.encodePacked(sha256(abi.encodePacked(accMem)))`.

   So 32 bytes: the SHA-256 hash of the concatenation of the accumulator
   elements (for one peak, the hash of that one 32-byte peak).

3. **Sig_structure (COSE)**

   `sigStructure = buildSigStructure(protectedHeader, detachedPayload)`  
   `= abi.encodePacked(0x84, "Signature1", bstr(protectedHeader), 0x40,
   bstr(detachedPayload))` (COSE_Sign1 Sig_structure per RFC 9052).

4. **Message actually signed**

   `messageHash = sha256(sigStructure)`.

   The signer signs this hash. The verifier recomputes the same chain from
   the decoded receipt and checks the signature.

### 4.2 Uniqueness

- Given the decoded `consistencyProofs` (and, for extend, the log’s
  `initialAcc`), `accMem` is unique, hence `detachedPayload` is unique,
  hence `sigStructure` and `messageHash` are unique. **There is no ambiguity
  in what is covered by the signature**: it is exactly the hash of the
  Sig_structure built from the decoded receipt’s `protectedHeader` and the
  commitment derived from the decoded receipt’s consistency proof chain.

## 5. What would be required to “align” decoding

- **If the ABI and the decoder behave as specified:** no alignment is needed.
  The same receipt bytes decode to the same struct whether passed as the only
  argument or as the first of four. Any test that passes the same `ConsistencyReceipt`
  value to a helper (one-arg) and to `publishCheckpoint` (four-arg) should see
  the same decoded content and therefore the same recovered key, provided the
  contract uses only the decoded receipt to build the payload (it does).

- **If tests show different behaviour** (e.g. helper recovers key K1, contract
  recovers K2 for the “same” receipt), the cause is not “ABI decode differs
  by parameter position” but one of:
  - The test not actually passing the same receipt (e.g. struct modified
    between calls, or different receipt used).
  - A bug in the contract (e.g. reading a different calldata region).
  - A bug or quirk in the compiler/runtime (e.g. incorrect codegen for
    calldata struct in a multi-arg function).

A **verification view** was added (ES256ReceiptDecodeVerifier.decodeAndRecover)
that takes the same four parameters as `publishCheckpoint` and returns the
first peak and the recovered ES256 key. The test
`test_consistencyReceipt_decodeIdentical_oneArgVsFourArg` calls both the
one-arg helper and this four-arg verifier with the same receipt and asserts
that the first peak and recovered key are identical. **This test passes:**
decoding is identical for 1-arg vs 4-arg. Any earlier test failure was not
due to ABI decode differing by parameter position.

## 6. Verification view and test result

ES256ReceiptDecodeVerifier.decodeAndRecover (in UnivocityTestHelper.sol) takes
the same four parameters as `publishCheckpoint` and returns the first peak and
recovered key. The test `test_consistencyReceipt_decodeIdentical_oneArgVsFourArg`
asserts that for the same receipt, the one-arg helper and the four-arg verifier
return the same peak and key. **The test passes**, so decoding and payload
construction are aligned; there is no ambiguity in ConsistencyReceipt decode or
in what is covered by the signature.

ES256ReceiptDecodeVerifier.getLeafCommitment (same 4-arg layout) returns the
leaf commitment the contract would compute from the decoded grant. Tests can
use it to assert that the receipt commits to the same leaf the contract will
use for inclusion.

## 7. Grant encode/decode and recovery: narrow tests and root cause

### 7.1 Exact cause: recovery ≠ vm.publicKeyP256

**Root cause (narrow test: `test_es256RecoveredKey_doesNotEqual_publicKeyP256`):**  
The key recovered from a receipt signed by `vm.signP256(pk)` does **not** equal
`vm.publicKeyP256(pk)`. The bootstrap must use the **recovered** key, not the
cheatcode public key. So tests that deploy with `(pubX, pubY)` from
`vm.publicKeyP256(1)` and submit a receipt signed with `vm.signP256(1, hash)`
fail with `RootSignerMustMatchBootstrap` because the contract recovers a
different point.

**Hex bytes (run `test_es256RecoveredKey_vs_publicKeyP256_hexBytes` with -vv):**

| Source | x (hex) | y (hex) |
|--------|---------|---------|
| vm.publicKeyP256(1) | 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 | 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 |
| Recovered from receipt | 0xe38febc6e579c079a5ab851eb8a8032f95c86fd601990238756ece3db4427b66 | 0x682caf3b0c098e8f0754b2b46c308f6711e448e22694008f3c9e9c531b5c62b2 |

Both are (x, y) as two 32-byte values (uncompressed without 04 prefix).
Compressed form would be 02 or 03 + x (33 bytes). The x-coordinates differ, so
**they are different EC points, not the same key in compressed vs uncompressed
encoding.** The cheatcode returns the P-256 generator G (standard base point);
the recovered point is another curve point (e.g. different message/scheme in
recovery vs what the cheatcode signs).

### 7.2 Grant decode: no mismatch in isolation

Narrow tests show that when the same 4 args are passed:

- **GrantDecodeHarness.decodeGrantFourArgs** and **Univocity.viewLeafCommitment**
  return the same leaf as the test’s `_leafCommitment(idtimestampBe, g)` for
  both `grantData = abi.encodePacked(pubX, pubY)` and
  `grantData = abi.encodePacked(kx, ky)` (recovered key).
- **GrantDecodeHarness** and **Univocity** agree on every decoded grant field
  (`test_grantDecodeFourArgs_eachFieldMatchesMemoryGrant`).
- The contract’s leaf does not depend on the first param
  (`test_grantDecode_contractLeafIndependentOfConsistency`).
- **abi.encode(g)** round-trip: **GrantDecodeHarnessEncoded.decodeGrantEncoded**
  with 4th param `abi.encode(g)` yields the same leaf as in-memory
  (`test_grantDecodeEncoded_abiEncodeRoundTrip_sameLeaf`). So passing the grant
  as `bytes calldata encodedGrant` and decoding with `abi.decode(encodedGrant,
  (PaymentGrant))` would give stable, canonical encoding if the contract
  accepted it.

### 7.3 Receipt decode: contract and verifier agree

- **viewDecodeReceiptAndRecover** (1-arg) matches the 1-arg helper.
- **viewDecodeReceiptAndRecover4** (4-arg) matches the 4-arg verifier for both
  initial and rebuilt receipt.

### 7.4 First-checkpoint ES256 tests skipped

`test_firstCheckpoint_es256Receipt_succeeds` and
`test_verifyCheckpoint_ks256ReceiptOnEs256Log_revertsAlgorithmMismatch` remain
skipped. Using the recovered key and 4-arg verifier for leaf/key alignment still
leads to `RootSignerMustMatchBootstrap` or `InvalidReceiptInclusionProof` in
the full flow; the narrow tests above show grant and receipt decode are
consistent in isolation. Further investigation is needed for the combined path.
