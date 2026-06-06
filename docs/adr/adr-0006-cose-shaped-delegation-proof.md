# ADR-0006: COSE-shaped delegation proof without on-chain certificate parsing

**Status:** DRAFT  
**Date:** 2026-05-19  
**Related:** [ADR-0002](adr-0002-cose-verifier-keys-caller-dispatch.md),
[ADR-0005](adr-0005-grant-constrains-checkpoint-signer.md),
[plan-0016](../plans/plan-0016-minimal-cose-cbor-api-predecode.md),
[plan-0023](../plans/plan-0023-consistency-receipt-abi-and-signature-payload.md),
[RFC 8949](https://www.rfc-editor.org/rfc/rfc8949),
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052),
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053)

## Question

Can delegation proofs be made more compatible with COSE Sign1 without requiring
the contract to parse full COSE/CBOR delegation certificates?

## Context

The current contract design follows the pre-decoded calldata approach from
[plan-0016](../plans/plan-0016-minimal-cose-cbor-api-predecode.md):

- checkpoint receipts carry `protectedHeader` and `signature`, but consistency
  proof material is supplied as typed ABI fields;
- the contract reconstructs the COSE `Sig_structure` for the checkpoint receipt;
- the contract intentionally does not parse a full COSE_Sign1 receipt or a rich
  CBOR payload on-chain;
- delegation currently uses a minimal proof with `delegationKey`, `mmrStart`,
  `mmrEnd`, `alg`, and `signature`.

That minimal delegation proof is gas- and audit-friendly, but it is not shaped
like a COSE Sign1 object. It verifies a raw signature over a bespoke canonical
message:

```text
sha256(logId || mmrStart || mmrEnd || delegatedKeyX || delegatedKeyY)
```

Meanwhile Arbor Sealer already uses COSE-oriented delegation certificates for
off-chain checkpoint material. Accepting those full certificates on-chain would
require parsing a COSE_Sign1 array, protected headers, payload maps, COSE_Key,
content type, log constraints, range constraints, and optional fields. That is
possible, but it expands gas cost, consensus-critical encoding surface, and
audit burden.

## Decision

Use a **COSE-shaped, ABI-typed delegation proof**.

The contract should continue to receive delegation fields as typed ABI values,
but the delegation signature should verify the COSE Sign1 `Sig_structure` over
a contract-derived canonical payload.

The delegation proof becomes:

```solidity
struct DelegationProof {
    bytes protectedHeader;
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    bytes signature;
}
```

The contract derives the payload from typed fields:

```text
payload = domain || logId || mmrStart || mmrEnd || delegationKey
```

The domain is the raw ASCII byte string
`forestrie.univocity.delegation.v1`. It is intentionally not cast to
`bytes32`; the string is 33 bytes long, and off-chain signers must use those
exact bytes when constructing the payload.

and verifies:

```text
Sig_structure = [
  "Signature1",
  protectedHeader,
  external_aad = h'',
  payload
]
```

This matches COSE Sign1 signature semantics from RFC 9052 while avoiding
on-chain parsing of a COSE_Sign1 delegation certificate.

The contract only requires that `protectedHeader` contains `alg: ES256`.
Minimal protected header bytes such as `h'a10126'` are suitable for tests and
vectors, but they are not an exact-byte requirement. Any additional protected
header fields remain signed because `protectedHeader` is part of the
Sig_structure.

The smart-contract implementation scope is limited to the ABI, verifier, and
contract tests. Arbor and Canopy proof production, issuer APIs, and publisher
wiring are separate follow-up work.

## Rationale

This keeps the same posture as checkpoint receipt verification:

- **COSE-compatible signature verification:** The bytes signed are a COSE
  Sig_structure, not an ad hoc raw hash.
- **No full COSE document parsing:** The contract does not parse a COSE_Sign1
  array, CBOR map payload, or COSE_Key.
- **ABI-native authorization fields:** `delegationKey`, `mmrStart`, and
  `mmrEnd` remain first-class typed contract fields.
- **Small consensus surface:** Optional certificate fields such as content type,
  `kid`, expiry, issuer metadata, and schema version stay off-chain unless the
  contract explicitly needs them later.
- **Off-chain compatibility:** The same `protectedHeader`, payload, and
  signature can be wrapped off-chain as a normal COSE_Sign1 delegation artifact.

The design preserves the key security invariant:

> A checkpoint signer is valid only if it is the log root key or a delegated key
> authorized by the log root key for the relevant MMR range.

The Ethereum transaction sender remains irrelevant to log authority.

## Suggested Code Diffs

These diffs are illustrative. They show the intended shape of the change, not a
complete implementation.

### `src/interfaces/types.sol`

```diff
 /// @notice Minimal delegation proof (plan 0016). No cert decode.
-///    delegationKey is alg-specific opaque bytes; for P-256/ES256 it is
-///    64 bytes (x || y). Decoding requires alg == P-256/ES256.
+///    delegationKey is alg-specific opaque bytes; for P-256/ES256 it is
+///    64 bytes (x || y). The signature is a COSE Sign1 signature over a
+///    contract-derived canonical delegation payload.
 struct DelegationProof {
+    bytes protectedHeader;
     bytes delegationKey;
     uint64 mmrStart;
     uint64 mmrEnd;
-    uint64 alg;
     bytes signature;
 }
```

### `src/checkpoints/lib/delegationVerifier.sol`

```diff
 import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
+import {extractAlgorithm, buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
+import {ALG_ES256} from "@univocity/cosecbor/constants.sol";

 /// @notice Verify ES256 delegation proof: root (storedRootX, storedRootY)
-///    signed canonical message binding (logId, mmrStart, mmrEnd, delegatedKey).
+///    signed a COSE Sign1 Sig_structure binding
+///    (domain, logId, mmrStart, mmrEnd, delegatedKey).
 ///    Delegation key is pre-decoded; use decodeDelegationKeyES256 first.
 function verifyDelegationProofES256(
+    bytes calldata protectedHeader,
     uint64 mmrStart,
     uint64 mmrEnd,
     bytes calldata signature,
     bytes32 logId,
     uint64 mmrIndex,
     bytes32 storedRootX,
     bytes32 storedRootY,
     bytes32 delegatedKeyX,
     bytes32 delegatedKeyY
 ) view {
+    if (extractAlgorithm(protectedHeader) != ALG_ES256) {
+        revert DelegationSignatureInvalid();
+    }
     if (signature.length != 64) {
         revert InvalidDelegationSignatureLength(signature.length);
     }
     if (storedRootX == 0 && storedRootY == 0) {
         revert DelegationSignatureInvalid();
@@
-    bytes32 canonicalHash = sha256(
+    bytes memory payload = abi.encodePacked(
+        "forestrie.univocity.delegation.v1",
+        logId,
+        mmrStart,
+        mmrEnd,
+        delegatedKeyX,
+        delegatedKeyY
+    );
+    bytes memory sigStructure = buildSigStructure(protectedHeader, payload);
+    bytes32 canonicalHash = sha256(sigStructure);
-        abi.encodePacked(logId, mmrStart, mmrEnd, delegatedKeyX, delegatedKeyY)
-    );
     bytes32 r;
     bytes32 s;
     assembly {
         r := calldataload(signature.offset)
         s := calldataload(add(signature.offset, 32))
```

### `src/contracts/_Univocity.sol`

```diff
 verifyDelegationProofES256(
+    delegationProof.protectedHeader,
     delegationProof.mmrStart,
     delegationProof.mmrEnd,
     delegationProof.signature,
     logId,
     claimedSize > 0 ? claimedSize - 1 : 0,
```

### Test/helper generation

Off-chain code should sign the same COSE Sign1 Sig_structure:

```diff
-message = sha256(logId || mmrStart || mmrEnd || delegatedKeyX || delegatedKeyY)
+payload = domain || logId || mmrStart || mmrEnd || delegatedKeyX || delegatedKeyY
+sig_structure = ["Signature1", protected, h'', payload]
+message = sha256(cbor(sig_structure))
 signature = sign(rootKey, message)
```

The protected header should contain at least:

```cbor-diag
{
  1: -7   / alg: ES256 /
}
```

An off-chain COSE delegation certificate may wrap the same protected header,
payload, and signature as a normal COSE_Sign1 object, but the contract should
continue to receive the pre-decoded fields.

## Standards References

- **RFC 8949, Concise Binary Object Representation (CBOR):** defines the CBOR
  data model and deterministic encoding considerations.
- **RFC 9052, CBOR Object Signing and Encryption (COSE):** defines
  `COSE_Sign1` and the `Sig_structure`:
  `["Signature1", body_protected, external_aad, payload]`.
- **RFC 9053, COSE Algorithms:** defines algorithm registrations including
  ES256 (`-7`).

The contract does not need to implement general RFC 8949 or RFC 9052 parsing.
It only needs enough functionality to:

1. read `alg` from a protected header;
2. construct a COSE Sign1 Sig_structure;
3. verify the signature with the expected root key.

## Consequences

- Delegation signatures become COSE Sign1 compatible.
- Contracts keep the pre-decoded calldata model.
- Off-chain systems can still publish richer COSE delegation certificates.
- The contract avoids full certificate parsing, COSE_Key parsing, and CBOR map
  validation.
- Existing minimal delegation proofs must be regenerated under the new payload
  and protected-header format.
- ES256 delegation is supported for ES256 root keys. KS256 root keys may
  delegate to ES256 checkpoint signers via `verifyDelegationProofKS256`
  (COSE Sign1 Sig_structure over the same canonical payload, verified with
  `keccak256` and `verifyKS256Raw`). KS256 consistency receipts still do not
  support delegation.

## Alternatives Considered

### Keep current minimal raw-hash delegation

This is simplest, but less aligned with COSE Sign1. Off-chain systems must
maintain a separate signature convention for on-chain delegation.

### Accept full COSE delegation certificates on-chain

This maximizes document-level compatibility but introduces significant
complexity: COSE_Sign1 array parsing, protected header validation, payload map
parsing, COSE_Key decoding, optional field policy, and more gas.

Rejected for now because the contract only needs a small authorization
predicate, not a rich document parser.

### Sealer issues both raw minimal proof and COSE certificate

This works as a transition strategy, but if the minimal proof remains a raw hash
it preserves two signature conventions. The COSE-shaped proof proposed here
lets the on-chain proof and off-chain COSE artifact share the same signature
semantics.

## Recommendation

Adopt the COSE-shaped delegation proof format for the contract ABI and require
issuers to sign the contract-derived delegation payload using COSE Sign1
Sig_structure semantics.

Do not require the contract to parse full COSE delegation certificates.
