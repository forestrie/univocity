# ARC-0002: Delegation cert labels and encoding alignment

**Status:** ACCEPTED  
**Date:** 2026-02-22  
**Related:** [plan-0013](../plans/plan-0013-adr-0032-delegated-checkpoint-verification.md),
ARC-0010 (devdocs), Arbor sealer (Go)

## Purpose

Reference for delegation cert labels and encoding between Univocity (Solidity),
the Arbor sealer (Go), and the delegation cert producer (delegation signer /
ARC-0010). Use this document when implementing or changing COSE/CBOR handling
for delegation.

## 1. Where the cert appears

| Layer | Label | Role |
|-------|--------|------|
| **Consistency receipt** (or checkpoint COSE) | Unprotected **1000** | Holds the delegation cert as a bstr (raw COSE_Sign1 bytes). |
| **Sealer** (`sealer.go`) | `delegationCertUnprotectedLabel int64 = 1000` | Injects `lease.CertBytes` at unprotected 1000 when building the checkpoint. |
| **Univocity** (cosecbor) | 1000 | Read in consistency receipt decoding; optional in consistency receipt. |

**Alignment**: All use **1000** for the delegation cert bytes.

## 2. Delegation cert COSE_Sign1 structure

The delegation cert is a COSE_Sign1 with four elements: protected, unprotected,
payload, signature. All sides assume this.

## 3. Delegation cert unprotected header

| Key | Univocity | Sealer (Go) |
|-----|-----------|-------------|
| **1001** | Recovery id (optional uint 0 or 1 for P-256). | Not read; cert producer may still emit it. |
| **1002** | Root public key (optional bstr). | Not read; cert producer may still emit it. |

Univocity reads **1001** and **1002**. The sealer only parses the cert for
display; verification is on-chain. No mismatch.

## 4. Delegation cert payload (integer-keyed map)

| Key | ARC-0010 / Plan 0013 | Univocity | Sealer |
|-----|----------------------|-----------|--------|
| **1** | log_id | bytes32(keccak256(_readBytesOrString(...))) | log_id as string |
| **2** | massif_id | Decoded | Skipped |
| **3** | mmr_start | _readUint | payloadMap[3] |
| **4** | mmr_end | _readUint | payloadMap[4] |
| **5** | delegated_pubkey (COSE_Key) | -2 (x), -3 (y) | COSE_Key at 5; -1 (crv) for display |
| **6, 8, 9, 10** | Optional | Skipped | Policy/display |
| **11** | root_public_key (optional) | Supported; conflict with 1002 enforced | Not read |

**Alignment:** log_id as tstr/bstr with keccak256 comparison on-chain; 3, 4, 5
aligned. Delegation signer should emit payload key **1** (log_id) in a form
consistent with on-chain `paymentGrant.logId` (e.g. `keccak256(log_id_tstr)`).

## 5. Delegation cert protected header

Only algorithm (key 1) is required for verification; alignment is fine.

## 6. Checkpoint payload (go-merklelog vs ARC-0010)

go-merklelog uses massif seal format (MMRState); Univocity expects ARC-0010
checkpoint payload (log_id, massif_id, mmr_size, mmr_root, mmr_index). These
are different profiles. The current consistency-receipt flow does not verify
the go-merklelog checkpoint payload on-chain; the delegation cert at 1000 is
what we align.

## 7. Summary

| Item | Status |
|------|--------|
| Unprotected **1000** = delegation cert bytes | Aligned. |
| Delegation cert unprotected **1001**, **1002** | Used by Univocity; sealer optional. |
| Payload **1, 2, 3, 4, 5** | Aligned; COSE_Key at 5 uses -2, -3 (x, y). |
| Payload **6, 8, 9, 10, 11** | We skip or support as above. |
| Checkpoint payload format | Different profiles; not used for consistency-receipt flow. |

No code changes required for interoperability; ensure delegation signer
emits log_id consistently with on-chain `paymentGrant.logId`.
