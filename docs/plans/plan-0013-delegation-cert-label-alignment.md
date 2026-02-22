# Delegation cert labels and encoding: Univocity vs go-merklelog and Arbor sealer

**Status**: DRAFT  
**Date**: 2026-02-22  
**Purpose**: Cross-check delegation cert labels and encoding between Univocity (Solidity), the Arbor sealer (Go), and the delegation cert producer (delegation signer / ARC-0010).

## 1. Where the cert appears

| Layer | Label | Role |
|-------|--------|------|
| **Consistency receipt** (or checkpoint COSE) | Unprotected **1000** | Holds the delegation cert as a bstr (raw COSE_Sign1 bytes). |
| **Sealer** (`sealer.go`) | `delegationCertUnprotectedLabel int64 = 1000` | Injects `lease.CertBytes` at unprotected 1000 when building the checkpoint. |
| **Univocity** (LibCbor, LibCose) | 1000 | Read in `readUnprotectedMapConsistencyProofsAndDelegation` and `decodeConsistencyReceiptCoseSign1`; optional in consistency receipt. |

**Alignment**: All use **1000** for the delegation cert bytes. No change needed.

---

## 2. Delegation cert COSE_Sign1 structure

The delegation cert is a COSE_Sign1 with four elements: protected, unprotected, payload, signature. All sides assume this.

---

## 3. Delegation cert **unprotected** header

| Key | Plan 0013 / Univocity | Sealer (Go) |
|-----|------------------------|-------------|
| **1001** | Recovery id (optional uint 0 or 1 for P-256). | Not read in `ParseDelegationCertificate`; cert producer may still emit it. |
| **1002** | Root public key (optional bstr, e.g. uncompressed point). | Not read in `ParseDelegationCertificate`; cert producer may still emit it. |

Univocity (LibCbor `readMapExtractDelegationUnprotected`) reads **1001** and **1002**. The sealer only parses the cert for display; it does not verify it. Verification is on-chain. So **1001** and **1002** are for Univocity and the cert producer; the sealer does not need to read them. No mismatch.

---

## 4. Delegation cert **payload** (integer-keyed map)

| Key | ARC-0010 / Plan 0013 | Univocity (LibCbor) | Sealer `ParseDelegationCertificate` |
|-----|----------------------|----------------------|-------------------------------------|
| **1** | log_id | `d.logId = bytes32(keccak256(_readBytesOrString(buf)))` | `payloadMap[1].(string)` → log_id as **string** |
| **2** | massif_id | `d.massifId = bytes32(keccak256(_readBytesOrString(buf)))` | Not read (skipped in parser) |
| **3** | mmr_start | `d.mmrStart = _readUint(buf)` | `payloadMap[3]` → mmr_start |
| **4** | mmr_end | `d.mmrEnd = _readUint(buf)` | `payloadMap[4]` → mmr_end |
| **5** | delegated_pubkey (COSE_Key) | `readMapExtractCoseKeyEc2` → x (-2), y (-3) | `payloadMap[5]` → COSE_Key; reads **-1** (crv) for curve |
| **6** | (optional constraints) | Skipped | Optional constraints, e.g. `log_id_prefix` |
| **8** | (optional issued_at) | Skipped | Read for display |
| **9** | (optional expires_at) | Skipped | Read for display |
| **10** | (optional delegation_id) | Skipped | Read for display |
| **11** | root_public_key (optional) | Read in LibCose `decodeDelegationCert`; conflict with 1002 | Not read |

**Alignment**:

- **1 (log_id)**: Univocity accepts both bstr and tstr via `_readBytesOrString` and compares `keccak256(...)` to `paymentGrant.logId`. The sealer expects a string. So if the delegation signer emits log_id as **text string** (e.g. UUID), both are fine; on-chain `paymentGrant.logId` must be `keccak256(that_string)` (or the same bytes). No change.
- **2 (massif_id)**: We decode it; Go parser skips it. Extra key is harmless.
- **3, 4, 5**: Same semantics; Solidity uses them for scope and delegated key. COSE_Key at 5: we use -2/-3 (x,y); Go uses -1 (crv) for display. Both are valid COSE_Key EC2 fields.
- **6, 8, 9, 10**: We skip unknown keys; cert can include them for policy/display.
- **11**: We support optional root key in payload; if both 1002 and 11 present we revert. Sealer does not read 11. No conflict.

---

## 5. Delegation cert **protected** header

| Key | COSE | Univocity | Sealer |
|-----|------|-----------|--------|
| **1** | alg | `extractAlgorithm` for verification | `asInt64(protectedMap[1])` |
| **3** | cty | Not used | Read for display |
| **4** | kid | Not used | Read for display |

Only algorithm is required for verification; alignment is fine.

---

## 6. Checkpoint payload (go-merklelog vs ARC-0010)

**go-merklelog** (`rootsigner.go`): Checkpoint payload is **MMRState** with keys 1=MMRSize, 3=Timestamp, 4=IDTimestamp, 6=CommitmentEpoch, 7=Version, 8=Peaks (CBOR keyasint). This is the **massif seal** format.

**Univocity** (`decodeCheckpointPayload`): Expects ARC-0010 checkpoint payload 1=log_id, 2=massif_id, 3=mmr_size, 4=mmr_root, 5=mmr_index.

These are **different profiles**: massif seal (go-merklelog) vs ARC-0010 checkpoint (Univocity). After the refactor, **publishCheckpoint** no longer takes a separate checkpoint COSE; it uses the **consistency receipt** (and optional delegation at 1000). So we do **not** verify the go-merklelog checkpoint payload on-chain; we verify the consistency-proof chain and the signature over the accumulator commitment. The delegation cert at 1000 is what we need to align, and that alignment is as above.

---

## 7. Summary

| Item | Status |
|------|--------|
| Unprotected **1000** = delegation cert bytes | Aligned (sealer, Univocity). |
| Delegation cert unprotected **1001**, **1002** | Used by Univocity; sealer does not need them. |
| Delegation cert payload **1, 2, 3, 4, 5** | Aligned; log_id as tstr/bstr with keccak256 comparison on-chain. |
| Payload **5** (COSE_Key): **-2**, **-3** (x, y) | We use for verification; Go also expects key at 5 with COSE_Key (crv -1). |
| Payload **6, 8, 9, 10** | We skip; cert may include them. |
| Payload **11** (root key) | We support; optional; conflict with 1002 enforced. |
| Checkpoint payload format | Different (go-merklelog vs ARC-0010); not used for current consistency-receipt flow. |

**Conclusion**: Delegation cert labels and encoding are aligned between Univocity, the sealer’s use of label 1000, and the delegation cert structure expected by the sealer’s parser. No code changes required for interoperability. Ensure the delegation signer emits payload key **1** (log_id) in a form consistent with on-chain `paymentGrant.logId` (e.g. `keccak256(log_id_tstr)` if log_id is a text string).
