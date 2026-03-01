# Plan 0013: ADR-0032 Delegated Checkpoint Signature Verification (Option 2)

**Status**: Implemented  
**Date**: 2026-02-22  
**Scope**: On-chain verification of Forestrie checkpoint COSE_Sign1 and delegation
chain in Univocity, per ADR-0032 Option 2. Root key from first checkpoint
(recovery or bootstrap); ES256 delegation; root’s first checkpoint requires
receipt signer to match bootstrap key (prevents front-running). See
`Univocity.sol` (_verifyCheckpointSignature, _checkpointSignersES256,
delegationVerifier.sol).

## 0. Specs and References

| Document | Role |
|----------|------|
| **ADR-0032** | Decision: Option 2 — contract accepts checkpoint COSE_Sign1 and verifies |
|          | delegation chain; binding of (size, accumulator) to signed payload. |
| **ARC-0008** | Delegation architecture: root → delegation cert → delegated key → |
|          | checkpoint; verification steps; scope (log_id, massif_id, mmr range). |
| **ARC-0010** | COSE/CBOR profiles: delegation cert payload (1 log_id, 2 massif_id, |
|          | 3 mmr_start, 4 mmr_end, 5 delegated_pubkey COSE_Key); checkpoint |
|          | unprotected 1000 = delegation cert bytes; checkpoint payload |
|          | (1 log_id, 2 massif_id, 3 mmr_size, 4 mmr_root, 5 mmr_index, …). |
| **ARC-0011** | Policy and extras (reference). |

Implementation target: `univocity/` (Univocity.sol, LibCose, LibCbor,
LibCheckpointVerifier, LibAuthorityVerifier). Existing crypto: OpenZeppelin
P256 (ES256), WitnetBuffer (Trail of Bits audited), native ecrecover (KS256).

**Code and artifact references (for agentic implementation):**

| Location | Purpose |
|----------|---------|
| `src/contracts/Univocity.sol` | Main contract; `_logs`, `publishCheckpoint`, `_updateLogState`. |
| `src/checkpoints/interfaces/IUnivocity.sol` | `LogState` struct, `publishCheckpoint` signature; extend with root key and new param. |
| `src/cose/lib/LibCose.sol` | `decodeCoseSign1`, `CoseSign1`, `_skipValue`, `buildSigStructure`, ES256 verify. |
| `src/cbor/lib/LibCbor.sol` | CBOR parsing, `_skipValue`; use for delegation/checkpoint payload decode. |
| `src/checkpoints/lib/LibAuthorityVerifier.sol` | Receipt verification; reference for COSE decode usage. |
| OpenZeppelin `P256.sol` | `P256.verify`, `P256.recovery(h, v, r, s)` for ES256. |

LogState today: `accumulator`, `size`, `initializedAt` (plan-0021 Phase E removes `checkpointCount`). Plan adds `rootKeyX`, `rootKeyY` (or equivalent) per log; leave zero until first checkpoint.

## 1. Prerequisites

- [Plan 0012](../history/plans/plan-0012-arc-0016-implementation-review.md) (historical; ARC-0016 reflection).
- Univocity receipt and MMR behaviour unchanged; this plan **adds** checkpoint
  COSE verification and **does not** remove existing receipt/consistency checks.
- Forestrie checkpoint producer emits COSE_Sign1 per ARC-0010 with delegation
  cert in unprotected header label 1000.

## 2. Dependency Strategy

**Goal:** Maximise use of well-audited third-party libraries for
cryptographically sensitive code; minimise new dependencies.

**Current stack (keep):**

- **OpenZeppelin Contracts** — `P256.sol` for ES256 (P-256 + SHA-256). Uses
  RIP-7212 precompile when available; fallback implementation. Already used
  for receipt verification.
- **WitnetBuffer** (witnet-solidity-bridge) — Trail of Bits audited; safe
  buffer reads. Used in LibCose and LibCbor; reuse for all new CBOR parsing.

**No new dependencies for Phase 1 (ES256-only):**

- Delegation cert and checkpoint signatures can both use **ES256** (P-256).
  Root key stored as (bytes32 x, bytes32 y). Verification uses existing
  `LibCose` + OpenZeppelin `P256`. No additional packages.

**Optional Phase 2 (ES256K support):**

- ARC-0010 allows **ES256K** (secp256k1 + SHA-256) for root/delegation. This
  is **not** the same as KS256 (secp256k1 + Keccak-256); EVM `ecrecover` is
  Keccak-based and cannot verify ES256K. Adding ES256K requires a small
  Solidity library for ECDSA secp256k1 with SHA-256.
- **Recommendation:** Add a **single** well-audited dependency if ES256K is
  required (e.g. a minimal secp256k1+SHA256 verifier used in production
  chains or by other SCITT/transparency implementations). If no suitable
  library is found, support **ES256-only** roots initially and document
  ES256K as a follow-up.

**Summary:** Minimal set = **zero new dependencies** for ES256-only
delegation/checkpoint verification. Optional one additional dependency for
ES256K.

## 3. High-Level Design

1. **Contract API**  
   Extend `publishCheckpoint` with a required argument  
   `bytes calldata checkpointCoseSign1` (the Forestrie checkpoint
   COSE_Sign1, including delegation cert in unprotected header 1000).

2. **Verification sequence (before existing receipt/MMR checks)**  
   - Decode checkpoint COSE_Sign1 (reuse/extend LibCose).  
   - Parse unprotected header; extract delegation cert bytes from label 1000.  
   - **Root key:** No global root. The root public key for a log is the key
     that signed the delegation cert in that log’s **first** checkpoint.  
   - **If this is the first checkpoint for the log:** Obtain the root from
     the delegation cert (recover public key from the delegation cert
     signature, or read from payload/header if the profile carries it); store
     it in log state for this logId.  
   - **If the log already has a stored root:** Verify the delegation cert
     signature with that **stored per-log root**.  
   - Validate delegation scope: `log_id` and `massif_id` match; checkpoint
     MMR index (or size) lies in `[mmr_start, mmr_end]`.  
   - **Binding:** Checkpoint payload `mmr_size` must equal submitted `size`;
     submitted accumulator must match what the signer committed to (see §4.4).  
   - Extract delegated public key from delegation payload (key 5, COSE_Key).  
   - Verify checkpoint signature with the delegated public key.  
   - Proceed with existing receipt, inclusion, bounds, and MMR consistency
     checks.

3. **Root key: per-log, from first checkpoint**  
   The contract does **not** store a global root key. For each log, the root
   public key is **established by the first checkpoint** for that log: it is
   the key that signed the delegation cert in that first checkpoint. The
   contract stores this per log (e.g. `_logs[logId].rootKeyX`, `rootKeyY` or
   a struct). For the **first** checkpoint of a log, the contract obtains the
   root by **recovering** the signer from the delegation cert signature
   (ES256: OpenZeppelin P256 has `recovery(h, v, r, s)`; COSE uses r||s so
   try v=0 and v=1, then verify with recovered key and store). For subsequent
   checkpoints of that log, the contract verifies the delegation cert with
   the stored root. No constructor or admin-set root; deployment does not
   require configuring root keys. Key rotation for a log would require a new
   logId or contract upgrade to allow root change.

4. **Binding of (size, accumulator)**  
   ADR-0032 and binding section: Univocity is accumulator-based; no
   requirement to "bag" the accumulator into a single root. For Option 2,
   the checkpoint payload must bind the **submitted** size and accumulator.  
   - **Preferred:** Payload carries the **full accumulator** (or a
     deterministic encoding of peaks) so the contract compares
     `payload.accumulator` to `accumulator` element-wise. This may require
     an ARC-0010 extension (e.g. new key for peak list) for on-chain use.  
   - **Alternative:** If payload keeps only `mmr_root` (single bstr), define
     a deterministic derivation from the submitted accumulator (e.g.
     `H(peak_0 || peak_1 || …)`) in ARC-0010 and have the contract derive and
     compare. ADR-0032 notes this would be a new convention, not current
     Univocity behaviour.  
   Plan assumes **binding via payload**; exact format (full accumulator vs
   single commitment) to be decided with ARC-0010 alignment.

### Security assessment: root from first checkpoint

**Model:** Root for each log = the public key that signed the delegation cert
in that log’s **first** checkpoint. No global root configuration.

**Why it remains secure:**

- **Authority log:** Only the bootstrap authority can publish the first
  checkpoint (the one that establishes the authority log). So the bootstrap
  authority is the only one who can set the root for the authority log. The
  delegation cert in that first checkpoint is signed by the intended root
  (e.g. Cloud KMS); we recover and store it. No third party can establish a
  different root for the authority log.
- **Other logs:** The first checkpoint for a given logId can be published by
  any address that has a valid receipt and a valid checkpoint COSE_Sign1.
  Whoever publishes that first checkpoint causes the contract to recover and
  store the root from the delegation cert. So **the first publisher
  establishes the root for that log** (first-publisher-wins).
- **Operational assumption:** In practice the receipt is issued to the
  intended log operator, who is expected to publish the first checkpoint with
  a delegation cert signed by their root. If the operator publishes first, the
  correct root is established. The design remains secure under that
  assumption.
- **Consistency:** Once a root is stored for a log, it cannot be changed
  (absent upgrade or new logId). All later checkpoints for that log must use
  delegation certs signed by that same root, so the chain is consistent.

**Considerations (document, not blockers):**

- **First-publisher-wins for non-authority logs:** If an attacker obtained a
  valid receipt for a log and published the first checkpoint with a
  delegation cert signed by a key they control, that key would become the
  log’s root. Mitigation: receipts are bound to a target log and issued to the
  operator; the operator is expected to publish first. Acceptable when the
  intended operator is the one submitting the first checkpoint.
- **Key rotation:** Rotating the root for an existing log would require a new
  logId or a contract change that allows updating the stored root (e.g.
  admin or governance). Document as a known constraint.
- **Recovery for first checkpoint:** For ES256 we use OpenZeppelin
  `P256.recovery(h, v, r, s)`; COSE delegation certs use r||s (64 bytes), so
  we try v=0 and v=1, verify with the recovered key, and store it. For
  ES256K we may not have recovery in our stack; then the first checkpoint
  would need to carry the root public key in the payload or header so we can
  verify and store it (or we support ES256K only for subsequent checkpoints
  once the root is established with ES256).

**Conclusion:** The “root matches the root present in the first checkpoint for
the log” model is secure for the authority log (bootstrap-only first
checkpoint) and for other logs when the intended operator publishes the first
checkpoint. No global root storage is required; the plan is updated
accordingly.

### Binding root key to the authority log commitment (first checkpoint)

**Idea:** Require that the receipt used for the first checkpoint **contains**
the log root public key (or a commitment to it) in its payload. The leaf is
already `H(receiptIdtimestampBe ‖ sha256(receipt))` per ADR-0030, so the
leaf **commits to the full receipt**—including whatever key or delegation
is inside it. The inclusion proof then proves that this receipt (with this
key) is in the authority log. So **only the operator's key can establish the
log**: the receipt that is in the log contains the key; we decode the
receipt to get that key and require the root recovered from the delegation
cert to match it. No change to the leaf formula and no need to add the key
separately to the leaf—the receipt is already part of the verified leaf, and
if the receipt contains the delegation (or root key), that is sufficient.

**How it works:**

- **Receipt payload:** Extend the payment receipt (COSE payload / CBOR
  claims) to include the **log root public key** (or a commitment, e.g. hash
  of the key) for the target log. The operator supplies their root key when
  obtaining the receipt; the receipt issuer signs a payload that includes it.
  So the receipt bytes (and hence `sha256(receipt)`) commit to that key.
- **Leaf formula:** Unchanged. Leaf = `H(receiptIdtimestampBe ‖
  sha256(receipt))`. The leaf commits to the receipt; the receipt contains
  the key; so the leaf commits to the key. No extra term in the leaf input.
- **First-checkpoint verification:** (1) Verify receipt (signature, bounds).
  (2) Verify receipt inclusion in the authority log using the existing leaf
  formula (so this receipt is the one in the log). (3) Decode the receipt
  payload to get the committed root key. (4) Recover the root from the
  delegation cert in the checkpoint. (5) Require recovered root == committed
  root (or matches the commitment). (6) Store the root for the log.
- **Effect:** Only a receipt that **contains** key K can be used for the
  first checkpoint of the log. The inclusion proof proves that receipt (with
  K in it) is in the authority log. So only key K can be established as the
  log's root. An attacker with a receipt that commits to the operator's key
  cannot substitute a different root (recovered key would not match the
  key in the receipt). So the operator's key is bound at payment time
  because the receipt carries it and the leaf commits to the receipt.

**Conclusion:** If the receipt contains the delegation (or the root key),
then the existing leaf and inclusion check are sufficient to ensure that
only the operator's key can establish the log. No separate binding of the
key into the leaf formula is needed—the receipt is already part of the
verified leaf. Implementation: extend receipt payload with root key (or
commitment); on first checkpoint decode receipt for that key and require
recovered root to match. Key rollover (revoked-keys map, etc.) remains a
possible follow-up.

**SCITT MMR profile and receipt payload:** The SCITT MMR profile
(draft-bryce-cose-receipts-mmr-profile) defines the MMR structure,
inclusion/consistency proof formats, and COSE Receipts of Inclusion and
Consistency. It does **not** define the **payload schema** of the **payment
receipt** (the COSE_Sign1 that Univocity uses as the leaf content in the
authority log). The profile says leaves are caller-defined; the content of
the payment receipt is defined by our application (ARC-0016, ADR-0025:
targetLogId, payer, checkpoint range, maxHeight). So we **cannot** conclude
from the SCITT MMR profile alone that "a valid COSE receipt has the
necessary elements to bind the operator's root key"—the profile does not
specify those elements. We must **extend our receipt format** (Forestrie /
Univocity) to include the root key (or commitment) in the signed payload.
Once we do that, any receipt that conforms to our **extended** format has
the binding; the SCITT profile remains compatible (it does not constrain
receipt payload content). So: binding is achieved by **our** receipt schema
extension, not guaranteed by the SCITT profile itself.

**Original plan and "first publisher wins":** The original plan (recover root
from the first checkpoint's delegation cert, store it per log) was **sound**.
The "first publisher wins" qualification was **not** invalid or wrong—it
was an **accurate** description of the trust assumption when the receipt
payload does *not* contain the root key: in that design, whoever publishes
the first checkpoint with a valid receipt establishes the root. Adding the
root key to the receipt **removes** that assumption (makes it unnecessary):
the receipt in the log then commits to the key, so only that key can
establish the log. So the first-publisher observation was correct for the
then-design; it is **obviated** by the receipt binding extension, not
refuted.

### Extensions to recover root public key from the delegation (for draft update)

To allow verifiers (including on-chain) to obtain the root public key from
the delegation certificate without a pre-configured root, the following
extensions can be required or optionally allowed in the profile (e.g.
draft-bryce-cose-receipts-mmr-profile or the Forestrie/ARC-0010
delegation profile).

**Context:** The delegation cert is a COSE_Sign1 signed by the **root** key.
Today the payload contains log_id, massif_id, mmr_start, mmr_end,
delegated_pubkey (key 5), etc., but **not** the root public key. The
signature is r || s (64 bytes). For ES256 (P-256), verifiers can recover
the signer by trying recovery id v=0 and v=1; for ES256K, recovery may not
be available on all platforms. The extensions below give the draft
normative or optional ways to support root recovery.

**1. Recovery id for ECDSA (optional or required)**

- **Option A — Signature format:** Allow or require the delegation cert
  signature to include a recovery id: `signature = r || s || v` (65 bytes)
  where `v` is one octet, value 0 or 1 (for P-256; or the appropriate range
  for the curve). Verifiers then recover the signer in one step without
  trying both values. The draft would specify: "For verifiers that need to
  recover the signer (e.g. on-chain), the signature MAY/ MUST be 65 bytes
  with the final octet as the recovery id."
- **Option B — Unprotected header:** Allow or require a delegation cert
  unprotected header parameter (e.g. a new label, e.g. 1001) whose value
  is the recovery id (uint 0 or 1). Signature remains r || s (64 bytes).
  Verifiers use the header value when calling recovery. The draft would
  define the label and semantics.

**2. Root public key in the delegation cert (optional or required)**

- Allow or require the **root public key** to be carried in the delegation
  cert so verifiers that cannot perform recovery can still obtain the key.
  Two placements:
  - **Unprotected header:** e.g. label 1002 (or another private-use label)
    value = bstr encoding of the root public key (e.g. for EC: uncompressed
    point 0x04 || x || y, or two bstrs for x and y, per COSE_Key convention).
  - **Payload:** Add a new key (e.g. 11) to the delegation payload CBOR map:
    `11 root_public_key : COSE_Key or bstr` (the root’s public key in
    COSE_Key form or a fixed encoding). Verifiers that support recovery can
    ignore it and recover; verifiers that don’t can read and verify.
- The draft would specify: "To support verifiers that cannot perform
  ECDSA public-key recovery, the delegation cert MAY/ MUST include the root
  public key in the unprotected header (label TBD) or in the payload (key
  TBD). If present, verifiers MAY use it instead of recovery; if present
  and recovery is used, the recovered key MUST match the included key."

**3. Normative text for the draft**

Suggested wording the draft could add (adapt to required vs optional):

- "**Root signer recovery.** Delegation certificates are signed by the root
  key. Verifiers that need to establish the root key from the certificate
  alone (e.g. for the first checkpoint of a log) MUST obtain the signer
  public key either by (a) ECDSA public-key recovery from the signature
  (when the signature includes a recovery id per §X, or by trying all
  valid recovery ids), or (b) reading the root public key from the
  delegation cert when present (unprotected header label 1002 or payload
  key 11). If both recovery and an included key are present, the recovered
  key MUST equal the included key."
- "**Signature format for recovery.** For algorithms that support signer
  recovery (e.g. ES256, ES256K), the delegation cert signature MAY be 65
  bytes with the last octet as the recovery id (0 or 1 for P-256). When 64
  bytes, verifiers that need recovery MUST try both recovery ids."

**4. Summary for draft authors**

| Extension | Where | Required / optional | Purpose |
|-----------|--------|---------------------|---------|
| Recovery id in signature (r\|\|s\|\|v, 65 bytes) | Delegation cert signature | Optional | One-step recovery for ES256/ES256K |
| Recovery id in unprotected header | Delegation cert, new label | Optional | Same, without changing signature length |
| Root public key in unprotected header | Delegation cert, new label (e.g. 1002) | Optional | Verifiers without recovery can read key |
| Root public key in payload | Delegation payload, new key (e.g. 11) | Optional | Same, in payload for CBOR consistency |

Implementations that support recovery (e.g. Univocity with P256.recovery)
can work with the current 64-byte format (try v=0 and v=1). The extensions
allow (a) more efficient one-step recovery when recovery id is present, and
(b) environments that cannot do recovery to still verify by using the
included root key. Updating the draft to **require** one of (recovery id or
included root key) would make first-checkpoint root establishment
interoperable across all verifier types.

### Why recovery id in unprotected headers (vs. recovering from signature only)

**We do not need the recovery id for correctness.** For ES256 the delegation
cert signature is r||s (64 bytes). A verifier can recover the signer by
calling recovery with v=0 and v=1, then verifying the delegation cert with
each candidate; whichever verifies is the root. So the root can always be
established from the delegation cert signature alone.

The recovery id (in unprotected header or as a third octet in the signature)
is **purely an optimization**: it allows one recovery call and one verify
instead of two. It avoids extra gas on-chain and simplifies code. The draft
can treat it as optional; verifiers that support try-both-v need not depend
on it. Normative text should say: when recovery id is absent, verifiers
that need recovery MUST try all valid recovery ids (e.g. 0 and 1 for
P-256).

### Is an included root public key secure? Does it undermine delegation?

**Including the root public key in the delegation cert does not weaken the
model** provided the verifier **always verifies the delegation cert
signature** with that key. The trust is still “the key that signed the
delegation cert is the root.” Whether we learn that key by (a) recovering it
from the signature or (b) reading it from the cert and then verifying the
signature with it, the outcome is the same: only the signer of the
delegation cert is accepted as root. An attacker cannot substitute a
different key in the payload/header and still pass verification, because
the signature would not verify under the substituted key.

The included root key is **for verifiers that cannot perform ECDSA
recovery** (e.g. some ES256K environments). For them, the only way to
establish the root from the cert alone is to have the key conveyed in the
cert and then to verify the signature with it. So the option is useful and
secure as long as the profile requires: “If the root public key is present
in the cert, verifiers MUST verify the delegation cert signature with that
key; they MUST NOT trust the key without verification.”

**Delegated signing model:** The log operator does not “choose” the root by
putting a key in the cert. The root is whoever **signed** the delegation
cert. If the cert includes a key, it is the signer’s key; verification
binds that key to the signature. So the authority remains the signer of the
delegation cert, not the presence of an arbitrary key in the payload. We
should not allow “trust the included key without verifying the signature”;
with that rule, permitting an included root public key is both useful (for
non-recovery verifiers) and secure.

### Delegation cert root-key handling: valid combinations and contract enforcement

The contract MUST enforce the following so that only legitimate uses of
recovery id and included root public key are accepted; invalid combinations
MUST cause a revert with a specific error.

**Reserved labels (delegation cert):**

- **1000** — delegation cert bytes (checkpoint unprotected; already in ARC-0010).
- **1001** — recovery id (delegation cert unprotected): optional uint 0 or 1
  (P-256); used only when delegation cert signature is r||s (64 bytes).
- **1002** — root public key (delegation cert unprotected): optional bstr
  (e.g. uncompressed EC point 0x04||x||y). Alternative: payload key **11**
  (root_public_key as COSE_Key or bstr). At most one of header 1002 or
  payload 11; if both present, revert (e.g. `DuplicateRootKeyInDelegation`).

**Signature format:**

- Delegation cert signature MUST be either **64 bytes** (r||s) or **65 bytes**
  (r||s||v with v = recovery id). Any other length → revert
  `InvalidDelegationSignatureLength`.
- If 65 bytes: the last octet is the recovery id; valid values for P-256 are
  0 and 1. If value is not 0 or 1 → revert `InvalidRecoveryId`.
- Recovery id MUST NOT appear in both the signature (65-byte form) and
  unprotected header 1001. If both are present → revert `RecoveryIdDuplicate`.

**Valid combinations (first checkpoint; establishing root):**

| Recovery id present?      | Included root key present? | Contract behaviour |
|--------------------------|----------------------------|---------------------|
| No (64-byte sig)         | No                         | ES256: try v=0 and v=1, verify with each; use key that verifies. ES256K without recovery: revert `MissingRootKeyForRecovery`. |
| No                       | Yes (1002 or payload 11)   | Verify delegation cert signature with included key; store that key. Do not perform recovery. |
| Yes (1001 or 65-byte sig)| No                         | Use recovery id for single recovery; verify with recovered key; store. |
| Yes                      | Yes                        | Recover using recovery id; verify delegation cert with recovered key; require recovered key == included key; revert `RecoveredKeyMismatchIncludedKey` if not equal; then store. |

**Invalid combinations (revert):**

- Recovery id in header 1001 and 65-byte signature (recovery id in two
  places) → `RecoveryIdDuplicate`.
- Recovery id (header or last octet) not in {0, 1} for P-256 →
  `InvalidRecoveryId`.
- Signature length not 64 or 65 → `InvalidDelegationSignatureLength`.
- Included root key present but delegation cert signature does not verify
  with that key → `DelegationSignatureInvalid` (same as wrong root).
- Both recovery and included key present but recovered key != included key
  → `RecoveredKeyMismatchIncludedKey`.
- ES256K, no recovery support, and no included root key →
  `MissingRootKeyForRecovery`.

**Subsequent checkpoints:** Root is already stored; contract verifies
delegation cert signature with stored root only. Recovery id and included
root key in the cert are ignored.

**Implementation checklist (agent):**

1. When decoding delegation cert: parse unprotected map for 1000 (required),
   optional 1001, optional 1002; decode payload for optional key 11. If both
   1002 and payload 11 present, revert `DuplicateRootKeyInDelegation`.
2. If signature length not 64 and not 65: revert
   `InvalidDelegationSignatureLength`.
3. If signature is 65 bytes and header 1001 present: revert
   `RecoveryIdDuplicate`.
4. Derive recovery id: from 65-byte signature last octet, or from header
   1001 when signature is 64 bytes; if from header, value must be 0 or 1
   else revert `InvalidRecoveryId`.
5. Apply the valid-combinations table above for first checkpoint; for
   subsequent checkpoints verify with stored root only.

## 4. Implementation Phases

**Phase ordering:** Phases 1 → 2 → 3 → 4 → 5 are strictly sequential; each
phase’s deliverables must be complete before starting the next. Phase 6
(ES256K) is optional and can follow Phase 5.

**Agentic implementation notes:**

- Each task has a clear deliverable (code, struct, function, or test); implement
  in task order within a phase. When a task says "revert with X", add the
  named error and use it in the revert.
- Prefer extending existing libraries (LibCose, LibCbor) over new files where
  the plan says "or new helper"; if creating a new library (e.g. delegation
  verifier), give it a single responsibility and document in NatSpec.
- Test each phase before proceeding: Phase 1 (root storage + getter), Phase 2
  (decode + extraction unit tests), Phase 3 (delegation verify + enforcement
  tests), Phase 4 (binding + checkpoint sig tests), Phase 5 (full integration).
- Binding format (full accumulator vs mmr_root derivation) must be decided
  with ARC-0010; implement the chosen option only; do not implement both
  without an explicit decision.

### Phase 1: Per-log root storage (from first checkpoint)

**Objective:** Contract can store and expose the root public key **per log**,
set when the log’s first checkpoint is published (recovered from or read from
that checkpoint’s delegation cert). No global root; no constructor root
parameters.

**Tasks:**

1.1. Extend log state (e.g. in `LogState` or `_logs[logId]`) with root key
     fields: for ES256 two `bytes32` (rootKeyX, rootKeyY) or a struct. Leave
     zero/empty until the first checkpoint for that log is processed.

1.2. Do **not** add constructor parameters or global config for root keys.
     Root is established only when the first checkpoint for a log is
     published.

1.3. Add a view function `getLogRootKey(bytes32 logId)` (or equivalent) that
     returns the stored root for that log (zero if the log has not yet had a
     first checkpoint with checkpoint COSE).

1.4. **No new dependencies.** Root for the first checkpoint is obtained by
     recovering the signer from the delegation cert signature (P256.recovery
     for ES256) or from a payload/header field if the profile carries it.

**Deliverables:** Per-log root storage and accessor; no global root;
unit tests that after a first checkpoint the log’s root is set and
readable.

---

### Phase 2: COSE/CBOR extensions for checkpoint and delegation

**Objective:** Decode checkpoint COSE_Sign1; extract delegation cert from
unprotected header; decode delegation and checkpoint payloads and COSE_Key.

**Tasks:**

2.1. **Unprotected header parsing (LibCose or new helper)**  
     - Current `decodeCoseSign1` (LibCose.sol) skips the unprotected map with
       `_skipValue`. Add a variant or helper that **parses** the unprotected
       map and returns: **1000** (delegation cert bytes, required for
       checkpoint); for the **delegation cert** (nested COSE_Sign1), parse its
       unprotected map for **1001** (recovery id, optional uint), **1002**
       (root public key, optional bstr).  
     - Reuse WitnetBuffer and existing CBOR length/read utilities.  
     - Checkpoint: if label 1000 missing or not a bstr → revert (e.g.
       `MissingDelegationCert` or `InvalidCheckpointCose`).  
     - Delegation cert: if both 1002 and payload key 11 present →
       `DuplicateRootKeyInDelegation`; signature length not 64 or 65 →
       `InvalidDelegationSignatureLength`; recovery id in both 65-byte sig and
       1001 → `RecoveryIdDuplicate`; recovery id not 0 or 1 →
       `InvalidRecoveryId` (see §3 enforcement table).

2.2. **Delegation payload decoding (LibCbor or new LibDelegationCbor)**  
     - Decode CBOR map with integer keys: 1 log_id (tstr → bytes32 or
       keccak256), 2 massif_id, 3 mmr_start, 4 mmr_end, 5 delegated_pubkey
       (nested COSE_Key map), **11 root_public_key** (optional COSE_Key or
       bstr; see §3 enforcement).  
     - Define struct `DelegationPayload { bytes32 logId; bytes32 massifId;
       uint64 mmrStart; uint64 mmrEnd; CoseKey delegatedPubkey; (optional)
       rootPublicKey; }`.  
     - Use WitnetBuffer; skip unknown keys for forward compatibility.  
     - If both payload key 11 and delegation cert unprotected 1002 are
       present, revert `DuplicateRootKeyInDelegation` (enforcement §3).

2.3. **COSE_Key decoding**  
     - Parse COSE_Key map: kty=2 (EC2), crv (-1), x (-2) bstr 32 bytes, y (-3)
       bstr 32 bytes.  
     - Support crv 1 (P-256) and optionally crv 8 (secp256k1) for later
       ES256K.  
     - Output struct suitable for P256.verify (x, y bytes32) or for
       ES256K verifier (same x,y).

2.4. **Checkpoint payload decoding**  
     - Decode CBOR map: 1 log_id, 2 massif_id, 3 mmr_size, 4 mmr_root (bstr),
       5 mmr_index, and optionally full accumulator if profile extended.  
     - Define struct `CheckpointPayload { bytes32 logId; bytes32 massifId;
       uint64 mmrSize; bytes mmrRoot; uint64 mmrIndex; ... }`.  
     - Ensure deterministic CBOR handling (RFC 8949) to match ARC-0010.

2.5. **Checkpoint COSE_Sign1 decode + delegation extraction**  
     - Single entry point: input raw checkpoint COSE_Sign1 bytes; output
       decoded checkpoint (protected, payload, signature, alg), plus
       delegation cert bytes.  
     - Use existing `decodeCoseSign1` plus new unprotected parsing; decode
       checkpoint payload via new CBOR helpers.

**Deliverables:** Library functions (or LibCose/LibCbor extensions) with
NatSpec; unit tests with CBOR test vectors (e.g. from ARC-0010 examples or
generated from Forestrie tooling).

**Dependencies:** None new; WitnetBuffer + existing LibCose/LibCbor.

---

### Phase 3: Delegation certificate verification

**Objective:** Verify delegation cert signature with root key; validate scope;
extract delegated public key.

**Tasks:**

3.1. **Decode delegation cert**  
     - Decode the COSE_Sign1 bytes (from unprotected 1000) using existing
       LibCose structure decode.  
     - Extract algorithm from protected header (ES256 or ES256K).

3.2. **Verify delegation cert signature**  
     - **Subsequent checkpoints:** Verify with the **stored per-log root**
       (x, y) for this logId. Build Sig_structure per RFC 9052. If alg is
       ES256: use OpenZeppelin P256 with stored root. If alg is ES256K: use
       ES256K verifier (Phase 6 or stub revert with UnsupportedAlgorithm).  
     - **First checkpoint for this log:** Obtain root per §3 valid-combinations
       table. (1) If included root key present (1002 or payload 11): verify
       delegation cert signature with that key; store it. (2) If recovery id
       present (1001 or 65-byte sig) and no included key: single recovery,
       verify, store. (3) If neither: ES256 try v=0 and v=1, verify with each,
       store the key that verifies; ES256K without recovery revert
       `MissingRootKeyForRecovery`. (4) If both recovery and included key:
       recover, verify with recovered key, require recovered == included else
       revert `RecoveredKeyMismatchIncludedKey`; then store. Enforce
       invalid-combination reverts from §3 (signature length, duplicate
       recovery id, invalid recovery id value).

3.3. **Validate scope**  
     - Delegation payload `log_id` must equal the `logId` passed to
       `publishCheckpoint`.  
     - Checkpoint payload `mmr_index` (or derived from size) must be in
       `[mmr_start, mmr_end]`.  
     - Revert with descriptive errors (e.g. `DelegationLogIdMismatch`,
       `CheckpointIndexOutOfDelegationRange`).

3.4. **Extract delegated public key**  
     - From delegation payload key 5 (COSE_Key); ensure curve matches root
       (ES256 → P-256, ES256K → secp256k1).  
     - Return (x, y) or equivalent for use in checkpoint signature
       verification.

**Deliverables:** `delegationVerifier` (or equivalent) with (a) logic for
first checkpoint: recover root from delegation cert, verify, store; (b) logic
for subsequent checkpoints: verify delegation cert with stored per-log root.
API may take optional stored root (zero means first checkpoint, recover and
store). Unit tests with valid/invalid certs and scope violations.

**Dependencies:** LibCose (decode + verify), P256 (ES256). No new
third-party libs for ES256-only.

---

### Phase 4: Checkpoint payload binding and signature verification

**Objective:** Ensure submitted (size, accumulator) match signed payload;
verify checkpoint signature with delegated key.

**Tasks:**

4.1. **Binding checks**  
     - Require `checkpointPayload.mmrSize == size` (submitted).  
     - **Accumulator binding:**  
       - If payload includes full accumulator: require
         `payload.accumulator` equals `accumulator` (element-wise, same
         length and each peak matches).  
       - If payload has only `mmr_root`: require a deterministic function
         `deriveCommitment(accumulator) == payload.mmrRoot` (e.g. defined in
         ARC-0010 as H(peaks in canonical order)). Implement the single
         derivation only if this option is chosen.  
     - Revert on mismatch (e.g. `CheckpointPayloadSizeMismatch`,
       `CheckpointAccumulatorMismatch`).

4.2. **Verify checkpoint signature**  
     - Build Sig_structure from checkpoint COSE_Sign1 (protected + payload).  
     - Verify with delegated key (P256 for ES256; or ES256K verifier if
       supported).  
     - Revert on failure (e.g. `CheckpointSignatureInvalid`).

4.3. **Algorithm consistency**  
     - Delegation cert alg and checkpoint alg must match (both ES256 or both
       ES256K). Delegated key curve must match.

**Deliverables:** Binding checks and checkpoint signature verification in
library or LibCheckpointVerifier extension; unit tests (valid checkpoint,
wrong size, wrong accumulator, wrong signature, replayed cert).

**Dependencies:** LibCose (Sig_structure, verify), P256.

---

### Phase 5: Univocity integration

**Objective:** Wire checkpoint COSE verification into `publishCheckpoint`;
keep existing behaviour for receipt and MMR.

**Tasks:**

5.1. **Interface and errors**  
     - Add `bytes calldata checkpointCoseSign1` to `IUnivocity
       .publishCheckpoint` (see `src/checkpoints/interfaces/IUnivocity.sol`).  
     - Add new errors (e.g. in `IUnivocityErrors` or Univocity.sol) so that
       agents and tests can rely on exact revert reasons:  
       `InvalidCheckpointCose`, `MissingDelegationCert`,
       `InvalidDelegationSignatureLength`, `InvalidRecoveryId`,
       `RecoveryIdDuplicate`, `DuplicateRootKeyInDelegation`,
       `RecoveredKeyMismatchIncludedKey`, `MissingRootKeyForRecovery`,
       `DelegationSignatureInvalid`, `DelegationVerificationFailed`,
       `DelegationLogIdMismatch`, `CheckpointIndexOutOfDelegationRange`,
       `CheckpointPayloadSizeMismatch`, `CheckpointAccumulatorMismatch`,
       `CheckpointSignatureInvalid`.

5.2. **Univocity.sol**  
     - At the start of `publishCheckpoint` (after first-checkpoint block if
       needed, and before or after _validateCheckpoint):  
     - Decode checkpoint COSE_Sign1; extract delegation cert.  
     - Call delegation verification (root key, scope, extract delegated key).  
     - Call checkpoint binding (size, accumulator) and signature
       verification.  
     - On any failure, revert with the appropriate error.  
     - Then run existing _validateCheckpoint, _checkAuthorization,
       consistency proof, _updateLogState.

5.3. **Root key source**  
     - No global root. For each log, the root is set from the **first**
       checkpoint for that log (recovered from delegation cert or read from
       payload). Subsequent checkpoints use the stored per-log root.

5.4. **First checkpoint**  
     - The **first** checkpoint for every log (including authority log
       bootstrap) must carry a valid checkpoint COSE_Sign1 with a delegation
       cert. The contract recovers (or reads) the root from that delegation
       cert and stores it for the log. So the first checkpoint both
       establishes the log’s root and passes verification. Document and
       test; ensure authority log’s first checkpoint is still bootstrap-only
       and establishes the intended root.

**Deliverables:** Updated Univocity.sol and IUnivocity; integration tests:
full publishCheckpoint with valid checkpoint COSE; tests that invalid COSE,
wrong binding, or invalid signature revert before state change.

**Dependencies:** Phases 1–4.

---

### Phase 6: ES256K support (optional)

**Objective:** Support delegation certs and checkpoints signed with ES256K
(secp256k1 + SHA-256).

**Tasks:**

6.1. **Select library**  
     - Choose a single, well-audited Solidity library for ECDSA
       secp256k1 with SHA-256 (not Keccak). Options: audit existing
       open-source implementations (e.g. used in other L2s or
       transparency systems); prefer minimal API (verify(hash, r, s, x, y)
       returning bool).

6.2. **Integrate**  
     - Add ES256K constant (e.g. -47) to LibCose; in delegation and
       checkpoint verification, dispatch to ES256K verifier when alg is
       ES256K.  
     - Root key storage for ES256K: store 64-byte pubkey (x,y) or two
       bytes32.  
     - No change to Sig_structure; only the hash is SHA-256 and the curve
       is secp256k1.

6.3. **First checkpoint with ES256K**  
     - If the library does not provide public-key recovery for secp256k1 +
       SHA-256, the first checkpoint for a log using ES256K must carry the
       root public key in the payload or in the delegation cert (e.g. ARC
       extension) so the contract can verify and store it.

6.4. **Tests**  
     - Test vectors (e.g. from IETF or ARC-0010) for ES256K sign/verify;
       integration test with ES256K delegation + checkpoint.

**Deliverables:** ES256K verification path; optional root key type or
storage; tests.  
**Dependencies:** One new dependency (minimal, audited). Can be deferred.

---

## 5. Testing Strategy

### 5.1 Unit tests

- **LibCose / CBOR:** Unprotected map parsing; extraction of label 1000;
  delegation and checkpoint payload decode; COSE_Key decode (P-256 and
  secp256k1); invalid CBOR and missing keys revert.
- **Delegation verification:** Valid cert verifies; wrong root fails; wrong
  log_id or mmr range fails; expired/issued_at if implemented.
- **Binding and checkpoint signature:** Correct (size, accumulator) and
  signature pass; wrong size or accumulator or signature fails.

### 5.2 Integration tests

- **Happy path:** Full `publishCheckpoint` with valid receipt, valid
  checkpoint COSE_Sign1 (delegation + checkpoint), valid consistency proof;
  state and events updated.
- **Failure paths:** Invalid checkpoint COSE; delegation cert signature
  invalid; log_id / massif_id / mmr range mismatch; checkpoint payload
  size or accumulator mismatch; checkpoint signature invalid; replayed
  delegation cert (e.g. wrong mmr_index).
- **First checkpoint:** If first checkpoint requires checkpoint COSE, test
  with valid delegation covering index 0 and valid checkpoint COSE; test
  that missing or invalid checkpoint COSE reverts.

### 5.3 Fuzz and invariants

- **Fuzz:** Checkpoint COSE and delegation CBOR parsing with random bytes
  (expect revert, no crash); binding checks with mutated size/accumulator.
- **Invariants:** Extend existing Univocity invariants: after each
  publishCheckpoint, log state remains consistent; add invariant that
  "checkpoint count only increases when full verification passes".

### 5.4 Test vectors

- **Deterministic CBOR:** Use or generate test vectors that match ARC-0010
  examples (delegation payload, checkpoint payload, COSE_Key) so that
  Solidity decoder matches Forestrie producer output.
- **Signatures:** At least one ES256 delegation cert + checkpoint signed with
  known keys and stored as calldata hex for regression.

## 6. Security and Audit Notes

- **Binding is critical:** The contract must enforce that the **submitted**
  (size, accumulator) are exactly what the signer committed to in the
  checkpoint payload. Otherwise a signer could sign one state and the
  submitter could pass another (split view).
- **No downgrade:** Do not allow a path that skips checkpoint verification
  when checkpoint COSE is "optional" in the same call (Option 2 = mandatory).
- **Root key:** Root is per-log, established by the first checkpoint (recover
  or read from delegation cert). No global root; key rotation for a log
  requires a new logId or contract upgrade. Document first-publisher-wins for
  non-authority logs.
- **Gas:** COSE decode, two signature verifications (delegation + checkpoint),
  and CBOR parsing will increase gas; measure and document.
- **Third-party crypto:** Prefer OpenZeppelin P256 and WitnetBuffer; add
  ES256K only with a library that has been audited or used in production.

### Correctness and consistency review

- **Verification order:** Checkpoint COSE (decode → delegation → binding →
  checkpoint sig) runs before existing receipt/MMR logic; failures revert
  before state change. Consistent with §2 and §5.2.
- **Root establishment:** First checkpoint only establishes root; subsequent
  use stored root. No global root; per-log storage. Receipt binding (root key
  in receipt) is described in §3 but is an extension of receipt format;
  implementation may do Phase 1–5 with recovery/included-key only and add
  receipt binding in a follow-up unless otherwise decided.
- **Binding:** Size and accumulator must match payload; exact accumulator
  format (full peaks vs derived commitment) deferred to ARC-0010; plan
  requires a single chosen option before implementing Phase 4.
- **Enforcement table (§3):** Valid combinations cover all four cases;
  invalid combinations have unique revert reasons; no path allows "trust
  included key without verify". Consistent with Phase 2.1, 2.2, 3.2, 5.1.
- **Phase order:** 1 (storage) → 2 (decode) → 3 (delegation verify) → 4
  (binding + checkpoint sig) → 5 (integration) is correct; Phase 6 optional.
- **Labels:** 1000 checkpoint, 1001/1002 delegation cert; no clash with
  ARC-0010 or COSE.

## 7. Out of Scope / Follow-ups

- **Option 4 (hybrid):** Optional checkpoint COSE; not in this plan; can be
  added later if backward compatibility is required.
- **Key rotation without upgrade:** Per-log root is fixed after first
  checkpoint; rotation would require a new logId or contract change (e.g.
  multiple roots, epoch-based).
- **Single consistency receipt:** A single consistency-proof blob (SCITT
  CBOR) can replace `size`, `accumulator`, and `consistencyProof` for
  **all** checkpoints (first = tree-size-1 0, empty paths, right-peaks =
  full accumulator); see **Appendix A**. Can be added as an overload or
  follow-up while keeping the current calldata API for comparison.

## Appendix A: Consistency receipt as single parameter

**Implemented behaviour:** The contract takes a full COSE **Receipt of
Consistency** (COSE_Sign1 with detached payload). It **always** verifies
both (1) the **consistency proof chain** (consistencyReceipt
verifyConsistencyProofChain) and (2) the **receipt signature** over the
accumulator commitment (LibCose verifySignatureDetachedPayload). The
signing key is bootstrap keys, a delegated key from the receipt’s
unprotected 1000, or the log’s stored root key. So consistency receipts
are both consistency-proof checked and signature verified on every
checkpoint.

**Question:** Can we pass only a **consistency receipt** (or a single
encoding of the consistency proof) and derive `size`, `accumulator`, and
the consistency proof from it, instead of passing `size`, `accumulator`, and
`consistencyProof` separately? And can we do that while keeping a calldata
API and without hurting simplicity or gas?

### A.1 Is it possible?

**Yes.** In the SCITT MMR profile (draft-bryce-cose-receipts-mmr-profile),
the **consistency proof** is a single CBOR structure:

```text
consistency-proof = bstr .cbor [
  tree-size-1: uint      ; previous tree size
  tree-size-2: uint     ; latest tree size (our "size")
  consistency-paths: [ + consistency-path ]   ; one path per old peak
  right-peaks: [ * bstr ]                     ; peaks completing the new accumulator
]
```

- **tree-size-2** is the new MMR size (leaf count) — so we get `size` from
  the receipt.
- **consistency-paths** are the inclusion paths from each old peak to the
  new tree; they correspond to the current `consistencyProof` (one path per
  old peak).
- **right-peaks** are the additional peak hashes that complete the new
  accumulator when appended to the roots produced by the consistency paths.

The contract already has **old** state: `log.size`, `log.accumulator`. The
draft defines **consistent_roots**(ifrom, accumulator_from, proofs), which
returns the list of roots (in descending height order, consecutive
duplicates collapsed). The **new accumulator** is exactly:
`consistent_roots(...) ++ right_peaks`. So we can **recompute** the new
accumulator on-chain from the decoded receipt and stored state; we do not
need to pass `accumulator` at all.

So from a single blob (the consistency-proof CBOR, or a full COSE Receipt
of Consistency that carries it) we can obtain:

- **size** = tree-size-2  
- **consistency proof** = consistency-paths (and right-peaks for the
  construction)  
- **accumulator** = recomputed as roots from consistent_roots + right_peaks  

Everything needed for consistency verification and state update is
extractible or derivable.

**First checkpoint:** The same consistency-proof structure covers the first
checkpoint: use **tree-size-1 = 0** (no previous tree), **consistency-paths =
[]** (no old peaks), and **right-peaks =** the full new accumulator (all
peaks for tree-size-2). Then consistent_roots(0, [], []) yields no roots, and
new_accumulator = right_peaks. So no special parameter shape is needed; the
single receipt format applies to all checkpoints including the first.

### A.2 Calldata API

**Yes.** We can keep a calldata-only API. The single parameter would be
`bytes calldata consistencyProofOrReceipt` (or similar). The contract reads
from calldata and decodes in place (e.g. with WitnetBuffer over a view of
calldata). No need to copy the whole blob to memory; we can decode
incrementally and only copy the parts we need (e.g. paths, right-peaks) when
we run `consistentRoots` and build the new accumulator. So the **caller** still
passes one calldata bytes; the **contract** decodes and uses it. Calldata
variants of inclusion and consistency checking can remain (we decode from
calldata and pass decoded paths to existing logic, or we add a decode path
that feeds `consistentRoots` and the new-accumulator construction).

### A.3 Simplicity and gas

- **Simplicity**
  - **Caller:** One parameter instead of three (`size`, `accumulator`,
    `consistencyProof`) for all checkpoints. Simpler.
  - **Contract:** One decode path for the consistency-proof structure
    (CBOR: tree-size-1, tree-size-2, consistency-paths, right-peaks). Then
    reuse existing `consistentRoots` and add one step: build new accumulator
    = roots ++ right_peaks, then validate length vs `peaks(tree-size-2 - 1)`
    and run the same checks as today. Complexity is bounded and localized.

- **Gas**
  - **Current design:** Caller passes `size` (fixed), `accumulator` (array
    in calldata), `consistencyProof` (array of arrays in calldata).
    Contract does no decode for these; it only reads and verifies.
  - **Single-blob design:** Contract must decode one CBOR structure
    (sizes, then a variable-length array of paths, then right-peaks). Decoding
    has a cost; building the new accumulator from roots + right_peaks is
    similar to what we do today (we already iterate and compare). So gas will
    likely **increase** somewhat due to decode, but:
    - We can keep decoding minimal (no full COSE if we use raw
      consistency-proof CBOR).
    - We avoid passing the new accumulator explicitly, so we save calldata
      size for the accumulator (which can be large). Smaller calldata can
      reduce gas.
  - **Conclusion:** Net gas impact is not clear without measurement. Decode
    adds cost; smaller calldata and one parameter may reduce cost. Recommend
    implementing and benchmarking before committing.

### A.4 Signed vs unsigned blob

- **Unsigned (raw consistency-proof CBOR):** A hypothetical design would
  pass only the consistency-proof structure as a single CBOR blob. The
  contract would decode it, recompute the new accumulator, and verify
  consistency. There would be **no** signature over that blob; some other
  binding (e.g. a separate checkpoint COSE) would attest to (size,
  accumulator). The **current implementation does not use this**; it uses
  the signed form below.

- **Signed (full COSE Receipt of Consistency):** The **implemented** design
  passes the full SCITT Receipt of Consistency (COSE_Sign1, payload
  detached). The contract decodes the receipt, extracts the
  consistency-proof from the unprotected header, runs the consistency proof
  chain to obtain the new accumulator, builds the detached payload
  (commitment to that accumulator), and **verifies the receipt signature**
  over that payload using bootstrap keys, a delegated key (from unprotected
  1000), or the log’s stored root key. So the consistency receipt is both
  consistency-proof checked and signature verified on every call to
  publishCheckpoint.

**Recommendation (historical):** The plan originally suggested supporting
unsigned single-blob first. The code instead implements the **signed** full
COSE Receipt of Consistency and verifies its signature in all cases.

### A.5 Plan impact

- **Feasibility:** Yes; everything is extractible or derivable from the
  consistency-proof structure; calldata API is keepable; simplicity is
  acceptable; gas impact should be measured.
- **First checkpoint:** Represented by the same receipt with tree-size-1 =
  0, empty consistency-paths, and right-peaks = full new accumulator; no
  separate parameter shape.
- **Suggested addition:** Add an optional phase or follow-up that
  introduces a **consistency-proof blob** parameter for all checkpoints
  (including first): decode to get tree-size-1, tree-size-2,
  consistency-paths, right-peaks; if tree-size-1 == 0 then new_accumulator =
  right_peaks, else new_accumulator = consistent_roots(...) ++ right_peaks;
  then run existing consistency and state-update logic. Keep the existing
  (size, accumulator, consistencyProof) overload or default for backward
  compatibility and gas comparison.

## 8. Acceptance Criteria

**Functional**

- [ ] `publishCheckpoint` requires a valid checkpoint COSE_Sign1 and
  reverts if missing or invalid.
- [ ] Delegation cert is verified with the **per-log root** (established from
  the first checkpoint for that log); scope (log_id, mmr range) enforced.
- [ ] Submitted (size, accumulator) are bound to the checkpoint payload
  and verified before state update.
- [ ] Checkpoint signature is verified with the delegated public key
  extracted from the delegation cert.

**Delegation cert root-key enforcement (§3)**

- [ ] First checkpoint with 64-byte sig and no recovery id / no included key:
  ES256 recovers via try v=0 and v=1; root stored.
- [ ] First checkpoint with recovery id (1001 or 65-byte sig) and no included
  key: single recovery, verify, store.
- [ ] First checkpoint with included root key (1002 or payload 11) and no
  recovery id: verify delegation sig with included key, store.
- [ ] First checkpoint with both recovery id and included key: recover,
  verify, require recovered == included; revert `RecoveredKeyMismatchIncludedKey`
  when they differ.
- [ ] Revert `InvalidDelegationSignatureLength` when delegation sig length is
  not 64 or 65.
- [ ] Revert `InvalidRecoveryId` when recovery id is not 0 or 1 (P-256).
- [ ] Revert `RecoveryIdDuplicate` when both 65-byte signature and header
  1001 present.
- [ ] Revert `DuplicateRootKeyInDelegation` when both 1002 and payload 11
  present.
- [ ] Revert `MissingRootKeyForRecovery` when ES256K is used, recovery not
  supported, and no included root key (Phase 6).

**Quality and references**

- [ ] All new CBOR/COSE parsing uses WitnetBuffer; no new dependencies for
  ES256-only path.
- [ ] Unit and integration tests cover happy path and all failure modes above;
  fuzz/invariants where appropriate.
- [ ] NatSpec and errors document the new behaviour; ADR-0032 and ARC-0010
  referenced.

## Appendix B: Implementation review, gaps, and test coverage

**Status:** Reflects code and tests as of 2026-02-22. This appendix reviews the
Univocity codebase against this plan, related plans (0014, 0015), ADRs
(0030, 0032), and ARCs (0008, 0010); summarizes remaining gaps and
divergences; and assesses test coverage.

### B.1 Reference documents

| Document | Role |
|----------|------|
| **This plan (0013)** | Phases 1–5 (per-log root, COSE/CBOR, delegation verify, binding +
  checkpoint sig, integration); Phase 6 ES256K optional; §3 delegation
  root-key enforcement. |
| **ADR-0032** | Option 2: contract verifies checkpoint COSE_Sign1 and delegation
  chain; binding of (size, accumulator) to signed payload. |
| **ADR-0030** | Leaf = H(idtimestamp ‖ H(receipt/grant)); compatibility with
  Forestrie ledger. |
| **ARC-0008** | Delegation architecture: root → delegation cert → delegated
  key → checkpoint. |
| **ARC-0010** | COSE/CBOR profiles: delegation cert payload (keys 1–5, 11),
  checkpoint payload (log_id, massif_id, mmr_size, mmr_root, mmr_index). |
| **Plan 0014** | Consistency receipt as single COSE parameter; calldata. |
| **Plan 0015** | publishCheckpoint API: payment receipt as Receipt of
  Inclusion; PaymentGrant; leaf commitment formula. |

### B.2 Implemented behaviour (summary)

**API (plan 0015):** `publishCheckpoint(consistencyReceipt, paymentReceipt,
paymentIDTimestampBe, paymentGrant)` is implemented. There is **no** separate
`checkpointCoseSign1` parameter. The consistency receipt carries optional
delegation cert bytes in unprotected label 1000.

**Consistency receipt (plan 0014, Appendix A):** Decode COSE Receipt of
Consistency via LibCoseReceipt; extract consistency-proof list and optional
delegation cert. consistencyReceipt runs the consistency proof chain
(consistentRoots / consistentRootsMemory), yields (size, accumulator). Build
detached payload commitment; verify **consistency receipt** signature with
bootstrap keys or, when delegation cert is present, with the delegated key
from delegationVerifier. Root is established from the first checkpoint
when delegation is present (recover or included key per §3).

**Delegation (plan 0013 Phase 2–3):** delegationVerifier decodes
delegation cert (LibCose.decodeDelegationCert), enforces signature length
64/65, recovery id (1001 or 65-byte sig), optional root in header 1002 or
payload key 11, and valid-combinations table (§3). Validates scope (logId,
mmrIndex in [mmr_start, mmr_end]); returns root key and delegated key. The
**delegated key is used to verify the consistency receipt signature**, not a
separate checkpoint COSE_Sign1.

**Per-log root (Phase 1):** LogState has rootKeyX, rootKeyY; getLogRootKey
(logId); root set when first checkpoint includes delegation and
delegationVerifier returns root.

**Payment and first-checkpoint (plan 0015, ADR-0030):** Leaf commitment =
SHA256(paymentIDTimestampBe ‖ SHA256(grant)). First checkpoint: verify
inclusion of that leaf in the new accumulator via verifyInclusion (no
paymentReceipt). Delegated (non-authority) logs: paymentReceipt required;
LibInclusionReceipt.verifyReceiptOfInclusion verifies RoI and inclusion in
authority log.

**Algorithms:** verifyInclusion, includedRoot,
consistentRoots, consistentRootsMemory, peaks — implemented and used.

### B.3 Gaps and divergences

**1. No checkpoint COSE_Sign1 or checkpoint payload binding (plan Phase 4)**

The plan and ADR-0032 Option 2 assume a **checkpoint** COSE_Sign1 (signed by
the delegated key, payload with log_id, massif_id, mmr_size, mmr_root,
mmr_index) and **binding** of the **submitted** (size, accumulator) to that
payload (e.g. payload.mmrSize == size, accumulator matches payload or
derived commitment).

**Implementation:** There is no checkpoint COSE_Sign1 parameter. Size and
accumulator are derived **only** from the consistency proof chain. The
signed artifact that binds to the new accumulator is the **consistency
receipt** (detached payload = commitment to that accumulator); the
consistency receipt is verified with the delegated key when delegation cert
is present. So the trust model is: “consistency receipt signed by delegated
key commits to (size, accumulator); we derive (size, accumulator) from the
receipt’s consistency proofs.” There is no second, separate “checkpoint”
signature over a checkpoint payload.

**Gap:** Phase 4 tasks 4.1 (binding checks: mmrSize == size, accumulator
match) and 4.2 (verify **checkpoint** signature with delegated key) are not
implemented. Phase 2 tasks 2.4 (CheckpointPayload decode) and 2.5 (checkpoint
COSE_Sign1 decode) are not implemented. Acceptance criteria that require
“checkpoint COSE_Sign1”, “CheckpointPayloadSizeMismatch”,
“CheckpointAccumulatorMismatch”, “CheckpointSignatureInvalid” are **not**
met.

**Divergence:** The implemented design deliberately uses the consistency
receipt as the single signed commitment to the new state; delegation cert
identifies the key that must sign that receipt. This achieves binding of
(size, accumulator) to the signer without a separate checkpoint COSE
artifact. If the plan is to be followed literally (separate checkpoint
COSE + binding), a follow-up phase would add checkpoint COSE decode,
payload binding, and checkpoint signature verification.

**2. Delegation cert enforcement (§3) — implemented but under-tested**

delegationVerifier implements the §3 valid/invalid combinations (signature
length, recovery id, included root key, duplicate recovery, duplicate root
key, recovered vs included key mismatch). Reverts: InvalidDelegationSignatureLength,
InvalidRecoveryId, RecoveryIdDuplicate, RecoveredKeyMismatchIncludedKey,
DuplicateRootKeyInDelegation, MissingRootKeyForRecovery, DelegationLogIdMismatch,
CheckpointIndexOutOfDelegationRange, DelegationSignatureInvalid. There are
**no** dedicated unit or integration tests that exercise the delegation
cert path (consistency receipt with unprotected 1000) or that trigger these
reverts. ES256 first-checkpoint test uses bootstrap keys only, not delegation.

**3. ES256K (Phase 6)**  
Not implemented. Only ES256 is supported for delegation.

**4. Single consistency-proof blob (Appendix A)**  
The API passes a full COSE Receipt of Consistency, not a raw
consistency-proof CBOR blob. Appendix A describes feasibility of a
single-blob parameter; the current implementation uses the signed receipt
form.

### B.4 Alignment with ADR-0030 and plan 0015

- **Leaf formula (ADR-0030 / plan 0015):** Implemented: inner =
  SHA256(logId‖payer‖maxHeight‖minGrowth‖ownerLogId‖createAsAuthority);
  leafCommitment = SHA256(paymentIDTimestampBe ‖ inner). Used for first-checkpoint
  inclusion and for payment receipt RoI. (checkpointStart/checkpointEnd removed;
  bounds are size-based only.)
- **Payment receipt as RoI:** Implemented via LibInclusionReceipt; authority
  log accumulator and size used for inclusion check.
- **PaymentGrant struct and bounds:** Implemented; maxHeight, minGrowth
  (size-based bounds only).

### B.5 Test coverage assessment

**Algorithms (unit):** Strong. peaks.t.sol (many sizes, heights, perfect
trees); includedRoot.t.sol (verifyInclusion, includedRoot, wrong sibling/
index/hash); consistentRoots.t.sol (multiple from/to sizes, reverts);
binUtils (log2floor, hashPosPair64, indexHeight, bitLength, mostSigBit,
allOnes) each with dedicated test files; fuzz where appropriate.

**COSE/CBOR (unit):** LibCose.t.sol: buildSigStructure, decodeCoseSign1,
verifySignature (KS256). LibCbor.t.sol: extractAlgorithm, decodePaymentClaims.
No dedicated unit tests for consistencyReceipt, LibInclusionReceipt, or
delegationVerifier; they are exercised only through Univocity and
CheckpointFlow integration tests.

**Univocity (integration):** Broad. First checkpoint (size zero revert,
receipt empty, wrong log, inclusion failure, size-two, non-bootstrap sender,
ADR-0030 leaf formula); authority log (bootstrap-only second checkpoint,
bootstrap can publish to any log); receipt and bounds (checkpoint count,
maxHeight, minGrowth, grant range); consistency (invalid proof revert);
invalid COSE revert; ES256 first-checkpoint (bootstrap keys, no delegation);
getLogState, isLogInitialized; error-coverage matrix for reachable errors.
**Missing:** Tests that pass a consistency receipt **with** delegation cert
(unprotected 1000) and verify root storage and subsequent use of stored
root; tests that trigger delegation-specific reverts (InvalidRecoveryId,
RecoveryIdDuplicate, RecoveredKeyMismatchIncludedKey, etc.).

**Integration (CheckpointFlow):** Bootstrap init and publish; user
checkpoints with receipt; same receipt different submitters. No
delegation or payment RoI failure paths in this file.

**Invariants:** Univocity.invariants.sol — checkpoint count monotonic, size
monotonic; handler uses bootstrap-only with valid accumulators. No
invariants that involve delegation or payment receipt.

**Summary:** Algorithm and core contract paths are well covered. Delegation
cert path (presence of delegation, root establishment, §3 enforcement
reverts) and consistencyReceipt / LibInclusionReceipt as standalone
libraries lack dedicated tests. Adding integration tests for consistency
receipts with delegation (happy path + invalid recovery id, duplicate root
key, log id mismatch, index out of range) would close the main coverage
gaps relative to this plan.
