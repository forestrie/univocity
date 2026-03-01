# Plan 0025: Assess verify-only (no key recovery) for ES256

**Status:** SUPERSEDED  
**Date:** 2026-02-23  
**Superseded by:** [plan-0026](plan-0026-verify-only-no-recovery.md) (implemented).  
**Related:** [PR #2 discussion r2869350137](https://github.com/forestrie/univocity/pull/2#discussion_r2869350137),
[ADR-0005](adr/adr-0005-grant-constrains-checkpoint-signer.md),
[plan-0024](plan-0024-p256-recovery-and-normalization.md)

## 1. Purpose

Assess the review suggestion: remove or reduce on-chain ES256 **key recovery** and
instead rely on (1) **signature verification failure** when the wrong key is used,
and (2) **binary comparison** of `grantData` to the bootstrap key (or to the
claimed signer). Goal: identify what protocol behaviour we could **not** achieve
without recovery, and whether we can unburden the protocol by moving to
verify-only + grant comparison.

## 2. Current use of recovery

Recovery is used in two places:

1. **`_checkpointSignersES256` (no delegation)**  
   For the first checkpoint to a log, the log has no stored root key. We
   **recover** (rootX, rootY) from the consistency receipt signature, then:
   - verify the receipt with that key,
   - for root: require recovered signer to match bootstrap
     (`_es256KeyMatchesBootstrap(rootX, rootY)`),
   - for root: require `grantData == bootstrapKey` (length + keccak256),
   - for non-root with GF_REQUIRE_SIGNER: require
     `keccak256(abi.encodePacked(rootX, rootY)) == keccak256(grantData)`.
   We then **persist** (rootX, rootY) as the log’s root key.

2. **`_checkpointSignersES256` (with delegation)**  
   First checkpoint with a delegation proof: the **delegate** signed the
   receipt; the **root** signed the delegation. We have no stored root key. We
   **recover** the root from the delegation signature via
   `recoverDelegationSignerES256`, then verify the delegation proof and the
   receipt, and persist the recovered root.

## 3. Verify-only + binary grant comparison

**Idea:** Do not recover. Treat `grantData` (when present and of the right
length) as the **claimed** signer key. Verify the receipt (or delegation) with
that key; if verification fails, revert. Then enforce grant rules by **binary
comparison** of `grantData` to the bootstrap key (root) or to the key we are
storing (non-root).

### 3.1 Root’s first checkpoint (no delegation)

- **Today:** Recover (rootX, rootY) from receipt → verify(receipt, rootX, rootY)
  → require recovered key matches bootstrap → require grantData == bootstrapKey
  → persist (rootX, rootY).
- **Verify-only:** Require root to set GF_REQUIRE_SIGNER and grantData length 64.
  Parse grantData as (x, y). **Verify(receipt, x, y)**. If it fails, wrong key →
  revert. Require **grantData == bootstrapKey** (binary compare; see note below).
  Persist grantData (or the parsed (x,y)) as root key. **No recovery.**

**Note (bootstrap key form):** Today we accept (x, y) or (x, P−y) as the same
bootstrap key (`_es256KeyMatchesBootstrap`). With verify-only we could either:
(a) require strict **binary** equality `grantData == storedBootstrapKey`, or
(b) keep one curve-point equivalence check for bootstrap only (grantData
interpreted as (x,y) matches bootstrap (es256X, es256Y) or (es256X, P−es256Y)).
Option (a) is simpler and avoids P256.P; (b) preserves “either encoding” for
bootstrap.

### 3.2 Non-root first checkpoint (no delegation)

- **Today:** Recover (rootX, rootY) from receipt → verify → if GF_REQUIRE_SIGNER
  require grantData == (rootX, rootY) → persist (rootX, rootY).
- **Verify-only:** If GF_REQUIRE_SIGNER: require grantData length 64, parse as
  (x, y), **verify(receipt, x, y)**, require grantData matches any additional
  constraint (e.g. same as root key to store), persist grantData. **No recovery.**

### 3.3 First checkpoint with delegation

- **Today:** Recover root from delegation signature; verify delegation with
  recovered root; verify receipt with delegate; persist recovered root.
- **Verify-only:** We need the **root** key to verify the delegation proof. So we
  must obtain it from somewhere. **Option:** When delegation is present for the
  first checkpoint, require **grantData to carry the root key** (e.g. 64 bytes
  for ES256). Then: verify(delegationSignature, grantData as root key); verify
  receipt with delegate; persist grantData as root key. **No recovery.**

So even for delegation we can drop recovery if we require the client to supply
the root key in the grant for that first-checkpoint-with-delegation case.

## 4. Behaviour we could NOT accomplish without recovery

Only one semantic is lost:

- **First checkpoint to a non-root log *without* GF_REQUIRE_SIGNER (“any signer”
  path).**  
  Today: we recover (rootX, rootY) from the receipt and store it; whoever signed
  becomes the log’s root key. No key in the grant is required.  
  Without recovery: we have no key to run **verify(receipt, key)** unless the
  caller supplies it. So we cannot support “submit a first checkpoint and have
  the contract discover and store the signer” without the signer (or some key)
  in the grant.

**Implications:**

- **Root:** ADR-0005 already requires GF_REQUIRE_SIGNER and grantData = bootstrap
  key for the root’s first checkpoint. So root is already “key in grant”; no
  recovery is strictly necessary.
- **Non-root with GF_REQUIRE_SIGNER:** Grant supplies the key; we verify with it
  and compare; no recovery needed.
- **Non-root without GF_REQUIRE_SIGNER:** This is the only path that **depends**
  on recovery today. If we are willing to **require** GF_REQUIRE_SIGNER (or
  otherwise require the signer key in the grant) for every first checkpoint, we
  can remove recovery entirely. If we want to keep “any signer” for non-root
  first checkpoint, we must keep recovery for that path (or redesign so the key
  is supplied elsewhere).

## 5. Summary and recommendation

| Scenario                              | Recovery needed today? | With verify-only + grant compare      |
|--------------------------------------|------------------------|----------------------------------------|
| Root first checkpoint (no delegation)| No*                    | Verify(receipt, grantData); grantData == bootstrap |
| Non-root first checkpoint, no deleg. | Only if no GF_REQUIRE_SIGNER | Verify(receipt, grantData); persist grantData |
| First checkpoint with delegation     | Yes (recover root)     | Require grantData = root key; verify(delegation, grantData); no recovery |

\*We could already use grantData for root; we today also check recovered key
matches bootstrap, which verify-only replaces by “grantData == bootstrap and
verify(receipt, grantData)”.

**Specific behaviour we could NOT accomplish without key recovery:**

- **First checkpoint to a non-root log without GF_REQUIRE_SIGNER**, where the
  contract “discovers” the signer from the receipt and stores them as root key
  without the client supplying that key in the grant.

If the protocol is willing to require that the signer key is always supplied in
the grant for the first checkpoint (root already does; non-root would need
GF_REQUIRE_SIGNER or equivalent), then **all recovery can be removed**: use
verify-only with the key from grantData and binary comparison for grant
semantics. That would allow removing `recoverES256` / `recoverES256FromDetachedPayload`
from the main path and `recoverDelegationSignerES256` for the delegation path,
relying only on `P256.verify` and grantData comparison, which significantly
unburdens the protocol (no recovery-id handling, no lexicographic tie-breaking,
fewer gas and edge cases).
