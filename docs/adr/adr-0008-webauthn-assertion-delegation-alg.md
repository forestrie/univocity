# ADR-0008: WebAuthn-assertion delegation algorithm (ALG_ES256_WEBAUTHN)

**Status:** ACCEPTED
**Date:** 2026-08-22
**Related:** [ADR-0006](./adr-0006-cose-shaped-delegation-proof.md),
[ARC-0017](../arc/arc-0017-auth-overview.md),
product `engineering/prd-passkey-log-custody.md` (§4, §5f, §5g, §7.1),
devdocs [ADR-0062](../../../devdocs/adr/adr-0062-canopy-derived-grant-flag-registry.md)

## Context

A passkey (WebAuthn credential) cannot sign arbitrary bytes. The
authenticator signs

```
ECDSA_P256( authenticatorData ‖ SHA256(clientDataJSON) )
```

with the caller's message carried inside `clientDataJSON.challenge`. The
existing `verifyDelegationProofES256` verifies over
`sha256(Sig_structure)`. Same curve, same key type — different signature
envelope. A raw WebAuthn assertion can never verify as a plain COSE
Sign1, so passkey-rooted logs need a distinct algorithm, not a tweak to
ES256.

Growing the algorithm set is expected: new algorithms land in new
immutable instances or in UUPS ones; deployed immutable instances keep
the set they shipped with. No upgrade machinery is added to
`ImutableUnivocity`.

## Decision

### 1. A distinct COSE algorithm id

`ALG_ES256_WEBAUTHN = -65800` (private use, adjacent to `ALG_KS256 =
-65799`), in `src/cosecbor/constants.sol`. A distinct alg — not `-7`
plus a flag — keeps unaware verifiers fail-closed: they reject on
unknown alg instead of attempting a plain ES256 verify that can only
fail late (or worse, appear to be a signature bug).

### 2. Challenge binding is the security argument

`verifyDelegationProofES256WebAuthn` rebuilds the canonical delegation
payload `(domain, logId, mmrStart, mmrEnd, delegatedKey)` and its COSE
`Sig_structure` exactly as the plain ES256 path does, then requires

```
clientDataJSON.challenge == base64url(sha256(Sig_structure))
```

before verifying `P256(sha256(authenticatorData ‖
sha256(clientDataJSON)))` against the stored root key. Without the
challenge equality the assertion proves key possession and says nothing
about this delegation. Each failure mode has a distinct error
(`DelegationChallengeMismatch`, `InvalidWebAuthnAssertion`,
`DelegationUserPresenceRequired`, `DelegationUserVerificationRequired`,
`DelegationRpIdMismatch`) so canopy can classify rejections without
re-running the verify off-chain.

### 3. Alg-specific data rides in a generic `algData` array

This was the largest single design choice. The WebAuthn variant needs
`authenticatorData` and `clientDataJSON` threaded to the verifier, and
`DelegationProof` is nested inside `ConsistencyReceipt`, the calldata
argument of `publishCheckpoint`. Four options were considered.

**Option A — extend the struct (rejected):**

```solidity
struct DelegationProof {
    bytes protectedHeader;
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    bytes signature;
    bytes authenticatorData; // empty unless ALG_ES256_WEBAUTHN
    bytes clientDataJSON;    // empty unless ALG_ES256_WEBAUTHN
}
```

An ABI change to `ConsistencyReceipt` and therefore to every encoder
and caller (go-univocity, canopy, thinker, every fixture). Every
non-WebAuthn checkpoint pays two empty dynamic fields of calldata
forever, and the struct grows again for every future envelope-shaped
algorithm — alg-specific semantics leaking into an alg-generic type.

**Option B — parallel struct (rejected):**

```solidity
struct WebAuthnDelegationProof {
    bytes protectedHeader;
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    bytes signature; // r ‖ s
    bytes authenticatorData;
    bytes clientDataJSON;
    uint256 challengeIndex;
    uint256 typeIndex;
}
```

Because `DelegationProof` is embedded in `ConsistencyReceipt`, a
parallel struct forces either a parallel `ConsistencyReceipt` plus
parallel `publishCheckpoint` overloads (a full-surface duplication), or
both structs side by side with one always empty — strictly worse than
Option A.

**Option C — opaque envelope inside `signature` (rejected after
implementation):** leave the struct untouched and pack the whole
assertion into the existing `signature` field as a flat-tuple encoding
(`abi.encode(r, s, challengeIndex, typeIndex, authenticatorData,
clientDataJSON)`, the layout OZ `WebAuthn.tryDecodeAuth` lifts out of
opaque bytes). Zero ABI change, and it matches how ERC-4337 wallets
smuggle assertions through fixed `bytes signature` interfaces. Two
reasons it lost to D: those wallets pack because their interfaces are
frozen — ours is not, and nothing is in production; and the hand-rolled
inner encoding is a papercut for every future encoder (the first
implementation was bitten by exactly this: `abi.encode(struct)`
prepends an offset word `tryDecodeAuth` does not accept, an error the
ABI itself can never catch). It also overloads `signature` to mean
"sometimes a signature, sometimes a container".

**Option D — generic `algData` array (chosen):** one one-time ABI
change that never needs another:

```solidity
struct DelegationProof {
    bytes protectedHeader;
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    bytes signature;  // always the signature itself; r ‖ s for P-256 algs
    bytes[] algData;  // alg-specific; count and meaning fixed per alg
}
```

Element count and meaning are fixed per algorithm and interpreted in
exactly one place per algorithm. For `ALG_ES256_WEBAUTHN`
(`decodeWebAuthnDelegationAlgData` is normative): `[0]`
authenticatorData (≥ 37 bytes), `[1]` clientDataJSON, `[2]` 16 bytes of
packed big-endian `uint64 challengeIndex ‖ uint64 typeIndex`. For
ES256/KS256 the array must be empty — a non-empty array under an
algorithm that defines no elements reverts
`UnexpectedDelegationAlgData` rather than being ignored (see §4's
fail-closed rule). Future algorithms with special data requirements add
an interpretation, not a field, so there is no never-ending series of
explicitly named struct members. Compared with C, the framing (count,
boundaries) is ABI-native — standard tooling encodes it from the outer
ABI and the only per-alg documentation is what each index means — and
`signature` keeps a single uniform meaning, so the plain-ES256 length
check applies to WebAuthn unchanged.

The elements stay opaque `bytes` interpreted by one verifier, which is
the industry-standard shape for passkey signatures on-chain:

- [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) — `bytes
  signature` fully opaque to the caller, interpreted by the verifying
  contract.
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) —
  `UserOperation.signature` is opaque bytes; passkey wallets pack the
  WebAuthn assertion inside it.
- [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol)
  — `SignatureWrapper.signatureData` carries
  `abi.encode(WebAuthnAuth)` for passkey owners, via
  [base/webauthn-sol](https://github.com/base/webauthn-sol).
- [Safe passkey module](https://github.com/safe-global/safe-modules/tree/main/modules/passkey)
  — signer verifies `abi.encode(authenticatorData, clientDataFields,
  r, s)` passed as opaque signature bytes through ERC-1271.
- [daimo-eth/p256-verifier](https://github.com/daimo-eth/p256-verifier)
  — the `WebAuthn.sol` both OZ and Base credit as prior art.
- [OpenZeppelin `WebAuthn.sol`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/WebAuthn.sol)
  — the audited reference whose verification steps and flag constants
  the univocity verifier mirrors (with distinct reverts instead of a
  boolean).

### 4. A native alg-policy flag band, mask-tested fail-closed (R1)

The verifier takes `bool requireUserVerification` and `bytes32
requiredRpIdHash` as parameters — policy is injected, never a constant.
User presence (UP) is always required; UV only when policy says so;
rpIdHash pinning only when nonzero.

UV policy is natively enforced protocol, so it cannot live in the
canopy-assignable derived band (ADR-0062 owns bits 35–39, wire byte 3,
and univocity has promised never to read those). Instead
`constants.sol` reserves a **native algorithm-policy band**:
`GF_ALG_MASK` = bits 40–47 (canopy wire byte 2), with
`GF_REQUIRES_USER_VERIFICATION = 1 << 40` as its first assignment. No
`GF_DERIVED` gating applies — these are native bits.

Each delegation algorithm declares which band bits it consumes
(`ALG_ES256_WEBAUTHN`: the UV bit; ES256/KS256: none), and
`_Univocity._checkDelegationAlgConstraints` rejects, before dispatch,
any set band bit the supplied algorithm does not consume — including
the case of no delegation proof at all
(`UnsupportedDelegationPolicyFlags`). The same rule covers `algData`
(`UnexpectedDelegationAlgData`). This is the load-bearing property of
the band: the publisher chooses which delegation algorithm to present,
so a stated policy that the presented algorithm cannot honour must
revert rather than be silently dropped — a UV-required grant can never
be satisfied by a plain ES256 proof.

`requiredRpIdHash` is passed as zero (pinning disabled) until a policy
channel is agreed — a 32-byte hash does not fit a grant flag;
candidates are `grantData` or a registry lookup.

## Consequences

- `_Univocity` bytecode changes (free functions inline), so this lands
  in new instances only; existing immutable deployments are unaffected
  and keep rejecting the alg fail-closed. Nothing is in production.
- Adding `algData` changes the ABI of `DelegationProof` and therefore
  of `ConsistencyReceipt`/`publishCheckpoint`: every off-chain encoder
  (go-univocity, canopy, thinker) appends the field — empty for
  ES256/KS256 — as a one-time migration. Acceptable now precisely
  because nothing is in production; the array absorbs all future
  alg-specific data without further ABI changes.
- Canopy and thinker are separate work: an unknown alg is rejected by
  everything not yet taught about it, so contracts can land first.
- Canopy's grant-wire layer must treat wire byte 2 as univocity-native
  (the `GF_ALG_MASK` band): the devdocs ADR-0062 registry needs a note
  that derived assignments stay in byte 3, and grant builders need a
  constructor for the UV bit (byte 2, mask 0x01). The derived band
  itself is untouched — a cleaner separation than promoting a derived
  bit would have been.
- Grants already issued with any byte-2 bit set would start reverting
  at checkpoint under this contract; none exist (the band was
  unassigned and nothing is in production).
- Measured gas for `verifyDelegationProofES256WebAuthn` (see
  `test_gas_webauthnDelegationVerify`): ~15.8k verifier overhead on the
  RIP-7212 path (≈19k total with the precompile's ~3.45k — Base
  Sepolia, Arbitrum Sepolia, Monad), ~378k with OZ's Solidity fallback
  (Filecoin FEVM). Degradation is cost, not capability.
- The committed test vectors are synthetic (forge `signP256` over
  exactly what an authenticator signs). A golden assertion captured
  from a real authenticator should be added as a fixture once the
  thinker-side ceremony exists.
