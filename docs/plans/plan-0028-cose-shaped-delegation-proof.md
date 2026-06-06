# Plan 0028: COSE-shaped delegation proof for Univocity contracts

**Status:** DRAFT  
**Date:** 2026-05-20  
**Related:** [ADR-0006](../adr/adr-0006-cose-shaped-delegation-proof.md),
[ADR-0002](../adr/adr-0002-cose-verifier-keys-caller-dispatch.md),
[ADR-0005](../adr/adr-0005-grant-constrains-checkpoint-signer.md),
[plan-0016](plan-0016-minimal-cose-cbor-api-predecode.md),
[plan-0023](plan-0023-consistency-receipt-abi-and-signature-payload.md)

## 1. Goal

Implement ADR-0006 in the Univocity smart contracts by replacing the raw
delegation hash with COSE Sign1 `Sig_structure` semantics while keeping the
pre-decoded calldata model.

The contract should receive typed delegation fields, derive the canonical
delegation payload itself, and verify the root signature over:

```text
["Signature1", protectedHeader, h'', payload]
```

where:

```text
payload =
  "forestrie.univocity.delegation.v1" ||
  logId ||
  mmrStart ||
  mmrEnd ||
  delegatedKeyX ||
  delegatedKeyY
```

## 2. Scope and non-goals

- **In scope:** Update `DelegationProof`, thread `protectedHeader` through the
  ES256 delegation verifier, build the ADR-0006 payload on-chain, and add
  Foundry coverage for delegated ES256 checkpoint publication.
- **In scope:** Keep old raw-hash delegation proofs invalid; no compatibility
  shim is required.
- **Out of scope:** Arbor proof generation, Canopy issuer alignment, publisher
  submission wiring, and any issuer API changes.
- **Out of scope:** KS256 delegation support. KS256 receipts remain supported,
  but KS256 with delegation continues to revert.
- **Out of scope:** Full COSE_Sign1 certificate parsing, CBOR payload map
  parsing, and COSE_Key parsing on-chain.

## 3. Design choices

### 3.1 ABI shape

Change `DelegationProof` from the plan-0016 minimal shape:

```solidity
struct DelegationProof {
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    uint64 alg;
    bytes signature;
}
```

to the ADR-0006 shape:

```solidity
struct DelegationProof {
    bytes protectedHeader;
    bytes delegationKey;
    uint64 mmrStart;
    uint64 mmrEnd;
    bytes signature;
}
```

Remove `alg` rather than keeping a temporary ignored field. The algorithm is
now carried in the COSE protected header, matching the receipt verification
model from ADR-0002.

### 3.2 Domain bytes

Use the raw ASCII bytes for `forestrie.univocity.delegation.v1`. Do not cast the
domain to `bytes32`; the literal is 33 bytes.

### 3.3 Protected header policy

Require `extractAlgorithm(protectedHeader) == ALG_ES256`, but do not require the
exact protected-header bytes to be `h'a10126'`. Additional protected fields are
allowed because the complete `protectedHeader` is included in the signed
Sig_structure.

### 3.4 Verification flow

For ES256 checkpoints with delegation:

1. Decode `delegationKey` as P-256 `x || y`.
2. Verify the delegation range contains `claimedSize - 1`.
3. Build the domain-tagged payload from contract inputs.
4. Build the COSE Sign1 Sig_structure using the supplied `protectedHeader`.
5. Verify `sha256(sigStructure)` with the stored root key or first-checkpoint
   `grantData` root key.
6. Verify the consistency receipt with the delegated key.

For ES256 checkpoints without delegation, keep the existing direct root-signed
receipt path. For KS256 checkpoints, keep the existing no-delegation rule.

## 4. Test plan

- Add a helper that signs ADR-0006 delegation Sig_structures using
  `vm.signP256`.
- Add positive tests for first-checkpoint and existing-checkpoint ES256
  delegation.
- Add negative tests for old raw-hash signatures, wrong protected-header
  algorithm, wrong log id, wrong delegated key, out-of-range MMR index, invalid
  delegation key length, and invalid delegation signature length.
- Preserve the existing KS256-with-delegation rejection test.
- Add a contract-side golden vector for payload bytes and Sig_structure hash so
  later Arbor and Canopy plans can align off-chain proof generation.

## 5. Verification commands

Run the focused delegation suite first:

```sh
forge test --match-path test/checkpoints/UnivocityDelegation.t.sol
```

Then run the broader checkpoint suite:

```sh
forge test --match-path 'test/checkpoints/*.t.sol'
```

Finally run the project build or full test suite if the surrounding branch risk
requires it.
