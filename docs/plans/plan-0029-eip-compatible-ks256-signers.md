# Plan 0029: EIP-compatible KS256 signers

**Status:** DRAFT  
**Date:** 2026-05-21  
**Related:** [ARC-0017 auth overview](../arc/arc-0017-auth-overview.md),
[ADR-0002](../adr/adr-0002-cose-verifier-keys-caller-dispatch.md),
[plan-0026](plan-0026-verify-only-no-recovery.md),
[plan-0028](plan-0028-cose-shaped-delegation-proof.md)

## 1. Goal

Allow KS256 logs to use Ethereum-compatible contract accounts, such as Safe
multisigs, as bootstrap and root signers without changing grant encoding,
root-key storage, or the KS256 COSE signature payload.

## 2. Decision

Keep `ALG_KS256` as the algorithm for Ethereum-address signers over
`keccak256(COSE_Sign1 Sig_structure)`. Extend the verifier so the expected
20-byte address may be:

- an EOA, verified with the existing `ecrecover` path; or
- an ERC-1271 contract account, verified with
  `isValidSignature(bytes32,bytes)`.

Do not introduce a new algorithm for Safe-style signers. A new algorithm is
reserved for signer identities that are not plain Ethereum addresses, such as
ERC-7913 verifier/key bytes or counterfactual ERC-6492 signatures.

## 3. Bootstrap flow

To bootstrap with a Safe:

1. Deploy Univocity with `ALG_KS256` and
   `bootstrapKey = abi.encodePacked(safeAddress)`.
2. Build the root auth log's first `PublishGrant` with
   `grantData = abi.encodePacked(safeAddress)`.
3. Build the consistency receipt for the new root auth log.
4. Have the Safe approve the KS256 hash:
   `keccak256(buildSigStructure(protectedHeader, detachedPayload))`.
5. Submit `publishCheckpoint` with the Safe signature bytes.

The submitter remains irrelevant to authorization; any account may pay gas if
the grant and receipt signature are valid.

## 4. Implementation summary

- Change `verifyKS256`, `verifyKS256DetachedPayload`, and `verifyKS256Raw` to
  `view` functions because ERC-1271 requires an external `staticcall`.
- Preserve the existing EOA `ecrecover` branch for addresses with no code.
- For contract addresses, call OpenZeppelin `SignatureChecker`'s ERC-1271
  helper with the same KS256 hash the EOA branch uses.
- Do not apply the 65-byte EOA signature-length requirement to contract
  signatures. ERC-1271 signatures are wallet-specific byte strings.
- Leave `_Univocity` root-key resolution unchanged: KS256 roots are still
  20-byte addresses in bootstrap config, `grantData`, and `LogConfig.rootKey`.

## 5. Test plan

- Add a focused ERC-1271 signer mock.
- Test root auth log bootstrap with an ERC-1271 bootstrap address.
- Test wrong ERC-1271 signatures revert with
  `ConsistencyReceiptSignatureInvalid`.
- Test a non-65-byte ERC-1271 signature succeeds when the contract account
  validates it.
- Test a later root auth log checkpoint signed by the ERC-1271 root.
- Test a child log first checkpoint whose `grantData` root is an ERC-1271
  contract account.
- Keep existing EOA KS256 tests passing unchanged.

## 6. Verification

Run:

```sh
forge test --match-path test/checkpoints/UnivocityEIP1271.t.sol
forge test --match-path test/cosecbor/cosecbor.t.sol
forge test --match-path 'test/checkpoints/*.t.sol'
forge build
forge test
```
