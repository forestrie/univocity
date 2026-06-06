# Plan 0030: Safe ImutableUnivocity deploy batch

**Status:** DRAFT  
**Date:** 2026-05-21  
**Related:** [ARC-0017 auth overview](../arc/arc-0017-auth-overview.md),
[Plan 0029](plan-0029-eip-compatible-ks256-signers.md)

## 1. Goal

Generate a Safe Transaction Builder batch that deploys
`ImutableUnivocity` with a Safe account as the KS256 bootstrap signer.
The default Safe is `0x1528b86ff561f617602356efdbD05908a07AA788`.

The batch deploys the immutable contract with:

- `bootstrapAlg = ALG_KS256`;
- `bootstrapKey = abi.encodePacked(safeAddress)`.

No contract logic or Foundry compiler configuration changes are required.

## 2. Deployment Shape

Use Safe's `CreateCall` helper so the Safe can deploy a contract from a
Transaction Builder batch:

1. Call `CreateCall.performCreate2(0, deploymentData, salt)`.
2. Build `deploymentData` from `type(ImutableUnivocity).creationCode` plus
   `abi.encode(ALG_KS256, abi.encodePacked(safeAddress))`.
3. Compute the CREATE2 address from the CreateCall address, salt, and
   deployment data.
4. Optionally append a second transaction that calls `publishCheckpoint(...)`
   on the predicted Univocity address.

## 3. Bootstrap Support

`ImutableUnivocity` has no initializer. The initial root authority log is
bootstrapped by the first successful `publishCheckpoint(...)` call.

The generator accepts either:

- `ROOT_BOOTSTRAP_CALLDATA`, raw `publishCheckpoint(...)` calldata; or
- `ROOT_BOOTSTRAP_JSON`, a JSON file with a `.data` or `.calldata` bytes field.

When supplied, the generator validates that the calldata selector is
`publishCheckpoint(...)` and appends it as the second Safe transaction.

## 4. Verification

Verification should include:

- `forge build`;
- a deploy-only generator run with a sample `CHAIN_ID`;
- JSON parsing of the generated Safe batch;
- selector checks for `performCreate2(...)` and optional
  `publishCheckpoint(...)` calldata.
