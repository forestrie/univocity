# Safe ImutableUnivocity batches (Base Sepolia)

Safe: `0x1528b86ff561f617602356efdbD05908a07AA788`

## Current deployment (KS256 delegation bytecode)

| Field | Value |
|-------|-------|
| **ImutableUnivocity** | `0x7A4E8ad88D6Df29FEBEc0d546d148Ed4bea8Cb94` |
| **CREATE2 salt** | `0x6aefb883198035ed3c88018a2c2d368a1f9ce214275897147f40b6eadd4e65b3` |
| **Bootstrap** | `ALG_KS256` + Safe address |
| **Authority logId** | `0x6d6c21779ef147a886fbd629b0fa9fe6bf4de826e8cdc2bfe67c134ddfc725c1` |

## Safe execution order

1. **Deploy** — propose with `scripts/propose_safe_imutable_batch.py`, then sign/execute:
   - **Safe UI** (if queue loads): [open Safe](https://app.safe.global/home?safe=basesep:0x1528b86ff561f617602356efdbD05908a07AA788)
   - **CLI** (owner key in `PRIVATE_KEY`, RPC from Doppler):

     ```bash
     cd univocity
     source .venv/bin/activate
     export PRIVATE_KEY=0x…   # must be a Safe owner key
     doppler run --project univocity --config dev -- python3 scripts/execute_safe_tx.py
     ```

     **New flows:** use `univocity-tools` `deployer deploy approve` (see
     `task imutable-deploy:default` and `.github/workflows/deploy-imutable.yml`).
     The Python script remains for legacy batches only.

     Optional env: `SAFE_TX_HASH` (defaults to deploy tx), `SAFE_TX_SOURCE=batch`
     (rebuild from batch instead of TX service), `DRY_RUN=1` (simulate only),
     `CONFIRM_ONLY=1` (post signature to TX service without executing).
2. **Bootstrap** — after deploy confirms on-chain, propose with `scripts/propose_safe_batch.py`, then execute **SignMessageLib** (delegatecall) then **publishCheckpoint** in nonce order.

Do not propose bootstrap until `cast code 0x7A4E8ad88D6Df29FEBEc0d546d148Ed4bea8Cb94` is non-empty.

## Artifacts

- `imutable-univocity-84532-safe-0x1528….json` — CREATE2 deploy batch
- `imutable-univocity-bootstrap-84532-safe-0x1528….json` — root auth bootstrap (2 txs)
- `root-bootstrap-payload-84532.json` — calldata / receipt hash reference

## Superseded

Legacy ImutableUnivocity (no KS256 delegation): `0x611dd70B2D36c87B29878089eD8a7aDc68E4441B`
