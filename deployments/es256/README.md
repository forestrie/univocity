# ES256 ImutableUnivocity (Base Sepolia)

Direct EOA deploy + P-256 root bootstrap (no Safe).

## Current deployment

| Field | Value |
|-------|-------|
| **ImutableUnivocity** | `0xb5906A91eF30dA435Ff13d27619Bc6F76282d19D` |
| **Bootstrap** | `ALG_ES256` + 64-byte x‖y from `BOOTSTRAP_PEM_ES256` |
| **Authority logId** | `0x6d6c21779ef147a886fbd629b0fa9fe6bf4de826e8cdc2bfe67c134ddfc725c1` |
| **E2E genesis log UUID** | `b5906a91-ef30-da43-5ff1-3d27619bc6f7` |

## One-shot deploy + bootstrap

```bash
cd univocity
doppler run --project univocity --config dev -- task deploy:imutable:es256
```

Or step-by-step:

```bash
doppler run --project univocity --config dev -- python3 scripts/deploy_imutable_es256.py
export IMUTABLE_UNIVOCITY_ADDRESS=0x…   # from deploy output
doppler run --project univocity --config dev -- python3 scripts/bootstrap_es256_root.py
```

Gas payer: `DEPLOY_KEY` when balance ≥ 0.0008 ETH, else `BOOTSTRAP_MULTISIG_SIGNER`.

## Doppler secrets (canopy + univocity dev)

| Secret | Value |
|--------|-------|
| `E2E_UNIVOCITY_ADDRESS_ES256_BOOTSTRAP` | `0xb5906A91eF30dA435Ff13d27619Bc6F76282d19D` |
| `E2E_UNIVOCITY_GENESIS_LOG_ID_ES256` | `b5906a91-ef30-da43-5ff1-3d27619bc6f7` |

## Artifacts

- `root-bootstrap-payload-84532.json` — reference calldata (optional `WRITE_ES256_BOOTSTRAP=1`)

## Related

KS256 Safe deployment: [../safe/README.md](../safe/README.md)
