**Status:** DRAFT  
**Date:** 2026-06-06  
**Related:** [plan-0030](plan-0030-safe-imutable-univocity-deploy.md), [plan-0031](plan-0031-ks256-delegation.md), [canopy plan-0031](../../canopy/docs/plans/plan-0031-ks256-forest-roots.md), [canopy plan-0028](../../canopy/docs/plans/plan-0028-forest-genesis-chain-binding.md)

# Plan 0032: ES256 ImutableUnivocity + dual-contract e2e

## Deployments

| Deployment | Bootstrap | Address env | Static log UUID env |
|------------|-----------|-------------|---------------------|
| **KS256 Safe** | Safe `0x1528…` | `E2E_UNIVOCITY_ADDRESS_KS256_BOOTSTRAP` | `E2E_UNIVOCITY_GENESIS_LOG_ID_KS256` |
| **ES256** | PEM `BOOTSTRAP_PEM_ES256` | `E2E_UNIVOCITY_ADDRESS_ES256_BOOTSTRAP` | `E2E_UNIVOCITY_GENESIS_LOG_ID_ES256` |

## ES256 deploy (non-interactive)

```bash
cd univocity
doppler run --project univocity --config dev -- task deploy:imutable:es256
```

Scripts: `scripts/deploy_imutable_es256.py`, `scripts/bootstrap_es256_root.py`,
`script/BootstrapEs256Root.s.sol`. Runbook: [deployments/es256/README.md](../../deployments/es256/README.md).

**Live Base Sepolia (dev):**

- Contract: `0xb5906A91eF30dA435Ff13d27619Bc6F76282d19D`
- E2E genesis log UUID: `b5906a91-ef30-da43-5ff1-3d27619bc6f7`

## Genesis POST

Canopy API and arbor univocity **reject genesis v1 POST**; writes are v2-only
(`genesisAlg` + `bootstrapKey`). v0/v1 **read** retained for legacy R2 objects.

## Verification

```bash
cast code 0xb5906A91eF30dA435Ff13d27619Bc6F76282d19D --rpc-url $RPC_URL
pnpm --filter @canopy/api test
cd arbor/services/univocity && go test ./...
doppler run --project canopy --config dev -- pnpm --filter @canopy/api-e2e exec playwright test \
  tests/system/univocity-genesis-chain-binding.spec.ts
doppler run --project canopy --config dev -- pnpm --filter @canopy/api-e2e exec playwright test \
  tests/system/univocity-genesis-ks256-chain-binding.spec.ts
```
