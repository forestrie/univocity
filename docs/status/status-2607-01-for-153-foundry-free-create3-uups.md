---
id: 2607-01
status: active
created: 2026-07-05
refs: [FOR-153, FOR-148]
---

# Status 2607-01 — FOR-153 foundry-free CREATE3 + UUPS deploy manifest

Workstream: [FOR-153](https://linear.app/forestrie/issue/FOR-153) (T1.4
foundry-free CREATE3 factory deploy), the final slice of the
[FOR-148](https://linear.app/forestrie/issue/FOR-148) Tier-1 foundry-free,
archive-based Univocity deploy effort. Related plans:
[plan-0030-safe-imutable-univocity-deploy](../plans/plan-0030-safe-imutable-univocity-deploy.md),
[plan-0032-es256-immutable-deploy](../plans/plan-0032-es256-immutable-deploy.md).

Delivered on branch `robin/for-153-foundry-free-create3-uups` via
[PR #25](https://github.com/forestrie/univocity/pull/25), merged to main
2026-06-28 (`5128638`). FOR-153 and parent FOR-148 (all children) are **Done**
in Linear.

## Status

- `scripts/generate_deploy_manifest.py` emits `UUPSUnivocity` and
  `ERC1967Proxy` entries (including the initialize ABI) in the
  deploy-manifest release asset.
- `scripts/verify_deploy_manifest_artifact.py` hardened with a `--contract`
  selector.
- Python tests added: `scripts/test_generate_deploy_manifest.py`,
  `scripts/test_verify_deploy_manifest_artifact.py` (both passing at merge).
- README documents the foundry-free CREATE3 + UUPS operator path.
- Merged; no uncommitted or unpushed work remains on the branch.

## Notables

- The manifest/verify work landed as Python release-tooling scripts in this
  repo; the viem port of `deploy create3` described in the FOR-153 issue body
  (`--release-root`, replacing `cast` calls) was tracked under the same
  Tier-1 umbrella — see FOR-148's children, all Done.
- Since the merge, main has moved onto the same release tooling:
  contract release channel metadata (#26) and a fix accepting orchestrator
  dispatch inputs on the release workflow (#27). Anything resuming here
  should build on current main, not the merged branch.
- Local checkout is stale: it sits on the merged FOR-153 branch and
  `origin/main` hasn't been fetched past the merge.

## Next steps

- Verify the CI release workflow on the next tag — the one unchecked item in
  PR #25's test plan ("CI release workflow on tag after merge").
- Sync the local checkout (`git fetch`, checkout `main`) and delete the
  merged `robin/for-153-foundry-free-create3-uups` branch.
- Flip this doc to `status: complete` once the tag run is confirmed green.

## Blockers

- None. The remaining verification only awaits the next release tag.
