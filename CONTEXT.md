# Univocity contracts

Foundry sources, deployment scripts, and on-chain Univocity smart contracts.
Platform domain terms live in [devdocs/glossary.md](../devdocs/glossary.md).
Cart and deployer tooling terms live in
[univocity-tools CONTEXT.md](../univocity-tools/CONTEXT.md).

## Language

**Contracts repo**:
This repository (`forestrie/univocity`) — Solidity sources, `forge script`,
Python Safe proposers.
_Avoid_: on-chain repo, univocity-tools repo.

**Contracts release**:
A GitHub Release on this repo triggered by a `v*` tag; ships **build
archives** for downstream deploy and verify without foundry.
_Avoid_: tools release (that is `forestrie/univocity-tools` CLI binaries).

**Protocol build**:
The main Foundry project at the repo root (`foundry.toml`, `src/`, `out/`).
_Avoid_: univocity contracts (ambiguous with the whole repo).

**CREATE3 factory build**:
The isolated, stability-locked Foundry project under `script/create3-factory/`
(`CREATE3Factory.sol`, dedicated `foundry.toml`).
_Avoid_: create3 alone (conflicts with Arachnid proxy, CREATE3 deploy step,
or factory address).

**Build archive**:
A portable `tar.gz` of forge `out/` (including `out/build-info`) plus
`cache/solidity-files-cache.json`, produced by Cart `contract-artefacts
archive`. See univocity-tools CONTEXT for full definition.
_Avoid_: artifact tarball, release bundle.

**Release root**:
Directory where **archive extract** places `out/`, `cache/`, and hydrated
Solidity sources — the layout downstream deploy tooling consumes.
_Avoid_: work dir (`.work` under the contracts checkout root).

## Example dialogue

**Dev:** We need the protocol build archive from the latest contracts release
for verify-only on staging.

**Ops:** Pull `univocity-<tag>.tar.gz` from the latest `v*` GitHub Release on
`forestrie/univocity`, run `contract-artefacts archive-extract` into your
**release root**, then point verify at `RELEASE_ROOT/out/`. For CREATE3
factory bytecode use `create3-factory-<tag>.tar.gz` from the same release —
that is the **CREATE3 factory build**, not the protocol build.
