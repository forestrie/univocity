# Contract release ships two validated build archives

Downstream deploy and verify should run without foundry at the consumer.
[univocity-tools ADR-0006](https://github.com/forestrie/univocity-tools/blob/main/docs/adr/adr-0006-build-archive-decouples-deploy.md)
defines the **build archive** format; this repo owns producing and publishing
those archives on **contracts release** (`v*` tags).

We publish two separate archives — **protocol build** (`univocity.tar.gz`)
and **CREATE3 factory build** (`create3-factory.tar.gz`) — because the
projects use different `foundry.toml` configs and stability profiles. A
single monolithic tarball would mix unrelated forge roots. On GitHub Release, assets are named `<name>-<tag>.tar.gz` (e.g.
`univocity-v0.1.1.tar.gz`); archive base names (`univocity`,
`create3-factory`) are unchanged. `release.yml` also uploads one workflow
artefact per base on every run (branch builds use `release-id` in the file
name) so `contract-artefacts fetch-run` can retrieve pre-tag builds.

Release is gated on the reusable `ci.yml` `check` job (`needs: ci` in
`release.yml`) so tags cannot ship when PR CI would fail. Packaging uses
`contract-artefacts` from a pinned univocity-tools release (v0.3.0+), not
in-repo Cart source.

Before publish, each archive is round-trip validated: `archive-extract` into
a temp **release root**, then `out/`, `cache/solidity-files-cache.json`,
and hydrated sources are diffed against the forge build tree that produced
the archive. Considered skipping validation (rejected: archives are the
stable interface to consumers). Considered one combined archive (rejected:
independent forge projects and ADR-0006 per-project `--archive-name`).
