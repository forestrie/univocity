---
name: arc-univocity
description: Univocity domain glossary (on-chain). Use when a task touches Solidity, checkpoints, grants, or on-chain Univocity.
when_to_use: "Checkpoints, grants, authority logs, ImutableUnivocity, CREATE3 deploy, Foundry tests, Slither."
user-invocable: false
---

# arc-context: univocity (on-chain)

Minimal glossary for **univocity** — Solidity contracts for on-chain split-view
protection of Forestrie transparency logs.

**Load when:** checkpoints, grants, authority logs, ImutableUnivocity, CREATE3
deploy, Foundry tests, Slither.

**Do not bulk-read** — use [univocity/AGENTS.md](https://github.com/forestrie/univocity/blob/main/AGENTS.md).

---

## Core terms

| Term | Meaning |
|------|---------|
| **Univocity** | On-chain contract verifying checkpoint consistency with prior state |
| **checkpoint** | Signed consistency receipt + grant inclusion proof bundle |
| **grant** | Authority to act on a log; inclusion proof in owner log |
| **authority log** | Hierarchical log tree rooted at bootstrap `R` |
| **ImutableUnivocity** | User-facing contract (distinct from Safe multisig) |
| **CREATE3** | Deterministic deploy address via shared factory |
| **LibCose / LibCbor** | COSE/CBOR crypto modules under `src/cose/` |

## Authorization model

Every checkpoint requires:

1. A **grant** (inclusion proof in the target log's owner)
2. A **consistency receipt** signed by the target log's signer

Caller identity is not part of the model. See
[ARC-0017 auth overview](https://github.com/forestrie/univocity/blob/main/docs/arc/arc-0017-auth-overview.md).

## Authoritative docs

| Topic | Path |
|-------|------|
| Agent router | [AGENTS.md](https://github.com/forestrie/univocity/blob/main/AGENTS.md) |
| Auth / grants | [docs/arc/arc-0017-auth-overview.md](https://github.com/forestrie/univocity/blob/main/docs/arc/arc-0017-auth-overview.md) |
| Log hierarchy | [docs/arc/arc-0017-log-hierarchy-and-authority.md](https://github.com/forestrie/univocity/blob/main/docs/arc/arc-0017-log-hierarchy-and-authority.md) |
| Grant verification (platform) | [devdocs ARC-0019](https://github.com/forestrie/devdocs/blob/main/archive/2603/arc/arc-0019-grant-verification-model.md) |
| Contract release | [ADR-0007](https://github.com/forestrie/univocity/blob/main/docs/adr/adr-0007-contract-release-build-archives.md) |

## MMR / COSE receipts

Checkpoint and receipt wire formats align with the
[COSE Receipts for MMRs](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile)
Internet-Draft. Local sibling checkout:
`~/Dev/personal/forestrie/draft-bryce-cose-receipts-mmr-profile/`.

Go implementations of MMR primitives live in
[go-merklelog](https://github.com/forestrie/go-merklelog).

## Deploy / secrets

- Deploy tasks: `doppler run -- task …` (project **univocity**)
- Foundry v1.5.1 pinned; `forge fmt` is authoritative after edits

## Sibling repos

| Repo | Role |
|------|------|
| univocity-tools | Cart CLI, contract-artefacts release |
| arbor/services/univocity | Off-chain grant store HTTP |
| canopy | SCRAPI register + grant verification at edge |
