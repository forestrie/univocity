---
name: solidity-comments
description: "Solidity comment conventions for univocity: NatSpec on exported functions, signposting crypto libraries, and linking the platform auth model and MMR wire format."
when_to_use: Writing or reviewing Solidity in univocity src/, script/, or test/.
paths: ["**/*.sol"]
user-invocable: false
---

# Solidity comments

**Scope:** Solidity in **univocity** (`src/`, `script/`, `test/`).

## Principles

1. **NatSpec on exported functions** — `@notice`, `@dev`, `@param`, `@return` as
   appropriate for checkpoint verification and grant checks.
2. **Signpost crypto modules** — link `LibCose`, `LibCbor`, checkpoint libraries
   rather than duplicating COSE structure in every contract.
3. **Link platform auth model** — [ARC-0017 auth overview](https://github.com/forestrie/univocity/blob/main/docs/arc/arc-0017-auth-overview.md),
   [devdocs ARC-0019](https://github.com/forestrie/devdocs/blob/main/archive/2603/arc/arc-0019-grant-verification-model.md).
4. **MMR wire format** — point to
   [draft-bryce-cose-receipts-mmr-profile](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile)
   when discussing receipt shapes.

## Formatting

Follow univocity `.cursorrules`: soft wrap at 79 chars, hard wrap at 100,
`forge fmt` is authoritative. Use **explicit named imports** only.

Full rules: [univocity/docs/agents/solidity.md](https://github.com/forestrie/univocity/blob/main/docs/agents/solidity.md).
