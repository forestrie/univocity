# Project purpose

univocity provides split view protection for the transparency logs maintained by
the [forestrie](https://github.com/forestrie/) transparency ledger.

Based on the consistency proof format described in
[draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html#name-cose-receipt-of-consistency),
univocity guarantees that log checkpoints can only be published on chain if
they are consistent with previously published checkpoints.

Agents working in this repository should prioritize:
- preserving the security properties of checkpoint verification
- keeping cryptographic code small, well-commented, and easy to audit
- favouring clarity and testability over micro-optimisation

# General conventions

General rules and guidance for agents updating code in this repository.

## Source layout

Under `src/` each logical module lives under a directory named `<name>`:

- `src/<name>/lib/` — libraries implementing core logic
- `src/<name>/interfaces/` — interfaces, events, and external-facing types

`<name>` is a module or strongly correlated set of functionality and is
lowercase (for example: `checkpoints`, `cose`).

`src/contracts/` — deployable contracts which compose elements from one or
more `<name>` modules.

Conventions for modules and libraries:
- types used in more than one file must be in a single file named after the
  type and live directly in `src/<name>/`
- events must be defined in `src/<name>/interfaces/IE.sol`
- strongly prefer implementations to be in libraries
- strongly prefer one library per file
- strongly prefer a library to be strongly associated with one particular
  type, and that type should typically be the first parameter, as a storage
  reference to functions on the library
- library files live in `src/<name>/lib/` and are named after the dominant
  type with a `Lib` prefix, e.g. `LibFoo` is the library that implements
  functions for the type `Foo`

Tests:
- `test/<name>/` — tests associated with `<name>`
- `test/shared/` — shared test infrastructure
- `test/deploy/` — tests and infrastructure relating to deployment scripts in
  `script/deploy/`, and shared support for integration-style tests which may
  need to deploy contracts

## Commits

- never include "Co-Authored-By" lines in commit messages
- commit titles must be no more than 79 characters
- commit body lines must be no more than 72 characters

## Formatting and Comments

- always run `forge fmt` to format sources after changes are applied
- all public functions and events must have clear and comprehensive NatSpec
comments
- All non trivial functionality should have clear comments. The should convey
contextual information that is not obvious from the local code: why it is
written the way it is, any non-obvious dependencies on other invariants or
state, the kind of context that conveys what the code is meant to achieve
rather than simply repeating a description of what the local code does
mechanically.
- Repetition between comment blocks is strongly discouraged, rather have a
terse logical reference like (see function xxx, or see function comment)


# univocity specific

- `src/checkpoints/` — cryptographically sensitive code for verifying
  checkpoints
- `src/cose/` — CBOR and COSE decoding and validation

Note: `checkpoints` and `cose` are `<name>` modules and follow the source
layout rules above.

### Agent guidance for checkpoints

- keep the on-chain checkpoint representation minimal and well-documented
- isolate cryptographic operations in dedicated libraries under
  `src/checkpoints/lib/`
- prefer pure/view functions where possible to make reasoning and testing
  easier

### Agent guidance for COSE

- decoding and validation logic belongs under `src/cose/lib/`
- keep COSE and CBOR parsing small and composable; avoid "god" libraries
- make all encoding/decoding assumptions explicit in comments and tests


# Deployment

scripts/deploy/ - will contain forge solidity scripts for deploying the
contracts. they will be re-usable by integration tests 


# Tooling

## Build

```shell
$ forge build
```

## Test

```shell
$ forge test
```

## Format

```shell
$ forge fmt
```

