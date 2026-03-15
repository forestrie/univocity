# Agents

## Cursor Cloud specific instructions

This is a Foundry-based Solidity smart contract project. There is no
web server or backend service to run — all development tasks are
`forge` commands.

### Key commands

| Task | Command |
|------|---------|
| Build | `forge build` |
| Test | `forge test -vvv` |
| Invariant tests only | `forge test --match-contract UnivocityInvariantTest` |
| Format check | `forge fmt --check` |
| Auto-format | `forge fmt` |
| Build with sizes | `forge build --sizes` |

See `README.md` and `AGENT_CONTEXT.md` for full project context,
source layout, and conventions.

### Environment notes

- **Foundry v1.5.1** is pinned (must match CI). Install via
  `foundryup --install v1.5.1`. The binaries live in
  `~/.foundry/bin`; ensure this is on `PATH`.
- **Git submodules** supply all Solidity library dependencies
  (`lib/forge-std`, `lib/openzeppelin-contracts`, `lib/solmate`,
  `lib/witnet-solidity-bridge`). Run
  `git submodule update --init --recursive` if `lib/` dirs are empty.
- The build uses `via_ir = true` and optimizer (200 runs), so initial
  compilation takes ~40 s. Incremental builds are fast.
- `forge fmt` is authoritative — never re-wrap output after running it.
- No database, Docker, or external service is needed for build/test.
  Deployment-only tooling (Doppler, Anvil, go-task) is optional.
