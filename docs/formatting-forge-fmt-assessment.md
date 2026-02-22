# Forge fmt vs standing formatting rules — assessment

**Date:** 2026-02-21  
**Standing rules:** `.cursorrules` (Comment wrapping, 79 soft / 100 hard; tag continuation indent; second pass re-join).

## Summary

**`forge fmt` (Foundry default, line_length = 120) is not fully compatible with the standing formatting rules.** Use `line_length = 79` in `foundry.toml` so that `forge fmt` output stays within the comment hard limit (100) and aligns with the 79-character soft target. A manual second pass (re-join short lines) remains recommended after fmt.

## Compatibility

| Rule | Forge fmt (default 120) | Compatible? |
|------|--------------------------|-------------|
| **Comment soft wrap 79** | Fmt wraps at 120; many comment lines end up 80–120 chars | No — comments exceed 79. |
| **Comment hard wrap 100** | Fmt allows lines up to 120; some comment lines exceed 100 | No — violates hard limit. |
| **Tag continuation indent (4 spaces)** | NatSpec continuations use `///    ` (4 spaces) | Yes. |
| **Second pass re-join** | Fmt does not re-join; it only wraps | No — manual pass needed. |
| **URL exemption** | Fmt does not treat URLs specially | N/A if no long URLs. |

## Evidence (after `forge fmt` with default config)

- **Univocity.sol:** Comment lines at 80–102 chars; code lines up to 120.
- **Univocity.t.sol:** Comment lines at 83–123 chars (e.g. `/// @notice Build a bootstrap receipt...` 123 chars; `// First checkpoint: bootstrap receipt...` 122 chars). These exceed both soft (79) and hard (100).

## Recommendation

1. **Set `line_length = 79` in `foundry.toml`** under a `[fmt]` section so that `forge fmt` never produces lines longer than 79. That keeps all lines (comments and code) within the standing soft limit and ensures no comment line can exceed the 100 hard limit.
2. **Run `forge fmt`** after adding that config; then do a **manual second pass** to re-join lines that were split but could fit in a single line ≤ 79 characters (per .cursorrules).
3. **CI / pre-commit:** Run `forge fmt` and optionally a lint/check that fails on any line > 79 (or > 100 for comments only) if you want to enforce the rules automatically.

## After setting `line_length = 79`

With `[fmt] line_length = 79` in `foundry.toml`, `forge fmt` wraps at 79 when it breaks lines, but it does not break every long line (e.g. long string literals, some single-token comment lines, or generated test output). So you may still see a few lines over 79. For full compliance with the standing rules (all comments ≤ 79 soft / ≤ 100 hard, plus second pass re-join), run `forge fmt` first, then do a manual pass to fix any remaining long comments and re-join short lines where appropriate.

## Stability for CI (manual format then forge fmt)

**Workflow:** Apply standing rules (wrap comments at 79, hard 100; tag continuation 4 spaces; re-join short lines where possible). Then run `forge fmt`. Then run `forge fmt` again (or `forge fmt --check`).

**Result (2026-02-21):** After one manual-format pass and one `forge fmt` run, a second `forge fmt` run produces **no changes** (exit 0, no files formatted). So `forge fmt --check` in CI will pass as long as contributors run `forge fmt` before pushing (or the repo is left in that state).

**Caveat:** Forge fmt may change some of the manually applied formatting (e.g. it reformatted 6 files when run after the manual pass). The final state is stable (idempotent) but may contain a few lines of 80–91 characters (e.g. long function names, or lines forge chose not to break). That is acceptable for CI: the check is “run forge fmt; no diff” rather than “every line ≤ 79”.
