# Add and commit (session changes)

Prepare and stage all current-session changes, run quality checks, then write a
conventional commit message to a file and output the git command. **Do not run
`git commit`** — only report the command.

Run all commands from the **repository root**.

---

## 1. Format and lint (until stable)

- Run `forge fmt`. If any file changed, run `forge fmt` again until no changes
  (idempotent).
- Run `forge build` (or `forge lint` if the project uses it). Fix any reported
  issues. If you edit files, re-run `forge fmt` then `forge build`/`forge lint`
  until both pass with no further edits.

## 2. Tests

- Run `forge test`. If any test fails, fix the cause and re-run from step 1
  (format/lint) as needed. **Do not proceed to step 3** until all tests pass.

## 3. Static analysis

- Run Slither: `mise run slither-check` (or `slither --fail-low src` if mise is
  unavailable). Address findings where feasible (fix or document accepted
  risk). If you change any source or config:
  - Re-run `forge fmt`, then `forge build`/`forge lint`, then `forge test`.
  - Repeat until format, lint, and tests pass with no further changes.

## 4. Stage changes

- Stage all changes: `git add -A` (or stage only the files you intend to
  commit, if the user prefers a partial commit). Ensure the set of staged
  files matches the scope of the commit message you will write.

## 5. Commit message (write only)

- Draft a **conventional commit** for the staged changes:
  - **Title:** one line, imperative mood, ≤ 79 characters.
  - **Body (optional):** wrap at ≤ 72 characters; blank line after title.
- **Commit conventions (this repo):** title ≤ 79 chars, body lines ≤ 72 chars;
  no Co-Authored-By; use only the repo’s configured git author.
- Write the full message (title + blank line + body) to the file
  **`COMMIT`** at the repository root, **overwriting** any existing content.
- **Do not run `git commit`.** Instead, output the exact command the user can
  run to commit using that file, for example:

  ```bash
  git commit -F COMMIT
  ```

  If you staged with `git add -A`, say so; if only some paths were staged,
  show the same command (the message applies to whatever is currently staged).

---

## Failure handling

- If **format/lint** cannot be satisfied after a reasonable number of fix
  attempts, stop and report the blocker; do not write `COMMIT` or suggest
  committing.
- If **tests** fail and cannot be fixed in this run, stop and report; do not
  proceed to Slither or commit message.
- If **Slither** reports issues that you do not fix (e.g. accepted risk),
  note that in the commit body or in your reply; still write `COMMIT` and
  output the commit command if the user asked to proceed.

---

## Summary (agent checklist)

1. `forge fmt` until idempotent; `forge build`/`forge lint` and fix until pass.
2. `forge test`; fix failures and re-run from 1 until all pass.
3. `mise run slither-check`; fix or document; if files changed, re-run 1–2.
4. `git add -A` (or chosen paths).
5. Write conventional message to `COMMIT`; output `git commit -F COMMIT`; do
   **not** execute the commit.
