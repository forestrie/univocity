# Push and follow up (CI loop)

Push the current branch, ensure a PR exists, monitor CI, fix any failures, and
repeat until stable or a cycle limit is reached. Run all commands from the
**repository root**.

---

## 1. Push the branch

- Ensure the current branch has an upstream: if not, create a tracking branch
  (e.g. `git push -u origin $(git branch --show-current)`).
- Push the latest commits: `git push`.

## 2. PR (create if missing or update description)

- If there is **no** open pull request for this branch:
  - Create a PR (via GitHub CLI, API, or instruct the user to open one).
  - Use the **most recent commit message** (or the contents of `COMMIT` if it
    exists and describes the change) as the basis for the PR title and
    description.
- If a PR already exists, update the PR description to be inclusive of the
additional changes

## 3. Monitor CI

- Triggered workflows run after the push. Monitor the relevant CI runs (e.g.
  GitHub Actions) for this branch/PR.
- **If all workflows succeed:** stop; you are done.
- **If any workflow fails:** collect the failing jobs and error summaries, then
  create a **todo list** of concrete fixes (one todo per logical fix or failing
  check).

## 4. Fix and re-commit

- Work through the todo list until every item is done.
- Run the **add-and-commit** command to stage changes, run format/lint/tests
  and static analysis, and write a conventional commit message to `COMMIT`.
- Run: `git commit -F COMMIT` to create the fix commit.
- **Return to step 1** (push the branch again and repeat from there).

## 5. Cycle limit

- If you have gone through the loop (push → monitor → fix → commit → push)
  **more than 3 times**, stop.
- Report the **remaining CI failures** and **propose fixes** (or next steps) in
  your reply; do not start another cycle.

---

## Summary (agent checklist)

1. Push branch (set upstream if needed); push commits.
2. If no PR exists, create one; use latest commit message (or `COMMIT`) for
   description.
3. Monitor CI; if all pass, stop. If any fail, create a todo list of fixes.
4. Complete todos → run add-and-commit → `git commit -F COMMIT` → go to 1.
5. After 3 full cycles, stop and report remaining issues and proposed fixes.
