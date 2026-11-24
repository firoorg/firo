---
name: firo-preflight
description: Check that a Firo branch is ready for review before opening or updating a pull request. Runs contrib/devtools/preflight.sh (committed and up to date with master, clean added lines, the CI Linux Debug build, unit and RPC tests), reviews the diff for bugs and needless code, and fixes what is real. Use before `gh pr create`, before pushing new commits to a PR, or when asked whether a branch is merge-ready.
---

# Firo preflight

1. Commit the work. On Linux with `depends/` built (WSL works), run `contrib/devtools/preflight.sh <RPC tests that cover the change>`. For a PR based on another PR's branch, set `BASE=origin/<that branch>`. The RPC tests need a Python with `asyncore` and `zmq` (3.11 or older). Fix every failure. Apply formatting suggestions only to lines the branch changed.
2. Review the branch's changes against its merge base with the `code-review` skill, then with the `simplify` skill. Fix the real findings, and leave lines the branch did not touch alone.
3. Read the diff against "Keeping changes small" and "Before opening a PR" in `AGENTS.md`, and drop anything the PR's intention does not need.
4. Order the commits so a reviewer can read them one at a time, then write the description by the rules under "PR and commit conventions" in `AGENTS.md`.

Report in a few lines what ran, what failed, and what could not run. Never paste logs or bot output into the PR.
