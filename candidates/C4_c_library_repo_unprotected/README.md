# C4 — Published C-library repo is unprotected; commit identity is forgeable

| | |
|---|---|
| **Area** | supply chain (deployment configuration) |
| **Severity** | 🟡 MEDIUM |
| **CWE** | 284 / 345 / 353 |
| **Affected** | `Dronecode/mavlink-military-c_library_v2`; `publish_c_library.sh`; `verify_c_library.yml` |
| **Reviewed at** | public GitHub API reads, 2026-10-28 |
| **State** | configuration, read via unauthenticated API |

## Summary

The generated C library — the main way integrators consume MAVLink-M — sits in a
repository with no branch protection and no commit signing. Integrators are told
to submodule its `main`, but nothing enforces that what they pull was produced by
CI, and the daily verification only checks `HEAD`, so a transient malicious commit
leaves no trace.

## Root cause

- `repos/Dronecode/mavlink-military-c_library_v2/rules/branches/main` → `[]`,
  `/rulesets` → `[]`, `/branches/main` → `protected:false`.
- Every commit is unsigned (`%G?=N`). The `github-actions[bot]` author is set by
  `git config` in `publish_c_library.sh:55-56`, so anyone with push can forge that
  identity, despite the README's "This repository is written by CI."
- Anyone with write on the repo, or the holder of `C_LIBRARY_DEPLOY_KEY`, can push
  or force-push; there is no non-fast-forward rule.
- `verify_c_library.yml` runs daily, clones `--depth 1`, and checks only `HEAD`
  (`check_c_library.py`). A bad commit reverted within 24 h never alarms, and a
  force-push erases the trace.

Getting the deploy key out of CI is gated (the `c-library` environment's branch
policy is `main`-only, confirmed via API), so the realistic attacker is a
compromised writer account or the deploy key itself.

## Impact

A compromised C-library writer or deploy key can plant headers in the repo every
integrator vendors, transiently and without detection. Combined with
[C1](../C1_ci_description_text_to_code/), the planted content need not even look
malicious in review.

## Fix

Add a ruleset on the C-library default branch: restrict updates/creations, block
force-push and deletion, allow only the deploy key as a bypass actor. Sign publish
commits (SSH signing key in the environment, or commit via a GitHub App token for
"Verified"). Have the daily check walk every commit since the last verified one,
not just `HEAD`, and consider tagging and attesting each publish.
