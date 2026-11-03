# GitHub publication — historical Push Protection review

**Current status (3 November 2026, supplied Git terminal output):** The owner successfully pushed `main` to the public `msemno/TBHM` repository, including commits `6d1f2bd` and `eafe694`; `main` tracks `origin/main`. Previously (2 November), GitHub rejected the initial push with `GH013` / Push Protection. This page preserves that event as a case study. The accepted push is not proof that all credentials are inert or that full secret scanning covered the repo. Never disclose tokens or values copied from test fixtures.

## Why the two secret-review outcomes differ

The private Gitleaks audit found 61 pattern matches, and a contextual review classified them as 39 hashes, 20 synthetic/test entries, and two occurrences of a dedicated local TLS fixture key. The log nevertheless contains GitHub detections for **Stripe-shaped test strings** in historical integration tests and manifests. A tool's local review and GitHub Push Protection are separate policies and rulesets. **Neither result automatically overrides the other.**

## Blocked path categories (names and lines only)

- `integration_test_v393.py` lines 50 and 84; `manifests/v3.9.5.json` line 1547; `manifests/v3.9.6.json` line 1549
- `integration_test_v395.py` lines 214 and 216
- `integration_test_v3941.py` line 393 (GitHub blocked log; this line was not listed in the previous 61-entry contextual review)

The extra line 393 merits a **fresh local inspection**. Do not assume it is benign solely because nearby findings were synthetic. This documentation does not include the token-shaped values or the unblock URLs.

## Recommended safety review for the already-published history

1. Keep all raw secret-audit logs and source reviews in `~/tbhm-work/publication/` (outside Git).
2. Confirm the **exact current** local files, blocked GitHub locations and any changed history; do not rely solely on an older contextual report. Check `git show 6d1f2bd:PATH` locally without pasting secrets to a chat.
3. Determine whether each blocked literal is an inert test fixture, a false positive, or a real credential. For real credentials, revoke/rotate immediately and remove them from the **commit history** before retrying. No bypass for a live key.
4. If *all* affected strings are demonstrably safe and you are authorized to publish them, GitHub's documented unblock flow offers **“It's used in tests”** or **“It's a false positive”** as appropriate. Inspect GitHub's specific blocked-push URLs in your private terminal output while signed into the pushing account. This may create an audit event and may require renewed approval; it does not mean the secret is verified safe by GitHub.
5. Alternatively, replace synthetic provider-shaped fixtures with non-provider-shaped tokens, update tests/serialized manifests/release inventory consistently, and **rebuild the affected initial commit history**. This is a separate source-change project, not a documentation edit. Never simply amend a later commit while the blocked initial commit still contains the same strings.
6. Reassess the already-published history if any test literal is later determined to be a real credential: revoke/rotate it, remove it from exposed Git history with an appropriate coordinated remediation, and re-run release validation. Do not interpret an accepted push as an audit verdict.

## Useful local commands

```bash
cd "$HOME/publish/TBHM"
git status --short
git log --oneline --max-count=4
git remote -v
.venv/bin/python scripts/validate_v4_release.py
git diff --check
# Confirm repository status without leaking credentials:
git status -sb
gh repo view msemno/TBHM --json visibility,defaultBranchRef
```

Never solve such a block by disabling secret scanning globally, hiding entire source/test directories, leaking keys in an issue, or force-pushing without a coordinated history-remediation plan. The owner confirmed the public default branch is `main`. The third-party and original-source licensing decision remains separate from whether GitHub accepted the push.

## Project license gate

The supplied `NOTICE.md` says original source rights were retained and no project-level license was selected. A third-party wheel's MIT/BSD/etc license does not authorize relicensing TBHM's original source. Obtain a valid source-rights decision before adding `LICENSE` or describing the repository as open source.

## Relevant GitHub documentation

- [Working with push protection from the command line](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/work-with-leak-prevention/push-protection-on-the-command-line)
- [Managing sensitive repository history](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Licensing a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)
