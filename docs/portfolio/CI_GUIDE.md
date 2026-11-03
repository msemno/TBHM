# TBHM 4.2.7 — CI foundation

**Implementation status:** The workflow is provided as an unexecuted proposal until a real GitHub Actions run is observed. Do not claim a green pipeline based on this file alone.

## What runs automatically on `main` pushes and pull requests

`package-integrity` runs on GitHub-hosted Ubuntu 24.04 x86-64 with Python 3.12. It uses the project's documented offline installer, then validates:

1. Installer dependency/wheel integrity and `pip check`.
2. `./tbhm --version` and `--help` startup.
3. `scripts/validate_v4_release.py`: compilation, imports, release manifest content inventory, and mapping of 145 phases to callable `run()` modules.

This is a **package-integrity gate**, not a proof that all phases ran or external scanners detected real vulnerabilities.

## Full regression is opt-in

Use GitHub > **Actions** > **TBHM 4.2.7 - Release Integrity** > **Run workflow**, selecting **full_regression: true**. The second job invokes the existing `scripts/run_tests.py --source . --workers 1` command and writes JSON to the runner's temporary directory.

This job is intentionally manual until the owner reviews its test dependencies and network/side-effect profile. The workflow never supplies a live target or real credentials. Unit/regression tests may use loopback services and generated fixtures. A passing job proves only that the invoked checks passed on that specific commit/runner; test gaps and skipped scanners remain separate.

No test logs or reports are uploaded by the workflow: a public artifact containing security fixture values would require explicit review and redaction first.

## Security decisions

- `permissions: contents: read` minimizes the default `GITHUB_TOKEN` scope.
- Checkout uses `persist-credentials: false` and there are no PATs, API keys, model credentials, or repository secrets.
- Trigger on `push` and `pull_request`; **no** `pull_request_target` or elevated token use.
- Hosted environment is Ubuntu 24.04 / Python 3.12, matching the Linux x86-64 wheel constraints; no matrix of unsupported platforms.
- `actions/checkout` and `actions/setup-python` use specific immutable-style release tags (`v7.0.1` and `v7.1.0` as selected when this kit was prepared). For stronger supply-chain pinning, separately verify their current upstream commit IDs and pin the full SHA; do not invent SHA values.
- CI is not a network-isolation sandbox. Running a test suite from an untrusted PR still executes code on a GitHub runner. Review and harden the project tests before enabling broader access or secrets.
- Deliberately **no blocking generic Gitleaks job yet**: the repository contains known synthetic provider-shaped redaction fixtures and an intentional local TLS key/cert pair. A future secrets gate needs a narrow reviewed policy with positive/negative controls and must not blanket-ignore tests, docs, or historical patches.
- This workflow does not decide the original-source project license. Third-party notices and the project-rights statement remain authoritative until the rights holder makes that decision.

## Confirm actual evidence

After pushing a CI commit:

```bash
gh run list --repo msemno/TBHM --workflow tbhm-ci.yml --limit 5
gh run view RUN_ID --repo msemno/TBHM
```

Only link a green badge after an actual successful run. Inspect failing-job logs for secrets before sharing them publicly. Keep the raw local Gitleaks audit private.

## Scope and acceptance

- [ ] `git status --short` clean after committing.
- [ ] `scripts/validate_v4_release.py` passes with the new manifest count.
- [ ] GitHub Actions shows `package-integrity` passing at the new commit.
- [ ] A deliberately invalid manifest on a test branch makes the integrity job fail (never change the real release just to test this).
- [ ] Owner reviews the regression harness; optionally run `full_regression` manually and inspect its complete result.
- [ ] Only then consider branch-protection required checks and a visible README CI badge.

**Not included:** remote vulnerability scans, container publishing, SAST false-positive suppression, artifact upload, independently attested release provenance, a demo, or proof of actual AI/model performance.
