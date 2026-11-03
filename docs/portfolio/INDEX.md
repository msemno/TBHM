# TBHM documentation hub

**Goal:** Make a complex security engineering project understandable without conflating features, test coverage and confirmed vulnerabilities.

## Choose your path

| You are... | Recommended reading path | Time focus |
| --- | --- | --- |
| Recruiter or hiring manager | [Project overview](RECRUITER_OVERVIEW.md) → [architecture](ARCHITECTURE_WALKTHROUGH.md) → [validation](TESTING_AND_VALIDATION.md) | Purpose, scope of contribution, evidence |
| Security engineer | [Architecture](ARCHITECTURE_WALKTHROUGH.md) → [proof model](PROOF_AND_FINDINGS.md) → [security boundaries](SECURITY_BOUNDARIES.md) | Trust boundaries and verification authority |
| Operator | [Workflows](WORKFLOWS.md) → [module map](MODULE_MAP.md) → [limits](../../KNOWN_LIMITATIONS.md) | Setup, policy, outputs and failure interpretation |
| Contributor | [Module map](MODULE_MAP.md) → [testing](TESTING_AND_VALIDATION.md) → [contribution claims](CONTRIBUTION_CLAIMS.md) | Reproducibility and scoped patches |
| Maintainer preparing GitHub | [Publishing](PUBLISHING_AND_PUSH_PROTECTION.md) → [release history](RELEASE_HISTORY.md) | Manifest integrity, history, secrets and licensing |

## Reading model

TBHM is not one monolithic vulnerability detector. There is a **planning/dispatch layer**, a range of **native and optional external analyses**, a **recording and evidence-verification layer**, an **operator review/reporting layer**, and an **optional local-model advisory path**. Treat those as distinct. A feature may be integrated at the architecture level while not validated for your environment.

## Source of truth

The files under `docs/portfolio/` are navigational and explanatory. The 4.2.7 release's executable code, manifest, bundled installer, `docs/PROOF-v2.md`, `docs/UPGRADE-v4.2.7.md`, `docs/review-v4.2.7/ARCHITECTURE.md`, `docs/review-v4.2.7/FILE_MAP.md` and `docs/review-v4.2.7/CLI_REFERENCE.md` remain authoritative for the precise implementation and CLI. This pack does not rename, reorganize or alter those source modules.

## What this documentation intentionally does not do

It does not claim every phase executed, every optional tool is installed, every vulnerability lead is real, every child process is fully contained, or a local LLM is accurate. There is no added fabricated screenshot, benchmark, target finding, award, production engagement, or CI result.
