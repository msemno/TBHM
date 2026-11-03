# TBHM — 5-minute technical portfolio walkthrough

**Problem statement.** Security tools produce heterogeneous outputs, incomplete runs and possible false positives. A mature assessment workflow needs explicit authorization, execution traceability, evidence qualification and deliverables that distinguish observed leads from verified vulnerabilities.

**System.** TBHM 4.2.7 is a Python-based orchestrator with 145 registered phase names, a broad native/optional-tool assessment catalog, an evidence/reporting pipeline, an offline-capable distribution and optional local-AI guidance. The included Go executor is optional. Registered phases do not equal validated live scanner coverage.

## A sample project narrative

1. **Select** an authorized target and configure the profile, inputs, budgets and appropriate network scope.
2. **Dispatch** matching phases, with external-tool availability and errors recorded separately from findings.
3. **Collect** observations without treating route names, status codes, heuristics or model statements as exploit proof.
4. **Verify** supported finding classes through bound captures, negative controls and distinct repeats.
5. **Review** the execution ledger and leads; surface missing coverage.
6. **Deliver** sanitized report and immutable-looking (hash-controlled, not signed) evidence snapshot.

This is an explanation of the architecture, not evidence that a particular commercial engagement occurred.

## Engineering topics worth discussing in interviews

| Subject | Specific demonstration to prepare |
| --- | --- |
| False-positive handling | Explain why an HTTP 200 on an anonymous-looking route is not an auth bypass |
| Evidence contracts | Show the role of identity binding, negative control and repeat captures |
| Security boundaries | Distinguish Python HTTP budget from external scanner subprocess traffic |
| Resilience | Describe parser failures, missing inputs, timeout and `finished_with_gaps` |
| Offline supply chain | Explain version-locked wheels, release manifest and SBOM roles |
| Local model integrity | Explain why inference advice is non-authoritative and optional |
| Privacy | Explain raw/working evidence separation and redacted delivery |

## Claims that must be earned separately

It would be inaccurate, on the materials reviewed, to claim “145 scanners proven against production targets”, “every finding automatically verified”, “full external-browser sandbox”, “real LLM accuracy benchmark passed”, “no secrets anywhere”, or “TBHM is fully open-source licensed”. Also do not claim authorship of inherited code without specific commits and provenance.

## Evidence pointers

- `docs/review-v4.2.7/ARCHITECTURE.md`, `FILE_MAP.md`, `ROOT_CAUSE_REPORT.md`
- `docs/PROOF-v2.md`, `KNOWN_LIMITATIONS.md`
- `RELEASE_MANIFEST-v4.2.7.json`, `SBOM.cdx.json`, `runtime.json`, `requirements.lock`
- [Validation commands and reported evidence](TESTING_AND_VALIDATION.md)
- [Contribution and provenance checklist](CONTRIBUTION_CLAIMS.md)
