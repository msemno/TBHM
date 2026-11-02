# TBHM v3.9.7.2 Validation Record

Release: `3.9.7.2-historical-coverage-restored`

Result: **PASS** — 20/20 static, compatibility, regression, and CLI validation checks passed.

## Verified results

- All 13 integration scripts passed in separate bounded subprocesses.
- The v3.9.7.2 restoration suite passed 9 offline cases, including every historical v3.9.6 CI/CD rule and cloud IAM indicator.
- The 21-case historical curl/Nuclei/false-positive/scanner/reverse/report suite passed.
- All 372 files from the packaged v3.9.7.1 baseline remain present.
- All 330 v3.9.7.1 CLI option strings remain; the final parser contains 332.
- All 129 v3.9.7.1 phases remain in the same canonical order.
- The capability registry validates with 16 registered capabilities.
- Python, JSON, YAML, and shell syntax checks passed.
- No unrestricted `shell=True` call, production `os.system`, symlink, nested archive, runtime cache, collected result file, or embedded private-key block was found.
- The real local CLI smoke produced the complete reporting aliases and two static leads without persisting the raw fixture secret.

## Restored work-impacting behavior

- CI/CD build-file coverage, privileged jobs, Docker socket mounts, remote-download shell pipes, broad event interpolation, and inline `pull_request_target`.
- Full historical AWS/Azure/GCP IAM indicator union and mixed-provider input handling.
- Compliance JSON/CSV compatibility aliases without converting unknown evidence into a pass.
- Historical OCSF fallback UIDs alongside the newer class-aware stable fingerprint.
- Explicit opt-in JSON/XML/HTML/TXT/Markdown secret and sink review with pre-redaction screening.

## Safety boundary

All validation used local synthetic fixtures. No third-party target was contacted, no credential was validated against a provider, no workflow or document content was executed, and no cloud action was performed.

Machine-readable records:

- `docs/validation/FINAL_STATIC_VALIDATION_v3.9.7.2.json`
- `docs/validation/TEST_MATRIX_v3.9.7.2.json`
- `docs/validation/CLI_SMOKE_v3.9.7.2.json`
- `docs/compatibility/BACKWARD_COMPATIBILITY_COMPARISON_v3.9.7.2.json`
