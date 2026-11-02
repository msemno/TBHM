# Historical Coverage Restoration — TBHM v3.9.7.2

## Review method

The v3.9.7.1 package was compared again against every supplied historical tree at four levels:

1. file, phase, CLI, profile, catalog, template, payload, and public-symbol preservation;
2. AST and constant-table comparison of scan-oriented modules;
3. behavioral fixtures for rewritten modules where names alone could hide regressions;
4. complete offline execution of the existing integration matrix plus a new restoration suite.

The review did not copy older modules wholesale. Newer implementations were retained when they were safer or more complete, and older behavior was merged only when a real use case was missing.

## Confirmed gaps and decisions

| Domain | Gap | Decision | Safety treatment |
|---|---|---|---|
| CI/CD | Build files, privileged mode, Docker socket, broad event interpolation, and inline `pull_request_target` were not all covered | Merge old rules/file classes into the new dataflow engine | Static local reads only; no workflow execution |
| Cloud IAM | Two historical roles and mixed-provider records could be missed | Restore the full historical indicator union and analyze all applicable providers | Leads only; effective permission and exploitability are not asserted |
| Compliance | Historical JSON/CSV aliases were absent | Preserve modern predicate schema and add aliases/separate legacy summary | `unknown` is never converted into a pass |
| OCSF | Fallback finding UID changed | Preserve the old fallback UID and retain the new stable fingerprint | Explicit IDs still take precedence |
| Source/data | v2.21 data/document secret and sink coverage was unavailable | Restore as explicit opt-in | Placeholder/entropy screening, redaction, hashing, lead-only status |

## Wider scan review

The following historical surfaces were independently checked and retained or superseded by tested safer implementations:

- all 23 historical source secret definitions;
- all 27 historical dangerous-sink definitions;
- source/mobile/SBOM/dependency/source-map/API/GraphQL/WebSocket/SSE/PWA coverage;
- the v3.8 code-security default list: `bandit,njsscan,gitleaks,trivy,grype,checkov,terrascan,tfsec`;
- JSON, JSONL, SARIF, nested-record, CWE, severity, provenance, deduplication, malformed-input, and bounded-recursion normalization;
- v2.16 curl-probe differential and body-validation behavior;
- Nuclei template discovery, workflow fallback, malformed-template handling, and executable identity checks;
- wildcard, catch-all, redirect, custom-404, body-similarity, and rate-limit false-positive controls;
- modern five-stage reverse engineering plus the dependency-free static fallback;
- report files, qualified posture wording, per-finding reproducer kits, and evidence manifests.

No additional useful scan family was found to be absent after the v3.9.7.2 fixes. Text-only differences that represented safer wording, moved implementation, or replacement by a shared normalizer were not restored as duplicate code.

## Operator impact

The restored CI/CD and cloud IAM coverage is automatic whenever those existing phases are enabled. Data/document full scanning is deliberately opt-in because operational notes, documentation, and exported configuration often contain examples and produce more noise than executable source.
