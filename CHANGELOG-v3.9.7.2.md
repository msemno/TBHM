# TBHM v3.9.7.2 — Historical Coverage Restored

This maintenance release patches the verified historical coverage and output-contract gaps found during a second behavioral review of v2.16-fixed, v2.21, v3.8-expanded, v3.9.5, v3.9.6, and v3.9.7.1.

## Restored scan coverage

### CI/CD and build definitions

The native static CI/CD analyzer again inventories all historical file classes:

- `.github/workflows/**`
- `.circleci/**`
- `*.workflow.yml` and `*.workflow.yaml`
- `Jenkinsfile`
- `.gitlab-ci.yml` and `.gitlab-ci.yaml`
- `azure-pipelines.yml` and `azure-pipelines.yaml`
- `Dockerfile`
- `Makefile`
- `package.json`
- `pyproject.toml`

It preserves the newer trust/dataflow engine and restores the complete v3.9.6 rule surface, including:

- `pull_request_target`, including inline event syntax;
- mutable action references;
- `permissions: write-all`;
- persisted checkout credentials;
- generic `${{ github.event.* }}` interpolation;
- privileged jobs or containers;
- Docker socket mounts;
- `curl|wget` piped to a shell.

No workflow, package script, Make target, container, or downloaded command is executed.

### Cloud IAM indicators

The graph analyzer now evaluates every applicable provider in a mixed input file and preserves every v3.9.6 indicator. Restored indicators include:

- Azure `Privileged Role Administrator`;
- GCP `roles/editor`;
- the full historical AWS, Azure, and GCP permission/role sets.

Permission text remains an evidence-backed lead. The analyzer does not assert exploitability, authenticate, assume a role, create a key, or modify cloud resources.

### Data and document source scanning

A disabled-by-default compatibility mode restores the v2.21 ability to review JSON, XML, HTML, TXT, and Markdown for secret assignments and dangerous sinks:

```bash
./tbhm.py --code-dir ./source --code-scan-data-files
```

Additional text extensions can be explicitly allowlisted:

```bash
./tbhm.py --code-dir ./source --code-scan-extra-extensions conf,properties,tmpl
```

Default behavior remains endpoint-only for these files. In opt-in mode:

- structured JSON, XML, HTML, properties, `.env`-style, and quoted assignments are recognized;
- placeholder and low-entropy values are suppressed;
- the real value is screened before redaction;
- raw values are never persisted;
- stored evidence contains a redaction and stable SHA-256 only;
- findings remain unconfirmed static leads.

## Restored compatibility contracts

- Compliance JSON rows again include `id` and `finding_refs` aliases.
- Compliance CSV preserves historical columns while retaining the evidence-predicate fields.
- `compliance_summary.json` keeps the v3.9.7.1 authoritative shape; a separate `compliance_legacy_summary.json` is emitted for old consumers.
- OCSF findings without an explicit ID retain the v3.9.6 fallback UID while the newer class-aware stable fingerprint remains available.
- `cloud_identity_paths.json` remains available beside the graph output.

## Truthful capability reporting

The capability registry now includes `source.data_document_static_scan` as a native, passive, disabled-by-default capability. Registry status does not imply activation or confirmation.

## Regression protection

`integration_test_v3972.py` adds offline fixtures for:

- every historical v3.9.6 CI/CD rule;
- every historical v3.9.6 cloud IAM indicator;
- mixed-provider IAM data;
- compliance aliases and CSV columns;
- OCSF legacy UID stability;
- default-off and safe opt-in data/document scanning;
- raw-secret non-persistence;
- placeholder suppression;
- retained Nuclei and code-security defaults.
