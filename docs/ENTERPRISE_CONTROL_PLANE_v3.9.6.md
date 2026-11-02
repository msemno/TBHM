# Enterprise Control Plane and Intelligence Depth — v3.9.6

## Design

TBHM remains an evidence-led security orchestration framework. v3.9.6 adds a
single-pane state model for separately governed operator actions, deeper
corporate OSINT, CI/CD and cloud-identity analysis, compliance matrices, OCSF
normalization and a declarative MCP-compatible capability manifest.

The agentic layer is **non-authoritative**. It may observe sanitized artifacts,
retrieve TBHM source, identify gaps and create a proposal. It cannot change
scope, confirmation, severity, code or execution state. No network MCP server is
started by `agentic_control_manifest`.

## Example: generate the agentic manifest

```bash
./tbhm.py -d example.com -y --agentic-manifest --dry-run
```

## Example: execution coordination without execution

```bash
./tbhm.py -d example.com -y \
  --execution-orchestration \
  --execution-plan templates/execution_plan_v396.yaml \
  --approval-manifest templates/approval_manifest_v396.yaml
```

The generated queue contains empty `commands` and `payloads` fields by design.
TBHM verifies the approval action and target, records required controls and
tracks imported evidence and cleanup.

## Example: OSINT depth

```bash
./tbhm.py -d example.com -y \
  --corporate-osint --osint-depth --osint-google-dorks \
  --osint-favicon-urls urls.txt --osint-live \
  --osint-request-budget 25
```

Every live request is scope checked. Provider, dark-web/paste and commercial
internet-search output is imported rather than scraped by TBHM. Person-level
collection requires both a PII policy and action approval.

## Example: CI/CD and supply chain

```bash
./tbhm.py -d placeholder.local -y \
  --code-dir ./repository --cicd-security \
  --attestation-dir ./attestations
```

The phase performs local review and optional safe scanner execution. It does not
publish artifacts, mutate registries, trigger pipelines or consume deployment
secrets.

## Example: cloud IAM path review

```bash
./tbhm.py -d placeholder.local -y \
  --cloud-identity-paths --cloud-iam-input ./iam-exports
```

This is a read-only static review. It does not access metadata services, assume
roles, create resources, alter policies or harvest cloud credentials.

## Example: compliance and OCSF

The extended compliance phase runs in the standard phase order. Restrict output:

```bash
./tbhm.py -d example.com -y \
  --compliance-frameworks pci-dss,iso27001,nist-800-53
```

Use `--compliance-catalog` for officially licensed or organization-specific
control text. The bundled catalog maps families and evidence expectations; it is
not a certification or legal opinion.

OCSF-oriented JSONL is emitted unless `--no-ocsf` is supplied. Native TBHM
findings remain the source of truth.

## High-impact boundary

The execution registry accepts only `plan_import` or `commercial_import` for
exploit, credential attack, C2, persistence, lateral movement, exfiltration,
phishing, MFA interception, wireless disruption, physical bypass and OT writes.
This is enforced by `core.execution_registry.validate_adapter()` and tested in
the offline v3.9.6 regression suite.
