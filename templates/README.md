# templates/

This directory contains operator-reviewable examples for:

- `engagement_plan.example.yaml`
- `opsec_manifest.example.yaml`
- `engagement_approval.example.yaml`
- `role_matrix.example.yaml`
- `purple_team_plan.example.yaml`
- `osint_pii_policy.example.yaml`
- `validation_plan.example.yaml`

These examples are not authorization. Replace all values with the signed client
engagement data before use.

Custom Nuclei templates may also be stored here and supplied with
`--custom-templates`.
## v3.9.6 templates

- `approval_manifest_v396.yaml` — sample authorization actions and targets.
- `execution_plan_v396.yaml` — plan/import action queue; no commands or payloads.
- `social_engineering_plan_v396.yaml` — safe simulation governance controls.
- `opsec_manifest_v396.yaml` — operator-supplied OPSEC assertions.

## Strict lifecycle and campaign examples

- `program_policy.example.yaml` — reviewed, machine-readable program/ROE policy.
- `identity_plan.example.yaml` — secret references only; no credentials.
- `workflow_plan.example.yaml` — versioned invariants and negative controls.
- `redteam_campaign.example.yaml` — complete ATT&CK lifecycle operation register.
- `redteam_operation_result.example.json` — sanitized, hash-bound imported proof,
  detection result and cleanup record.

The templates are schemas/examples, not authorization and not executable
payloads. Replace references with signed engagement data and operator-controlled
secret-provider IDs.
