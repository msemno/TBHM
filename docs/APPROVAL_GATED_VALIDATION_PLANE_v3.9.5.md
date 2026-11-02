# Approval-Gated Validation and Purple-Team Plane — v3.9.5

TBHM separates evidence collection from intrusive operator activity. The normal
phase pipeline does not autonomously perform credential attacks, coercion,
relay, remote execution, persistence, C2, phishing, wireless disruption, OT
writes, destructive actions, or dynamic malware execution.

## Approval manifest

A manifest must contain an engagement ID, approver, expiry, authorized actions,
and optionally exact domains, URLs, IPs, and CIDRs. Missing, expired, malformed,
or mismatched manifests fail closed.

## Controlled validation

`controlled_validation_plane`:

- validates planned actions against the manifest;
- records ATT&CK technique, target, impact, duration, request limit, evidence,
  stop conditions, and cleanup requirements;
- marks approved actions `AUTHORIZED_NOT_EXECUTED`;
- imports result files produced by the separately governed operator workflow;
- preserves evidence hashes and cleanup status;
- never launches exploit, C2, phishing, credential, coercion, or disruptive
  tooling itself.

## Purple-team validation

`purple_team_validation` normalizes an ATT&CK/D3FEND detection matrix containing:
expected telemetry, actual alert result, investigation result, response result,
and cleanup evidence. Atomic Red Team, CALDERA, Stratus, PurpleSharp, Sigma and
YARA are result/import integrations unless a separate client-controlled process
executes the approved test.

## Propose and approve

The AI plane follows the same rule for code evolution: knowledge may be ingested,
reasoned over and converted into a pending proposal, but no model-generated patch
is applied. Human review, source control, test execution, provenance and rollback
remain mandatory.
