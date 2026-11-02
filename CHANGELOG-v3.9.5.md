# TBHM v3.9.5 — Corporate Intelligence, Standards, Data, and Supervised Learning

## New architecture

- 116 ordered phases; existing v3.9.4.1 phases remain in relative order.
- Separate corporate OSINT, authenticated-session, identity, cloud posture,
  extended mobile/reverse, vulnerability-intelligence, data-analysis,
  purple-team, controlled-validation and AI-supervision phases.
- Versioned 483-entry external-tool catalog with explicit integration modes and
  risk labels. Catalog presence is not represented as live execution support.
- Safe extended installer plans only vetted low/medium-risk command recipes.
  High-risk, approval-only, commercial and service/manual tools are never
  silently installed or executed.
- Provenance-aware company/entity graph with SQLite, JSON, CSV, GraphML and STIX
  2.1 custom-object exports.
- Engagement lifecycle/objective model and declared-control OPSEC preflight.
- Local standards manifest and explicit CISA KEV/FIRST EPSS/OSV cache updater.
- Approval-gated validation register and purple-team detection matrix.
- Bounded continuous AI learning from sanitized T3 run artifacts, plus
  advisory/proposal-only supervision. Corporate red-team profiles enable this
  local observer by default and expose `--no-ai-observe` as an explicit opt-out.

## Correctness and operator controls

- `--exclude-tests`/`--include-tests`, `--reachable-only`, `--threads`,
  `--confidence-threshold`, `--dep-filter`, `--fp-review`, and `--notify` now
  have concrete runtime consumers.
- Notifications are one-shot sanitized summaries over HTTPS; no targets,
  evidence or finding titles are sent.
- Vulnerability enrichment commits immediately and never changes confirmation.
- Corporate OSINT hashes email identities unless an explicit PII policy enables
  authorized identity collection.
- Approval target matching supports domains, subdomains, URLs, IPs and CIDRs.
- New adapter-contract and binary/tool provenance primitives.

## Safety statement

This release does not add autonomous exploitation, credential use, password
cracking, remote execution, persistence, C2, phishing, wireless disruption, OT
writes, destructive testing, or self-applying AI code changes. Those activities
remain external, separately approved, and evidence-import only.
