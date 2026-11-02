# TBHM 4.2.6 corrective release

- Reconciles the 15 hash-verified runtime repairs and reviewed dev1 source changes.
- Separates local inference budgets from assessment requests; keeps AI optional.
- Replaces runtime full-cache rebuilds with bounded, resumable row checkpoints.
- Bounds content-discovery/phase dispatch, propagates cancellation, cleans owned
  descendants and defers model work during partial reporting.
- Adds durable event journaling, accepted native HTTP accounting, observer/wall
  timing and explicit final AI-store status.
- Repairs exact-host archive intake, HTTPX JSON parsing, Nmap host attribution,
  explicit GCP project arguments and Nuclei partial/malformed-output handling.
- Makes diagnostics presence-only; preserves explicit installation/update actions.
- Removes browser/regex shell false positives, preserves Node flows, narrows JS
  and passive MFA classifications, and fixes per-URL host attribution.
- Keeps generated reproducers separate from captured evidence; records curl
  negative/blocked attempts and sanitized response artifacts without proof authority.
- Excludes the synthetic local-analysis label from live endpoint mapping.
- Retains all 145 phase identities, original strict proof classes/golden vectors,
  SQLite semantics and reviewed scenario-learning controls.
- Adds current-build test receipts and a read-only inference connection doctor.

Real Kali scanner versions, Windows/GPU/tunnel ownership, the absent original
AI database and target proof artifacts remain live acceptance work. No training,
universal wire containment, complete writer privacy or all-class auto-confirmation
claim is made. See docs/incident-analysis/ROOT_CAUSE_REPORT.md and OUTSTANDING_WORK.csv.
