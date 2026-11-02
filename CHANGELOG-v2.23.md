# TBHM v2.23 — Red-team alignment, global safe-writes, honest leads

This release addresses four gaps found while preparing TBHM for a full-scope,
real-simulation company red team. It is additive to v2.22-redteam. No detection
logic or phases were removed.

## 1. Branch matrix aligned 1:1 with the field playbook (34 branches)

`phases/redteam_governance.py` previously tracked 22 branches whose titles did
not match the playbook. It now tracks all **34 branches (BR01–BR34)** using the
exact titles from the playbook's Section 5 (BR01–BR26) and the additive Section
5B (BR27–BR34). The playbook defines 200 objectives per branch = **6,800
objectives** total; the governance matrix records this and emits
`redteam/00_governance/branch_matrix.json` so the report renders the same matrix.

Each branch carries an `automation` hint (`partial` = TBHM probes part of it;
`checklist` = worked manually) so the report never implies a checklist-only
branch was automatically tested.

## 2. Safe-writes is now enforced globally

Previously several phases called `requests.post()` / `requests.request()`
directly, bypassing `core/safe_writes.py`. That made the README's "mutating
methods blocked by default" claim only partially true.

Fixed:
- `core/safe_writes.py` gained `configure()`, `global_gate()`, `ctx_gate()`, and
  `guarded_request()`. `tbhm.py` calls `configure()` once at startup with the
  resolved `--allow-writes` flag and profile name, so even context-free helpers
  enforce the gate.
- Gated every previously-bypassing mutating call site:
  `phases/api_specific.py` (GraphQL introspection/batching, webhook, LLM probes),
  `phases/business_logic.py` (mass-assignment POST/PUT/PATCH),
  `phases/web3.py` (eth RPC + IPFS POST),
  `phases/upload_race.py` (upload POST),
  `core/diff_engine.py` (`collect_baseline`, `send_one`),
  `core/verifier.py` (non-GET verification).
- `phases/api_key_pivot.py`: under `passive_only`, live third-party key
  verification is skipped entirely and secrets are recorded as UNVERIFIED leads —
  no outbound vendor call is made.
- `core/reporter.py`: generated reproducer scripts for POST/PUT/PATCH/DELETE now
  carry a safe-writes warning banner.

`core/sbom.py` still POSTs to `api.osv.dev` (Google's public vulnerability
database) — this is a read-only dependency lookup, not a target write, and is
intentionally left as-is.

Verified: with writes off, GET passes and POST is blocked; with `--allow-writes`,
POST passes but destructive paths (`/delete`, `/refund`, …) still require manual
handling; `passive_only` blocks all writes.

## 3. Reporter is red-team aware

`core/reporter.py`:
- `METHODOLOGY_AUDIT.md` now renders the full 34-branch coverage table with a
  per-branch status derived from actual evidence. Branches with mapped findings
  show `Tested (partial, automated)`; the rest show `Not Tested — manual` or
  `Not Tested — automation available, no evidence yet`. The audit states plainly
  that **absence of a finding is not proof of safety** and lists the seven-value
  status vocabulary.
- The developer report's methodology section references the branch matrix instead
  of only the web/API pipeline.
- Safe-writes enforcement state is printed in the audit header.

## 4. Heuristic findings are labelled as leads, not confirmed vulnerabilities

New `core/finding_class.py`, invoked from `Ctx.save_finding` in `tbhm.py`, tags
every finding as `lead` or `confirmed`:
- Heuristic phases (`business_logic`, `upload_race`, `access_control`,
  `cache_deception`, `smuggling`, `api_fuzz`, `backend_map`) and hedged titles
  (`possible`, `candidate`, `shaped`, `race-prone`, `accepted file`, …) → `lead`.
- Leads get a `[LEAD]` title prefix, are forced to LOW confidence, and receive a
  `validation_required` note.
- The executive summary counts confirmed and leads separately, computes posture
  from confirmed only, and keeps leads out of "top concerns".
- `finding_class` / `validation_required` persist via a new nullable `extra_json`
  column in `storage.py` and are rehydrated in `all_findings()`.

Nothing is hidden — leads still appear in the report; they are just no longer
presented as proven vulnerabilities.

## Files changed
- `phases/redteam_governance.py` (34-branch matrix + branch_matrix.json)
- `core/safe_writes.py` (global policy + wrappers)
- `phases/api_specific.py`, `phases/business_logic.py`, `phases/web3.py`,
  `phases/upload_race.py`, `phases/api_key_pivot.py` (gated writes)
- `core/diff_engine.py`, `core/verifier.py` (global gate on ctx-free helpers)
- `core/reporter.py` (branch-aware audit, lead/confirmed split, reproducer banner)
- `core/finding_class.py` (new)
- `core/storage.py` (extra_json column + rehydrate)
- `tbhm.py` (configure safe-writes; tag findings)
