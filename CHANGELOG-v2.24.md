# TBHM v2.24 — Full playbook alignment: interface coverage + objective taxonomy

Additive to v2.23. **No phase, detection, template, or feature was removed.**
Two new phases and a handful of wiring changes close the remaining gaps between
the field playbook (`authorized_red_team_master_playbook_2026 … ADDITIVE …
EXECUTION_CARDS.md`) and what TBHM automates or tracks.

## 1. New phase: `interface_probe` (read-only interface/identity discovery)

`phases/interface_probe.py` adds the protocol/identity interfaces the playbook
calls out that TBHM did not yet probe. Every check is **GET / OPTIONS / gRPC
reflection only** — no mutating request, no credential guessing, no data pull.

| Interface | Playbook ref | Branch | What it does |
|---|---|---|---|
| gRPC server reflection | §42.3 | BR10 | `grpcurl list` on scoped host:port (default 443,50051; `--interface-grpc-ports`). Flags reflection-enabled servers + service list. |
| Socket.IO transport | §42.4 | BR10 | Reads the Engine.IO open handshake (`/socket.io/?EIO=4&transport=polling`). |
| AsyncAPI spec | §42.5 | BR10 | Discovers a public AsyncAPI document (event/channel map). |
| JSON:API + host-meta | §42.6 | BR10 | Detects `application/vnd.api+json` and `.well-known/host-meta` (RFC 6415). |
| SAML / SSO metadata | §47 SAML | BR30 | Finds federation descriptors / EntityDescriptor endpoints. |
| SCIM provisioning | identity federation | BR30 | Detects SCIM 2.0 endpoints; distinguishes unauthenticated ServiceProviderConfig (MEDIUM) from correctly-protected (INFO). |
| MCP + shadow-MCP | §50 agentic/MCP | BR20 | Discovers MCP endpoints and warns when multiple are found (shadow-MCP reconciliation). |

**Not duplicated** (already covered, left untouched): SOAP/WSDL, XML-RPC, OData,
JSON-RPC, GraphQL variants (`phases/spec_scan.py`); WebSocket, SSE, LLM,
webhooks (`phases/api_specific.py`); OpenAPI/Swagger (`phases/spec_scan.py`).

## 2. New phase: `coverage_map` (full objective taxonomy ingestion)

`phases/coverage_map.py` embeds the **entire** playbook coverage skeleton
auto-extracted from Section 5 / 5B / additive appendices: **42 branch groups,
632 distinct sub-topics**. Previously governance tracked only the 34 branch
titles; the per-branch sub-topic breakdown from the .md was not represented in
the tool. Now it is.

It writes:
- `redteam/00_governance/objective_coverage_map.csv` — one row per (branch,
  sub-topic) with automation hint, mapped phases, phases-with-evidence, status.
- `redteam/00_governance/objective_coverage_map.json` — machine-readable summary.
- Additively enriches `branch_matrix.json` with each branch's `subtopics` list
  and `subtopic_count` (existing keys untouched).

A `SUBTOPIC_PHASE_MAP` cross-references which automated phase(s) exercise which
sub-topic; a sub-topic is marked `Tested (partial, automated)` only when a
mapped phase actually produced evidence this run. Untouched sub-topics are
`Not Tested — manual/checklist only`. **Nothing is ever marked "Safe."**

## 3. Reporter: objective-level coverage in the audit

`core/reporter.py`:
- `METHODOLOGY_AUDIT.md` now prints an **Objective-level coverage** section
  ("N/632 sub-topics have automated evidence; the rest are manual") beneath the
  existing 34-branch table, sourced from `objective_coverage_map.json`.
- `interface_probe` → BR10 and `coverage_map` → BR02 added to the phase→branch
  map so their findings fold into branch status.

## 4. Wiring

- `tbhm.py`: `interface_probe` registered after `api_specific`; `coverage_map`
  registered before `report` (so it sees all findings) and added to
  `REDTEAM_PHASES`. New `--interface-grpc-ports` argument.
- `profiles/authorized_redteam.yaml`: both phases added to the explicit list
  (this profile hard-codes its phases, so PHASE_ORDER alone was not enough).
- `core/storage.py`: `playbook_branch` now persisted in `extra_json`.

## Safety

All additions are read-only / evidence-oriented, consistent with the playbook's
non-destructive mandate and the v2.23 global safe-writes gate. No credential
theft, persistence, exploitation, DoS, OT/ICS writes, or key extraction was
added. Objective statuses remain in the seven-value vocabulary — never "Safe".

## Files changed
- `phases/interface_probe.py` (new)
- `phases/coverage_map.py` (new)
- `tbhm.py` (register phases, new CLI arg, version bump)
- `profiles/authorized_redteam.yaml` (phase list)
- `core/reporter.py` (audit objective-level section + phase map)
- `core/storage.py` (persist playbook_branch)
