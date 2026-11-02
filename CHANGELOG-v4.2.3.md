# TBHM 4.2.3 — additive research capabilities

Implementation baseline: **4.2.2**. All 145 phase names/order and the 452 existing
CLI argument signatures are retained; nine opt-in arguments bring the total to
461. SQLite DDL, the controller's dispatch functions/classes (apart from the
new opt-in parser declarations), Runner/Ctx,
scope/rate gates, offline isolation and proof-v2 code are unchanged. No runtime
dependency, scanner bundle or model weight was added.

## New opt-in capabilities

1. **Brokered read-only HTTP replay:** explicit native and socket-isolated
   `pipe-v1` requests share transactional request-slot, accepted decoded-body and
   host-cooldown accounting. Shared pacing and counters work across ledger users.
   The parent broker owns HTTP; the packaged child exchanges only approved request
   IDs and cannot open sockets. Requests still use existing TBHM URL scope,
   program/method/rate controls, TLS validation and redirect refusal. Unsupported
   arbitrary scanners/browser drivers fail before launch. Incomplete replay keeps
   its ledger/report and fails the phase. This capability does **not** meter all
   legacy traffic or all wire bytes.
2. **Prior-delivery privacy audit:** verify a prior sealed snapshot, scan supplied
   canary encodings in raw/SQLite bytes and bounded ZIP/tar/gzip contents, and
   report unknown formats/budgets as incomplete. No extraction, source rewrite or
   raw canary value occurs. `--require-private-delivery` blocks on fail/incomplete.
3. **LLM security evidence import:** normalize documented Garak evaluation counters,
   Promptfoo boolean assertion results and a reviewed-export schema. Provider
   errors, missing/contradictory grades and unscoreable cases stay unresolved.
   Imported scores, model judgments and jailbreak text never produce proof receipts.
   Optional taxonomy annotations are pinned to the 2025 research edition, not
   framework coverage or latest-edition certification.
4. **Learning corpus hygiene:** audit operator-declared reuse permission, license/
   data-use basis, human labels, sanitized-text review hashes, and cross-split
   project/root-cause/content leakage. Technical validity and program outcome stay
   separate. Optional reviewed training records become fenced, untrusted retrieval
   cards. Re-auditing revokes unchanged generated cards when permissions/labels
   change; manually modified/untracked files block regeneration. No model training
   or installable agent skill is created.

New inputs select a narrow set of existing phases. An explicit `--phases` override
remains authoritative. All new arguments and typed capabilities are off by default.

## Evidence and preserved flow

- New unit/CLI tests exercise the real isolated child, shared quotas, denied
  origins/ports, cooldown, decompression/format uncertainty, import schema errors,
  rights and split leakage, permission revocation, and normal sealed reporting.
- `knowledge/flow_contract_v422.json` protects the original controller functions,
  key core file hashes, and original phase behavior after opt-in hooks.
- Existing research ledgers are extended rather than discarded; current decisions,
  fixture outputs, source inventory, writer review status and deferred work are
  under `docs/research-v4.2.3/`.

## Gates remaining open

Global online child/browser/native wire metering, full sensitive-writer/opaque
format closure, additional vulnerability-class proof contracts, attributable
public OAST confirmation, admin/tenant/reversible-write workflows, representative
field calibration and full standards coverage remain open. The supplied spec
simultaneously requests proof-pipeline expansion and forbids changing it; this
release honors the preservation contract and leaves new confirmation classes
unimplemented. It also preserves exact phase equality instead of appending phases.

There is no new live-target, bounty acceptance, model-quality or payout claim.
See `docs/UPGRADE-v4.2.3.md` and measured `VERIFICATION.json` before use.
