# 4.2.4 engineering review

The actual 4.2.3 distribution is the implementation baseline. Its 682 manifest
entries were verified with no mismatches; archive SHA-256 is
`0fab069eff205fff26872f376928d28869ed15d8802088862c8447327bdd950e`.
`BASELINE_STATE.json` records every path/hash and the Python top-level symbol
inventory. The baseline passes 58 regression groups and 312 unittest cases.
The available working tree is a source distribution, not an external Git checkout.
Development used a separate 4.2.4 copy and retained the baseline intact.

The new attachment explicitly permits compatible proof-engine growth. It
supersedes the former hash freeze and exact-phase-equality acceptance rule.
`INPUT_REGISTER.json` binds the supplied specification. The earlier six inputs,
research/tool decisions, changelogs, upgrade guides and unresolved work remain
in the package. Product claims in research remain unverified unless separately
supported; no accepted bounty/payout or vendor-performance assertion is adopted.

## Ownership and changes

| Component | Implementation / acceptance |
|---|---|
| Controller/phase order | `tbhm.py`, existing import/registration; only opt-in parser declarations and one guarded existing-phase call added. Canonical 145-entry phase/CLI manifest extracted from the real baseline |
| Runner/Ctx/storage | Existing code and SQLite DDL unchanged. Baseline-created database row IDs, target, evidence and run metadata survive opening; disabled new options preserve the prior resume fingerprint |
| Proof authority | `core/proof_contracts.py`, `core/assertion_engine.py`, `core/finding_class.py` gain additive extension points; 42 executed old vectors retain outcomes, flags, reasons and receipts |
| New class semantics | `core/strict_classes_v424.py`; dedicated controlled traversal and owned-role read-function BFLA. Missing/invalid/unstable evidence remains inconclusive |
| Reachable execution | `core/strict_replay.py` through `controlled_validation_plane`; scoped, approved GETs produce actual signed captures, attempts, findings, graph and sealed reports |
| Native traffic | Existing Requests/HTTP policy remains; explicit pinned transport adds resolved-address validation and numeric connects for the supported workflows |
| External/browser/Go | Existing optional adapters and offline syscall filter retained; their online traffic is not claimed to enter the pinned ledger |
| Evidence delivery | Existing raw/sanitized snapshot separation unchanged; prior-delivery audit gains supported encodings and bounded container types |
| Correlation | Existing graph keys/IDs retained; additive observation associations, never confirmed exploit chains |
| LLM | Existing untrusted evidence, structured IDs, advisory confirmation boundary and corpus rights/split/revocation protections retained; no new model privileges or weights |
| Reporting/compliance | Normal reports/operator page and proof restoration exercised end-to-end. No new full standards-coverage claim or automatic CWE/CVSS severity escalation |
| Build | Central version, installer, SBOM, manifests and complete package; unchanged offline dependency set and platform baseline |

## Reproducible corrections

`SECURITY_CORRECTIONS.json` records exact commands/return codes against both
versions: three failing cases in 4.2.3, all cases pass in 4.2.4. The shared-cooldown case
uses a real oversized HTTP 429 response and a fresh context. The graph case shows
that imported JSON-style flags could set `proof_verified`. Header-time cooldown
and receipt-based graph/operator authority fix these independently. The third canary-name
test already passed in the baseline; it is retained as a regression, not called
a newly fixed defect.

No valid existing proof semantics were intentionally changed. The new-class
router leaves the three original class implementations intact. New `ControlHeld`
results apply only to complete, stable explicit denials under new class contracts.
Invalid signatures, missing controls, expired privileged identities, public
function controls and inconsistent repeats are never interpreted as clean.

## Research and integration choices

The release improves the existing Requests integration and evidence model instead
of bundling overlapping scanners. `INTEGRATION_REVIEW.csv` records file-level
overlap, optional dependency, scope/offline compatibility, trust, resource and
distribution limitations for the requested Nuclei/ZAP/Burp/Semgrep/CodeQL/MobSF/
EMBA/Slither/Foundry/BBOT review. A textual code reference is not a tested vendor
runtime. The historical tool ledger is preserved and extended.

Relevant primary references checked:

- [MITRE CWE-22](https://cwe.mitre.org/data/definitions/22.html) for restricted-directory traversal terminology.
- [MITRE CWE-862](https://cwe.mitre.org/data/definitions/862.html) for missing function authorization terminology.
- [urllib3 2.8 advanced usage](https://urllib3.readthedocs.io/en/stable/advanced-usage.html) for hostname/SNI/certificate separation. The exact bundled Requests 2.34.2 / urllib3 2.8.0 source was inspected; actual TLS fixtures test the integration.

These are terminology/transport references, not certification of detection
coverage. No source text or proprietary tool code was copied into the runtime.

## Measured scope and remaining limits

`benchmarks/paired_evaluation.json` compares the same authenticated captures with
both releases for four local vulnerable/patched cases. The baseline has no
audited contract for the new labels and abstains; the candidate confirms the
vulnerable cases and records stable control-held results for the patched cases.
Those results measure confirmation on these fixtures. They do not establish
discovery recall, independent held-out field performance or zero false positives.
Repeat captures are not counted as extra samples. Conditional metrics, abstention
counts, full-denominator bounds and descriptive intervals are explicit.

No authorized model dataset/runtime or representative independently labeled
field corpus was available. Real-model RAM/VRAM/latency/quality and training are
not measured or fabricated. No new weights or mandatory dependency is bundled.
Existing optional/local runtime choices remain unchanged; this release does not
increase the user's workstation model memory requirements.

Global online containment, full writer closure and the remaining proof classes
are still acceptance gates for broader automation. They do not receive blanket
COMPLETE status from passing the supported incremental workflows. Matrices and
`ROADMAP.md` state these boundaries explicitly.
