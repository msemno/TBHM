# Platform audit — TBHM 4.2.0

The authoritative baseline was the previously delivered 4.1.0 ZIP (SHA256 `a63291ff61c8b2414ac57cf9a0b470158ab3a1a7c861487fff9186a008f5edde`). Its offline core installed successfully; all 41 original regression script groups passed before modification.

The Python CLI builds a profile/target/policy context, schedules phases, runs native checks or optional subprocess adapters, stores normalized findings in SQLite, applies proof contracts, generates role-oriented reports, and creates a redacted sealed delivery. The optional Go executor remains an execution backend; Python owns scheduling and evidence classification. Portable AI state remains separate from the tool folder. Existing SQLite entity graphs, rule catalogs, adapters, proof contracts and report machinery were reused.

The source contains 441 baseline / 450 current argparse actions and 145 dispatched phase names. The extended catalog has 507 registrations; it is not a list of 507 working detectors and excludes some older core integrations. The capability registry grows from 16 to 22 bounded capability records. Original paths/options/phase names are retained; changed content is recorded in PLATFORM_AUDIT.json. No new runtime dependency is added to the ten pinned core packages.

## Material findings and changes

| Finding | Baseline behavior | 4.2.0 behavior | Remaining limit |
|---|---|---|---|
| Python taint | Reassignments retained taint; broad escape matching hid paths; argv subprocess calls appeared as shell injection | Conservative branch/loop/exception joins, overwrite kills, narrow whole-value numeric controls, shell semantics | Intra-procedural approximation; aliases, closures and library effects remain incomplete |
| Flow association | A nearby AST flow could be attached to a different CWE/sink | Same-line/CWE association and stored source location | Regex-only candidates remain visible |
| Catch-all filter | Matching status or broad hex normalization could suppress different responses | Exact response-body matching and per-run reset | Dynamic wildcard pages may remain inconclusive |
| Attack paths | Flag did not gate output; unrelated assets/single records could satisfy several steps; synthetic chain findings raised reported severity | Exact asset grouping, distinct records, explicit hypotheses and no new synthetic vulnerability findings | No verified precondition/transition graph planner |
| Web3 | Ordinary 64-hex/12-word text matched secrets; raw urllib fetch escaped Requests boundary; read APIs labeled HIGH | Assignment context/redaction, brokered scoped GETs, ordinary read APIs INFO, bounded Slither import | No native contract compiler, symbolic execution, fuzzing or BIP39 validity proof |
| Model triage | Response IDs allowed all selected batches and model values could fill main metadata | Current-batch IDs, duplicate/omission checks, advisory metadata, grounded optional refutation | Model semantic accuracy not benchmarked; comments remain untrusted data |
| Android | Rough exported regex ignored permission context | Decoded component/permission/SDK/deep-link inventory with unknown states | AAPT component semantics and runtime permission enforcement not implemented |
| Offline/HTTP | Early maintenance branches could download before policy; rate errors lacked shared cooldown | Explicit offline maintenance conflict and shared broker cooldown | Child process/browser traffic is not globally metered or universally sandboxed |
| Workflow | Several local flags needed a fake target/manual subset; code repository attribute names were wrong | Additive target-free source/mobile/API/import phase composition | Explicit --phases overrides automatic selection |

## Audit and runtime limits

All Python modules are parsed/imported by the release validator. Focused source review and behavioral fixtures cover the changed boundaries, proof/storage/report lifecycle and representative local workflows. This is not an independent penetration test or a line-by-line audit of every legacy module. Real provider credentials, public targets, mobile devices, firmware emulation, cloud accounts, production WAFs and deployed smart contracts were not used. Optional scanner installation, upstream command compatibility and full detector quality remain separately testable dependencies.

The existing strict confirmation contracts cover only access control, sensitive-data exposure and open redirect. Other detector classes can produce leads; scanner text and model output cannot self-confirm them. Generated reports and graph associations do not supply missing runtime evidence. Hash manifests provide integrity rather than independent authenticity.
