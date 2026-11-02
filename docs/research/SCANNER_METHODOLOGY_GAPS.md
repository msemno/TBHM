# Scanner methodology review

| Methodology | Actual supplied execution evidence | Corrected behavior | Remaining requirement |
|---|---|---|---|
| Source analysis | Omarchy 29 code_scan + 88 code_intel observations; no proof executions | Source evidence retained; synthetic local target excluded from live-base mapping | Owned application runtime and entrypoint controls |
| Recon | Verisk partial DNS/HTTPX; 48 reported live URLs | Partial results labelled; -json contract; exact intake and scope filters | Actual versions/stderr and filtered candidate files |
| URL collection | Verisk 73,657 retained URLs; killed Katana with partial URLs | Query boundary before collection; deterministic downstream scope filter | Archive source coverage is not live test coverage |
| JS analysis | Live Nation 37 lexical paths + five map references | Regex exec is not shell exec; runtime-aware sinks; explicit leads | Browser reachability and execution-context controls |
| Content discovery | Timeout/cancel evidence; no complete Verisk result set | Phase deadline, cancellation, scoped input, stale-file removal, partial parser | Real ffuf version/response fixtures on Kali |
| Template scanning | Nuclei timeouts plus external atlassian leads | Preserve partial evidence, classify invocation failures, typed parser errors | Real nuclei binary/Go/templates compatibility |
| Curl probes | 43 findings, only positive-signal test rows; no response_raw | Metered attempt ledger and sanitized response artifacts | Class-specific assertions and repeat/control proof |
| Auth/MFA | Passive URL patterns and heuristic auth observations | Exact hostname attribution and lead status | Valid owned sessions, roles, tenant and MFA-flow controls |
| Business logic | 35 heuristic leads, no strict attempts | Preserved as leads; missing-proof status made explicit | Approved workflow-specific invariants and actors |
| SQLi/XSS/SSRF/SSTI | Phase selection/tool attempts do not prove completed control tests | Existing scope/write/proof contracts retained; false browser SQL/shell signals removed | Vulnerable/patched application controls for each actual execution path |
| API authorization | No supplied run has complete assertion/proof input | Existing strict BOLA/access-control/BFLA producers tested with local owned fixtures | Original targets' controlled identities, objects and permission plan |
| Cloud/mobile/network | Many prerequisite returns; unavailable tools/import workflows | Nmap XML host fix; explicit GCP project; MobSF upload remains submission | Live cloud credentials/project scope; mobile device analysis separately authorized |
| Learning | Deferred queue with zero updated vectors in Live Nation | Bounded, checkpointed homogeneous vector maintenance | Actual AI database/cache/model lock and retrieval benchmark |

No methodology is expanded by inventing a strict verifier. The existing six
classes remain authoritative. Static, imported and LLM observations cannot confer
confirmation. Related findings are grouped for review without deleting their IDs.
