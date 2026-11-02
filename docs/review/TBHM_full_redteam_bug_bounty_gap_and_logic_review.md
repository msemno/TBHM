# TBHM v3.9.7.3 — Full Red-Team and Bug-Bounty Gap Review

## Scope of this review

This is a static/offline architecture and logic review of the supplied TBHM ZIP. I reviewed the entry point, profiles, 129 ordered phases, capability registry, finding classification, false-positive filtering, verification, exploitability assessment, coverage accounting, storage, evidence handling, reporting, and representative web/API/mobile/AI/AD/IoT/reverse-engineering phases.

This review does **not** execute live scans, exploitation, payloads, target binaries, or firmware.

---

# 1. Executive verdict

TBHM is already a broad and serious **security assessment orchestration, evidence normalization, triage, and reporting platform**. It has strong foundations in:

- Authorization and scope gates
- Multi-domain phase orchestration
- External-tool adapters
- Evidence redaction
- False-positive archiving
- Lead/supported/confirmed report separation
- Static code, mobile, firmware, network, cloud, AI, and web coverage
- Multiple report formats and per-finding evidence kits

However, it is **not yet a full red-team platform**, and it is **not yet a complete autonomous bug-bounty hunter**.

The main reason is not the number of phases. The main issue is that TBHM currently mixes five very different things under a common “finding” concept:

1. Coverage/control records
2. Asset observations
3. Heuristic candidates
4. Tool-imported alerts
5. Reproduced vulnerabilities

A full platform needs separate databases and state machines for:

- **Tests performed**
- **Observations collected**
- **Candidate hypotheses**
- **Validation attempts**
- **Confirmed vulnerabilities**
- **Attack-path or campaign objectives**
- **Reports and retests**

The highest-priority redesign is therefore the **finding engine and evidence model**, not a language rewrite.

---

# 2. What TBHM currently is

## 2.1 Current architectural identity

TBHM currently behaves as a Python control plane that:

1. Parses targets, profiles, and authorization options.
2. Builds scope allow/deny rules.
3. Runs a fixed ordered list of phases.
4. Calls internal Python logic and external security tools.
5. Converts outputs into a common finding dictionary.
6. Applies scope, eligibility, and false-positive gates.
7. Persists redacted findings to SQLite.
8. Enriches them with exploitability, intelligence, and attack-path text.
9. Produces executive, technical, confirmed-only, leads-only, SARIF, CSV, JSON, HTML, and per-finding kits.

## 2.2 Current phase scale

The reviewed build contains:

- **129 ordered phase modules**
- **86 phases that call `save_finding()`**
- **28 phases that make direct HTTP requests**
- **27 phases with identifiable external-tool execution**
- **26 centrally classified heuristic/import-oriented phases**

A machine-generated inventory of every phase, its functions, direct HTTP methods, external tools, safety flags, and finding behavior is supplied separately as `TBHM_phase_logic_inventory.csv`.

## 2.3 Current execution model

The phase engine runs modules sequentially:

```text
for each phase in PHASE_ORDER:
    import phase
    run phase
    record phase time/state
```

This gives deterministic execution and easy resume behavior, but it does not model:

- Phase dependencies as a graph
- Parallel independent work
- Resource classes
- Per-target queues
- Per-protocol queues
- Test-case state
- Backpressure
- Cancellation propagated to all child processes

---

# 3. Current structure before a finding exists

The following is the tool’s current practical pre-finding flow.

```text
CLI / profile / target list
        ↓
Authorization confirmation
        ↓
Scope include/exclude construction
        ↓
Toolchain and capability checks
        ↓
Sequential phase execution
        ↓
Recon / imported evidence / static analysis / active probe
        ↓
Phase-specific condition or heuristic matches
        ↓
Phase constructs a generic finding dictionary
        ↓
ctx.save_finding(...)
```

## 3.1 Input and governance logic

TBHM receives combinations of:

- Targets or target lists
- Scope allowlists and exclusions
- Bug-bounty program URL as audit metadata
- Profiles such as passive, authorized-safe, full, red-team, or assumed-breach
- Optional code, binary, firmware, mobile, cloud, AD, and external-tool evidence
- Flags controlling payloads, writes, secret validation, and high-risk actions

For active profiles it requires explicit user authorization. Its stated hard limits prohibit destructive payloads, denial of service, real data exfiltration, credential theft, persistence, and similar activities.

### Missing here

The bug-bounty program URL is recorded but not converted into a complete machine-enforced policy. A mature program-policy layer should parse and store:

- Exact in-scope asset types
- Wildcard semantics
- Out-of-scope subsidiaries and third parties
- Eligible vulnerability classes
- Explicitly excluded classes
- Rate limits
- Automation restrictions
- Authentication restrictions
- Data-access and privacy limits
- Safe-harbor language
- Disclosure requirements
- Per-program report fields
- Testing windows and emergency contacts

## 3.2 Asset and surface discovery logic

Current discovery uses a combination of:

- DNS/subdomain and external reconnaissance
- Alive-host checks
- Port/service enumeration
- URL collection
- JavaScript URL extraction
- Stateful crawling
- Forms and parameter collection
- API/spec discovery
- Cloud and management-surface hints
- Imported scanner output
- Source, mobile, firmware, and binary artifacts

The crawler creates an application graph containing observed methods, parameters, content types, status codes, and forms. Endpoint scores are then used by selected phases to prioritize work.

### Missing here

The graph is URL-centric rather than **workflow-centric**. It needs first-class nodes and edges for:

- User identities and roles
- Tenants and organizations
- Objects and object ownership
- Session and token states
- CSRF state
- Multi-step transactions
- Preconditions and postconditions
- Mobile deep links and app screens
- WebSocket/gRPC subscriptions and streams
- Background jobs and asynchronous callbacks
- File creation, processing, and serving lifecycle
- LLM agents, tools, data stores, and trust boundaries

## 3.3 Endpoint prioritization logic

The existing endpoint score combines concepts such as sensitivity, authentication, input, state mutation, and exposure. It is useful as a queue hint.

### Missing here

The score should not decide vulnerability status. It should only decide **what test to run next**. Add separate dimensions:

- Expected bounty value
- Program eligibility
- Novelty/duplicate likelihood
- Test cost
- Side-effect risk
- Required identities
- Required environment
- Confidence that the endpoint is actually reachable in the current session
- Prior test coverage
- Technology-specific relevance

---

# 4. How TBHM currently “thinks” about finding vulnerabilities

TBHM does not have one vulnerability-discovery algorithm. It uses several logic families.

## 4.1 Pattern and shape heuristics

Examples:

- Numeric or UUID paths look like possible IDOR targets.
- Endpoint names such as `coupon`, `withdraw`, or `purchase` look race-sensitive.
- Payment/cart paths look suitable for price or quantity manipulation.
- Mobile/API hostnames are flagged for additional attention.
- Management ports or device signatures are labeled as risky surfaces.

### Value

Good for prioritization and generating a test plan.

### Limitation

A shape is not a vulnerability. These records should be `candidate_hypothesis` objects, not vulnerability findings.

## 4.2 Baseline-and-differential active testing

The strongest native web logic is in the `audit` phase:

1. Collect three baseline responses.
2. Discover insertion points.
3. Apply a vulnerability-specific mutation.
4. Compare status, body, length, timing, errors, and similarity with the baseline.
5. Retest suspicious mutations.
6. Save a high-confidence record.

It includes checks for:

- SQL injection
- Reflected XSS indicators/context
- SSTI arithmetic behavior
- Path traversal signatures
- Time-based command injection
- OAST-assisted SSRF

### Value

This is the correct general architectural pattern.

### Limitations

- It mainly audits GET-oriented URLs.
- It does not replay complete captured POST/JSON/multipart/browser requests as the primary workflow.
- Generic score repetition is sometimes treated as verification instead of checking the vulnerability’s exact assertion.
- XSS reflection does not necessarily prove browser execution.
- Timing checks require stronger controls for network jitter and paired control payloads.
- Stateful business workflows are not modeled.

## 4.3 Direct response-indicator checks

Many phases send one or a small number of requests and look for:

- A reflected canary
- A status code
- A header combination
- A schema marker
- A known error string
- A timing change
- A known file signature
- An endpoint accepting a method/body

### Value

Useful for screening.

### Limitation

The meaning of the response must be vulnerability-specific. Examples of current overreach include:

- A live URL does not verify an existing vulnerability.
- GraphQL introspection is usually an exposure/configuration observation, not automatically a vulnerability.
- An LLM repeating a user-provided canary does not by itself prove prompt injection; normal chat systems are expected to follow user instructions.
- A duplicate HTTP parameter being reflected does not by itself prove authorization or WAF bypass.
- A webhook accepting an unsigned-looking request does not prove it processed a trusted event.
- A CORS header pair on a generic endpoint does not prove authenticated sensitive data is readable from a browser origin.

## 4.4 Static-analysis logic

The code, mobile, firmware, and reverse-engineering phases use combinations of:

- Keyword/pattern matching
- Secret detection
- Manifest/plist analysis
- Strings extraction
- File metadata
- Imported SAST/SARIF/scanner results
- Static taint or route-reachability support in selected code-intelligence paths
- External reverse-engineering tool adapters

### Value

Strong breadth, especially with false-positive context handling for tests, documentation, placeholders, manifests, and scanner source files.

### Limitation

Static evidence needs a structured distinction between:

- Source/sink occurrence
- Reachability
- User control
- Sanitizer effectiveness
- Runtime path existence
- Deployed-version correspondence
- Exploitability

## 4.5 Imported-tool logic

TBHM can normalize output from various external tools. The central classifier correctly treats many imported sources as leads unless separately verified.

### Missing here

Each adapter needs a declared evidence contract:

```text
adapter_id
adapter_version
rule_id
source artifact hash
original severity/confidence
normalized weakness
runtime vs static
proof type
known false-positive conditions
verification requirements
```

## 4.6 Correlation and attack-path logic

The tool enriches findings with possible access paths and can produce attack-path narratives.

### Limitation

Much of the correlation is based on free-text titles, evidence, phase names, and regex. A reliable attack graph needs structured entities and verified edges such as:

- Identity A can authenticate to service B
- Role A can read object class C
- Host A can reach service B on port P
- Credential X is valid for principal Y
- Principal Y has permission Z
- Vulnerability V changes privilege from state S1 to S2

## 4.7 AI logic

The local AI plane is advisory and non-authoritative, which is the correct safety boundary.

### Missing here

The AI should reason over structured test/evidence objects and cite exact artifact hashes. It should never infer confirmation from prose. Its roles should be limited to:

- Test-plan suggestions
- Evidence summarization
- Similarity/duplicate hints
- Missing-control identification
- Report wording
- Human-review prioritization

---

# 5. Current finding-save logic

When a phase calls `ctx.save_finding(finding)`, the current pipeline is approximately:

```text
1. Add defaults: phase, severity, confidence, timestamp
2. Determine whether it is special exercise evidence
3. Enforce network scope at persistence boundary
4. Apply HackerOne Core-ineligible suppression unless overridden
5. Run centralized false-positive filtering
6. Optionally validate secrets live
7. Apply lead/supported/confirmed classification
8. Pass to storage
9. Redact sensitive material
10. Apply an additional noise filter
11. Attach a curl reproducer when possible
12. Generate fingerprint and deduplicate
13. Insert into SQLite
14. Log FIND event
```

## Strengths

- Out-of-scope records are blocked at persistence.
- Dropped records are archived rather than silently lost.
- Sensitive values are redacted before persistence.
- Imported and heuristic phases are generally kept out of confirmed reports.
- Reproducers and per-finding kits improve triage usability.

## Problems

### 5.1 Scope enforcement occurs too late for network safety

A direct `requests.get/post` can already follow or contact an unintended location before the persistence gate rejects the record. Scope must be enforced **before every network hop**, including redirects, DNS resolution changes, callbacks, and imported URL follow-up.

### 5.2 Bug-bounty eligibility is hardcoded too globally

The central logic includes HackerOne Core-style ineligibility rules. Programs differ. Eligibility must be attached to a specific program policy and should not be a universal security truth.

### 5.3 False-positive filtering and confirmation are too prose-dependent

The classifier can infer confirmation from:

- High confidence
- Evidence words such as `verified`, `reproduced`, or `introspection enabled`
- Generic presence of `response_raw`

A response body merely proves that a request received a response. It does not prove the security assertion.

### 5.4 Deduplication is too payload/phase-specific

The fingerprint includes target, URL, method, parameter, payload, title, and phase. Therefore the same root cause can survive as multiple records when found by:

- Different payloads
- Different phases
- Different tools
- Slightly different titles

Use two keys:

1. **Observation fingerprint** — exact test/payload/evidence.
2. **Root-cause fingerprint** — asset + endpoint/component + weakness + security boundary + affected operation.

### 5.5 Severity is assigned too early

Many phases hardcode severity before confirmation and before business context. Severity should be calculated after:

- Proof state
- Privileges required
- User interaction
- Scope change
- Confidentiality/integrity/availability impact
- Number/type of affected users or tenants
- Business flow
- Program-specific rating rules

### 5.6 CVSS derivation is circular

The current CVSS helper starts with the phase-assigned severity and maps it to a generic vector. A proper process starts with vector metrics and derives the score, not the reverse.

---

# 6. Current logic after a finding is saved

The post-finding pipeline contains:

```text
Stored finding
    ↓
curl_verify
    ↓
verify / shadow replay
    ↓
exploitability assessment
    ↓
vulnerability intelligence enrichment
    ↓
attack-path narrative/correlation
    ↓
false-positive review and dashboard
    ↓
confirmed / supported / lead report grouping
    ↓
per-finding evidence kits
    ↓
evidence manifest/finalization
    ↓
optional local AI run analysis
```

## 6.1 `curl_verify` does not verify the original vulnerability

For existing high/critical findings it performs a generic GET to the URL and counts the record as live when the URL returns a nontrivial response. It does not replay the original method, headers, body, role, parameter mutation, or assertion. It also does not persist a proper `verified=true` result.

This is **endpoint liveness**, not vulnerability verification.

## 6.2 `verify` / shadow replay does not evaluate the vulnerability assertion

It reissues requests and records status, length, and snippets. It does not compare the result to the original proof condition and does not update the finding’s verification state.

## 6.3 Exploitability assessment is useful but text-driven

The exploitability layer derives possible access from regex over titles/evidence and creates PoC/impact/remediation/retest text. It improves report structure but cannot substitute for a proof object.

## 6.4 Report grouping is better than the underlying evidence model

The reporter separates:

- Confirmed vulnerabilities
- Supported findings pending final verification
- Unconfirmed leads and observations

That is good. But the classification engine needs stronger inputs; otherwise the report can be polished while the underlying proof remains ambiguous.

---

# 7. The correct vulnerability-finding logic

A finding engine should be based on a **security assertion**, not a suspicious response.

## 7.1 Required state machine

```text
PLANNED_TEST
    ↓
EXECUTED_TEST
    ↓
OBSERVATION
    ↓
CANDIDATE_HYPOTHESIS
    ↓
SUPPORTED
    ↓
INDEPENDENTLY_VALIDATED
    ↓
CONFIRMED_VULNERABILITY
    ↓
TRIAGED / REPORTED
    ↓
RETESTED
    ↓
CLOSED | REOPENED | ACCEPTED_RISK | DUPLICATE | N/A
```

These should be records in different tables or explicit typed objects. Do not use title wording to move between states.

## 7.2 A test must declare its assertion before execution

Example abstract assertion:

```text
Given:
  identity=A, role=member, tenant=T1
  object=O2, owner=B, tenant=T2
When:
  operation=GET /resource/O2
Then expected:
  access denied and no protected fields returned
Failure condition:
  2xx plus object identity O2 plus protected field set
Negative control:
  identity=A requesting A-owned object succeeds
```

The verifier then checks that exact condition. This works for authorization, injection, mobile, cloud, AI-agent, and internal-network tests.

## 7.3 Required proof bundle

A confirmed vulnerability should require:

- Test case ID and version
- Exact asset and scope decision
- Baseline request/response hash
- Mutation request/response hash
- Expected security invariant
- Observed invariant violation
- Negative control result
- Repetition count
- Identity/role/tenant context
- Timing/jitter data where relevant
- OAST interaction ID where relevant
- Side effects and cleanup status
- Independent verifier ID/method
- Evidence artifact hashes
- Human reviewer decision when impact is sensitive

## 7.4 Vulnerability-specific verifier plugins

Every weakness class needs its own verifier. Examples:

- **BOLA/IDOR:** confirm cross-object access, ownership mismatch, protected data, and a valid own-object control.
- **BFLA:** compare same operation across role identities and confirm a privileged state/action.
- **Mass assignment:** confirm the unauthorized property was persisted and changes an authorization/business decision.
- **Race condition:** show a violated invariant from synchronized attempts, with sequential control and cleanup.
- **XSS:** prove execution in the intended browser context and origin; reflection alone is a lead.
- **SQL injection:** prove deterministic boolean/error/time/OAST behavior with paired controls.
- **SSRF:** require a correlated out-of-band interaction or a controlled internal-resource difference.
- **File upload:** prove storage, serving/parsing behavior, content handling, access control, and cleanup.
- **CORS:** prove a browser origin can read a sensitive authenticated response.
- **GraphQL:** introspection alone is exposure; prove an authorization, batching, complexity, or data-boundary impact.
- **LLM prompt injection:** prove that untrusted data or user input overrides a higher-trust instruction or causes an unauthorized disclosure/tool action. Echoing a requested word is not sufficient.
- **Secrets:** prove the value is non-placeholder, belongs to the target, is deployed/reachable, and—only when authorized—has a valid status and bounded privilege.

---

# 8. What is missing for a complete bug-bounty hunter

## P0 — essential correctness gaps

### 8.1 Program-policy engine

Build a per-program policy object, not a global HackerOne eligibility filter.

Required logic:

- Parse scope tables and asset types
- Store exact source text and timestamp
- Resolve wildcard and apex semantics
- Track acquisitions/third parties/CDNs
- Define allowed automation and rates
- Define prohibited tests
- Define eligible/ineligible categories
- Define evidence/data-handling rules
- Block execution before network contact when policy is unclear

### 8.2 Authenticated request and browser workspace

Add:

- Import of Burp/Chrome HAR and raw HTTP requests
- Cookie/token vault with redacted report rendering
- CSRF token refreshers
- Browser contexts for separate identities
- Role and tenant labels
- Request replay with exact headers/body/content type
- Session expiry and re-auth hooks
- Browser-side proof capture

### 8.3 Two-account / multi-role authorization engine

The current IDOR logic mostly identifies shapes. A real engine needs:

- Account A/B/Admin/tenant contexts
- Object ownership discovery
- Object ID corpus per account
- Read/write/delete/action matrices
- Property-level authorization checks
- Function-level authorization checks
- Tenant-isolation checks
- Before/after state verification

### 8.4 Business-workflow model

Add a workflow DSL or graph for:

- Registration and verification
- Password reset and account recovery
- Invite and organization membership
- Checkout, coupon, credit, refund, wallet, transfer
- Subscription and entitlement
- File/document sharing
- Approval and moderation
- Booking/reservation
- Rate and quota consumption

Tests should express invariants such as “balance cannot become negative,” “coupon can be consumed once,” or “a user cannot approve their own request.”

### 8.5 Real verification engine

Replace generic URL liveness with assertion-specific validation and persist:

- `verified`
- `verified_at`
- `verification_method`
- `verifier_version`
- `negative_control_passed`
- `observed_delta`
- `artifact_hashes`

## P1 — coverage gaps

### 8.6 Full request-body coverage

Native audit should operate on captured requests and cover:

- Query parameters
- Path segments
- Form bodies
- JSON/XML
- Multipart
- Headers
- Cookies
- Nested objects and arrays
- Alternate content types

### 8.7 Client-side/browser security

Add browser instrumentation for:

- DOM XSS sinks and actual execution
- postMessage origin/validation
- Prototype pollution paths
- Client-side redirects
- CSP behavior
- Service workers
- Web storage/session leakage
- Source-map and bundle-to-source correlation

### 8.8 Modern API protocols

Expand from discovery probes to stateful testing of:

- GraphQL operations, object/property/function authorization
- WebSockets and authenticated message actions
- Server-sent events and stream authorization
- gRPC reflection plus method/request testing
- Async APIs, queues, webhooks, callbacks
- Version drift and undocumented operations

### 8.9 Race and concurrency test engine

Build a bounded, policy-gated synchronized request engine with:

- HTTP/1.1 and HTTP/2 strategies
- Barrier synchronization
- Sequential control
- State snapshot before/after
- Invariant evaluator
- Automatic cleanup
- Strict request and impact limits

### 8.10 File-upload lifecycle engine

Cover:

- Extension/MIME/content mismatch
- Storage location and retrieval
- Access controls
- Image/document parsing
- Archive extraction boundaries
- Filename/path handling
- Metadata handling
- Virus scanning workflow
- Signed URL lifetime
- Processing races
- Cleanup

### 8.11 Mobile dynamic testing

Current mobile support is mainly static/adapters. Add a device/emulator workflow mapped to mobile security controls:

- App install/launch state
- Proxy and TLS behavior
- Local storage at runtime
- Inter-process communication/deep links
- WebViews
- Runtime secrets/logs
- Authentication/session behavior
- Root/jailbreak handling
- Backend authorization using mobile identities

### 8.12 Duplicate and novelty system

Use root-cause clustering across:

- Paths and API versions
- Parameters and objects
- Scanner rules
- Similar response/proof deltas
- Historical submissions
- Fixed/reopened variants

### 8.13 Submission and triage workflow

Add program-specific export containing:

- Clear title
- Scope asset
- Weakness
- Prerequisites
- Exact reproduction
- Actual result
- Expected result
- Impact with demonstrated boundary
- Evidence attachments
- Suggested severity
- Privacy-safe cleanup statement
- Duplicate search notes
- Retest status

## P2 — advanced hunter intelligence

- Technology-specific test-plan generation
- Changelog/new-release diffing
- JavaScript/API diff across deployments
- Source-to-live endpoint correlation
- Parameter and object corpus learning
- Historical response clustering
- Target-specific wordlists
- Bounty-value/duplicate-risk prioritization
- Human decision feedback with calibrated confidence

---

# 9. What is missing for a full red-team platform

A full red-team platform must model objectives and adversary behavior across an engagement, not only vulnerabilities. TBHM currently covers many branches as inventories, safe checks, imported evidence, or manual catalogs, but intentionally excludes major active-adversary functions.

## 9.1 Threat-informed campaign model

Add a versioned model linking:

- Engagement objective
- Target assets and crown jewels
- Threat actor/emulation profile
- Techniques and sub-techniques
- Required prerequisites
- Detection expectations
- Approval level
- Evidence required
- Cleanup/recovery steps
- Outcome and control effectiveness

## 9.2 Separate controlled-execution plane

Do not put high-impact actions inside default bug-bounty profiles. Create a physically and logically separate, approval-gated execution plane for authorized lab or signed-statement-of-work engagements.

It should provide governance for—not automatic uncontrolled execution of—activities such as:

- Initial-access simulations
- Execution and privilege-transition validation
- Persistence-control validation
- Credential-control validation
- Lateral-movement path validation
- Command-and-control detection validation
- Collection/exfiltration simulations using inert canaries
- Impact/resilience exercises

Each action must have an approval record, time window, target list, stop conditions, telemetry expectation, and cleanup proof.

## 9.3 Session and operation management

Current session/beacon handling is import-oriented. A complete platform needs:

- Operation/campaign IDs
- Session inventory and ownership
- Host/user/identity context
- Task status
- Approval status
- Kill/stop control
- Cleanup status
- Evidence chain
- Separation of operator actions from AI suggestions

## 9.4 Identity and Active Directory depth

Current AD behavior is predominantly read-only inventory/import. Missing areas include structured, authorized validation of:

- Effective privilege paths
- Delegation and trust boundaries
- Service-account exposure
- Tiering violations
- Certificate and federation abuse paths
- Local-admin relationships
- Identity-to-cloud pivots
- Detection coverage for identity techniques

These should be implemented as controlled validators and graph edges, not as automatically executed attack chains.

## 9.5 Cloud/SaaS and non-human identities

Add native provider-aware models for:

- Effective IAM permissions
- Role assumption/trust relationships
- Service principals/workload identities
- Federation and conditional access
- Secrets and key lifecycle
- Cross-account/cross-tenant paths
- Public-to-private exposure paths
- Audit-log and detection validation

## 9.6 Detection and purple-team loop

A full red-team result is not merely “action succeeded.” It should answer:

- Was the action prevented?
- Was it logged?
- Was it detected?
- Was the alert routed?
- Did the analyst triage it correctly?
- How long did each stage take?
- Which telemetry fields were missing?

Add telemetry connectors, expected event schemas, alert correlation, and detection-gap findings.

## 9.7 Social, physical, wireless, OT/ICS, and hardware

Many of these are currently governance/checklist/passive/import branches. A full platform needs structured exercise records for:

- Approval and target population
- Safe pretexts and payload-free simulations
- Physical access observations
- Passive versus active wireless boundaries
- OT process safety and operator coordination
- Hardware/firmware lab procedures
- Evidence and restoration

## 9.8 Campaign cleanup and restoration

Every controlled action should have:

- Cleanup plan prepared before execution
- Artifact/session/account inventory
- Automated cleanup where safe
- Independent cleanup verification
- Client acceptance
- Residual-risk record

---

# 10. Domain-by-domain maturity assessment

| Domain | Current logic | Current maturity | Main missing capability |
|---|---|---:|---|
| Governance / ROE | Authorization prompt, profiles, scope gates, coverage taxonomy | Strong foundation | Machine-readable per-program/per-engagement policy and per-action approval |
| External recon / OSINT | Broad collection and tool adapters | Good | Asset ownership confidence, change tracking, novelty, redirect/DNS-rebinding-safe scope enforcement |
| Network discovery | Nmap/tool orchestration and service labeling | Good inventory | Protocol-aware authenticated assessment and test-level result records |
| AD / identity | Read-only discovery, imports, graph-oriented phases | Partial | Effective privilege validation, identity attack-path proof, detection loop |
| Web discovery | Crawl, URL/JS/form graph, scoring | Good | Workflow graph, browser state, request capture/replay |
| Web injection | Differential `audit`, scanners, payload phases | Partial-to-good | POST/body coverage, exact assertion verifiers, browser proof, robust timing controls |
| Authorization | ID-shaped heuristics, protected route checks, offline role matrix | Weak for proof | Two-account/multi-role object/property/function engine |
| Business logic | Endpoint-name heuristics and limited mutations | Weak | Stateful workflow invariants and before/after validation |
| API | Specs, fuzzing, GraphQL/interface hints | Partial | Stateful GraphQL/WebSocket/gRPC, BOLA/BOPLA/BFLA and sensitive-flow engine |
| Source/SAST | Native patterns plus adapters and FP context | Good triage | Uniform taint/reachability/deployed-version contracts |
| Supply chain / CI/CD | Review and imported tooling | Partial | Provenance graph, pipeline identity/permission paths, runtime linkage |
| Mobile | Static APK/IPA/source checks and MobSF adapter | Partial-static | Dynamic device/emulator workflow and backend authorization correlation |
| Reverse engineering | Static triage plus tool adapters and imported dynamic evidence | Good orchestration | Unified normalized IR/dataflow, managed sandbox, dynamic-to-static mapping |
| Firmware / IoT | Binwalk/strings and service inventory | Partial | Structured extraction graph, emulation lifecycle, protocol/auth/update validation |
| Cloud / Kubernetes | Recon, exposure and tool adapters | Partial | Provider-native effective IAM and authenticated posture/path validation |
| AI / LLM | Safe catalog, simple canary probes, adapters | Early | Trust-boundary model, RAG/tool/action proof, agentic workflow and data-flow testing |
| Social / physical / wireless / OT | Mostly governance, safe/passive checks, imports | Checklist/partial | Controlled exercise execution, safety telemetry, outcomes and cleanup |
| Verification | Generic replay and curl liveness | Weak | Vulnerability-specific assertion engine with negative controls |
| Correlation | Regex/text enrichment and attack narratives | Partial | Typed entity/edge graph with proof-backed state transitions |
| Reporting | Excellent breadth and separation of leads/support/confirmed | Strong | Underlying evidence state must become stricter; program-native submission lifecycle |

---

# 11. Recommended target architecture

```text
                           ┌──────────────────────────┐
                           │ Policy / Authorization    │
                           │ Program + ROE + approvals │
                           └─────────────┬────────────┘
                                         │
                           ┌─────────────▼────────────┐
                           │ Asset / Identity / Scope  │
                           │ graph and secure vault    │
                           └─────────────┬────────────┘
                                         │
                  ┌──────────────────────▼──────────────────────┐
                  │ Test Planner and Dependency Scheduler        │
                  │ tests, prerequisites, risk, cost, coverage   │
                  └───────────────┬──────────────────────────────┘
                                  │
       ┌──────────────────────────┼────────────────────────────┐
       │                          │                            │
┌──────▼──────┐            ┌──────▼──────┐             ┌──────▼──────┐
│ HTTP/browser│            │ Code/mobile │             │ Network/RE  │
│ workers     │            │ workers     │             │ workers     │
└──────┬──────┘            └──────┬──────┘             └──────┬──────┘
       └──────────────────────────┼────────────────────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │ Evidence and Test Results │
                    │ immutable artifact hashes │
                    └─────────────┬────────────┘
                                  │
                    ┌─────────────▼────────────┐
                    │ Assertion / Verification  │
                    │ vulnerability-specific    │
                    └─────────────┬────────────┘
                                  │
               ┌──────────────────▼───────────────────┐
               │ Findings / Root-cause correlation    │
               │ severity / eligibility / duplicates  │
               └──────────────────┬───────────────────┘
                                  │
                  ┌───────────────▼────────────────┐
                  │ Reports / Submission / Retest   │
                  │ campaign and bug-bounty outputs │
                  └────────────────────────────────┘
```

## 11.1 Recommended data stores

Use separate tables/collections for:

1. `program_policies`
2. `engagements`
3. `assets`
4. `identities`
5. `sessions`
6. `objects`
7. `workflows`
8. `test_definitions`
9. `test_executions`
10. `observations`
11. `candidate_hypotheses`
12. `validation_attempts`
13. `findings`
14. `finding_instances`
15. `attack_graph_nodes`
16. `attack_graph_edges`
17. `artifacts`
18. `reports`
19. `submissions`
20. `retests`
21. `cleanup_actions`
22. `human_decisions`

## 11.2 Recommended implementation split

Keep Python for:

- Policy and profile logic
- Domain plugins
- Evidence normalization
- AI and analytics
- Reporting
- Existing security ecosystem integration

Add an optional Go execution service for:

- Dependency-aware scheduling
- Bounded worker pools
- Streaming subprocess output
- Cancellation and process-tree control
- Per-target rate limits
- Resource accounting
- Long-running worker supervision

Use existing native tools or small C/Rust workers only for demonstrated hot paths. Do not rewrite mature scanners and reverse-engineering platforms.

---

# 12. Recommended structure before, during, and after findings

## 12.1 Before a candidate

```text
A. Load authorization and policy
B. Normalize target and prove scope decision
C. Identify asset, owner, environment, and technology
D. Establish identities/sessions/roles/tenants
E. Build endpoint/object/workflow graph
F. Select a versioned test definition
G. Confirm prerequisites and side-effect budget
H. Capture baseline and negative control
I. Execute bounded mutation/probe
J. Save test execution and raw artifact hashes
K. Evaluate the predefined assertion
```

Output: `test_execution`, not immediately a finding.

## 12.2 Candidate creation

Create a candidate only when an assertion signal exists:

```text
candidate = {
  hypothesis,
  weakness_type,
  affected_boundary,
  supporting_observations,
  contradictory_observations,
  confidence,
  required_validation,
  eligibility_state
}
```

## 12.3 Validation

```text
A. Replay exact request/session/workflow
B. Run vulnerability-specific positive proof
C. Run negative control
D. Repeat enough times for the signal type
E. Confirm side effects and cleanup
F. Verify scope and data minimization
G. Independent verifier decides pass/fail/inconclusive
```

## 12.4 Finding creation

Only after validation should a `finding` be created with:

- Root-cause ID
- Confirmed affected instances
- Proof state
- Technical impact
- Business impact
- Preconditions
- Severity vector
- Eligibility
- Duplicate status
- Evidence hashes
- Reproduction package

## 12.5 After the finding

```text
Root-cause clustering
    ↓
Severity and business impact review
    ↓
Attack-path / related-instance correlation
    ↓
Human quality gate
    ↓
Program/client-specific report
    ↓
Submission / remediation assignment
    ↓
Retest using the same assertion and controls
    ↓
Close, reopen, duplicate, accepted risk, or not applicable
    ↓
Feed validated lesson into pattern library
```

Only human-reviewed, validated outcomes should train the hunter-memory or payload-success logic.

---

# 13. Recommended report structure

TBHM’s current report structure is already good. The following refinement would make it suitable for both enterprise red-team work and bug bounty.

## 13.1 Front matter

- Engagement/program identity
- Authorization and scope version
- Test dates
- Profile and tool build hash
- Limitations
- Evidence handling statement
- Reviewer/sign-off

## 13.2 Executive view

- Confirmed vulnerabilities only
- Business-impact themes
- Attack paths/crown-jewel exposure
- Detection/control outcomes for red-team work
- Remediation priorities
- Explicit count of supported/candidate records outside the confirmed total

## 13.3 Coverage view

Coverage must come from `test_executions`, not findings.

Statuses:

- Tested — no issue observed
- Tested — candidate generated
- Tested — confirmed issue
- Partially tested
- Blocked
- Not authorized
- Not applicable
- Manual review required
- Tool unavailable

## 13.4 Per-finding structure

1. Title
2. Root cause and weakness classification
3. Affected asset(s)/instances
4. Scope and eligibility decision
5. Preconditions and required role
6. Expected security invariant
7. Actual invariant violation
8. Exact reproduction steps
9. Positive proof
10. Negative control
11. Repeatability
12. Demonstrated technical impact
13. Business impact
14. Severity vector and rationale
15. Evidence/artifact hashes
16. Cleanup/data-handling statement
17. Remediation
18. Regression test
19. Retest outcome

## 13.5 Red-team-only sections

- Campaign objectives
- Threat/emulation mapping
- Timeline
- Attack graph
- Control/prevention outcomes
- Detection and response timeline
- Telemetry gaps
- Cleanup and restoration

## 13.6 Bug-bounty-only sections

- Program asset and policy version
- Eligibility rationale
- Duplicate search notes
- Minimal safe proof
- Reporter contact/handle fields
- Platform-ready markdown and attachments
- Submission and triage status

---

# 14. Prioritized development plan

## Release A — Finding correctness

1. Add typed test definitions and test-execution records.
2. Replace `curl_verify` liveness with exact reproducer execution and assertion checks.
3. Replace shadow replay with verifier plugins.
4. Require structured `baseline`, `proof`, and `negative_control` objects.
5. Stop confirming from high confidence or evidence words.
6. Separate observations, candidates, supported records, and vulnerabilities.
7. Derive CVSS from metrics, not severity.
8. Add root-cause correlation separate from observation deduplication.
9. Fix coverage accounting to use executed tests, including negative outcomes.
10. Enforce scope before every request and redirect.

## Release B — Bug-bounty core

1. Program-policy parser and rule engine.
2. Secure browser/session/identity workspace.
3. Two-account authorization matrix.
4. Captured-request body-aware audit engine.
5. Workflow/business-invariant DSL.
6. Race/file-upload engines.
7. Client-side browser instrumentation.
8. Program-native submission/retest lifecycle.

## Release C — Domain depth

1. Stateful GraphQL/WebSocket/gRPC testing.
2. Mobile dynamic device workflow.
3. Cloud effective-IAM graph.
4. Firmware sandbox/emulation manager.
5. AI/RAG/agent trust-boundary graph and verifier plugins.
6. Reverse-engineering normalized artifact/data-flow model.

## Release D — Full red-team control plane

1. Versioned threat-informed campaign model.
2. Per-action approval and stop conditions.
3. Controlled execution service isolated from bug-bounty mode.
4. Session/operation/cleanup management.
5. Telemetry and detection-validation connectors.
6. Campaign timeline, attack graph, and control-outcome reporting.

## Release E — Performance and scale

1. Phase dependency graph.
2. Concurrent bounded scheduler.
3. Streaming subprocess logs.
4. Process-tree cancellation.
5. Resource-aware queues.
6. Evidence caching for repeated binary/firmware analysis.
7. Batched AI embeddings and DB writes.
8. Optional Go executor after profiling.

---

# 15. Final conclusion

You are moving in the right direction. The tool already has unusually broad domain coverage and a strong reporting/evidence foundation.

The next milestone should **not** be “add more phase names” and should **not** be “rewrite everything in Go or C.”

The next milestone should be:

> Convert TBHM from a phase-driven finding generator into a policy-driven test, evidence, assertion, and verification platform.

Once the test and finding lifecycle is correct, the same engine can support two separated operating modes:

- **Bug-bounty mode:** minimal-impact, program-policy-constrained, submission-oriented.
- **Red-team mode:** objective-driven, approval-gated, detection-aware, campaign-oriented.

The reporting layer is already close to the needed quality. The verification, test-state, identity/workflow, and policy layers are what must now catch up.
