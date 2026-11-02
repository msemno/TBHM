# TBHM v4.0.0 — Unified Safe Release (Lifecycle + Firmware + Deep Reverse + Go-Safe)

This release unifies the strict-evidence lifecycle and optional Go executor control plane with the universal deep-reverse, firmware analysis and complete JavaScript intelligence capability set. Python remains the authoritative, fail-closed control plane; all high-impact reverse, firmware and red-team operations remain bounded, import-only and approval-gated.

---

# TBHM v3.9.7.3 — Strict Evidence Lifecycle and Optional Go Executor

This patched build preserves the tested v3.9.7.3 Python control plane while
adding an optional statically linked Go subprocess executor, strict typed
evidence lifecycle, a fail-closed bug-bounty policy/identity/workflow workspace,
and a complete red-team campaign register. High-impact red-team operations are
approval-gated and import-only; TBHM validates structured evidence, detection
outcomes and cleanup rather than autonomously launching weaponized activity.

Key commands:

```bash
# Optional Go helper (Python remains the fallback)
./scripts/build_go_executor.sh

# Bug-bounty workspace (targetless: reviewed local inputs only)
./tbhm.py --profile authorized_full -y \
  --program-policy templates/program_policy.example.yaml \
  --identity-plan templates/identity_plan.example.yaml \
  --workflow-plan templates/workflow_plan.example.yaml \
  --session-har /path/to/session.har --executor-backend auto

# Red-team campaign control and approved evidence import (targetless)
./tbhm.py --profile authorized_redteam -y --redteam --redteam-campaign \
  --campaign-plan templates/redteam_campaign.example.yaml \
  --campaign-results /path/to/sanitized-results \
  --approval-manifest /path/to/signed-approval.yaml --executor-backend auto

# Offline regression validation
python3 integration_test_v398_safe_lifecycle.py
```

The Go helper is optional. Python remains authoritative and automatically
falls back when the helper is absent. Reverse-analysis metadata is cached by
file identity, and local embeddings use a bounded worker pool only after a
successful loopback model probe.

Architecture and boundaries: `docs/STRICT_EVIDENCE_AND_CAMPAIGN_ARCHITECTURE.md`.

---

# TBHM v3.9.7.5 — Universal Deep Reverse and Complete JavaScript Intelligence

This release preserves the v3.9.7.3/v3.9.7.4 scanner surface and adds normalized
decompiler IR, bounded interprocedural taint, JavaScript/WebView/JNI/native
correlation, TBHM-owned disposable container/QEMU lifecycle management, dynamic
address mapping, symbolic/concolic test-input generation, fuzz-harness proposals,
crash deduplication/minimization, function-level binary diffing, campaign artifact
deduplication, managed UEFI/driver/mobile/protocol/hardware evidence, strict
package verification and complete JavaScript usefulness analysis over Katana,
ParamSpider, ZAP and crawler results.

Static analysis remains the default. Runtime actions require explicit local
images/commands and `--confirm-isolated-execution`. RouterSploit is catalog/import
only. EMBA host execution is limited to static/SBOM profiles; emulation/full
requires an already-present sandbox image and fails closed if the strict policy
is incompatible with the image.

Quick validation:

```bash
python3 integration_test_v3975_deep_reverse.py
python3 integration_test_v3974_reverse.py
python3 tbhm.py --doctor
python3 tbhm.py --help
```

Representative local workflows:

```bash
# Static binary IR + taint + harness proposals
python3 tbhm.py --profile authorized_redteam -y   --binary-path /absolute/path/program   --reverse-ir --reverse-taint --reverse-fuzz-harness

# Analyze a managed artifact family
python3 tbhm.py --profile authorized_redteam -y   --reverse-family-path /absolute/path/artifact   --reverse-family-tooling

# EMBA static mode
python3 tbhm.py --profile authorized_redteam -y   --firmware /absolute/path/firmware.bin --emba --emba-mode static

# EMBA emulation/full: prepared image only, no automatic pull
python3 tbhm.py --profile authorized_redteam -y   --firmware /absolute/path/firmware.bin --emba --emba-mode emulation   --emba-sandbox-image local/emba-reviewed:tag   --confirm-isolated-execution

# Verify a release ZIP
python3 tbhm.py --profile authorized_safe -y   --verify-package /absolute/path/TBHM-v3.9.7.5-FULL.zip
```

Release documents:

- `CHANGELOG-v3.9.7.5.md`
- `VALIDATION-v3.9.7.5.md`
- `docs/REVERSE_ENGINEERING_STATUS_v3.9.7.5.md`
- `docs/JS_INTELLIGENCE_v3.9.7.5.md`
- `docs/PACKAGING_VERIFICATION_v3.9.7.5.md`
- `docs/compatibility/BACKWARD_COMPATIBILITY_REPORT_v3.9.7.5.md`

---

# TBHM v3.9.7.4 — Installer Stability and Environment Isolation

TBHM v3.9.7.4 preserves the v3.9.7.2 scanner, reporting, compatibility, and phase behavior while correcting the full installer path. Core TBHM dependencies remain small; optional Python applications are installed into one isolated virtual environment per tool, npm packages use a user-owned prefix, Ruby and Composer executables are exposed through `~/.local/bin`, apt recipes are preflighted, and known Python/platform incompatibilities are reported as explicit skips rather than destructive shared-environment upgrades.

The release adds an offline installer doctor and a conservative, plan-first cleanup helper for environments previously affected by the v3.9.7.2 shared-user Python installs. It does not automatically downgrade Kali packages or remove shared dependency libraries.

Historical behavior from v2.16-fixed, v2.21, v3.8-expanded, and v3.9.5 was compared semantically against v3.9.6. Older code was restored only where it improved correctness, safety, evidence integrity, scope enforcement, or compatibility. The release keeps planned, unavailable, import-only, and adapter-backed capabilities visibly distinct from native operational features.

Safety boundaries remain strict: no credential theft, automatic exploitation, arbitrary command execution, payload generation, C2 startup, persistence, lateral movement, destructive wireless behavior, or AI-directed shell execution was added.

Quick validation and status commands:

```bash
python3 integration_test_v3973_installer.py
python3 integration_test_v3972.py
python3 integration_test_v3971.py
python3 integration_test_historical_regressions_v3971.py
./tbhm.py --capability-status
./tbhm.py --doctor
./tbhm.py --list-profiles
./tbhm.py --code-dir ./source --code-scan-data-files
./tbhm.py -y --safe-plan plan.json --safe-plan-dry-run -o results/plan-validation
```

Installation modes:

```bash
# Core install only
./install.sh

# Full vetted safe optional surface; incompatible tools are skipped truthfully
INSTALL_CODE_SECURITY=1 \
INSTALL_REVERSE_TOOLING=1 \
INSTALL_ANGR=1 \
INSTALL_OLLAMA=1 \
INSTALL_AI=1 \
AI_NO_PULL=1 \
INSTALL_PLAYWRIGHT=1 \
INSTALL_ALL_SAFE_EXTENDED=1 \
./install.sh

# Offline diagnostics and legacy-environment review
python3 scripts/installer_doctor.py
python3 scripts/repair_legacy_python_environment.py
# Review first; apply removes only known top-level legacy tools that have isolated replacements
python3 scripts/repair_legacy_python_environment.py --apply
```

Release evidence and design records:

- `CHANGELOG-v3.9.7.4.md`
- `VALIDATION-v3.9.7.4.md`
- `docs/INSTALLER_STABILITY_v3.9.7.4.md`
- `docs/compatibility/BACKWARD_COMPATIBILITY_REPORT_v3.9.7.4.md`
- `docs/CAPABILITY_DEPTH_v3.9.7.2.md`
- `docs/HISTORICAL_ARCHAEOLOGY_v3.9.7.2.md`
- `docs/compatibility/BACKWARD_COMPATIBILITY_REPORT_v3.9.7.2.md`
- `docs/historical/HISTORICAL_DECISION_REGISTER.md`
- `RELEASE_MANIFEST-v3.9.7.2.json`

---

# TBHM v3.9.4.1 — AI-plane correctness and safety hardening

This package preserves the v3.9.4 portable AI Control Plane and fixes the
remaining audited correctness issues: stale source-index documents, full
re-embedding on small deltas, mixed embedding spaces, raw resource persistence,
pre-request/redirect scope gaps, passive crawl requests, public-suffix scope,
static-taint classification, reverse artifact correlation, phase-resume state,
and evidence-boundary scope/redaction. Reports now surface conservative coverage
and posture context without fabricated remediation-time estimates.

Important commands:

```bash
./tbhm.py --ai-sync-tool
./tbhm.py --ai-review-delta
./tbhm.py --ai-propose-delta
./tbhm.py --ai-backup
./tbhm.py --ai-restore <backup.tar.gz>
python integration_test_v3941.py
```

See `CHANGELOG-v3.9.4.1.md`. The AI plane remains non-authoritative: it cannot
execute tools, change finding status, apply patches, or bypass scope/safety gates.

---

# TBHM v2.0 — The Bug Hunter Master

> أداة Bug Bounty مبنية بـ Python بناءً على **design document v1.0** الكامل (280+ فكرة معمارية)
> مع تكامل **SecLists** و **methodologies** من Jason Haddix والمراجع الحديثة.

## ⚠️ صراحة مهمة قبل أي حاجة

**مفيش أداة في الدنيا تضمن نسبة اكتشاف ثابتة.** أي حد بيوعدك بـ "90% bug discovery" بيكدب. الـ TBHM v2 بتعمل:

- ✅ تـ **filter 90% من الـ noise** (تشيل اللي مش مهم من النتايج)
- ✅ تـ **flag الـ 10% المثيرة بدقة** عبر confidence scores وverification
- ✅ تـ **توفر 80% من وقت الـ recon اليدوي** عبر pipeline متكامل
- ✅ تـ **تـ document كل خطوة** عشان تتعلم وتقدر تعيد يدوياً
- ✅ تـ **تحترم الـ target** (rate limits, hard limits, no destructive payloads)

اللي بيحول الـ leads دي لـ bounty حقيقي = **انت**. الأداة بتجمع، انت بتأكد وبترفع.

---

## 🆕 v2.6 — Atlassian Deep Dive + IDOR Engine + Cloud FP Filters

Based on feedback about real Atlassian bug bounty hunting and false-positive
patterns observed on `atlassian-backup` style buckets.

### ✨ New Phases (added — nothing removed)

| Phase | What it does |
|---|---|
| `atlassian_audit` | Jira REST API + Confluence REST API anonymous access tests. Specifically tests for: **IDOR on tickets** (sequential project keys PROJ-1, PROJ-2 + alternate project enumeration SUPPORT/INFRA/SEC/INTERNAL), **JQL injection** (ORDER BY, IS NOT EMPTY, recent issues), **Service Desk customer request enumeration**, **Confluence space anon access**, **user/group enumeration**. Detects PII patterns, credentials, JWTs, internal markers in returned content. |
| `cloud_recon_extended` | DigitalOcean Spaces, Cloudflare R2, Backblaze B2, AWS Lambda URLs, Azure Functions, Google App Engine, Heroku. **WITH the FP filters from review feedback**: typo detection (`atlassain` ≠ `atlassian`), ownership verification (target name must appear in file keys or body), billing-dead bucket detection (GCP UserProjectAccountProblem), and 403-AccessDenied = NOT a finding. |
| `vuln_scan_extended` | retire.js (JS library CVEs — huge for SPAs), dalfox (XSS specialist), nuclei with tech-stack tags (WP, Jenkins, GitLab, K8s, Grafana, Elastic, Mongo, Redis, JIRA, Confluence), nuclei Atlassian-specific tag, wpscan (auto-runs if WordPress detected). |

### ✨ New Core Module

| Module | What it does |
|---|---|
| `core/idor_engine.py` | Reusable IDOR primitives: **detects** numeric IDs / UUIDs / ticket keys (PROJ-123) / query params, **mutates** them (id±1, sequential project keys, random UUIDs), **fingerprints** responses (status + length + body hash + content-type), and **classifies** results as IDOR_LEAK / PROPER_DENIAL / NEW_CONTENT / INCONCLUSIVE using baseline differential testing. |

### 🎯 Atlassian — What Gets Tested Specifically

**Jira (12+ endpoint probes per host):**
- `/rest/api/2/project` — anonymous project list
- `/rest/api/2/search?jql=...` — 6 different JQL payloads (ORDER BY, all-projects, recent, keyword-based)
- `/rest/api/2/issue/PROJ-{1,100,999}` — IDOR sweep over common project keys (SUPPORT, INTERNAL, SEC, INFRA, OPS, ADMIN, ENG, DEV, IT, HR)
- `/rest/api/2/user/search` + `/rest/api/3/users/search` — user enumeration
- `/rest/servicedeskapi/request` — customer support ticket leak
- `/rest/api/2/group?groupname=jira-administrators` — admin enumeration
- `/rest/api/2/filter/favourite` — saved JQL filters

**Confluence (8 endpoint probes per host):**
- `/wiki/rest/api/space?limit=200` — list all spaces anonymously
- `/wiki/rest/api/content?limit=200` — list all pages
- `/wiki/rest/api/content/search?cql=...` — CQL search bypass
- `/wiki/rest/api/content/{1,100,1000,65536,100000}` — page ID IDOR sweep

**Severity logic:** 200 + sensitive pattern (PII/credentials/JWT) → CRITICAL. 200 + internal marker → CRITICAL. 200 + 5+ entities → HIGH. 200 empty → LOW. 401/403 → not a finding.

### 🛡️ Cloud Recon FP Filters (from your earlier review)

```
✗ 403 AccessDenied      → no finding (bucket properly secured)
✗ Empty bucket          → INFO only (not CRITICAL)
✗ "UserProjectAccountProblem" → INFO (billing-dead, files unfetchable)
✗ Typo "atlassain" when target is "atlassian" → confirmed: false (third-party)
✗ No ownership signals  → confirmed: false (manual review needed)
✓ 200 + bucket listing + target name in keys + non-billing-dead → CRITICAL
```

### 📊 Pipeline (now 29 phases)

```
preflight → recon → ports → discovery → smart_crawl → backend_map →
content_discovery → protected_routes → vuln_scan → nuclei_extended →
vuln_scan_extended → deep_scan → audit → atlassian_audit → injections →
access_control → auth_advanced → api_specific → upload_race →
business_logic → cloud_recon → cloud_recon_extended → console_leaks →
api_key_pivot → secrets_misc → visual → curl_verify → verify →
dashboard → report
```

### 🛠️ External Tool Installation

For `vuln_scan_extended` to fire all sub-scanners:

```bash
# retire.js (JS library CVEs)
npm install -g retire

# dalfox (XSS specialist)
go install github.com/hahwul/dalfox/v2@latest

# wpscan (WordPress)
gem install wpscan
# Get API token from wpscan.com for CVE details
```

If a tool isn't installed, that sub-scanner is silently skipped — nothing breaks.

---



Based on real feedback from running v2.3 against Anthropic targets:

## 🆕 v2.7 — Infra Exposure + More Cloud Providers

Based on common bug-bounty findings (Spring Boot heap dumps, Docker registries,
K8s API exposure, and oversights in cloud-provider enumeration).

### ✨ New Phase

**`phases/infra_exposure.py`** — 43 checks for misconfigured infrastructure:

| Category | Examples | Why it matters |
|---|---|---|
| Spring Boot Actuator | `/actuator/env`, `/actuator/heapdump`, `/env`, `/heapdump`, `/jolokia` | Heap dumps contain JWTs, session cookies, DB passwords. `env` leaks the entire config. |
| Docker Registry | `/v2/_catalog`, `/v2/` | Image names enumerable + pull access |
| Kubernetes | `/api/v1/namespaces`, `/api/v1/pods` | Control-plane exposure = cluster takeover |
| HashiCorp Vault | `/v1/sys/health`, `/v1/sys/seal-status` | If unsealed: full secret DB access |
| etcd | `/v2/keys/`, `/v3/kv/range` | Backing store of K8s/many systems' secrets |
| Consul | `/v1/agent/self`, `/v1/catalog/services` | Service catalog disclosure |
| Elasticsearch | `/_cat/indices`, `/_cluster/state`, `/_search` | Data exfil + cluster topology |
| Grafana | `/api/datasources`, `/api/admin/users` | DB creds in datasource config |
| Jenkins | `/script`, `/manage` | Script console = RCE |
| Prometheus | `/metrics` | Internal hostnames + version disclosure |
| Sentry DSN | regex on collected JS | Quota exhaustion + alert flooding |
| GraphQL | `/graphql?query={__schema{...}}` | Introspection often left on |

Each check has a **confirm pattern** — a regex that must match the response body
before the finding is raised. This prevents the false positives that plague
"200 == vulnerable" scanners. Example: a 200 on `/actuator/env` only fires if
the body contains `"propertySources"` (the Spring marker).

### ✨ Extended Cloud Recon

`cloud_recon_extended.py` now covers **14 providers** (up from 6):

`digitalocean_spaces`, `cloudflare_r2`, `backblaze_b2`, `google_appengine`,
`azure_functions`, `heroku`, **`oracle_oci`**, **`wasabi`**, **`ibm_cos`**,
**`linode_objects`**, **`vultr_objects`**, **`alibaba_oss`**, **`scaleway_objects`**,
**`firebase_storage`** (new).

Bucket-name permutations expanded from 80 → 200, now including suffixes that
matter for bug bounty: `secrets`, `confidential`, `archive`, `dumps`,
`snapshots`, `exports`, `audit`, `compliance`, `legal`, `hr`, `finance`,
`payroll`, `credentials`, `vault`, `ci`, `cicd`, `artifacts`, `releases`,
`uat`, `stage`, `legacy`, `v1`/`v2`/`v3`, etc.

### 📊 Pipeline (now 30 phases)

```
preflight → recon → ports → discovery → smart_crawl → backend_map →
content_discovery → protected_routes → vuln_scan → nuclei_extended →
vuln_scan_extended → infra_exposure → deep_scan → audit → atlassian_audit →
injections → access_control → auth_advanced → api_specific → upload_race →
business_logic → cloud_recon → cloud_recon_extended → console_leaks →
api_key_pivot → secrets_misc → visual → curl_verify → verify → dashboard → report
```



### 🐛 Bugs Fixed
| Bug | Fix |
|---|---|
| Tool dies when screen turns off / laptop sleeps | New `--background` flag detaches via `setsid` + caffeinate/systemd-inhibit |
| Tons of false positives from `chrome-extension://`, Facebook, analytics | New `core/noise_filter.py` drops these BEFORE they hit findings DB |
| Worried about damaging target backend (POST/PUT/DELETE) | New `core/safe_writes.py` — non-GET methods blocked by default, `--allow-writes` to enable |

### ✨ New Phases (added, nothing removed)

| Phase | What it does |
|---|---|
| `backend_map` | For each page, identify the API endpoints it calls (page → API graph). Flags "lonely admin APIs" called by only 1 page. |
| `protected_routes` | Classify routes as admin/billing/internal/etc. Test anonymous access. Boost their score so audit phase prioritizes them. |
| `console_leaks` | Scan JS bundles for `console.log(apiKey)` / `console.log(token)` — devs forget to remove these in production. |
| `api_key_pivot` | When a Google/Stripe/GitHub/Slack/etc key is found, automatically test it against the live service to see if it's active. The user's manual Google API workflow, automated. |

### ✨ New Core Modules

| Module | What it does |
|---|---|
| `core/noise_filter.py` | Central blocklist: chrome-extension://, Facebook, analytics, CDNs, app stores. Severity-aware (HIGH-severity findings on out-of-scope hosts still kept for review). |
| `core/anti_block.py` | Adaptive throttling + rotating browser fingerprint (real Chrome/FF/Safari UAs + browser-like headers). Detects 429/captcha and exponentially backs off. |
| `core/safe_writes.py` | Gates POST/PUT/PATCH/DELETE. Default = block. `--allow-writes` opens it. Even with `--allow-writes`, destructive paths (`/delete`, `/cancel`, `/refund`) need manual approval. |

### 🛠️ How to Use the New Features

**Background mode (screen-off-safe):**
```bash
# Use the wrapper script (recommended)
./run-bg.sh -d target.com -y --deep

# Or the flag directly
./tbhm.py -d target.com -y --deep --background

# Output:
# [✓] TBHM running in background (PID 12345)
#     Log:     tail -f results/.../run.log
#     Results: results/target.com_YYYYMMDD_HHMMSS
#     Stop:    kill 12345
```

**Safe writes (default):**
```bash
# Default — only GET requests sent. Safe for production targets.
./tbhm.py -d target.com -y --standard

# Enable POST/PUT/PATCH/DELETE for mass assignment + business logic tests
./tbhm.py -d target.com -y --standard --allow-writes
```

**Pipeline (now 25 phases):**

```
preflight → recon → ports → discovery → smart_crawl → backend_map →
content_discovery → protected_routes → vuln_scan → deep_scan →
audit → injections → access_control → auth_advanced → api_specific →
upload_race → business_logic → cloud_recon → console_leaks →
api_key_pivot → secrets_misc → visual → verify → dashboard → report
```



## 🆕 v2.4 — Bug-Bounty Pain Points Fixed

See earlier sections for full v2.4 / v2.5 / v2.6 details.

## 🆕 v2.3 — Burp/ZAP Architecture + Bug-Bounty Focus

### Phases جديدة (مضافة فوق v2.1 / v2.2 من غير ما تشيل حاجة)

| Phase | الفايدة | Files |
|---|---|---|
| **`smart_crawl`** | ZAP-style stateful crawler. بيبني Application Graph (مش URL list). Optional headless via Playwright لـ SPAs. | `phases/smart_crawl.py` |
| **`audit`** (v2.2) | Burp-style active scanner: insertion-point discovery → baseline (3x) → mutate → diff → verify (2x). Low false-positive. | `phases/audit.py` + `core/insertion_points.py` + `core/diff_engine.py` |
| **`business_logic`** | Mass assignment, price/qty manipulation, HTTP parameter pollution, IDOR/race flagging. **Gold mine لـ bug bounty.** | `phases/business_logic.py` |
| **`cloud_recon`** | S3/GCS/Azure bucket enumeration + Firebase RTDB checks. Easy wins. | `phases/cloud_recon.py` |
| **`dashboard`** | Single static HTML file. تفتحها في browser، فيها search/filter/sort. | `phases/dashboard.py` |

### Core modules جديدة (v2.2 + v2.3)

| Module | الفايدة |
|---|---|
| `core/insertion_points.py` | Burp-style insertion point discovery (QUERY/BODY_FORM/BODY_JSON/BODY_XML/HEADER/COOKIE/PATH_SEGMENT) |
| `core/diff_engine.py` | Baseline vs mutation comparison مع statistical variance (Jaccard similarity, error pattern matching) |
| `core/session_state.py` | Cookie + CSRF + JWT tracking عبر الـ scan كله |
| `core/knowledge.py` | **Knowledge engine** — DB في `~/.tbhm/knowledge.db` بتتعلم من كل scan: payloads ناجحة، subdomains، vulnerable endpoints |
| `core/correlation.py` | بيربط findings ببعض (same param, same CWE, same host) → clusters للـ dashboard |

### الـ Knowledge Engine (memory of the platform)

```bash
# الـ tool بيخزن في ~/.tbhm/knowledge.db
# - subdomains اللي شفناهم على كل domain
# - payloads اللي نجحت في كل context  
# - endpoints اللي طلعت vulnerable قبل كده

# في next scan، الـ tool بيستخدم الذاكرة دي عشان يـ prioritize:
# 1. Subdomains معروفة بتدخل recon من غير brute-force
# 2. Payloads ناجحة قبل بيتجربوا الأول  
# 3. Endpoints vulnerable قبل بتتعاد لازم (forensic_recheck profile)
```

### الـ Dashboard

بعد ما الـ scan يخلص:
```bash
firefox results/<target>_<date>/dashboard.html
# أو
xdg-open results/<target>_<date>/dashboard.html
```

ملف HTML واحد ساكن — مفيش server محتاج تشغّله. فيه:
- Stats grid (critical/high/medium/low/info counts)
- Search box (يفلتر بـ title/URL/parameter/payload)
- Severity + phase filters
- Sortable columns
- Click على أي finding يفتح modal فيه كل التفاصيل

### Pipeline الجديد (21 phase)

```
preflight → recon → ports → discovery → smart_crawl →
content_discovery → vuln_scan → deep_scan → audit → injections →
access_control → auth_advanced → api_specific → upload_race →
business_logic → cloud_recon → secrets_misc → visual → web3 →
verify → dashboard → report
```

### الفلسفة (مهمة)

| المبدأ | التطبيق |
|---|---|
| **Burp-philosophy، مش Burp-replacement** | Same architectural pattern (baseline+diff+verify), simpler implementation |
| **Add, don't replace** | v2.3 = v2.1 + v2.2 + v2.3 phases. مفيش حاجة اتشالت |
| **Resource-aware** | كل scanner له timeout. ResourceMonitor بيوقف لو RAM > 85% |
| **Honest confidence labels** | HIGH/MEDIUM/LOW على كل finding. Verified findings (audit phase) دايماً HIGH |

## ⚠️ صراحة عن البديل لـ Burp Pro / ZAP

اللي عملته هنا هو **Burp-philosophy automation**، مش بديل عن Burp Pro. لو محتاج:
- **Proxy interception** + manual request editing → Burp/ZAP لازم
- **Repeater** لـ iterative manual testing → Burp/ZAP لازم
- **Decoder/Comparer** للـ binary analysis → Burp/ZAP لازم

اللي بنعمله هنا:
- **Automated wide coverage** على 100s of subdomains
- **High-quality leads** بـ low false positives via diff engine
- **Business logic detection** اللي معظم scanners بيـ skip-ها
- **Cloud asset discovery** اللي Burp مش بيعملها
- **Single-file dashboard** للـ triage السريع

## 🆕 v2.3 → v2.1 history (cumulative)

### v2.0 → v2.1 fixes

- 🐛 **Multi-target bug** — كانت v2.0 بتفحص أول target بس. v2.1 بتـ iterate على كل target في الـ list.
- 🐛 **httpx parsing** — كان بيرجع 0 live في 0 ثانية. v2.1 بتستخدم plain text output (أصدق) مع JSON كـ bonus.
- 🐛 **PATH issues** — `$HOME/go/bin` بيتضاف لـ PATH تلقائياً.

### v2.1 additions
- ✨ **Intensity modes**: `--quick / --standard / --deep / --insane`
- ✨ **3 phases جديدة**: `ports`, `deep_scan`, `visual`
- ✨ **10+ tools جديدة**: naabu, nmap, masscan, nikto, jaeles, wapiti, gowitness, gospider, hakrawler, gotator, findomain, chaos, github-subdomains, amass
- 🐛 **httpx parsing** — كان بيرجع 0 live في 0 ثانية. v2.1 بتستخدم plain text output (أصدق) مع JSON كـ bonus.
- 🐛 **PATH issues** — `$HOME/go/bin` بيتضاف لـ PATH تلقائياً.


**TBHM v2 مش بديل عن Burp Suite Pro أو OWASP ZAP.** دول tools احترافية فيها سنين R&D ومش ممكن أداة CLI واحدة تعمل ما يعملوه. اللي بتعمله v2.1:

| الخاصية | TBHM v2.1 | Burp Pro | ZAP |
|---|---|---|---|
| Recon (subdomains/JS) | ✅ ممتاز | ❌ ضعيف | ❌ ضعيف |
| Port scanning | ✅ via naabu+nmap | ❌ مش بتعمل | ❌ مش بتعمل |
| Web app crawling | 🟡 via katana | ✅ ممتاز | ✅ ممتاز |
| Manual testing | ❌ مش لها | ✅ ممتاز | ✅ كويس |
| Vulnerability scanning | ✅ 5+ scanners | ✅ Scanner Pro | ✅ Active scan |
| Repeater / Intruder | ❌ | ✅ | ✅ |
| AI prompt-injection probing | ✅ | ❌ | ❌ |
| Multi-target automation | ✅ ممتاز | 🟡 manual | 🟡 manual |
| Web3 specifics | ✅ | ❌ | ❌ |
| Burp/ZAP integration | 🔮 future | — | — |

**الـ workflow الموصى به:**
1. TBHM للـ recon + automated scanning واسع
2. Findings من TBHM → manual verification في Burp/ZAP
3. Manual hunting في Burp/ZAP بناءً على ما لقت TBHM

| المحور | v1 (bash) | v2 (Python) |
|---|---|---|
| اللغة | bash + Python script | Python 3.10+ orchestrator |
| Config | flags فقط | **profile-based** (passive_only / authorized_safe / authorized_full / forensic_recheck) |
| Storage | JSON files | **SQLite** + Hunter Memory + Pattern Library |
| Wordlists | bundled small | **SecLists integration** مع fallback |
| Scoring | بدون | **Endpoint Scoring Algebra** (المعادلة من Section 3.1) |
| Reports | report.md + report.html | **4 audiences:** Executive / Manager / Developer / Defender + per-finding Reproducer Kits |
| Hard limits | warnings | **enforced في الكود** (Section K1) |
| Verification | بدون | **Shadow Replay** (B2) + MRS scores (B3) |
| Phases | 18 bash modules | **13 Python phases** + content_discovery بـ ffuf |
| فحوصات جديدة | — | 2FA bypass, JWT audit, GraphQL introspection, Webhooks, Mobile API, **LLM prompt injection**, Prototype Pollution hints, Web3 RPC + IPFS |

---

## 🚀 التثبيت

### المتطلبات

- Linux (Ubuntu/Debian/Kali recommended) أو macOS
- Python 3.10+
- Go 1.20+
- Internet connection

### خطوات

```bash
# 1. فك الضغط
unzip TBHM-v2.zip && cd TBHM-v2

# 2. شغل المثبت
chmod +x install.sh tbhm.py
./install.sh

# 3. شيك إن كل حاجة شغالة
./tbhm.py --list-profiles
./tbhm.py --code-dir ./source --code-scan-data-files
```

المثبّت بيركّب:
- Go tools: subfinder, httpx, nuclei, katana, dnsx, assetfinder, waybackurls, gau, dalfox, subzy, **ffuf**
- Python tools: arjun, trufflehog
- **SecLists** (لو مش موجودة، بيـ clone من GitHub لـ `/opt/SecLists`)
- Python deps: requests, PyYAML, psutil

---

## 📖 الاستخدام

### الـ Profiles الأربعة + الـ Intensity الأربعة

```bash
./tbhm.py --list-profiles
./tbhm.py --code-dir ./source --code-scan-data-files
```

**Profile = الأمان** (rate limits, forbidden payloads):

| Profile | الوصف |
|---|---|
| `passive_only` | Zero-touch reconnaissance بس |
| `authorized_safe` | Default. Active probing بـ rate محافظ |
| `authorized_full` | Full pentest. محتاج SoW |
| `forensic_recheck` | إعادة فحص bugs قديمة |

**Intensity = الشدّة** (wordlist size, scanner depth):

| Flag | الوقت | المحتوى |
|---|---|---|
| `--quick` | 10-20 دقيقة | 5K subdomains, top-100 ports, critical/high nuclei بس |
| `--standard` (default) | 1-3 ساعات | 20K subdomains, top-1000 ports, jaeles |
| `--deep` | 6-12 ساعة | 110K subdomains, top-5000 ports, **nikto + jaeles + wapiti** |
| `--insane` | 12-48 ساعة | 1M subdomains, **كل الـ 65K ports**، كل templates |

الـ profile والـ intensity منفصلين — تقدر تجمع أي اتنين:
```bash
./tbhm.py -d target.com --profile authorized_safe --quick -y       # سريع وآمن
./tbhm.py -d target.com --profile authorized_safe --deep -y        # عميق وآمن
./tbhm.py -d target.com --profile authorized_full --insane -y      # كل حاجة
```

### 🔑 API Keys — حاسمة لـ recon قوي

من غير API keys، الـ subfinder وبقية الـ recon tools بترجع نتايج هزيلة. ده مش bug، ده طبيعة الـ tools دي. سجّل ودخّل الـ keys مجاناً:

| Key | المصدر | مجاني؟ | الفايدة |
|---|---|---|---|
| `CHAOS_KEY` | https://chaos.projectdiscovery.io | ✅ | + ملايين subdomains من ProjectDiscovery dataset |
| `GITHUB_TOKEN` | https://github.com/settings/tokens | ✅ | github-subdomains + GitHub dorks |
| `SHODAN_API_KEY` | https://shodan.io | ✅ (محدود) | tech fingerprinting أعمق |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | https://censys.io | ✅ (محدود) | cert search, exposed services |
| `VIRUSTOTAL_API_KEY` | https://virustotal.com | ✅ | passive DNS history |
| `SECURITYTRAILS_KEY` | https://securitytrails.com | محدود | DNS history premium |

اضفهم لـ `~/.bashrc`:
```bash
echo 'export CHAOS_KEY="your_key_here"' >> ~/.bashrc
echo 'export GITHUB_TOKEN="ghp_..."' >> ~/.bashrc
source ~/.bashrc
```

الأداة بتـ report عند بداية كل scan إيه الـ keys متاحة وإيه مش.

### 🆕 v2.1 Phases الجديدة

```
preflight → recon → ports → discovery → content_discovery →
vuln_scan → deep_scan → injections → access_control → auth_advanced →
api_specific → upload_race → secrets_misc → visual → web3 → verify → report
```

- **`ports`**: naabu + nmap + masscan port scanning مع service detection. بيـ raise findings تلقائياً على exposed Redis, MongoDB, Elasticsearch, Docker API إلخ.
- **`deep_scan`**: nikto + jaeles + wapiti كـ scanners إضافية مع nuclei (مختلفين في الـ signatures).
- **`visual`**: gowitness screenshots لكل host (تريّاج بصري سريع).

### مثال أساسي

```bash
# Passive recon فقط (الأكثر أماناً)
./tbhm.py -d hackerone.com --profile passive_only

# Bug bounty عادي
./tbhm.py -d target.com --profile authorized_safe -y

# Full pentest
./tbhm.py -l scope.txt --profile authorized_full -y \
  --bug-bounty-program https://hackerone.com/target/policy

# Web3 / dApp
./tbhm.py -d uniswap.org --profile authorized_safe --web3 -y

# مع OOS list
./tbhm.py -d target.com --profile authorized_safe -y \
  --exclude oos.txt --scope scope.txt
```

### الـ Flags المهمة

| Flag | الوصف |
|---|---|
| `-d / --domain` | Single domain |
| `-l / --list` | File of domains |
| `-u / --url` | Single URL |
| `-U / --urls` | File of URLs |
| `--profile` | اختر profile |
| `-y / --yes-i-am-authorized` | **مطلوب** للـ active profiles |
| `--bug-bounty-program` | URL الـ program للـ audit log |
| `--scope` | File of in-scope patterns |
| `--exclude` | File of OOS patterns |
| `--web3` | فعّل Web3 phase |
| `--phases` | Override phase list (comma-separated) |
| `--dry-run` | اطبع plan وخرج بدون ما تشغل حاجة |
| `--notify` | Discord/Slack webhook |
| `-s / --silent` | اخفي الـ banner |

---

## 🏗️ المعمارية (للمهتمين)

### الـ Phases (13 phase)

```
preflight        → legal check + scope validation
recon            → DNS + WHOIS + crt.sh + subfinder + assetfinder + dnsx brute-force (SecLists)
discovery        → URLs (waybackurls/gau/katana) + JS analysis + secrets + params (arjun)
content_discovery → ffuf + SecLists raft/common/quickhits/api-endpoints
vuln_scan        → nuclei templates + subdomain takeover (subzy)
injections       → XSS (dalfox) + SQLi (sqlmap) + LFI + Open Redirect + SSRF
access_control   → IDOR heuristics + CORS misconfig
auth_advanced    → 2FA bypass paths + JWT audit + OAuth callback flags
api_specific     → GraphQL introspection + Webhook receivers + Mobile API hints + LLM prompt injection
upload_race      → File upload tests + Prototype pollution hints
secrets_misc     → .git/.env/.actuator + Host header + Security headers + Dangerous methods
web3             → Web3 secrets in JS + RPC port probe + IPFS API
verify           → Shadow replay (B2) + Hunter memory predictions (A1)
report           → 4 layered reports + Reproducer kits
```

### الـ Hard Limits (لا يمكن تجاوزها)

من Section K1 من الـ design document:

- **Forbidden payloads:** DROP TABLE, DELETE FROM, rm -rf, format c:, fork bombs
- **Forbidden methods (افتراضياً):** DELETE, PUT
- **Max records per IDOR test:** 3 (مش بنـ enumerate users)
- **Max response size to store:** 2 MB
- **Max global rate:** 50 req/sec (hard ceiling)
- **Auto-cleanup:** test uploads always cleaned up

ده مكدد في `core/safety.py` كـ constants — مفيش flag يقدر يـ disable.

### الـ Endpoint Scoring Algebra (Section 3.1)

كل endpoint بياخد score من 0–100 بناءً على:

```
Score = (Sensitivity × 0.40) +     ← /admin /payment /pii
        (AuthComplexity × 0.20) + ← oauth, multi-step
        (InputSurface × 0.15) +    ← params count, JSON, XML
        (StateMutation × 0.15) +   ← POST/PUT/DELETE, /charge
        (Exposure × 0.10)          ← no auth, public cache
```

أعلى score = أعلى أولوية في الـ scan.

### الـ Reports (4 طبقات + Reproducer Kits)

كل scan بينتج:

- **`REPORT.html`** — interactive، self-contained
- **`REPORT_executive.md`** — صفحة واحدة للـ business
- **`REPORT_manager.md`** — مع effort estimates
- **`REPORT_developer.md`** — full technical detail
- **`REPORT_defender.md`** — IOCs لـ blue team
- **`METHODOLOGY_AUDIT.md`** — اللي اتعمل واللي ما اتعملش
- **`PER-FINDING/<sev>_<title>_<id>/`** لكل HIGH/CRITICAL:
  - `WORKBOOK.md` — خطوات يدوية بالتفصيل (Section 6.2)
  - `curl.sh` — one-liner
  - `reproducer.py` — Python script
  - `finding.json` — raw data

### Hunter Decision Memory (A1)

لما تـ tag finding كـ "valid" أو "false positive":
```bash
# (قريباً CLI واجهة كاملة — حالياً عبر sqlite3)
sqlite3 results/<run>/tbhm.db \
  "INSERT INTO hunter_memory (finding_fingerprint, finding_pattern, decision, decided_at)
   VALUES ('<fp>', 'access_control:CWE-639', 'fp', datetime('now'))"
```

بعد 50 قرار، الأداة بتبدأ تتنبأ بقرارك على findings مشابهة.

---

## 📚 الـ Wordlists (SecLists Integration)

الأداة بتدور على SecLists في:
1. `$SECLISTS` env var (لو محدد)
2. `/usr/share/seclists` (Kali default)
3. `/opt/SecLists`
4. `~/SecLists`
5. `/usr/local/share/seclists` (macOS brew Intel)
6. `/opt/homebrew/share/seclists` (macOS brew Apple Silicon)

لو مش موجودة → بترجع للـ bundled wordlists في `wordlists/`.

### Wordlists اللي بنستخدمها

| الـ Phase | اسم الـ Wordlist | المسار في SecLists |
|---|---|---|
| Subdomain brute | `subdomains_small/medium/large` | Discovery/DNS/subdomains-top1million-*.txt |
| Content discovery | `content_quickhits/raft/common` | Discovery/Web-Content/* |
| API endpoints | `api_endpoints/objects` | Discovery/Web-Content/api/* |
| Parameters | `params_burp` | Discovery/Web-Content/burp-parameter-names.txt |
| LFI | `lfi_jhaddix/linux/windows` | Fuzzing/LFI/* |
| SSRF | `ssrf_urls` | Fuzzing/SSRF/SSRF-URLs.txt |
| XSS | `xss_jhaddix/polyglots` | Fuzzing/XSS/* + Polyglots |

---

## 🧪 الـ Workflow الكامل (مثال عملي)

```bash
# 1. تحضير الـ scope
echo 'https://hackerone.com/target/policy' > program.txt
echo 'target.com' > scope.txt
echo '*.dev.target.com' > oos.txt   # exclude dev

# 2. dry-run عشان تشوف الـ plan
./tbhm.py -l scope.txt --profile authorized_safe \
  --exclude oos.txt --bug-bounty-program "$(cat program.txt)" \
  -y --dry-run

# 3. شغل الـ scan الفعلي
./tbhm.py -l scope.txt --profile authorized_safe \
  --exclude oos.txt --bug-bounty-program "$(cat program.txt)" \
  -y -o results/target_run1

# 4. شوف الـ HTML report
xdg-open results/target_run1/REPORT.html
# أو على macOS: open results/target_run1/REPORT.html

# 5. لـ كل HIGH/CRITICAL في الـ PER-FINDING:
ls results/target_run1/PER-FINDING/

# 6. اقرأ الـ WORKBOOK.md، اعمل reproduce يدوياً في Burp
cat results/target_run1/PER-FINDING/HIGH_*/WORKBOOK.md

# 7. لو الـ finding أكدت يدوياً → اعملها report للـ program
# لو طلعت false positive → سجلها في الـ hunter_memory
sqlite3 results/target_run1/tbhm.db <<EOF
INSERT INTO hunter_memory (finding_fingerprint, finding_pattern, decision, decided_at)
VALUES ('<fp_from_report.json>', 'pattern_here', 'fp', datetime('now'));
EOF

# 8. بعد ما الشركة تـ patch:
./tbhm.py -d target.com --profile forensic_recheck \
  -o results/target_run1 -y
# هتشوف لو الـ fix فعلاً شغال
```

---

## 🛡️ الأمان والـ Legal

### الـ Pre-flight Legal Check

كل active profile محتاج:
- `-y / --yes-i-am-authorized` (إقرار صريح)
- (موصى به) `--bug-bounty-program <url>` للـ audit log

من غير الـ flags دي → الـ scan ما هيبدأش.

### الـ Audit Trail

كل action مسجل في `tbhm.db` و `tbhm.log`:
- Timestamp
- Profile applied
- Targets
- Bug bounty program URL
- All findings with discovery time

### الـ Scope Drift Detection (K2)

لو لقت finding خارج الـ scope → بتـ flag كـ banner أحمر في الـ report:
> ⚠️ This finding is on `cdn.thirdparty.com` which is OUT OF SCOPE. Showing for context only.

---

## 🐛 لو حصل problem

### ما لقاش tools

```bash
which subfinder httpx nuclei ffuf
# لو مش لاقي → أعد ./install.sh
# أو أضف $HOME/go/bin لـ PATH:
export PATH="$HOME/go/bin:$PATH"
```

### SecLists مش موجودة

```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists
# أو
export SECLISTS=/path/to/SecLists
```

### Python deps

```bash
pip3 install --user --break-system-packages -r requirements.txt
```

### الـ scan بيوقف فجأة

شوف `tbhm.log` في الـ output dir. كل phase بيـ log error وبيكمل (H1: tool health). الـ report بيتعمل حتى لو phase وقع.

---

## 📂 هيكل المشروع

```
TBHM-v2/
├── tbhm.py                    # Main Python orchestrator
├── install.sh                 # Tool installer
├── requirements.txt           # Python deps
├── README.md                  # هذا الملف
├── CHECKLIST.md               # Manual review checklist
├── core/
│   ├── config.py              # Profile loader + hard limits
│   ├── storage.py             # SQLite + hunter memory + pattern library
│   ├── safety.py              # Hard limits enforcement + resource monitor
│   ├── scoring.py             # Endpoint scoring algebra (3.1)
│   ├── runner.py              # Subprocess wrapper with rate limiting
│   ├── reporter.py            # 4-audience reports + reproducer kits
│   ├── verifier.py            # Shadow replay (B2)
│   └── seclists.py            # SecLists path resolver
├── phases/                    # 13 phase modules
│   ├── recon.py
│   ├── discovery.py
│   ├── content_discovery.py   # ffuf + SecLists
│   ├── vuln_scan.py
│   ├── injections.py
│   ├── access_control.py
│   ├── auth_advanced.py       # 2FA + JWT + OAuth
│   ├── api_specific.py        # GraphQL + Webhooks + Mobile + LLM
│   ├── upload_race.py
│   ├── secrets_misc.py
│   ├── web3.py
│   ├── verify.py
│   └── report.py
├── profiles/                  # YAML profiles
│   ├── passive_only.yaml
│   ├── authorized_safe.yaml
│   ├── authorized_full.yaml
│   └── forensic_recheck.yaml
├── payloads/                  # Fallback payload files
├── wordlists/                 # Fallback wordlists (SecLists preferred)
└── checklists/                # Methodology checklists
```

---

## 🤝 الإسهام

التحسينات المرحب بها:
- إضافة YAML profiles جديدة (forensic, fast-recon, deep-api)
- Phase modules جديدة (e.g. cloud assets enum, cookie analysis)
- تحسين الـ hunter_memory CLI
- ML model للـ A1 (decision prediction)

---

## ⚠️ Disclaimer

استخدام الأداة على أي target من غير تصريح = جريمة في معظم البلدان.

- ✅ Bug bounty programs (لو في scope)
- ✅ Pentests بـ Statement of Work موقّع
- ✅ شركتك بتاعتك
- ✅ Lab environments (DVWA, JuiceShop, HackTheBox)
- ❌ أي حاجة تانية

المسؤولية القانونية على المستخدم. الأداة دي tool — مش ترخيص.

---

## 📚 المراجع

- Jason Haddix — The Bug Hunters Methodology v4
- SecLists — https://github.com/danielmiessler/SecLists
- OWASP Top 10 + API Top 10
- amrelsagaei — Bug-Bounty-Hunting-Methodology-2025
- 0xmaximus — 2FA bypass checklist
- ProjectDiscovery toolkit
- TBHM v1.0 design document (280+ ideas)

---

**TBHM v2.0** — مبني بـ Python، مدفوع بـ SecLists، مستلهم من المنهجية اليدوية، مش بديل عنها.

---

## v2.22-redteam enterprise expansion

TBHM v2.22-redteam keeps the original web/API/mobile bug-hunting pipeline and adds a safe enterprise red-team layer.

### New safe red-team profile

```bash
./tbhm.py -d company.com \
  --profile authorized_redteam \
  -y --redteam \
  --scope scope.txt \
  --corp-cidr 10.10.0.0/16 \
  --dc-ip 10.10.10.10 \
  --ad-domain corp.local \
  --deep \
  -o company-redteam
```

Optional read-only LDAP bind, without placing the password in shell history:

```bash
export TBHM_AD_PASSWORD='READ_ONLY_PASSWORD_HERE'
./tbhm.py -d company.com --profile authorized_redteam -y --redteam \
  --corp-cidr 10.10.0.0/16 --dc-ip 10.10.10.10 --ad-domain corp.local \
  --ad-user readonly@corp.local
```

Optional firmware/static reverse engineering:

```bash
./tbhm.py -d company.com --profile authorized_redteam -y --redteam --firmware ./camera-fw.bin
```

Optional AI/LLM/RAG endpoint catalog:

```bash
./tbhm.py -d company.com --profile authorized_redteam -y --redteam --ai-endpoints-file ai-endpoints.txt
```

### What the red-team expansion tests

- Governance, ROE, high-risk approval register, residual-risk matrix.
- External recon, perimeter, service exposure, DNS/CNAME/cloud exposure.
- Internal CIDR safe discovery, service inventory, segmentation review signals.
- AD/DC read-only checks: DC services, DNS SRV, anonymous LDAP, optional read-only LDAP inventory.
- IoT/CCTV/sensors/printers/VoIP/BMS protocol exposure inventory.
- Wireless/RF, physical/social engineering, and SOC detection checklists and evidence registers.
- Firmware/static reverse-engineering review with hashes, binwalk signatures, strings, and pattern hits.
- AI/LLM/RAG/agentic coverage catalog and optional endpoint header baseline.
- Existing web/API/mobile/source/cloud/container/client-platform testing remains available.

### What it intentionally does not automate

This version does **not** automate credential theft, password spraying, phishing collection, malware, C2, persistence, EDR bypass, exploit execution, destructive testing, denial of service, unsafe physical actions, RF jamming/deauth, or real data exfiltration. Those paths are tracked as `Needs High-Risk Approval`, `Simulation`, `Lab Only`, or `Not Tested` so the report does not falsely say the company is safe.

## v3.9.1 — Integrated local LLM and authorized exercise evidence

- `--local-llm` is integrated into the report path and reuses one loopback-only Ollama runtime.
- `--local-llm-status` checks hardware and model readiness without a target.
- `--local-llm-setup` explicitly pulls or creates the configured local model.
- `--engagement-evidence PATH` sanitizes and normalizes artifacts from a separately governed exercise.
- `--exercise-simulation` creates a non-operational instructor scenario.

The evidence importer stores provenance hashes and defensive metadata, not credentials, hashes, payloads, or operational command lines. All imported observations remain leads until independently validated.

## v3.9.2 — Evidence confirmation, final-report redesign, and reverse engineering

v3.9.2 adds a global `exploitability_assessment` phase for every stored finding. It determines whether the evidence supports a possible attacker access path, but only produces `CONFIRMED` status when a deterministic verifier or controlled proof is stored. Scanner, static, imported, and LLM observations remain leads by default.

The final report now includes a table of contents, executive summary, scope, methodology, findings summary, confirmed vulnerabilities, supported findings, unconfirmed leads, remediation roadmap, retest criteria, and conclusion. Every confirmed vulnerability contains its own summary, proof of concept, confirmed reproduction steps, security impact, remediation, and retest criteria.

The reverse-engineering pipeline now includes:

- `reverse_triage`
- `reverse_static_analysis`
- `reverse_dynamic_evidence`
- `reverse_symbolic_analysis`
- `reverse_correlation`

Static backends include Ghidra headless, licensed IDA batch mode, Radare2, and Rizin. Runtime/debugger/instrumentation/sandbox evidence is imported from a separately isolated workflow. Strict runtime confirmation additionally requires `--reverse-verification-manifest` with a matching SHA-256-bound controlled/reproduced/approved decision. Optional bounded angr analysis does not synthesize exploits or payloads.

See `docs/REVERSE_ENGINEERING_AND_REPORTING_v3.9.2.md` and `CHANGELOG-v3.9.2-evidence-confirmation-reverse.md`.

## v3.9.7.4 — Firmware and universal reverse workflows

A firmware image or extracted root filesystem can now be analyzed without a
fake web target.

### Static firmware image and validated extraction

```bash
./tbhm.py \
  --firmware /absolute/path/device.bin \
  --firmware-extract \
  --firmware-tooling \
  -y -o device-firmware-analysis
```

### Audit an already extracted root filesystem

```bash
./tbhm.py \
  --firmware-rootfs /absolute/path/squashfs-root \
  -y -o device-rootfs-analysis
```

### Run an installed EMBA static profile

Run this only inside a disposable firmware-analysis VM:

```bash
./tbhm.py \
  --firmware /absolute/path/device.bin \
  --emba --emba-path /opt/emba \
  -y -o device-emba-analysis
```

EMBA emulation is a separate explicit gate:

```bash
./tbhm.py \
  --firmware /absolute/path/device.bin \
  --emba --emba-emulation --confirm-isolated-execution \
  --emba-path /opt/emba \
  -y -o device-emba-emulation
```

### Import an existing EMBA report

```bash
./tbhm.py \
  --emba-results /absolute/path/emba-logs \
  -y -o imported-emba-analysis
```

### Build a RouterSploit module catalog without execution

```bash
./tbhm.py \
  --routersploit-root /opt/routersploit \
  --routersploit-catalog \
  -y -o routersploit-catalog
```

### Import authorized RouterSploit output

```bash
./tbhm.py \
  --routersploit-results /absolute/path/reviewed-router-output \
  -y -o imported-router-results
```

TBHM does not execute RouterSploit exploit, scanner, credential, generic-attack
or payload modules. Catalog entries and imported positive lines remain leads
until the exact device model, version, exposure and harmless reproduction are
independently verified.

See `CHANGELOG-v3.9.7.4.md`,
`docs/REVERSE_ENGINEERING_STATUS_v3.9.7.4.md`, and
`VALIDATION-v3.9.7.4.md`.
