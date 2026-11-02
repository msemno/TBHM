# TBHM v2.11 — Changelog

Rule kept: **additive only.** New files, new flags, new phase. Existing code was
touched only to fix real bugs; no features removed.

## Bugs fixed

1. **`ctx.intensity` was never set.** `nuclei_extended.py` and
   `vuln_scan_extended.py` read `getattr(ctx, "intensity", "standard")`, but the
   `Ctx` object never assigned it — so `--quick/--deep/--insane` were silently
   ignored for nuclei rate-limiting. Now set in `Ctx.__init__`.

2. **`storage.boost_endpoint_score()` wrote a non-existent column** (`scored_at`;
   the schema has `last_scanned`). The INSERT failed silently inside a try/except,
   so smart_crawl's score boosts never persisted. Fixed the column name.

3. **`storage.update_pattern()` used `ON CONFLICT(rowid)`** — a no-op, since every
   INSERT gets a fresh rowid. The pattern library never accumulated success/FP
   counts. Added a `UNIQUE(tech_stack, vuln_type, payload_variant)` index and
   pointed the UPSERT at it.

4. **None-slicing crash** in `save_finding()`: `f.get("response_raw","")[:200000]`
   throws if the key exists with value `None`. Guarded with `(... or "")`.

5. **`curl_cmd` built then discarded** in `nuclei_extended._to_finding()`. The
   reproducer is now attached to the finding (`reproducer_curl`).

6. **`install.sh` never ran `nuclei -update-templates`.** This is the #1 cause of
   "nuclei finds nothing" — nuclei with an empty template store reports zero. The
   installer now downloads templates and prints the count, plus the bundled
   custom-template count.

## New: self-healing setup (`core/bootstrap.py`)

Detects and fixes the two silent-empty-scan causes automatically:

- `ensure_nuclei_templates()` — runs `nuclei -update-templates` if the store is
  empty/stale.
- `ensure_seclists()` — locates SecLists; shallow-clones it if absent.
- `ensure_custom_templates()` — resolves the bundled `nuclei-templates/tbhm/`.

Runs automatically at the start of every active scan (skip with `--no-bootstrap`),
and on demand via `--setup`.

## New: custom nuclei templates (`nuclei-templates/tbhm/`)

22 templates curated for the **LOW / INFO** band that hunters still want flagged.
All validated against the official nuclei v3 JSON schema, RE2-regex-safe, and
logic-tested against vulnerable + safe responses:

- Missing security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy
- Weak cookie flags: missing Secure, missing HttpOnly
- Disclosure: Server version, X-Powered-By / framework headers, stack traces
- CORS: reflected arbitrary origin, null origin
- Exposed files: `.env`, `.git/config`, `.DS_Store`, backup archives, phpinfo
- Misconfig: directory listing, TRACE enabled, write methods via OPTIONS
- Hygiene: missing `security.txt`

Regenerate from source with `python3 nuclei-templates/_build_templates.py`.

## New: phase `custom_nuclei`

Runs the bundled templates and **captures every severity** (info → critical),
unlike `vuln_scan` which honours the profile's severity floor. Inserted right
after `nuclei_extended` in the phase order.

## New CLI flags

```
--setup                 Download/refresh nuclei templates + SecLists, then exit
--update-templates      Force template refresh before scanning
--no-bootstrap          Skip the automatic self-heal at scan start
--nuclei-severity LIST  Override nuclei severities (e.g. info,low,medium,high,critical)
--nuclei-tags LIST      Extra nuclei tags for the vuln_scan sweep
--custom-templates DIR  Additional template directory to run alongside the bundled set
--include-info          Also capture INFO/LOW findings in vuln_scan
--rate-limit / --rps N  Override global requests/sec (still capped by hard limits)
--proxy URL             Route nuclei/HTTP probes through a proxy (e.g. Burp at :8080)
--threads N             Concurrency hint where supported
--no-cloud              Skip the slow cloud_recon + cloud_recon_extended phases
--only-nuclei           Fast path: recon + the three nuclei phases + report
```

## Quick start after upgrade

```bash
./tbhm.py --setup                              # one-time: pull templates + SecLists
./tbhm.py -d target.com -y --only-nuclei       # fastest template-based pass
./tbhm.py -d target.com -y --standard --include-info --no-cloud
./tbhm.py -d target.com -y --proxy http://127.0.0.1:8080   # mirror into Burp
```

---

# TBHM v2.12 — Ineligible-finding suppression

Adds HackerOne Core/Platform Standards suppression. Merges two filter snippets
(`filters/ineligible_findings.py` + `lib/categorization.py`) into one module,
fixing the gaps that would have stopped the raw snippets from working.

## New: `core/ineligible_findings.py`
- `CORE_INELIGIBLE` — exact template-id set (missing headers, cookie flags,
  self-xss, open-redirect-no-impact, empty-bucket, SPF/DMARC, TLS-weakness, etc.)
- `NEVER_REPORT_PATTERNS` — regex set, limited to the always-ineligible
  header/cookie class (catches `tbhm-`, `http-`, and community-prefixed ids).
- `is_never_report(id)` / `should_suppress(finding)` — your original APIs, kept.
- `classify(finding)` — id (exact + regex) OR title-signature match.
- Title signatures catch findings with no clean id (e.g. cloud empty buckets).
- User extension via `~/.tbhm/ineligible_extra.txt`.

## Gaps fixed vs the raw snippets
1. Findings are dicts, not objects — `finding.template_id` would crash; module
   takes dicts (and still tolerates objects).
2. Bundled templates are `tbhm-`prefixed, so exact-set match alone missed them;
   ids are normalised and also regex-matched.
3. Conservative: regex list is header/cookie-only. A real open redirect,
   clickjack-with-impact, or readable/non-empty bucket is NOT suppressed
   (verified against 14 finding shapes — 11 ineligible suppressed, real bugs and
   open/data buckets passed through).

## Behaviour
- Default: ineligible findings are tagged `severity=SUPPRESS` + `suppress_reason`,
  routed to the `dropped_findings` archive (visible in fp/review output), and kept
  out of the main report. Not deleted.
- `--include-ineligible` keeps them in the main report.
- Scan summary shows the suppressed count.

## Wiring
- `template_id` now stored on findings from `custom_nuclei`, `nuclei_extended`,
  and `vuln_scan` (was absent — required for id-based matching).
- Suppression hooks into `Ctx.save_finding`, the single funnel all phases use.

---

# TBHM v2.13 — Catch-all-aware API fuzzing

Solves the "every path returns 200 + the same body" gateway problem, where the
API answers unknown routes with a constant envelope like
`{"status":false,"message":"Invalid endpoint.","code":"invalid_endpoint"}` (72 B).
Normal fuzzers report every guess as "found" because status and size never move.

## New: `core/api_baseline.py`
- `make_signature()` — fingerprints a response (status, length, body hash, JSON
  status/code/message), normalising reflected random tokens.
- `detect_catch_all()` — fires random nonsense paths; if they all return the same
  signature, the host is a catch-all gateway.
- `classify()` — flags only responses that DEVIATE from the baseline. Strongest
  signal: the JSON `code` field changing (invalid_endpoint -> unauthorized /
  method_not_allowed / validation_error), which proves a route exists under a
  constant-200 gateway. Tolerates tiny body deltas (reflected values).
- `RateLimiter` — global min-interval limiter, default 2 req/sec.

## New: phase `api_fuzz`
1. Calibrates the catch-all baseline per host.
2. Fuzzes a curated API wordlist, reporting only deviations.
3. Method-fuzzes each path — GET + POST by default; PUT/PATCH/DELETE only with
   `--allow-writes`; OPTIONS probed for the Allow header.
Classifies each hit: auth-required / wrong-method / needs-params / returns-data /
server-error, and writes `<output>/api/discovered_endpoints.txt`.

## New: `wordlists/api-endpoints.txt`
149 curated API paths (versioned prefixes, auth, users, admin, payments, docs,
actuator, internal, etc.). Merged with any `--api-wordlist` and SecLists' api list.

## New CLI flags
```
--api-base URL      Point api_fuzz at one API base directly (skips recon)
--api-rate RPS      Requests/sec (default 2.0 — matches 'automated tool: 2 req/sec')
--api-methods LIST  Methods to fuzz per path (default GET,POST)
--api-wordlist PATH Extra API path wordlist
--api-budget N      Max total api_fuzz requests (default 6000)
--proxy URL         Now also routes api_fuzz through Burp/ZAP
```

## Verified
Against a mock of the exact gateway (constant 200 + invalid_endpoint, 72 B, with
4 hidden routes): catch-all detected, all 4 real endpoints found and correctly
classified — including one reachable only via POST — while every nonsense path
(356 requests total) was filtered out. Rate limiter holds at exactly 2 req/s by
default. 8/8 classification logic tests pass, including catch-all-not-flagged.

## Usage for this exact case
```bash
./tbhm.py -u https://api.target.com --api-base https://api.target.com \
    --phases api_fuzz --api-rate 2 --api-methods GET,POST --allow-writes
# mirror into Burp for manual testing of each hit:
./tbhm.py -u https://api.target.com --phases api_fuzz --proxy http://127.0.0.1:8080
```

---

# TBHM v2.14 — Authoritative rate limiting

`--rate-limit N` (alias `--rps N`) is now a hard ceiling that EVERY rate-consuming
phase respects. Previously it was ignored or multiplied by several phases:
ports/naabu ran at rate×100, content_discovery/ffuf at rate×5, and the three
nuclei phases used a hardcoded intensity rate (150/s on --deep) regardless of the
flag — so a stated "2 req/sec" limit was silently exceeded.

- New `core/ratelimit.py` `cap()` — clamps any phase's computed rate to
  `rate_limit.hard_cap`, set only when --rate-limit is passed.
- Applied in ports, content_discovery, nuclei_extended, custom_nuclei,
  vuln_scan_extended. vuln_scan and recon already used global_rps directly.
- Without --rate-limit, hard_cap is unset and all phases keep their defaults.

Verified: with --rate-limit 2 on --deep, every phase clamps to 2 req/s
(naabu 200→2, ffuf 10→2, nuclei 150→2); without the flag, nuclei stays 150.

Note: api_fuzz has its own --api-rate (default 2), independent of --rate-limit.

---

# TBHM v2.15 — Enforced scope (--scope now actually works)

`--scope` (in-scope allowlist) was parsed but never applied to the scan, so
out-of-scope hosts could still receive traffic. Now enforced.

- New `core/scope.py` `Scope` — glob patterns ('*' wildcard), host-boundary
  anchored so `domain.com` does NOT match `notdomain.com` or
  `domain.com.evil.com`. Excludes always win over includes.
- Wired into recon (the chokepoint feeding all phases) and discovery:
  - --scope set      -> only matching hosts/URLs are kept; everything else dropped
  - --exclude set    -> matching hosts/URLs dropped (unchanged, still works)
  - neither set      -> everything kept (unchanged)
- `collect_includes()` reads the --scope file; `ctx.scope` applied per phase.

Verified against 19 cases: allowlist keeps only in-scope hosts, wildcard
carve-outs honoured, anchoring blocks the `*.evil.com` suffix bypass.

How to write scope:
  Allowlist (only these in scope, everything else out):
    printf 'app.domain.com\napi.domain.com\n*.api.domain.com\n' > scope.txt
    ./tbhm.py -d '*.domain.com' --scope scope.txt -y --profile authorized_full --deep
  Wildcard with carve-outs:
    printf '*.domain.com\n' > scope.txt
    printf 'blog.domain.com\n*.dev.domain.com\nthirdparty.com\n' > oos.txt
    ./tbhm.py -d '*.domain.com' --scope scope.txt --exclude oos.txt -y --deep

---

# TBHM v2.17 — Source-code & mobile static analysis

Two new phases that turn open-source targets and mobile apps into endpoint/secret
intelligence (the Filen workflow: the SDK/app holds the real routes).

## New: core/code_patterns.py (pure Python, no external tools)
- find_secrets — 25+ provider-specific patterns (AWS/GCP/GitHub/Stripe/Slack/
  Twilio/SendGrid/Firebase/JWT/private keys + entropy-checked generic assignments;
  placeholders filtered out).
- find_endpoints — extracts URLs, API paths (quoted AND unquoted for binaries), hosts.
- find_sinks — SAST-lite: eval/exec, child_process, os.system, innerHTML,
  dangerouslySetInnerHTML, pickle/yaml unsafe load, SQL concat, weak crypto,
  TLS-verify-disabled.

## New: phase code_scan
Inputs: --code-dir PATH | --code-repos URL,URL | --code-repos-file PATH.
Clones (shallow) and walks the tree (skips node_modules/.git/vendor/minified),
emits secret + sink findings, and writes extracted endpoints/hosts to
<output>/code/{endpoints,urls,hosts}.txt. Runs gitleaks + semgrep too if installed.
Verified: caught Google/Stripe keys + os.system + SQL concat, extracted API paths
and hosts.

## New: phase mobile_scan
Inputs: --apk PATH | --ipa PATH | --mobile-src PATH.
- APK: unzip, strings on classes*.dex/resources.arsc/assets → secrets+endpoints;
  AndroidManifest via aapt/aapt2 (string-grep fallback) → flags debuggable,
  allowBackup, cleartext traffic, exported components, deep-link schemes.
- IPA: unzip, Info.plist (ATS exceptions, URL schemes) + Mach-O strings → secrets+endpoints.
- Source: walks the tree through the shared engine.
Writes endpoints/hosts to <output>/mobile/. Verified against a built APK: found
AWS/Google/Stripe/Firebase + all 5 manifest issues + extracted hosts/paths.

## Workflow
  ./tbhm.py -d example.com -y --code-repos https://github.com/org/sdk --phases code_scan
  # then feed discovered routes into the API fuzzer:
  ./tbhm.py -u https://api.example.com --api-base https://api.example.com \
     --phases api_fuzz --api-wordlist <out>/code/endpoints.txt --api-rate 2 --allow-writes

Both phases self-skip silently when no code/mobile input is given, so the default
pipeline is unchanged.

---

# TBHM v2.18 — SBOM/CVE, source-map recovery, GraphQL/WS, XXE+crypto, SARIF report

Real, detection-only additions distilled from an over-broad "find everything /
zero-day" spec. No autonomous exploitation, no fictional completeness claims.

1. SBOM + CVE (core/sbom.py): parses package.json/requirements.txt/go.mod/
   Cargo.lock/pom.xml/Gemfile.lock, emits CycloneDX 1.5 (sbom.cyclonedx.json),
   queries OSV.dev for known CVEs → HIGH findings (reachability NOT verified —
   manual triage). Wired into code_scan. Offline = SBOM without vuln data.

2. Source-map recovery (core/sourcemaps.py): reconstructs original TS/JSX from
   shipped .map sourcesContent; recovered tree is scanned for secrets/endpoints.
   Verified: recovered a hidden.ts and extracted its secret + /v3/internal/keys.

3. GraphQL depth + WebSocket (api_specific): on an introspectable endpoint, flags
   sensitive schema field names and query batching; detects ws://\wss:// endpoints
   from crawl/JS/code output for manual auth testing.

4. XXE + crypto-misuse static patterns (code_patterns): lxml/DocumentBuilder/PHP
   libxml/.NET XML; weak PRNG, PBKDF2 low-iter, hardcoded/zero IV, small RSA, CBC.

5. HTTP request smuggling (phases/smuggling.py, --smuggle, OPT-IN): CL.TE/TE.CL
   timing-differential DETECTION only, rate-limited, off by default.

Report upgrade (reporter + core/cwe_cvss.py): every finding enriched with a CWE id
and an estimated CVSS 3.1 vector/score; new report.sarif (SARIF 2.1.0 → GitHub
Security tab) and report.csv (bug-tracker import) alongside existing formats.

What was NOT added and why: "finds all bugs" (undecidable), "creates zero-days"
(a scanner matches known patterns), "reconstruct private source from asset hashes"
(hashes don't reverse), autonomous DB-dump/webshell/DNS-exfil/500-thread exploitation
(violates the tool's hard limits and program rules). See prior reply for rationale.

---

# TBHM v2.19 — API spec discovery, extra interfaces, PWA, CNAME takeover, SSE

Buildable detection-only gaps from the OWASP 2026 playbook. Manual/credentialed
items (two-account BOLA, OAuth/SAML flow, gRPC, MCP/RAG authz, CI/CD/IaC) were
NOT added — they require sessions, running features, or pipeline access.

1. phases/spec_scan.py — probes /openapi.json /swagger.json /v3/api-docs etc.,
   parses the spec (JSON/YAML), extracts every path+method+params → spec/endpoints.txt
   (feed --api-wordlist). Also probes SOAP/WSDL, OData, JSON-RPC, XML-RPC, GraphQL
   IDEs and flags presence. Optional schemathesis runner behind --spec-fuzz (staging).
   Runs before api_fuzz so documented routes feed the fuzzer. Verified: extracted
   3 documented paths from a mock OpenAPI spec.

2. phases/client_platform.py — fetches service-worker.js/sw.js + manifest.json;
   flags broad SW scope + auth-cache (stale-auth-after-logout lead). Verified.

3. phases/cname_takeover.py — CNAME inventory (dnsx -cname, socket fallback) +
   dangling-takeover heuristic against 35+ takeover-prone providers. LOW confidence,
   manual-confirm. Complements subzy. Verified matching.

4. api_specific — added Server-Sent Events detection (text/event-stream on
   /events /stream /sse) alongside the existing WebSocket detection.

All rate-limited via the global cap; all detection-only. schemathesis + dnsx used
if installed, graceful fallback otherwise.

---

# TBHM v2.20 — two long-standing defects fixed

1. --resume now works. Infra existed (mark_phase_done/is_phase_done + phase_state
   table) but the main loop never checked it. Now: with --resume and the same -o,
   phases already marked done in that run's DB are skipped. Verified.

2. curl_verify honours --rate-limit. curl_probes was unthrottled (flagged since
   v2.16). Added a module rate limiter (curl_probes.set_rate/_throttle); curl_verify
   sets it from the global cap. Verified: rps=2 → 2.0s for 5 probes; disabled → no delay.

No new phases. Audit confirmed already-present: arjun (param discovery, optional),
gotator/altdns (DNS permutation, optional), so those were not re-added.

---

# TBHM v2.21 — catch-all false-positive fix (Filen scan: 2312 findings, ~all FP)

Root cause: hosts that answer EVERY path the same way. app.filen.io is a SPA
(200 + app shell), gateway/ingest.filen.io are API gateways (200 + invalid_endpoint).
Detections keying on status 200 fired on every wordlist entry.

Fixes:
- api_baseline.classify: never flag 404/410; never flag when body == catch-all
  baseline even under a different status. Kills ~652 api_fuzz FPs (it was flagging
  HTTP 404 responses as "endpoint discovered").
- content_discovery: ffuf -ac auto-calibration + dominant-size-cluster post-filter
  (>40% same status+size and >25 hits = wildcard, dropped). Kills ~1423 FPs.
- infra_exposure: fail CLOSED for unconfirmed CRITICAL/HIGH; reject HTML app-shell
  bodies for spring_/docker_/k8s_ checks. Kills the /heapdump CRITICAL FPs
  (spring_heapdump_legacy had no confirmation pattern → any 200 fired).
- waf_evasion_ssrf: removed generic "127.0.0.1"/"localhost:" metadata markers
  (present in benign JS bundles → false CRITICAL); length-differential alone now
  caps at LOW/unconfirmed, requires >60% delta. Kills SSRF CRITICAL FPs.
- core/soft404.py: shared lazy per-host catch-all detector, wired into
  upload_race, auth_advanced, api_specific webhooks — drops path-probe findings on
  catch-all hosts (the ingest.filen.io 2FA/webhook/upload FPs).
- code_patterns.is_minified: catch versioned-min (jquery.min.3.5.1.js) + vendor +
  lockfiles so code_scan stops flagging vendored libs.

Verified by unit tests reproducing each FP class from the uploaded tbhm.db.
