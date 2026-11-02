# TBHM v3.1-redteam-safe Changelog

v3.1 adds the **source-code intelligence** layer requested for "better v3
source-code testing logic". It is fully additive: every v2.24 / v3.0 phase runs
unchanged, and the existing `code_scan` phase is untouched. The new work lives in
a dedicated phase (`code_intel`) plus one new engine module (`core/code_intel.py`).

## The core idea

`code_scan` greps a tree for secrets/endpoints/sinks. `code_intel` does the full
reviewer workflow and, most importantly, **connects the dots**:

```
source code  ->  live endpoint  ->  exploit hypothesis  ->  safe verification  ->  report
```

## New engine: core/code_intel.py

Pure, read-only static logic (no third-party deps):

- **Repo intake + stack detection** — language histogram, package managers
  (npm/composer/pip/go/maven/gradle/bundler), and framework fingerprinting
  (Laravel, Django, Flask, FastAPI, Express, NestJS, Next.js, React, Vue,
  Angular, Spring, Rails, Android, Gin/Echo, ASP.NET).
- **Framework-aware route extraction** — Express/NestJS decorators, Laravel
  `Route::`, Flask/FastAPI decorators, Django `path()/re_path()`, Spring
  `@*Mapping`, Rails routes, Retrofit `@GET/@POST`, Go gin/echo, React Router.
- **Code intelligence map** — auth mechanisms + middleware, roles/permissions,
  DB models (Sequelize/TypeORM, Mongoose, Django ORM, SQLAlchemy, Eloquent,
  JPA, Prisma), and handler surfaces: upload, payment, admin, webhook, cloud/IAM,
  mobile API, AI/LLM.
- **Source -> vulnerability tracing** — for each dangerous sink it walks upward
  for the closest taint source and emits: `file -> function -> input -> sink ->
  missing control -> possible vuln -> how to safely test live`.
- **Endpoint -> live matching** — normalises code routes and pairs them with the
  real in-scope hosts.

## New phase: phases/code_intel.py

Orchestrates the whole pipeline and integrates with native TBHM findings and
reporting. Runs 15 branch modules, each with its own output file:

```
code_secrets  code_dependencies  code_routes  code_auth  code_access_control
code_business_logic  code_injection  code_uploads  code_payments  code_webhooks
code_admin  code_cloud  code_mobile_api  code_ai_api  code_ci_cd
```

Endpoint→live mapping is **reachability only**: one safe request per endpoint
(no payloads), recording status, response size, and whether an auth challenge
was observed. A source `/admin` route that maps to a live endpoint answering
without an auth challenge is raised as a HIGH finding.

## Safety model (unchanged)

- Source analysis is **read-only**.
- Live mapping is **reachability-only** — no payloads, no mutation.
- Exploit *confirmation* is intentionally delegated to the existing consented
  active phases (`add_sqli`, `injections`, `business_logic`, `access_control`).
  `code_intel` produces the hypothesis and a safe test plan; it never exploits,
  dumps data, or changes state.
- Live mapping only runs with `--map-code-to-live` or an active profile.

## New CLI flags

```
--github-token-env ENV       # clone private --code-repos with a token from ENV
--domains-file PATH          # in-scope domains (also seed targets + live map)
--urls-file PATH             # in-scope URLs (also seed targets + live map)
--code-branches LIST         # 'all' (default) or a comma list of branches
--map-code-to-live           # enable reachability mapping (auto-on active profiles)
--code-live-budget N         # cap endpoint×host probes (default 200)
--include-dependencies --include-ci-cd --include-secrets --include-business-logic
--include-access-control --include-admin-routes --include-api-routes
--include-payment-flows --include-upload-flows --include-webhook-flows
--include-auth-flows --include-cloud-config --include-mobile-api
```

`--code-dir`, `--code-repos`, and `--code-repos-file` are reused from v2.17.

## Phase-order integration

`code_intel` runs immediately after `code_scan` (so it can also feed extracted
endpoints to `api_fuzz`), and is in both the default `PHASE_ORDER` and the
`authorized_redteam` profile phase list. It is **not** gated as a redteam-only
phase — it runs in any profile whenever code input is supplied, and silent-skips
otherwise (same contract as `code_scan`).

## Output structure

```
results/<run>/source_code_full/
├── REPORT.html
├── source_code/
│   ├── repo_inventory.json
│   ├── framework_detection.json
│   ├── route_map.json
│   ├── discovered_endpoints.json
│   ├── endpoint_to_live_map.json
│   ├── orphaned_admin_routes.json
│   ├── hidden_api_routes.json
│   ├── auth_logic_map.json
│   ├── role_permission_matrix.json
│   ├── secrets_findings.json
│   ├── dependency_findings.json
│   ├── sbom.cyclonedx.json
│   ├── business_logic_findings.json
│   ├── injection_findings.json
│   ├── upload_findings.json
│   ├── payment_findings.json
│   ├── webhook_findings.json
│   ├── admin_route_findings.json
│   ├── ci_cd_findings.json
│   ├── source_to_vuln_traces.json
│   └── remediation_plan.md
├── evidence/
│   ├── code_snippets/
│   ├── live_requests/
│   └── screenshots/
└── logs/
    ├── source_scan.log
    ├── skipped_checks.log
    └── errors.log
```

## Example (the full source-code run)

```bash
export GITHUB_TOKEN="your_token_here"

python3 tbhm.py \
  --profile authorized_redteam -y --redteam \
  --code-repos-file repos.txt \
  --domains-file domains.txt \
  --urls-file urls.txt \
  --github-token-env GITHUB_TOKEN \
  --code-branches all \
  --map-code-to-live \
  --include-dependencies --include-ci-cd --include-secrets \
  --include-business-logic --include-access-control --include-admin-routes \
  --include-api-routes --include-payment-flows --include-upload-flows \
  --include-webhook-flows --include-auth-flows --include-cloud-config \
  --include-mobile-api --deep \
  -o results/source_code_full
```

Source-only, no live mapping:

```bash
python3 tbhm.py -d example.com --profile authorized_safe -y \
  --phases code_intel --code-dir ./src --code-branches all
```
