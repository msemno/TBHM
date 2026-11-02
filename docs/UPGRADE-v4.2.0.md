# TBHM 4.2.0 upgrade and operator guide

4.2.0 extends the delivered 4.1.0 project. It fixes evidence-quality and offline-boundary defects, adds bounded local review workflows, and preserves the existing CLI options and 145 dispatched phase names. The distribution targets Linux x86-64, glibc 2.27+, Python 3.12. Optional scanner tools and model weights are installed separately.

## Install in a new directory

Extract `TBHM-4.2.0-linux-x86_64.zip`, enter `TBHM-4.2.0`, and run:

```bash
bash install.sh --python python3.12
./tbhm --version
./tbhm --doctor
```

If the Python 3.12 executable is named `python3`, use `--python python3`. The installer verifies the release manifest, creates `.venv`, installs the unchanged pinned core wheels without an index, and runs `pip check`. It needs working venv/ensurepip support. No sudo, system pip modifications, or optional-tool downloads are part of this installation. `bash install.sh --online` is an explicit alternate download source for the same locked dependencies.

Keep the old tool folder and prior evidence deliveries until your migration is verified. Install a new environment; do not copy the old `.venv`. Portable AI state remains outside the project under the existing `TBHM_AI_HOME` convention. Back up that state through the existing AI commands if you use it. Do not copy credentials, caches or result directories into the new application tree.

SQLite uses the existing backward-compatible schema and enrichment fields; 4.2.0 does not require a destructive database migration. New runs are recommended when comparing detection changes. `--resume` skips compatible completed work only when the effective configuration and input bytes match; changed contract, baseline, HAR or Slither bytes invalidate the fingerprint. Reporting and derived evidence are rebuilt according to the existing resume policy. Prior sealed deliveries remain separate snapshots.

## Local source review

```bash
./tbhm --code-dir /absolute/path/project --offline --profile passive_only \
  --no-ai-observe -o /absolute/path/results/source
```

Source/mobile/API/import flags can now select a narrow local workflow without an invented network target. Multiple supported local inputs are composed into one phase set. An explicit `--phases` list remains the final operator override. Existing repository URL inputs are supported; `--offline` blocks cloning and requires a local source tree.

The Python taint engine models intra-procedural flows and conservative joins. It handles simple reassignment, numeric conversion and shell invocation semantics more accurately. HTML escaping, arbitrary `validate` names, an unrelated sanitizer call, or URL encoding in a JavaScript sink are not accepted as general mitigation. AST flows are matched to their sink line and CWE. Regex-only candidates remain review leads, including when precise flow analysis cannot support them.

`source_code_full/source_code/analysis_coverage.json` records Python AST, lexical JS/TS, pattern-only and parse-error modes. Parse errors and dataflow-engine failures produce a partial ledger outcome. A parsed file or a reachable route is not proof that a sink was exercised. This is not a whole-program semantic analyzer; closures, aliases, dynamic dispatch, library behavior and full interprocedural flow still require specialized tools and manual review.

## Offline API contract and traffic review

```bash
./tbhm --openapi-input /absolute/path/current.yaml \
  --openapi-baseline /absolute/path/previous.yaml \
  --api-observations /absolute/path/session.har \
  --offline --profile passive_only --no-ai-observe \
  -o /absolute/path/results/api
```

Only `--openapi-input` is required. The other two flags require it. Inputs may be JSON or YAML up to 4 MiB. Supported contract families are Swagger 2.0 and OpenAPI 3.0.x/3.1.x; unsupported versions are explicit errors. Server URLs, callbacks, examples and external `$ref` documents are never fetched or executed.

Normalization is capped at 2,000 operations, 10,000 parameter records and a 16 MiB output. Large repeated schema/body structures are summarized by hashes; oversized security expressions remain unknown. Limit hits are partial/error outcomes.

The inventory preserves path/operation parameter inheritance, bounded local parameter/request-body references, root/operation security overrides, AND/OR requirement structure, empty security arrays and anonymous alternatives. Missing security is `unspecified`; malformed schemes/requirements remain `unknown`. Contract requirements do not demonstrate runtime enforcement. Shared schema definitions are hashed for change detection; this is not a full JSON Schema resolver, conformance validator or semantic breaking-change engine. Ambiguous reference siblings, cycles and unresolved references are reported rather than guessed.

Outputs are `spec/contract_review.json` and `spec/endpoints.txt`. Diffs identify added/removed operations, changed security/parameters/body structures/servers and changed shared-schema hashes. HAR comparison retains method, hostname and path only; query values, tokens, headers and bodies are not copied. Declared-host and server-base-path matching provide observation inventory. Unknown host alignment is labeled. `path_method_observed` never means authentication, authorization or security testing succeeded, and `not_observed` does not mean an endpoint is dead.

The existing network spec discovery mode remains available. Public API documentation is an INFO surface observation, not a vulnerability merely because it is public. The prior opt-in Schemathesis invocation remains unvalidated against current upstream CLI versions; imported local contracts are not automatically fuzzed. If you explicitly use the endpoint list for `api_fuzz`, normal scope, method, rate and write gates still apply:

```bash
./tbhm -u https://api.example.test --profile authorized_safe -y \
  --api-wordlist /absolute/path/results/api/spec/endpoints.txt \
  --phases api_fuzz,report,evidence_finalize --no-bootstrap \
  -o /absolute/path/results/api-live
```

Replace the example with an expressly authorized target. Parameter templates and inferred hosts still require operator review; no contract entry expands scope automatically.

## Mobile manifest review

```bash
./tbhm --mobile-src /absolute/path/mobile-source --offline \
  --profile passive_only --no-ai-observe -o /absolute/path/results/mobile
```

Existing `--apk` and `--ipa` inputs also remain available. APK/IPA extraction retains the existing archive safety controls. Decoded `AndroidManifest.xml` files now produce `mobile/manifest_<id>.json` with explicit settings, SDK declaration, components, inherited permissions, provider read/write permissions, path/URI-grant markers and deep links. Disabled and explicitly unexported components are distinguished. Missing/resource-based exported values and platform defaults stay unknown.

An exported activity/service/provider may be intentional. No runtime permission enforcement, unauthorized invocation, deep-link association, protected data access or application exploit is established from the manifest alone. Permission declaration names are review context, not proof of permission strength on a device. Binary AXML/string/AAPT dumps retain the older explicit application-boolean handling; full component semantics require decoded XML. Incomplete inventories are recorded as partial instead of clean. iOS runtime storage/keychain, device instrumentation, Frida/MobSF services and actual traffic require separately configured tooling and devices.

## Web3 and Slither result intake

Generate Slither JSON in your separately reviewed contract-analysis environment, then import the existing file:

```bash
./tbhm --web3-results /absolute/path/slither.json --offline \
  --profile passive_only --no-ai-observe -o /absolute/path/results/contracts
```

The importer validates the standard `success`/`results.detectors` envelope, bounds input size/count, rejects malformed records, deduplicates identical detector records, and persists static review leads through the normal storage/report pipeline. `web3/slither_import.json` records complete, partial or error status and the input digest. Slither optimization/informational results remain INFO. No contract compilation, build hooks, RPC signing, fork execution, fuzzing or financial transaction occurs.

The existing `--web3` network mode is retained. JavaScript fetches now use the scope/budget/redirect broker and honor passive/offline mode. Arbitrary 64-hex values and ordinary 12-word prose are not secret indicators. Private-key/seed assignments remain redacted, unvalidated candidates; BIP39 checksum, key ownership and live use are not proven. Ordinary read-only RPC block-number or IPFS-version responses are INFO observations. Privileged namespace, pinning or signing access is not inferred.

## Grounded local-AI review

```bash
./tbhm --local-llm-status
./tbhm --code-dir /absolute/path/project --offline --profile passive_only \
  --llm-refute --local-llm-model your-installed-model \
  --local-llm-max-findings 20 --llm-refute-max-findings 10 \
  --local-llm-context 4096 --no-ai-observe \
  -o /absolute/path/results/advisory
```

`--llm-refute` implies `--local-llm`. It adds a sequential counterevidence pass after normal metadata enrichment, with a default refutation limit of 20 and hard maximum of 100. The normal triage limit defaults to 100 (maximum 500). A local model must already be available for offline use. Explicit model setup/pull requires a separate online command; `--offline --setup`, `--offline --update` and `--offline --local-llm-setup` fail before a download. Offline AI initialization skips model pulls. Loopback model inference is an explicitly permitted local service, not a target/provider request.

The existing client uses Ollama JSON output and application-level validation. Finding IDs are bound to the current batch; duplicate, foreign, malformed and omitted IDs are recorded. Source findings with file/line metadata can include bounded redacted excerpts and one-hop local Python imports inside `--code-dir`; symlinks/outside paths are rejected. Source comments, scanner output and research are untrusted data. Context is deliberately partial; no source content can instruct TBHM to run commands.

`redteam/31_local_llm_triage/refutation_review.json` records `counterevidence_observed`, `unresolved` or `needs_validation`, supplied evidence references, missing proof and non-authoritative rationale. The model cannot suppress, confirm, reclassify or change severity. Suggested CWE/CVSS values stay in advisory enrichment. A failed reproduction, missing context, timeout, unsupported verdict or invented citation never becomes a false-positive verdict. `--local-llm-required` makes incomplete required inference a run failure while reports are still written.

The loopback HTTP model fixture validates integration and response contracts; it does not measure a real model's security judgment. No actual model weights, GPU throughput, 14B/32B feasibility, multi-model debate or advertised FP reduction was benchmarked here. Your reported host/VM RAM and VRAM are planning constraints. Run `--local-llm-status` on the actual Kali setup, reserve host/other-VM headroom, and remember that a host GPU is not automatically available inside a VM. Core source/API/import workflows require no GPU or new service.

## Correlation and operator review

Open `OPERATOR.html` after a run. It links real generated artifacts and shows a searchable queue from stored findings: evidence class, missing independent validation work and advisory refutation status. `operator_queue.json` and `evidence_graph.json` provide machine-readable equivalents. The main report links back to this view. Outcome counts come from recorded ledger events; there is no simulated progress, scan-coverage percentage or assumed clean result.

`--chain-simulate` now actually gates chain hypotheses. Findings must refer to one exact normalized asset and distinct records for distinct steps. Previous synthetic `attack_path` records are excluded from inputs. Hypotheses list unresolved preconditions and do not create additional high/critical vulnerability findings or invent confirmed exploit transitions. Similar CWE/parameter groups and title-independent root-cause candidates preserve every source record. Host association does not prove ownership or active permission. Conceptual MITRE keyword associations are not observed adversary execution.

Strict v2 runtime proof remains limited to the existing supported access-control, sensitive-data-exposure and open-redirect contracts. Captured negative controls, repeats and matching context remain necessary. Static analysis, imports, route reachability, generated curl commands, LLM agreement and graph co-occurrence do not replace those contracts.

## Rate/error behavior and remaining boundaries

Brokered native Requests retain scope/policy/method checks, shared request/rate budgets, TLS verification, explicit proxy handling, response limits and redirect checks. HTTP 429/503 now starts a shared host cooldown from a bounded `Retry-After` value (default 30 seconds, range 1–300). Subsequent brokered requests to that host are blocked before consuming budget. There is no implicit retry, proxy rotation or long sleep. Review the ledger and rerun when permitted.

This broker does not impose a global packet quota on external scanner processes, browsers, device tools or every legacy direct subprocess. `--offline` uses the existing subprocess allowlist and native request boundary; it is not an operating-system network namespace. Strict offline isolation of untrusted executables still requires an externally configured sandbox/network policy. Existing dynamic firmware execution contracts, approval/import boundaries and controlled plan modes are preserved.

## Evaluate explicit labeled fixtures

```bash
./.venv/bin/python scripts/evaluate_taint_fixtures.py --output-dir /absolute/path/evaluation
./tbhm --evaluate-labels /absolute/path/evaluation/labels.json \
  --evaluate-predictions /absolute/path/evaluation/predictions.json \
  --evaluation-output /absolute/path/evaluation/metrics.json
```

Labels are a JSON array of unique string `id`, boolean `vulnerable` and optional string `category`; predictions use unique string `id` and boolean `detected`. Duplicate/malformed IDs or string booleans are errors. Unlabeled predictions and missing predictions are reported separately and cause partial status; missing data is never silently counted as a clean case. Undefined denominators are `null`. Per-category and overall TP/FP/FN/TN, precision, recall, F1 and false-positive rate apply only to matched labeled cases.

The included 18 Python snippets were deliberately selected for the fixed taint-regression behaviors. They assume source/sink semantics and do not execute vulnerabilities. They are not an independent benchmark, a full-report precision measurement, or evidence of zero false positives on real projects. Regex-only review leads may still be emitted by the overall tool.

## Verify and troubleshoot

```bash
./.venv/bin/python -m pip check
./.venv/bin/python scripts/validate_v4_release.py
./.venv/bin/python scripts/run_tests.py --workers 3
./tbhm --capability-status all
```

The regression runner copies the distribution into isolated temporary workspaces. A successful phase means its code completed without a recorded partial/error condition; it is not vulnerability-test coverage. Inspect `execution_ledger.json`, the per-feature status files, `REPORT_leads.md` and `REPORT_confirmed.md`. A malformed contract/import still produces a partial report and nonzero run result. Missing optional tools/models are not silently reported as successful assessments.

`evidence_manifest.json` points to a sealed `delivery/run-.../` snapshot containing redacted outputs and a consistent SQLite backup. Deliver that snapshot rather than the live working directory. Sealing uses byte hashes for integrity; an unsigned manifest does not establish independent authenticity or a legal chain of custody.

The full HTML playbook contains the 109 research decisions, primary-source corrections, complete CLI reference, phase inventory, catalog boundaries, verification evidence and deferred roadmap. Historical manuals describe earlier releases and may contain older claims; use this guide and the new applicability record for 4.2.0 behavior.
