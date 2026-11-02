# TBHM 4.2.7 — install, reconnect, run and review

This is an incremental release built from the supplied 4.2.6 Linux package. Keep the old directory for rollback. The release preserves all 145 phase identities and 470 existing argument actions, adds four argument actions, and keeps both SQLite schemas at their existing compatible versions. Review `docs/review-v4.2.7/ROOT_CAUSE_REPORT.md` for measured changes and open work.

## 1. Upgrade the code; keep durable AI state

Finish or stop existing scans before an upgrade. Do not resume a 4.2.6 output directory with a changed build, scope or model configuration. Keep its reports and start a separate 4.2.7 run.

In **Kali**, back up with the currently installed version first:

```sh
cd "$HOME/tools/TBHM-4.2.6"
./tbhm --ai-backup --ai-home "$HOME/.local/share/tbhm-ai"
```

Download the new release ZIP and its checksum file into Downloads. Verify the checksum **before** extraction. Use the checksum delivered alongside this exact build; do not reuse a checksum from an older repair script or ZIP.

```sh
cd "$HOME/Downloads"
sha256sum -c TBHM-4.2.7-linux-x86_64.zip.sha256
mkdir -p "$HOME/tools"
unzip -n TBHM-4.2.7-linux-x86_64.zip -d "$HOME/tools"
cd "$HOME/tools/TBHM-4.2.7"
```

The distribution bundles pinned core wheels for Linux x86-64 and Python 3.12. Use your already available Python 3.12 interpreter. Core installation does not need sudo, a network connection, node/npm, cargo, model training, or an all-tools install.

```sh
bash install.sh --offline --python "$HOME/tools/TBHM-4.2.6/.venv/bin/python"
./tbhm --version
.venv/bin/python -m pip check
.venv/bin/python -c 'from core.package_verifier import verify_tree; import json; r=verify_tree(".",compile_python=True,require_manifest=True); print(json.dumps(r,indent=2)); raise SystemExit(0 if r["passed"] else 1)'
```

Expected: version 4.2.7, no broken core dependencies, package verification `passed: true`. Other optional scanners remain installed separately. Do not install every catalog entry to make a readiness count look complete. `--no-bootstrap` prevents bootstrap; scanner applicability and missing optional capabilities remain visible in the ledger.

Keep `$HOME/.local/share/tbhm-ai`. Do not copy `.venv` between release directories or replace the live AI database with a fresh empty one. The existing model weights stay on Windows. CVE/CWE catalog data stays in `knowledge/public-catalog.sqlite3`; it does not need downloading again for this upgrade.

## 2. Start Windows inference and the existing private link

In **Windows PowerShell**, start the previously configured task only when it is ready:

```powershell
$TbhmTaskName = "TBHM-Ollama-Kali-$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
Get-ScheduledTask -TaskName $TbhmTaskName | Where-Object { $_.State -eq 'Ready' } | Start-ScheduledTask
Get-ScheduledTask -TaskName $TbhmTaskName | Select-Object TaskName, State
curl.exe --noproxy "*" --connect-timeout 5 --max-time 15 -fsS http://127.0.0.1:11434/api/tags
ollama ps
```

A Running task means its process is running. It does not prove an SSH tunnel or inference is healthy. `ollama ps` reports actual loaded model placement; an empty NVIDIA inventory inside VMware does not describe the Windows GPU. This release does not modify your scheduled task, GPU settings, firewall, VPN, SSH keys or Windows power settings.

In **Kali**:

```sh
systemctl is-active ssh
ip -4 -brief address show eth0
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS http://127.0.0.1:11435/api/tags
cd "$HOME/tools/TBHM-4.2.7"
.venv/bin/python scripts/tbhm_connection_doctor.py --endpoint http://127.0.0.1:11435 --model qwen2.5:1.5b --embedding-model nomic-embed-text:v1.5 --probe-inference --timeout 30
```

Expected: tags list the installed models; generation and embedding respond; the embedding is finite, normally 768 dimensions for this model. Readiness is separate from security reasoning accuracy. `security_reasoning_accepted: false` and `training_executed: false` remain correct unless an independent evaluation or actual training establishes otherwise.

Locking the desktop does not necessarily suspend work. Actual host sleep, shutdown or VM suspension stops computation and breaks transport continuity. A Linux sleep inhibitor cannot keep a sleeping Windows host executing. Keep the host/VM awake under your established power policy during long jobs; reconnect and verify the API after wake.

### If connectivity fails

| Symptom | First check | Meaning / action |
| --- | --- | --- |
| Kali cannot reach `192.168.178.2`, neighbour stays INCOMPLETE | VMware VMnet8 / NAT on Windows | This was the original VM network fault. DNS edits alone cannot repair an unreachable NAT gateway. |
| Internet works; port 11435 refuses immediately | SSH active, Kali IP, task state | The reverse listener is not established yet. Wait for the existing reconnect loop, then retry the health request. |
| Listener exists but API times out; Windows 11434 works | `sudo ss -lntp '( sport = :11435 )'` | Historically a stale SSH session occupied 11435 while new forwards failed. Identify its exact owning `sshd-session` PID before stopping that session; do not kill every sshd or Ollama process. |
| Windows log says forwarding failed | Check the owning listener in Kali | The port is occupied; repeated client restarts do not free a stale remote listener. |
| PowerShell `Get-Content ssh.log` says in use | API health first | The log reader sharing conflict is separate from API health. Do not restart a healthy GPU service just to read a locked log. |
| `ollama` missing in Windows | `Get-Command ollama` | Kali installation does not install Windows Ollama. |
| Bash syntax such as `&&` errors in PowerShell | Shell label above each block | Run Linux commands inside Kali, Windows commands in PowerShell. |

The old fixed IP `192.168.178.128` in the link script must match the current `eth0` address. This guide does not silently replace pinned SSH host keys.

## 3. Synchronize source knowledge once after the upgrade

Only run this after the model link is healthy. Use the same embedding model as the existing vector manifest. An explicit model flag now overrides the command's model lock selection, without rewriting the persistent lock. A changed embedding space requires deliberate indexing; vectors from different spaces are never mixed.

```sh
cd "$HOME/tools/TBHM-4.2.7"
./tbhm --ai-migrate --ai-home "$HOME/.local/share/tbhm-ai" --local-llm-url http://127.0.0.1:11435 --local-llm-model qwen2.5:1.5b --ai-embedding-model nomic-embed-text:v1.5 --ai-embedding-workers 1
./tbhm --ai-doctor --ai-home "$HOME/.local/share/tbhm-ai" --local-llm-url http://127.0.0.1:11435 --local-llm-model qwen2.5:1.5b --ai-embedding-model nomic-embed-text:v1.5
./tbhm --ai-regression-check --ai-home "$HOME/.local/share/tbhm-ai" --local-llm-url http://127.0.0.1:11435 --local-llm-model qwen2.5:1.5b --ai-embedding-model nomic-embed-text:v1.5
```

Read the result: no stale source, readable database, intact audit chain, finite vectors in one space, and complete cache coverage are the desired maintenance state. Scan-time observation can deliberately leave pending vectors. Do not confuse that backlog with a failed database or successful training. `--ai-sync-tool` processes source deltas; `--ai-index-tool` requests an explicit full source reindex. Do not rebuild thousands of embeddings at every boot.

## 4. A small local acceptance run before live work

The following checks run local fixtures and protocol simulators; they do not scan the target domains from the supplied archives and do not evaluate the quality of your actual model.

```sh
cd "$HOME/tools/TBHM-4.2.7"
.venv/bin/python scripts/tbhm_release_acceptance.py --module test_v427_findings.py --module test_v427_runtime_control.py --module test_v427_service_wait.py --module test_v427_upgrade.py --output "$HOME/tbhm-work/validation-v427"
```

The slow-service case deliberately waits slightly over 15 seconds to reproduce the previous inference ceiling. Expected final `SUMMARY.json`: `passed: true`, every expected case executed, no skipped cases. Full packaged regressions are available with:

```sh
.venv/bin/python scripts/run_tests.py --source . --workers 1 --output "$HOME/tbhm-work/full-regression-v427.json"
```

Use one worker on the small VM. The packaged release validation receipts record what ran in the build environment; running them locally checks your own runtime.

## 5. Start a scoped web/API run with operational AI priority

Use assets and constraints from the actual current program policy. A public bug-bounty listing does not make unrelated hosts, IPs, operations, accounts, or uploads in scope. Retain the program's required attribution/header controls; the four target archives are evidence for this review, not an authorization file for a new scan.

Create `targets.txt` with one authorized URL or host per line, and `scope.txt` with one exact authorized host per line using `=host.example` when you want exact-host matching. Put exclusions into `exclude.txt`. Do not put an App Store URL, package identifier, wildcard shell expansion, semicolon-joined hosts or a GitHub page into a web target list. Use the program-policy file for typed assets and tighter path/method restrictions.

After substituting your reviewed file paths:

```sh
cd "$HOME/tools/TBHM-4.2.7"
./tbhm -l "$HOME/audits/my-project/targets.txt" --scope "$HOME/audits/my-project/scope.txt" --exclude "$HOME/audits/my-project/exclude.txt" --program-policy "$HOME/audits/my-project/program-policy.json" --profile authorized_safe --quick --no-bootstrap -y --phases preflight,discovery,spec_scan,api_fuzz,surface_correlation,protected_routes,strict_finding_validation,test_coverage_ledger,report,evidence_finalize --rate-limit 1 --threads 1 --max-parallel-tools 1 --api-rate 1 --api-budget 100 --ai-control adaptive --ai-control-max-decisions 2 --ai-home "$HOME/.local/share/tbhm-ai" --local-llm-url http://127.0.0.1:11435 --local-llm-model qwen2.5:1.5b --ai-embedding-model nomic-embed-text:v1.5 --ai-embedding-workers 1 --local-llm-context 2048 --local-llm-timeout 120 -o "$HOME/audits/my-project/v427-first"
```

Check `./tbhm --help` if your existing scripts used a different exclusion form. The command above is a bounded initial methodology, not an exhaustive test. Some adapters may be blocked when they cannot demonstrate policy enforcement. A rate and API budget are separate limits, not a promise that every scanner shares one perfectly global network budget.

`--ai-control adaptive` is the new main-process feature. The model can prioritize `spec_scan` versus `api_fuzz` when they are in the same ready window. It cannot add targets, add phases, skip verification/reporting, execute generated commands, alter scope, or mark a vulnerability confirmed. The normal phase dispatcher and each request's authorization checks remain responsible for execution.

To add per-finding advisory review to a later run, explicitly include `local_llm_triage` before report and supply `--local-llm --llm-refute --local-llm-max-findings 10 --llm-refute-max-findings 5`. Use a fresh output directory. `--local-llm-required` makes unavailable or incomplete model work fail the run instead of silently treating it as complete.

### Source and mobile input choices

For an already downloaded, authorized source tree, use `--code-dir /absolute/path/to/repository`, `--profile passive_only`, and this phase set:

```text
preflight,code_scan,code_intel,code_security_tooling,supply_chain_review,ci_cd_supply_chain_security,local_llm_triage,strict_finding_validation,test_coverage_ledger,report,evidence_finalize
```

Enable the actual optional work with `--code-security-tooling --cicd-security`. The source independent-check window is where the runtime model can prioritize the three source/CI review phases. Missing optional executables stay explicitly unavailable. Do not execute repository install/build/test scripts just because code is being audited. A declaration file is not executable source, but tests, fixtures, libraries and privileged workflows still deserve contextual analysis; location alone does not prove they are harmless.

`--apk /path/app.apk`, `--ipa /path/app.ipa`, and `--mobile-src /path/source` take actual local artifacts. Include `mobile_scan` in the phase plan. An app store page or package name is not an APK/IPA. Missing explicitly supplied inputs fail, while omitted optional inputs are recorded as not requested. Static package analysis does not perform device, jailbreak, runtime instrumentation, authenticated backend, or all-business-workflow testing.

Port scanning now also requires `--network-scope /path/authorized-ips.txt`; that file contains literal IPs/CIDRs explicitly authorized for network testing. The addresses must also pass a supplied program policy. DNS/CDN association alone is insufficient. `--port-rate 10` controls packet rate separately from HTTP RPS. Without explicit network authorization, `ports` records its missing prerequisite and launches no network scanner.

## 6. Read results in the right order

| Artifact | What it answers | What it does not prove |
| --- | --- | --- |
| `OPERATOR.html` | Stored findings, evidence state, review queue, links to receipts | A count is not confirmed vulnerability coverage |
| `REPORT_confirmed.md` | Findings with deterministic proof authority | Empty does not mean the target is secure |
| `REPORT_leads.md` | Supported/unconfirmed findings needing independent validation | Severity is not proof |
| `execution_ledger.json` | Actual phase/tool/request outcomes and missing/blocked work | A completed phase is not every security test passing |
| `evidence/test_coverage_ledger/coverage_ledger.json` and methodology audit, when produced | Recorded test execution / gaps | Catalogue registration is not execution |
| `llm_analysis/runtime_decisions.json` | Candidate phases, model proposal, accepted/fallback choice, actual order | Schema acceptance is not a model accuracy certificate |
| `protected_routes_review.json` | Anonymous response inventory and limitations | Public HTML or a SPA shell is not an auth bypass |
| `recon/port_scope_review.json` | Explicitly authorized IPs and denied relationships | A hostname resolving to a CDN is not ownership of its IP |
| `mobile/capability_receipt.json` | Supplied/missing/not-requested inputs and static attempts | Dynamic mobile testing is not inferred |
| `evidence_manifest.json` / delivery snapshot | Integrity of retained artifacts | Integrity does not establish exploitability |

Runtime decisions are bounded to three requests by default, at most eight with the CLI flag; the controller stops asking after two decision failures. Generation has a separate failure circuit from embeddings. Three consecutive transport/server failures open that purpose's circuit for the invocation; remaining reviews stay incomplete. Start a deliberate fresh invocation after repairing service health. There is no background loop that edits source code or approves lessons while you sleep.

## 7. Manual review after the scan

For every lead, identify the exact asset, input, actor, expected security rule, observed response/action, negative control and repeatability. Use owned accounts and objects. Record unknowns as inconclusive instead of asking the LLM to fill evidence gaps.

- **Web/API authorization:** compare authorized and unauthorized actors using the same owned object; include public-object and nonexistent-object controls. Public `200`, a login shell, an `Allow` header or a `403` is insufficient.
- **Uploads/downloads:** review content validation, processing steps, ownership and signed-link constraints using harmless owned test artifacts. A storage hostname or MIME acceptance alone is inventory.
- **Source/CI:** follow input to sink, examine sanitizers, call sites, runtime conditions, permissions, workflow triggers and deployment context. A declared `exec` signature, a feature handler or a passed Checkov check is not a vulnerability.
- **Dependencies:** resolve workspace/file links and actual release dependencies before asserting dependency confusion. Keep missing, escaping or remote links for review. A valid local dependency still needs ordinary code review.
- **Mobile:** establish what artifact and version were examined, manifest permissions/exported components, runtime context and in-scope backend authorization. Device-only checks need a device environment and explicit execution evidence.
- **Blind/OAST and race behavior:** require attributable test identifiers, controls and bounded repeatability. Missing infrastructure or a safe inability to reproduce remains inconclusive.
- **LLM advice:** verify every cited source and quoted code line. Keep unsupported counterclaims as advice requiring validation. Do not let a model's confidence replace source, actor or execution evidence.

A report should describe observed behavior and impact under the tested conditions. Do not submit a scanner count, a method-unsupported reply, an exposed public document or an LLM hypothesis as a proven vulnerability.

## 8. Learning and improvement remain deliberate

The existing persistent store, reviewed scenario API, source RAG, public CVE/CWE FTS catalog, evaluation, proposal approval and rollback remain available. For reuse of private project cases, provide `--ai-scenario-context` with that project's actual scope and permissions. Pending, quarantined, revoked or unapproved cases are not eligible runtime lessons. The new scheduler retrieves reviewed eligible scenarios only with explicit reuse permission and project scoping. Importing CVEs or generating embeddings does not train model weights.

Independent validation labels and frozen evaluation sets must remain separate from development data. The supplied old model smoke failures do not become passes just because GPU placement or schema validity improves. Fine-tuning stays optional and requires approved data, independently validated results, resources and a measured comparison.

At each boot: start the existing task, confirm SSH/API health, then run the desired assessment. Reinstall, pull models, reimport CVE/CWE data or rebuild the index only when there is an actual change or a maintenance diagnosis requiring it.

## 9. Rollback

Use the old directory for old results and a new output directory for a new run. Point your shell helper back at 4.2.6 if you need to compare behavior. This release did not change SQLite DDL or overwrite Windows model files. If you explicitly changed durable memory during testing, retain both backups and use the documented `--ai-restore` flow into a separate AI home first; do not overwrite the only copy of your current state.
