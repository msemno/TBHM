# Upgrade and validation on Kali

Keep the old source tree and the persistent AI home. Extract this release into a
new TBHM-4.2.6 directory. The original 4.2.5 manifests remain historical records;
the new manifest describes the corrected package. Do not run the old runtime
repair against this release: its hash allowlist intentionally targets 4.2.5.

From the extracted directory, Kali bash/zsh:

```bash
bash install.sh --offline --python python3.12
./tbhm --version
./tbhm --help
./tbhm --ai-backup
./tbhm --ai-status --local-llm-url http://127.0.0.1:11435
.venv/bin/python scripts/tbhm_connection_doctor.py --endpoint http://127.0.0.1:11435
```

Installation uses only the included hash-locked core wheels, with no sudo,
system Python edits or scanner downloads. It does not install optional tools,
pull models, change VPN/firewall settings or alter a Windows supervisor. Retain
the existing AI_HOME/TBHM_AI_HOME selection and check that status names the
expected persistent database before indexing it. Back up the existing store
before explicit maintenance. GPU placement is observed only for currently loaded
models via /api/ps; model inventory alone does not establish it.

The existing Windows Ollama loopback 11434 → SSH reverse-forward → Kali loopback
11435 architecture is supported. Do not expose the API on all interfaces, disable
host-key checking or kill generic SSH/Ollama processes to fix connectivity.
Host-side ownership/listener failures still require diagnosis on that host.

After selecting the actual installed advisor and embedding model, optional
inference probes can be requested explicitly:

```bash
.venv/bin/python scripts/tbhm_connection_doctor.py --endpoint http://127.0.0.1:11435 --model qwen2.5:1.5b --embedding-model nomic-embed-text --probe-inference
.venv/bin/python scripts/tbhm_ai_acceptance.py --tool-home "$PWD" --endpoint http://127.0.0.1:11435 --model qwen2.5:1.5b --self-test
```

The second command exercises independent native controls, not model reasoning.
Omit --self-test only when deliberately running the real-model experiment and
retain its raw/guarded output. The model names above match the supplied log's
inventory; choose the reviewed installed model rather than assuming readiness.

For an idle, backed-up AI store with a valid model lock, the supplied strict
maintenance command retains checkpoints between attempts:

```bash
.venv/bin/python scripts/tbhm_strict_reindex.py --tool-home "$PWD" --ai-home "$HOME/.local/share/tbhm-ai" --url http://127.0.0.1:11435 --dimension 768 --max-seconds 1800
```

Use that AI-home path only after the preceding status check confirms it is your
store. Dimension 768 is appropriate only for the locked model that produced that
space. A failure does not authorize deleting the store or replacing its model
lock. No command here silently turns fallback hashes into Nomic embeddings.

Before a real scan, inspect tool identity, versions, template inventory and scope
using your existing authorized workflow. Missing tools/API keys/OAST remain
explicit coverage gaps. Reuse the actual reviewed scope and policy files from
the engagement; none were reconstructed from the incomplete debug bundle.
Cancellation keeps partial evidence and exits 2. Tool timeout 124 is recorded
per operation. Resume fingerprints now include the control-plane source build,
so incompatible old-build phase completions are not silently reused.

Supported profile runtime settings (the existing profile configuration mechanism):

| Setting | Default | Meaning |
|---|---:|---|
| http_policy.service_request_budget | 2048 | Separate loopback inference attempts |
| runtime.service_timeout_seconds | 15 | Scan-time inference socket ceiling |
| runtime.phase_timeout_seconds | 3600 | Deadline at migrated dispatch boundaries |
| runtime.content_discovery_seconds | 900 | Cumulative ffuf phase allowance |
| runtime.require_external_containment | false | If true, raw subprocess adapters refuse execution |

Legacy HTTP target budgets/rates remain unchanged. External tools' individual
requests and wire bytes are not universally brokered. Offline syscall filtering
is Linux x86-64 isolation, not a network namespace. Sensitive raw-writer closure
and every vulnerability class are not certified by this release.

Reproduce core acceptance from the source root:

```bash
.venv/bin/python scripts/tbhm_release_acceptance.py --output /tmp/tbhm-426-acceptance
.venv/bin/python scripts/validate_v4_release.py
```

The first command requires every expected test to finish and a current-build
receipt. The second verifies syntax/imports/package integrity/phase resolution.
scripts/check_done.py is a different high-level milestone gate and is expected
to remain nonzero while the published containment/privacy/coverage gaps are open.
