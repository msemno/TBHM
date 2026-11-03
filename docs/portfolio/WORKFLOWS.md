# Operator playbook — controlled, reproducible workflows

**Audience:** security engineers running their own local projects or explicitly authorized engagements. The examples below reflect command forms in the 4.2.7 publication README; verify all flags against `./tbhm --help` in your exact build.

## Prerequisites and environment

- Linux x86-64 with glibc 2.27+ and a working **Python 3.12** interpreter (3.12.14 was tested).
- Full TBHM 4.2.7 release contents, including `vendor/wheels`, `requirements.lock` and release manifest.
- Local disk for private outputs. For network activities, documented target authority, approved rates and clear stop criteria.
- External scanners, browser integration and a local AI model are **optional** and must be validated separately.

## Step A — install and establish a baseline

```bash
cd "$HOME/publish/TBHM"
bash install.sh --offline --python "$HOME/tools/TBHM-4.2.7/.venv/bin/python"
.venv/bin/python -m pip check
./tbhm --version
./tbhm --help
.venv/bin/python scripts/validate_v4_release.py
```

The path above is the Python 3.12 environment shown in the supplied Kali workflow. On a different machine, supply your own compatible interpreter. Installation validates **packaging and imports**. It does not certify installed scanners or AI.

## Step B — offline source workflow

```bash
mkdir -p "$HOME/tbhm-work/runs"
./tbhm --code-dir /path/to/a/local/project --offline \
  --phases code_scan,code_intel,report,evidence_finalize \
  --no-ai-observe -o "$HOME/tbhm-work/runs/offline-source" -y
```

**Expected intent:** analyze locally supplied code, inventory relevant findings, produce local SBOM/report/delivery. **Do not claim:** all source paths are reachable, dependency advisories were enriched online, or checked-out code is sandboxed for execution. Inspect the execution ledger for missing inputs and tools.

## Step C — authorized web workflow

Use an example hostname only as a template; **never execute it against an unapproved public target**.

```bash
./tbhm -u https://authorized.example.com --profile authorized_safe \
  --rate-limit 2 --no-bootstrap \
  -o "$HOME/tbhm-work/runs/approved-web" -y
```

Before running: record the authorized origins/IPs, methods, accounts, expiry, concurrency and rate limits. For port/network scanning, provide explicitly authorized IP/CIDR scope and packet-rate policy in the relevant configuration. Check that child adapters are installed and their own limits are appropriate. Monitor blocked phases, 429/503 cooldowns and resource use.

## Step D — triage responsibly

Read in this order: `execution_ledger.json` → `REPORT_leads.md` → `REPORT_confirmed.md` → `REPORT_final.md` → evidence manifest/delivery. Compare them, never cherry-pick a severity label. For each candidate: confirm target and identity bindings, reproduce using controlled accounts, record a negative control, and rerun the positive case. If the vulnerability class has no supported contract, present it as a lead for manual confirmation rather than automatic confirmation.

## Step E — deliver and retain

Final delivery snapshots are under `delivery/run-.../`; the working directory can contain private state and owner-only capture keys. Export only reviewed, sanitized artifacts. Keep scanner raw logs, auth tokens, cookies, client data, AI memory and working databases out of public Git. File hashes detect accidental changes but do not provide an independent authenticity signature.

## Acceptance checklist

- [ ] The executed build and Python version are recorded.
- [ ] The target and scope are approved and documented.
- [ ] Each necessary tool is installed and its output is actually parsed.
- [ ] Missing input/timeout/policy block is marked *incomplete*, not *clean*.
- [ ] Findings are grouped as confirmed, leads, or review-required.
- [ ] Proof class has applicable bindings, controls and repeat captures.
- [ ] Delivered files are sanitized; private working state remains outside the repository.

**Further reading:** [proof](PROOF_AND_FINDINGS.md), [boundaries](SECURITY_BOUNDARIES.md), `docs/UPGRADE-v4.2.7.md`, `docs/review-v4.2.7/CLI_REFERENCE.md`.
