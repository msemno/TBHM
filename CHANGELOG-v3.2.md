# TBHM v3.2-redteam-safe Changelog

Two parts: (1) confirmation that v3.1 lost nothing from v3, and (2) a batch of
upgrades from the "full red-team / real-world scenarios" recommendations. All
additive — nothing removed, every prior phase still loads and behaves the same.

## Part 1 — v3.1 vs v3 regression (verified)

- File-level diff: the only files v3.1 removed relative to the original v3 zip
  were stale `results/*` scan databases/logs from earlier test runs — no tool
  capability. Every phase, core module, profile, wordlist, template, and doc is
  intact.
- All original phases import cleanly (59 in the original tree, 60 with the v3.1
  `code_intel` phase).
- `tbhm.py` diff vs original: purely additive (no lines removed).

Conclusion: v3.1 is a strict superset of v3. v3.2 continues that: **66 phases
total, all loadable**, and `tbhm.py` remains additive-only.

## Part 2 — new v3.2 modules

### Read-only analysis phases

- **`attack_path`** (`--chain-simulate`) — correlates the whole findings set into
  multi-stage attack **chains** (`chained_attack_path.md`, `attack_path.json`) and
  maps every finding to **MITRE ATT&CK** (`mitre_attack_map.json` +
  `mitre_attack_layer.json`, importable into ATT&CK Navigator). HIGH/CRITICAL
  chains are raised as their own findings. The MITRE map runs regardless;
  `--chain-simulate` adds the chain narrative.
- **`compliance_coverage`** — maps findings onto **OWASP Top 10 (2021)**, a **CWE**
  histogram, and **PCI-DSS v4.0** requirement touch-points, and flags **coverage
  gaps** (OWASP categories with a capable phase that did not run). Outputs
  `compliance_coverage.{json,html}`.
- **`supply_chain_review`** — static **dependency-confusion**, **typosquatting**, and
  **lockfile-integrity** review over supplied source (builds on the SBOM work).
  No installs, no network resolution.
- **`honeypot_detection`** — heuristic deception/trap warning from data already
  collected (known honeypot fingerprints + implausible port spreads). Warns; does
  not attack.

### Network phases (safe, opt-in)

- **`egress_canary`** (`--test-egress-canary`, `--egress-canary-host HOST`) — the
  DLP / egress-monitoring reachability matrix. **Canary tokens only, no data
  exfiltrated**: TCP channels connect-and-close (zero payload), DNS/HTTP/ICMP
  tests carry only a random token to *your* listener. Produces `egress_matrix.json`.
- **`iac_drift`** (`--terraform-state PATH`, `--live-inventory PATH`) — read-only
  IaC **drift / shadow-resource (ClickOps)** detection: compares a `terraform.tfstate`
  against a live cloud inventory JSON. No cloud API calls of its own.

### Cross-cutting ops / safety

- **`evidence_finalize`** — runs last and provides:
  - `--evidence-manifest` : SHA256 manifest of every output file + a **redaction
    scan** that greps the deliverable for secrets that shouldn't ship.
  - `--roe-ticket ID` : stamps the authorization ticket into `ROE_STAMP.txt`, run
    metadata, and the manifest header (legal defensibility).
  - `--ci` : emits `ci_summary.json` + `junit.xml` and exits **non-zero (2)** when
    any CRITICAL/HIGH finding exists, so a pipeline can gate on it.

### New CLI flags

```
--chain-simulate
--test-egress-canary        --egress-canary-host HOST
--terraform-state PATH      --live-inventory PATH
--evidence-manifest         --roe-ticket ID        --ci
```

### Phase-order integration

`honeypot_detection` after `ports`; `egress_canary` after `internal_network_safe`;
`supply_chain_review` after `mobile_scan`; `iac_drift` after `cloud_recon_extended`;
`attack_path` + `compliance_coverage` after `verify`; `evidence_finalize` after
`report`. All are in both the default `PHASE_ORDER` and the `authorized_redteam`
profile, run in any profile, and silent-skip when their inputs/flags are absent.

## What was deliberately built as safe-review, not weaponized

The recommendations list several **execution/exploitation** capabilities. TBHM's
entire design — every `*_safe` phase — treats those as detection/review, not
automation, and v3.2 keeps that boundary. The following were implemented in their
safe/detection form (or already exist as such) rather than as weaponized
automation, because building the exploitation layer would break the tool's stated
safety model:

- C2 frameworks (Cobalt Strike / Mythic) and Metasploit post-exploitation — not added.
- Wireless active attacks (deauth, evil-twin, PMKID capture) and RFID/NFC cloning
  — remain the existing `wireless_physical_soc` **checklist** review.
- Kerberoasting/AS-REP **with ticket requests + offline cracking**, DCSync
  execution, NTLM relay, lateral-movement execution — the existing `add_net_ad`
  phase **detects** roastable/delegation/DCSync-rights exposure read-only; ticket
  requests and cracking are not automated. (A future BloodHound-compatible
  read-only export is a clean next step.)
- Live phishing sends (GoPhish/KnowBe4) — the existing social-engineering
  **checklist** is retained; the tool does not send campaigns.
- Frida/Objection runtime instrumentation and pinning bypass — `mobile_scan`
  stays static; `code_intel`'s `code_mobile_api` branch flags the surface.

These are noted so scope is explicit, not silently dropped. The egress-canary and
IaC-drift modules ARE included because they are genuinely non-destructive
(reachability/comparison only).

## Example commands

Attack chains + MITRE + compliance + signed evidence + CI gate:

```bash
python3 tbhm.py -d target.example --profile authorized_redteam -y --redteam \
  --code-dir ./src --chain-simulate \
  --evidence-manifest --roe-ticket ENG-2026-042 --ci
```

Safe egress matrix against your own listener:

```bash
python3 tbhm.py -d target.example --profile authorized_safe -y \
  --phases egress_canary --test-egress-canary \
  --egress-canary-host abcd.oast.fun
```

IaC drift / shadow-resource detection:

```bash
python3 tbhm.py -d target.example --profile authorized_safe -y \
  --phases iac_drift \
  --terraform-state ./terraform.tfstate --live-inventory ./live_inventory.json
```
