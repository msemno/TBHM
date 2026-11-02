# TBHM v3.3-redteam-safe Changelog

Continues the roadmap from the recommendations doc. Additive as always — the v3
baseline still holds (all original phases load; nothing removed). Phase count is
now **78** (v3.2 had 66; +12 new phases).

## New coverage / scenario phases (12)

- **`auth_modern_review`** — detection-only JWT (alg:none, HS/RS confusion, kid,
  missing exp), OAuth (state/PKCE/implicit-grant/redirect_uri), and SAML
  (unsigned-assertion / signature-wrapping surface) review. No cracking, no forged
  auth sent. Flags: `--jwt`, `--saml-metadata`.
- **`graphql_audit`** — introspection / suggestion / batching detection and
  schema-based depth/alias risk. Never fires an amplification query. `--graphql-url`.
- **`k8s_recon_safe`** — anonymous kube-apiserver / kubelet / etcd read-only
  probes. `--k8s-api`.
- **`llm_agent_tool_call_abuse`** — OWASP-LLM-Top-10 safe test catalog + optional
  benign canary prompt-injection probe against an authorized endpoint (`--llm-endpoint`).
  Inert markers only.
- **`mfa_bypass_safe`** (also conditional-access review) — MFA/CA bypass-pattern
  register + passive legacy-auth endpoint detection. No brute force / phishing.
- **`lateral_movement_paths`** — read-only AD attack-path analysis with a
  BloodHound-compatible export and shortest-path-to-Tier-0 computation from a
  supplied `--ad-graph` or the read-only `add_net_ad` output. Pure graph BFS; no
  live AD interaction.
- **`ot_ics_safe`** — OT/ICS connect-only discovery (Modbus/DNP3/BACnet/S7/
  EtherNet-IP/…) + SCADA web fingerprint. Never writes registers/coils. `--ot-enable`.
- **`modern_protocols_discovery`** — passive mDNS/SSDP (`--lan-discovery`) +
  WebSocket / graphql-ws / MCP / AsyncAPI / SSE HTTP detection.
- **`cloud_inventory_safe`** — read-only multi-cloud inventory via installed CLIs
  (list/describe only) or a provided file. `--cloud-profiles aws,gcp,azure`.
- **`browser_extension_audit`** — offline fleet-extension risk review against
  dangerous-permission / blocklist / allow-list rules. `--browser-extension-audit`
  (+ `--ext-allowlist`, `--ext-blocklist`).
- **`backup_restore_simulation`** — backup/ransomware-recovery tabletop register +
  exposed-backup detection. `--backup-sim`. Never deletes/encrypts/restores.
- **`playbook_integration`** — `--playbook-mode`: `coverage_tracker.csv`,
  per-branch `BRxx-*.md` objective cards, `master_coverage.html`, and
  `residual_risk_register.json`, with a TBHM-phase → BR-branch map.

## Ops & safety

- **`--no-destructive` / `--force-write`** — global write gate (`ctx.allow_mutation()`);
  v3.3 network phases are read-only regardless.
- **`--recheck-only REPORT`** — remediation validation: re-runs only the phases
  that produced findings in a prior results dir / findings JSON (+ verify/report).
- **`--update`** — self-heal alias that refreshes nuclei templates / SecLists.
- **`phase_timings.json`** — per-phase performance profile for large engagements.
- **`tbhm.jsonl`** — structured JSON log line per event for SIEM/Splunk ingestion.
- **Input validation** — warns on duplicate/malformed target entries.
  (Also fixed a latent bug: `json` was never imported at module scope in
  `tbhm.py`, which would have silently broken the two writes above.)

## Phase-order integration

Each new phase is inserted next to its peers in both `PHASE_ORDER` and the
`authorized_redteam` profile, runs in any profile, and silent-skips when its
flag/input is absent (e.g. `ot_ics_safe` needs `--ot-enable`, `playbook_integration`
needs `--playbook-mode`, `lateral_movement_paths` needs an AD graph).

## Still intentionally NOT weaponized

Same stance as v3.2, matching the tool's `*_safe` design: no C2/Cobalt Strike/
Mythic, no Metasploit post-exploit, no live wireless attacks (deauth/evil-twin/
PMKID), no RFID cloning, no Frida runtime instrumentation, no live phishing sends,
no Kerberoast-with-cracking / DCSync / relay execution. The safe detection/review/
analysis forms of these are what v3.1–v3.3 provide. Also deferred (need
infra/creds, not safety): distributed multi-worker scanning and the real-time
websocket ops dashboard.

## Example

```bash
python3 tbhm.py -d target.example --profile authorized_redteam -y --redteam \
  --code-dir ./src --ad-graph ./bloodhound.json \
  --jwt "$TOKEN" --graphql-url https://target.example/graphql \
  --cloud-profiles aws --browser-extension-audit ./fleet_extensions.json \
  --backup-sim --playbook-mode --chain-simulate \
  --evidence-manifest --roe-ticket ENG-2026-042 --ci
```
