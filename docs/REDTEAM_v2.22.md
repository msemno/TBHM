# TBHM v2.22-redteam upgrade notes

This upgrade turns TBHM from a mostly web/API/mobile pentest orchestrator into a broader authorized red-team coverage tool.

## New phases

| Phase | Purpose | Safety boundary |
|---|---|---|
| `redteam_governance` | Coverage matrix, high-risk approval register, residual-risk wording | No testing traffic |
| `internal_network_safe` | Approved CIDR host discovery and service inventory | nmap read-only discovery; no exploitation/bruteforce |
| `ad_identity_safe` | DC service review, DNS SRV, anonymous LDAP, optional read-only LDAP inventory | No Kerberoast, relay, DCSync, dumping, lateral movement |
| `iot_cctv_safe` | IoT/CCTV/sensors/printers/VoIP/BMS service inventory | No credential use, stream viewing, device takeover, protocol writes |
| `wireless_physical_soc` | Wireless/physical/social/SOC checklists and passive inventory when interface supplied | No deauth, jamming, evil twin, badge cloning, tailgating, phishing |
| `firmware_reverse_safe` | Firmware hash, binwalk, strings and pattern inventory | No flashing or device modification |
| `ai_redteam_safe` | AI/LLM/RAG/agentic test catalog and optional endpoint header baseline | No jailbreak/exfiltration automation |
| `redteam_final_summary` | Final red-team evidence index and report rules | No testing traffic |

## New CLI flags

```text
--redteam
--corp-cidr CIDR[,CIDR]
--corp-cidrs-file PATH
--dc-ip IP[,IP]
--dc-ips-file PATH
--ad-domain DOMAIN
--ad-user USER
--ad-password-env ENV
--wireless-interface IFACE
--firmware PATH
--firmware-extract
--ai-endpoints-file PATH
```

## Reporting statuses

Use these statuses in the final report:

```text
Tested
Simulated
Lab Only
Not Authorized
Not Applicable
Blocked
Needs High-Risk Approval
Not Tested
```

Never say `no other gaps exist` unless the full asset inventory is complete and every branch has a tested/simulated status with evidence.
