# What TBHM v2.22-redteam tests

TBHM v2.22-redteam is an authorized security-testing orchestrator. It keeps the original web/API/mobile pentest engine and adds enterprise red-team coverage. The expansion is intentionally safe: it inventories, validates, simulates, records evidence, and tracks residual risk. It does not automate malware, persistence, credential theft, EDR bypass, destructive exploitation, denial of service, unsafe RF actions, or real data exfiltration.

## Original web/API/mobile coverage already present

| Area | What it tests |
|---|---|
| Scope/preflight | Authorization confirmation, scope includes/excludes, safety hard limits |
| Diagnostics | Tool availability, nuclei templates, SecLists, provider config, OAST support |
| Recon | Subdomains, alive hosts, technology fingerprints |
| CNAME takeover | CNAME inventory and dangling takeover heuristics |
| Ports | External service exposure with naabu/nmap and interesting-port findings |
| Discovery/crawling | URLs, JavaScript, parameters, smart crawl, backend API mapping |
| Content discovery | Hidden paths, admin/billing/internal route discovery |
| Spec/API testing | Swagger/OpenAPI/SOAP/OData/JSON-RPC discovery, API fuzzing, GraphQL, webhooks |
| Source/mobile static | Code repos, source maps, endpoints, secrets, dangerous sinks, Android APK, iOS IPA, mobile source |
| Vulnerability scanning | nuclei, custom nuclei templates, retire.js, dalfox, WP/Atlassian checks, infra exposure |
| Web app testing | injection checks, access control, IDOR/BAC/CORS, auth/session/JWT/OAuth, uploads, race/business logic, cache deception, PDF/CSV injection |
| Cloud/client | S3/GCS/Azure/R2/DO/B2 buckets, client platform/PWA/service worker, console leaks, API key pivoting |
| Evidence/reporting | curl verification, false-positive review, dashboard, executive/manager/developer/defender reports |

## New v2.22-redteam coverage

| New phase | What it tests | Main outputs |
|---|---|---|
| `redteam_governance` | Enterprise coverage matrix, high-risk approval register, residual-risk wording | `redteam/00_governance/*` |
| `internal_network_safe` | Approved internal CIDR discovery, live hosts, internal service inventory, segmentation signals | `redteam/04_internal_network/*` |
| `ad_identity_safe` | DC ports, DNS SRV discovery, anonymous LDAP exposure, optional read-only LDAP inventory | `redteam/05_active_directory_identity/*` |
| `iot_cctv_safe` | Cameras, RTSP, printers, VoIP/SIP, SNMP, MQTT, CoAP, Modbus, BACnet, Tridium/Niagara, BMS/OT-like protocol exposure | `redteam/07_iot_cctv_sensors/*` |
| `wireless_physical_soc` | Wireless/RF checklist, optional passive SSID inventory, physical/social approval checklist, SOC detection validation catalog | `redteam/08_20_19_wireless_physical_soc/*` |
| `firmware_reverse_safe` | Firmware hash, binwalk signature scan, strings extraction, credential/endpoint/service pattern hits | `redteam/12_firmware_reverse/*` |
| `ai_redteam_safe` | AI/LLM/RAG/agentic test catalog, optional endpoint header baseline, tool permission/data-boundary checklist | `redteam/18_ai_llm_rag_agents/*` |
| `redteam_final_summary` | Red-team evidence index and final residual-risk rule | `redteam/99_final_summary/*` |

## New CLI examples

Full safe enterprise red-team mode:

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

Read-only LDAP inventory without putting the password in shell history:

```bash
export TBHM_AD_PASSWORD='READ_ONLY_PASSWORD_HERE'
./tbhm.py -d company.com --profile authorized_redteam -y --redteam \
  --corp-cidr 10.10.0.0/16 \
  --dc-ip 10.10.10.10 \
  --ad-domain corp.local \
  --ad-user readonly@corp.local
```

Firmware static review:

```bash
./tbhm.py -d company.com --profile authorized_redteam -y --redteam --firmware ./device-fw.bin
```

AI endpoint catalog:

```bash
./tbhm.py -d company.com --profile authorized_redteam -y --redteam --ai-endpoints-file ai-endpoints.txt
```

## Report rule

A branch with no input or no authorization is **Not Tested**, not **Safe**. The report must preserve the status for each branch: Tested, Simulated, Lab Only, Not Authorized, Not Applicable, Blocked, Needs High-Risk Approval, or Not Tested.
