# TBHM v3.9.6 — Enterprise Control Plane and Intelligence Depth

## Release intent

v3.9.6 closes coordination, OSINT-depth, compliance, cloud-identity,
CI/CD/supply-chain and data-normalization gaps without converting TBHM's normal
assessment pipeline into an autonomous exploitation, C2, credential-attack,
phishing, persistence, lateral-movement or exfiltration engine.

High-impact operator activities are represented through an approval-gated,
plan/import state machine. TBHM records objective, target, authorization,
evidence provenance and cleanup status, but does not generate operational
payloads or commands and does not start high-impact frameworks.

## Additive phases

1. `agentic_control_manifest` — local declarative MCP-compatible capability and trust manifest; no server is started.
2. `osint_depth_collectors` — bounded favicon hashing, approved AXFR, reviewable dork plans and provider-result normalization.
3. `social_engineering_governance` — approved exercise register and sanitized metric import; no message delivery or credential/MFA capture.
4. `ci_cd_supply_chain_security` — local CI/CD trust review, safe scanner imports and attestation inventory.
5. `cloud_identity_path_analysis` — read-only AWS, Azure/Entra and GCP IAM privilege-path indicators.
6. `execution_orchestration_plan` — single-pane objective/approval/evidence/cleanup state machine; no high-impact execution.
7. `compliance_reporting_extended` — policy-driven PCI DSS, HIPAA, GDPR, ISO 27001, NIST 800-53, PTES, OSSTMM and VDP coverage matrix.
8. `ocsf_normalization` — parallel OCSF-oriented JSONL export while preserving native findings.

The ordered phase surface is now 124 entries. No v3.9.5 phase is removed.

## Architecture additions

- `core/execution_registry.py` and `tooling/execution_adapter_registry_v396.json`
  provide a declarative adapter contract. High-impact capability types are
  rejected unless their mode is plan/import.
- `core/mcp_registry.py` emits a deny-by-default local capability manifest. It
  grants no tool permissions and marks all tool/run outputs as untrusted.
- `core/compliance_catalog.py` and
  `knowledge/compliance_frameworks_v396.json` provide an extensible policy
  catalog without claiming certification or legal compliance.
- `core/ocsf.py` emits deterministic OCSF-oriented finding events.
- `tooling/tool_catalog_v396.json` expands the safe catalog to include CI/CD,
  signing/attestation, MCP-manifest and OCSF-export capabilities.

## OSINT depth

The dedicated OSINT-depth phase supports:

- in-scope favicon SHA-256 and MurmurHash3 collection;
- imported ASN/BGP/RDAP, Shodan, Censys, FOFA, Quake, BinaryEdge, Netlas,
  lawful paste/provider and job-posting results;
- bounded, explicitly approved DNS AXFR checks;
- reviewable Google-dork query generation without automated search-engine
  requests;
- hashed username planning with PII-policy and approval controls.

Discovered assets remain intelligence candidates. They never expand active
scope automatically.

## CI/CD and cloud identity

- Adds local workflow/build-file review and optional `actionlint`/`zizmor`
  evidence capture.
- Inventories SLSA, in-toto, Sigstore/cosign, VEX and other attestation files.
- Adds read-only IAM permission/path indicators for AWS, Azure/Entra and GCP.
  Permission names remain leads until effective-resource, trust and condition
  context is verified.

## Reporting and interoperability

- Richer SARIF 2.1.0 output with stable fingerprints, invocation records,
  automation details and rule metadata.
- Parallel OCSF-oriented finding JSONL.
- Policy-driven framework matrices and tested/not-tested/manual/findings state.
- Version synchronized to `3.9.6-enterprise-control-plane` in the main CLI and
  reporter.

## Safety boundary

TBHM does not autonomously:

- exploit targets or generate payloads;
- create C2 listeners, redirectors, beacons or sessions;
- perform password spraying, credential dumping, Kerberos abuse, relays or
  name-resolution poisoning;
- deliver phishing, intercept MFA, clone badges or bypass physical controls;
- establish persistence, move laterally, collect client data or exfiltrate it;
- disrupt wireless/OT systems or perform destructive writes.

Those activities, when contractually authorized, must remain in separately
controlled operator infrastructure. TBHM can create a sanitized plan and import
signed evidence and cleanup status.

## Validation

Run:

```bash
python integration_test_v396.py
python -m compileall -q .
bash -n install.sh run-bg.sh
```

External APIs, commercial products and target-dependent behavior require the
operator's licensed environment and written rules of engagement.
