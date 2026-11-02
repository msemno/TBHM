# Corporate Intelligence, Data Analysis, and AI Supervision — v3.9.5

TBHM v3.9.5 adds corporate intelligence as a separate evidence workflow rather
than mixing company research with active reconnaissance. It also adds a separate
data-analysis phase and continuous, bounded AI run learning.

## Design boundaries

- Discovered companies, subsidiaries, domains, IPs, identities, repositories and
  third parties are **candidates**. They are never added to active scope.
- Live OSINT collectors require `--osint-live` and an unexpired approval manifest
  authorizing `corporate_osint`.
- Person collection additionally requires `--osint-person-collection` and a PII
  policy. Without that policy, email addresses are stored as hashes.
- Raw source artifacts are never executed by the AI plane. Changed textual
  outputs are secret-redacted, fenced as T3 untrusted data, chunked with hard
  limits and indexed in the portable AI store.
- The model may write an advisory or a pending proposal. It cannot apply code,
  change scope, alter finding status, run tools, or approve its own proposal.
- `authorized_redteam` and `authorized_assumed_breach` enable local observation
  and sanitized run-artifact learning by profile. Use `--no-ai-observe` for a
  run that must not update the portable AI store.

## Main phases

1. `toolchain_readiness` — inventories the versioned 483-entry tool catalog and
   distinguishes live, import-only, service/manual, and approval-only support.
2. `opsec_preflight` — verifies declared corporate OPSEC, evidence, retention,
   egress and stop controls. It does not claim anonymity.
3. `engagement_objectives` — records crown jewels, adversary profiles, success
   criteria, stop conditions, and ten lifecycle stages.
4. `standards_knowledge_sync` — registers local standards and optionally updates
   bounded public vulnerability-intelligence caches.
5. `corporate_osint` — creates a provenance-aware SQLite/JSON/CSV/GraphML/STIX
   entity graph from approved seeds, documents, safe collectors, and imported
   BBOT/SpiderFoot/Maltego/Internet-intelligence results.
6. `data_analysis_intelligence` — normalizes CSV/JSON/JSONL, builds relationship
   and timeline outputs, performs data-quality checks, and optionally exports
   DuckDB/Parquet.
7. `ai_supervision` — compares phase output and tool readiness, then writes an
   advisory. `--ai-propose-improvements` creates a human-review proposal only.

## Example

```bash
./tbhm.py -d example.com -y --profile authorized_redteam \
  --scope scope.txt \
  --corporate-osint --organization-name "Example Ltd" \
  --organization-domains-file domains.txt \
  --osint-seeds company-seeds.yaml \
  --osint-results imported-osint/ \
  --opsec-manifest templates/opsec_manifest.example.yaml \
  --approval-manifest templates/engagement_approval.example.yaml \
  --data-analysis --data-input evidence/ \
  --ai-observe --ai-supervise
```

Live collection is opt-in:

```bash
./tbhm.py -d example.com -y --corporate-osint --osint-live \
  --osint-tools asnmap,theharvester,exiftool \
  --approval-manifest engagement-approval.yaml
```

## Installation planning

The catalog is comprehensive, but commercial services and high-risk operator
frameworks are not silently installed. Review the plan before applying it:

```bash
python scripts/install_extended_tools.py --bundle corporate-osint --json
python scripts/install_extended_tools.py --bundle corporate-osint --apply
INSTALL_CORPORATE_OSINT=1 INSTALL_DATA_ANALYSIS=1 ./install.sh
```

`INSTALL_ALL_SAFE_EXTENDED=1` installs only low/medium-risk entries with vetted
argument-vector recipes. Approval-only, high-risk, commercial, service/manual,
and import-only entries remain operator managed.
