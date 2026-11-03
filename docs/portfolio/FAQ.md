# TBHM questions and explanations

**Does “145 phases” mean 145 tools were actually executed?** No. The publication clone check showed 145 phase names resolve to run-capable modules. Each optional tool/target/input must be independently assessed.

**Is the output entirely confirmed?** No. TBHM separates leads, supported verified proof contracts and incomplete coverage. Read `REPORT_leads.md`, `REPORT_confirmed.md` and `execution_ledger.json` together.

**Is every bug class automatically confirmed?** No. Documented proof-v2 automatic contracts currently cover cross-actor object access, anonymous sensitive-data exposure, and controlled open redirects.

**Can AI verify exploitation?** No. The model can suggest counterevidence and optional scheduling hints. It is not authoritative proof.

**Can TBHM execute without the internet?** Core installation can use bundled offline wheels; specified local source phases support offline operation. That is not a guarantee of arbitrary third-party tool or untrusted-code isolation.

**Are scanner subprocesses covered by the Python HTTP request counter?** No. Each external adapter has separate controls and failure modes.

**Does a manifest hash prove the code is trustworthy?** No. It establishes recorded byte integrity, not independent build provenance, code safety, or signature authenticity.

**Are the Gitleaks findings all live secrets?** The reviewed 61 detections were classified as 39 SHA-256/hash data entries, 20 synthetic/example fixtures, and two occurrences of an actual local-only TLS test key. GitHub separately rejected Stripe-shaped synthetic strings in the initial commit. Revalidate any changed repository before publishing.

**Is TBHM openly licensed?** Not yet established by the 4.2.7 publication kit. Source-rights decision is pending. Public visibility is not an open-source license.

**Can I just force push the source?** No. Force-push is not a remedy for GitHub push protection and can destroy history. Use GitHub’s supported review/bypass workflow only for independently reviewed benign test fixtures, or remediate the source and all affected commits.
