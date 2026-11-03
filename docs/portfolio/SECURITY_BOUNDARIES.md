# Security, authorization and privacy boundaries

This document describes the limits reported for 4.2.7. It does not expand the tool's actual guarantees.

## Authorized scope

The operator must independently establish permission for each target and technique. The Python HTTP path has policy, TLS, redirect, budget and response-size controls. Port scanning requires explicit IP/CIDR authority with its own packet-rate policy; resolving a hostname is not itself authorization to send arbitrary packets. External scanners and browsers have distinct adapter controls.

## High-risk interpretation failures to avoid

| Signal | Incorrect claim | Correct treatment |
| --- | --- | --- |
| HTTP 200 on a route | Route is vulnerable / auth bypass confirmed | Observation needing identity + policy proof |
| Reflected input | XSS execution confirmed | Reflection lead; browser execution evidence may be missing |
| Static function/import name | Reachable exploit path exists | Inventory or heuristic until control/dataflow substantiates |
| Scanner exits 0 | Comprehensive check succeeded | Inspect parsed findings and execution ledger |
| Scanner crashes or times out | No vulnerability | Mark incomplete; preserve diagnostic |
| LLM output | Exploit verified | Advice only; require a supported evidence contract |
| File SHA-256 matches | Independent attestation | Byte integrity under the recorded manifest, not signer identity |

## Source and dependencies

Offline source review is not a sandbox that can safely execute untrusted project code. Bundled Python wheels are pinned for offline installs, but external scanner versions/licensing are managed separately. The package includes a SBOM and notices; their existence does not imply a security audit of the entire supply chain.

## Privacy and data handling

Keep target authorization, credentials, session tokens, raw scanner logs, databases, original engagement artifacts and AI memory private. The publication kit previously removed six engagement-derived diagnostic records and generalized three linked reports while retaining originals in a private backup. A sanitized release must still be reviewed for secrets, proprietary data and third-party rights. Never publish raw Gitleaks reports or the owner-only capture key.

## Local synthetic TLS fixtures

The reviewed tree contains `tests/data/v424/loopback-key.pem`, a real private key used exclusively with the self-signed local `pin.test` test certificate. The publication review found a duplicate of it in a historical patch. It is not a production credential and must never be redeployed as one. Do not blanket-hide the entire tests/provenance directories to conceal it.

## Honest outcome language

“Not tested”, “blocked”, “needs review”, “no matching pattern found” and “confirmed under proof-v2 contract” are distinct results. Report them separately.
