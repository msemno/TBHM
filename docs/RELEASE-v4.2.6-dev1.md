# TBHM 4.2.6-dev1 — incident-driven development candidate

**Status: DEVELOPMENT / NOT PRODUCTION VALIDATED.** This tree is derived from the uploaded `TBHM-4.2.5-knowledge-and-migration(1).zip` archive. The incident report states that this archive predates later runtime repairs. Those repairs are **not** silently assumed merged.

## Implemented source changes

1. JS taint analysis: filter browser-origin dataflow claims leading directly to Node-only OS-command / SQL sinks. Node-origin dataflow and browser DOM XSS leads are retained. This is lexical screening, **not** dynamic browser confirmation.
2. Nuclei: check local templates without automatic downloads during scanning; classify CLI incompatibility, timeouts, missing templates, and tool errors independently from clean no-match results. Results without original request+response remain leads. Scanner claims are never proof receipts.
3. Diagnostics: stop running arbitrary installed executable version flags and template build scripts. Tool presence is NOT labelled operational readiness.
4. Finding persistence: keep suggested curl reproducers separate from the actual original `request_raw`. Existing redaction protections remain.
5. Nmap XML network import: retain the host IP despite ElementTree leaf elements evaluating false.
6. Path/content provenance tagging for third-party JS sources; does not blindly discard library findings.
7. Offline/passive origin-IP candidate attribution with literal authorized-IP matching; no active origin discovery or bypass.
8. Offline firewall-response comparison; no firewall-bypass execution or vulnerability confirmation.
9. New unit tests for the above source changes.

## Measured review of uploaded runs

| Run | Findings | Blocked HTTP ledger events | Request+response fields present |
|---|---:|---:|---:|
| omarchy/run1 | 117 | 61 | 0 |
| verisk/01-manual-recon | 2 | 32,458 | 0 |
| livenation/04-deep | 144 | 17,993 | 3 |

`request_raw` in the historical runs may be a synthetic curl reproducer, not a real original request. The CSV/JSON output does not attest to full scanner capture coverage. All three runs had 0 confirmed vulnerability claims. Do not assume a correct vulnerability was missed merely because proof was unavailable.

## Validation

- New tests: 10/10 passed in this source-review environment.
- Existing proof behavior: 2/2 passed.
- Existing v4.2.5 security checks: 3/3 passed.
- F02/F03 remediation tests: 4/4 passed; F04: 3/3 passed.
- The old v4.2.3 flow-contract suite currently fails due to stale source/AST hash freezes (including a file untouched from the supplied archive); this candidate does NOT claim a green full suite.
- Full suite was attempted, but did not complete within the execution budget. One strict-class test run timed out separately. No full clean extraction/offline installation test was performed on Kali/Python 3.12; external tools and Windows Ollama runtime were not accessible.

## Outstanding / not implemented

- Full request/response capture for *every* external scanner, with bounded private raw-evidence vault and operator permission.
- Vulnerability-specific active negative-control/differential/repeatability engines and headless DOM execution proof.
- First/third-party source content hashing and complete bundled provenance.
- Universal child/browser wire metering, full sensitive-writer closure, and robust global cancellation/early-stop on HTTP budget exhaustion.
- Tested live Nuclei version readiness on the user's Kali VM; evidence bundle lacks raw per-tool logs.
- Real model semantic acceptance and Windows GPU/tunnel reliability.
- Active origin IP discovery, live WAF/firewall validation or bypass; offline candidate/behavior analysis only.
- Complete baseline repair reconciliation from the user's currently running installation.

**Do not replace the stable installed TBHM directory with this development build.** Compare/merge with actual deployed repair receipts and run on owned local fixtures before using on an authorized engagement.
