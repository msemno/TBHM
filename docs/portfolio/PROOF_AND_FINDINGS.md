# Evidence engineering: a lead is not a verified vulnerability

TBHM 4.2.7 separates observed signals from verified findings. This distinction is central to the portfolio's value.

## Three statuses with different meanings

| Category | What is known | What can be claimed |
| --- | --- | --- |
| Observation / lead | An analyzer, scanner or model surfaced a potential issue | Requires review; exploitability and impact are unverified |
| Confirmed within supported proof contract | Verifier accepted bound captures, controlled negative case and distinct repeats | Claim supported by that **specific** contract and scope; still document limits |
| Incomplete execution | Phase blocked, timed out, skipped, missing a tool/input, or parser failed | Coverage gap; cannot conclude vulnerability absent |

Severity (impact), confidence (evidence quality) and coverage (what ran) are different axes. `finished_with_gaps` is a run state, not a finding type.

## Proof v2: required building blocks

Documented requirements for a supported automatic class-specific confirmation are:

1. A **version-2 finding-class contract** (not merely a generic score).
2. **Authenticated local captures** with a trustworthy capture chain.
3. **Target, request and identity binding** matching the intended test case.
4. A **negative control** that distinguishes expected authorized behavior from the alleged failure.
5. **Two distinct repeat captures** of the positive observation.
6. Review of output, scope and classification; AI reasoning is supplemental.

The documented automatic verification contracts currently cover **cross-actor object access**, **anonymous sensitive-data exposure**, and **controlled open redirects**. Do not claim generic automatic verification for every injection, XSS, SSRF, auth, or business-logic weakness.

## A concrete reasoning example (illustrative, not a live TBHM run)

Suppose an API returns an invoice for user B to authenticated user A. A professional test would record A's intended account, the target object owner, an authorized same-owner baseline, the cross-actor request, a policy-preserving negative control, and independent repeats. Merely seeing HTTP 200 or finding `/invoice` in a URL is insufficient. **This is an educational example, not a claim that TBHM discovered an invoice flaw.**

## Artifacts to inspect

- `REPORT_confirmed.md` — accepted verifier output.
- `REPORT_leads.md` — signals requiring review.
- `execution_ledger.json` — what happened, including failed or blocked work.
- `evidence_manifest.json` and `delivery/run-.../` — packaged final evidence with redaction and integrity records.
- `docs/PROOF-v2.md` — exact machine contract; do not implement against this summary alone.

## Reviewer questions

Can a second person distinguish owner from non-owner? Is the failed control independent? Were repeated captures different events rather than reusing the same response? Is the scanner reporting process failure as a finding? Could a redirect or proxy invalidate the scope? Was the evidence created in a local lab or a live approved target? **Document the answer; do not assume it.**
