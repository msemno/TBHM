# TBHM v3.6 — Confirmation Engine

Builds on v3.5 (false-positive hardening). v3.5 stopped emitting noise; v3.6 adds
the machinery to turn surviving leads into *confirmed* findings, so the report
distinguishes "regex saw a pattern" from "the tool proved it."

## 1. Static taint / dataflow analysis  (NEW: core/taint_engine.py)
Replaces the old ±12-line "taint keyword near a sink" heuristic with real
intra-procedural source->sink dataflow.

- **Python**: stdlib `ast`. Tracks assignments from taint sources (request.args/
  form/json/cookies/headers, input(), etc.) through variables into dangerous
  sinks (os.system, subprocess, eval/exec, pickle/yaml.load, cursor.execute,
  open). Recognises sanitisers (shlex.quote, escape, int(), re.escape, bleach…)
  on the path.
- **JS/TS**: dependency-free lexical dataflow. Sources (req.query/body/params,
  location.*, document.*, process.env) -> variables -> sinks (innerHTML,
  document.write, eval, Function, child_process.exec, .query). Recognises
  DOMPurify/encodeURIComponent/textContent/parseInt sanitisers.

Outcomes wired into code_intel.trace_vulns:
  - confirmed flow, no sanitiser  -> confidence HIGH, class `confirmed_static`,
    finding marked verified (verified_at + verification_method=static-taint-
    dataflow) so it can serve as a real finding AND a verified hop in chains.
  - sanitised flow                -> class `mitigated`, severity INFO.
  - regex sink, no proven flow    -> stays a lead (v3.5 gate downgrades it).

Conservative by construction: a result is emitted ONLY on a concrete
source->var->sink chain, so it never manufactures a flow that isn't there.

## 2. Live credential validation  (NEW: core/secret_validator.py, --validate-secrets)
Opt-in. For secrets that pass the static gate, makes ONE read-only identity call
to the provider and records the result:
  - GitHub /user, Slack auth.test, Stripe /v1/balance, SendGrid /v3/scopes,
    Google API key check, AWS STS GetCallerIdentity (via boto3 if present).
  - LIVE  -> promotes to confirmed / HIGH / verified_at set.
  - DEAD  -> downgrades to INFO (rotated/placeholder that slipped through).
  - unknown/skipped/error -> finding unchanged, note attached.
GATED behind --validate-secrets because it touches third-party APIs with found
credentials — authorised engagements only. Default off. Zero hard dependency
(urllib; boto3 optional, only for AWS).

## 3. _has_runtime_proof evidence-format fix  (core/fp_filters.py)
Now recognises live-probe HTTP evidence — "GET url -> 200 (len=…)", "HTTP/1.1
200", "status=200" — plus live-credential validation results and taint-confirmed
findings. The live-probed [code_admin] finding now correctly counts as a verified
hop when chains are built on top of it. Synthetic chains with no proof still
downgrade.

## 4. CVE references  (core/cwe_cvss.py)
enrich() now attaches representative real-world CVEs per CWE class
(references_cve field) — e.g. CWE-89 -> CVE-2019-6340, CWE-78 -> Log4Shell/
Shellshock. These are reference exemplars for the report, NOT a claim the target
is affected. Real SCA findings keep their own OSV CVE ids untouched.

## Explicitly NOT added
The two tool-list documents requested "add the functions in these tools." The
detection/analysis tools were folded in where they fit (templated verification,
LLM probing, firewall-config audit remain on the roadmap). The offensive
categories — C2 frameworks (Cobalt Strike/Sliver/Havoc/Mythic), EvilGinx2
phishing proxy, Mimikatz credential dumping, AV/defense-evasion — were NOT added.
TBHM is a detection + verification framework; weaponisation/evasion/credential-
harvesting capability is out of scope by design.

## Verification
- taint engine: confirmed/sanitised/no-flow cases correct on Python + JS.
- end-to-end trace_vulns: real cmdi + DOM-XSS -> confirmed_static HIGH with the
  actual dataflow string; constant -> no trace.
- validator: LIVE->confirmed, DEAD->INFO annotation correct.
- _has_runtime_proof: code_admin live-probe True, synthetic chain False, taint-
  confirmed True.
- FP regression: 8/8 (all v3.5 drops/downgrades hold; 4 real findings keep).
- Full-package syntax check clean; tbhm.py --help OK; --validate-secrets present.

## New/changed files
- core/taint_engine.py      (new, 342 lines)
- core/secret_validator.py  (new, 171 lines)
- core/cwe_cvss.py          (CVE reference map + enrich)
- core/fp_filters.py        (runtime-proof recogniser)
- core/code_intel.py        (taint integration in trace_vulns)
- phases/code_intel.py      (confirmed/mitigated emission + verified marking)
- tbhm.py                   (--validate-secrets, validation in save_finding, helpers)
