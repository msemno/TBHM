# TBHM 4.2.4

Baseline: 4.2.3. Preserves all 145 phase names/ordinals, 461 existing CLI argument
signatures, SQLite DDL, Runner/Ctx and controller dispatch. Two opt-in arguments
bring the total to 463. No new phase is needed; the original phase sequence is
the exact prefix required by the revised contract. No runtime dependency or
model weight is added. Disabled new options do not invalidate legacy resume
fingerprints; enabled plan changes still invalidate them.

## Implemented

- Two narrow strict proof-v2 contracts and a reachable approved replay workflow:
  controlled outside-root TBHM canary file traversal and owned-role protected
  read-function BFLA. Both require authenticated captures, a known valid
  baseline, denied/missing controls and two distinct repeats. BFLA additionally
  requires separate credentialed roles and an anonymous same-function control.
  Neither generic reflection, HTTP 200 nor a scanner/model judgment can confirm.
- `--strict-replay-plan` / `--approve-strict-replay` use the existing controlled
  validation phase, storage, reports and sealing. Whole-plan preflight, reviewed
  GET policy and origin/IP pins are mandatory. Incomplete transport fails with
  review artifacts retained. Stable explicit denials disprove only that case;
  errors, expired privileged accounts and ambiguous results remain inconclusive.
- Destination-pinned native/fixed-pipe HTTP replay. Every DNS answer must match
  reviewed numeric pins; actual connects use numeric addresses without a second
  DNS lookup. Original hostname/SNI/certificate checks remain. Cross-origin
  redirects are not followed; proxy and arbitrary scanner/browser drivers are
  unsupported. A cross-process lock permits one pinned dispatch at a time.
- Privacy audit adds UTF-32, URL, hex, HTML, JSON and URL-safe base64 canary
  variants, filename checks, bounded BZip2 and memory-limited XZ decoding.
  Concatenated/truncated/oversized XZ remains incomplete. Existing ZIP/tar/gzip
  bounds remain. Empty integrity-checked files have no opaque content to inspect.
- Additive graph associations for routes, parameters, declared identities and
  capture references. They preserve original graph keys, retain finding IDs and
  do not establish exploit chains, delete duplicates or escalate severity.
- Stage/class quality metrics include all four cells, inconclusive counts,
  coverage, conditional metrics, full-denominator bounds, labeled Wilson
  intervals and project-split leakage checks. The paired evaluator measures
  four local synthetic new-class confirmation cases, separately from discovery.

## Demonstrated corrections

1. An oversized/aborted 429/503 response could fail before the broker persisted
   its shared cooldown. A header hook now persists the pause before body parsing.
2. Evidence graph/operator projections trusted imported `verified` and class flags.
   They now require an in-process authenticated proof receipt and derive confirmed labels from the classifier.

Both defects fail executable fixtures against 4.2.3 and pass against 4.2.4. The
three existing proof contracts match 42 executed baseline vectors, including
positive, benign, missing-control, tampered, replayed and unrelated-class cases.
The three proof modules can evolve; old source hashes no longer freeze them.
Immutable release artifacts continue to use current manifests/hashes.

## Retained limits

Global online child/browser/native wire metering, full sensitive-writer/opaque
format closure, other vulnerability-class contracts, state-changing API flows,
full standards coverage and representative field calibration remain open.
Existing LLM imports/triage/corpus protections remain advisory and permission
aware. No real-model benchmark, training, external scanner/headless run, bounty
acceptance or general accuracy claim is made.

See `docs/UPGRADE-v4.2.4.md` and `docs/research-v4.2.4/VERIFICATION.json` for actual
commands, results and the precise supported scope.
