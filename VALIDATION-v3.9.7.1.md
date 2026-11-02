# TBHM v3.9.7.1 Validation Record

Release: `3.9.7.1-backward-compatibility`  
Implementation baseline: original uploaded `TBHM-v3.9.6-enterprise-control-plane(1).zip`  
Historical references: v2.16-fixed, v2.21, v3.8-expanded, and v3.9.5.

## Source-of-truth and archive validation

The original v3.9.6 archive was verified before modification, extracted into an isolated working tree, and tested before the upgrade. Historical archives were independently integrity-tested and hashed. The historical archive inventory, normalized manifests, file lineage, symbol lineage, and decision register are included under `docs/historical/` and `manifests/`.

| Reference | Uploaded filename | SHA-256 | Integrity |
|---|---|---|---|
| v2.16-fixed | `TBHM-v2.16-fixed(2).zip` | `a2080c17e3decabce2cef1bb68125a3e52b32236c7b0f45002c19bd64ce0325d` | PASS |
| v2.21 | `TBHM-v2.21(4).zip` | `703fdbf6075d175c3166a2d48e853189f3defe5f5872f3c6156ba9be61f1956d` | PASS |
| v3.8-expanded | `TBHM-v3-redteam-safe-v3_8-expanded(1)(5).zip` | `ce7eb2b568a4cc63cc6628f4d25510417c60cd8aace32a2b53ce2a8832691dd1` | PASS |
| v3.9.5 | `TBHM-v3.9.5-corporate-intelligence(2).zip` | `cfe126cfda799e5d4c9c82b242c7bdcfed4502f3cd30d1430f04c70db83360bd` | PASS |
| v3.9.6 baseline | `TBHM-v3.9.6-enterprise-control-plane(1).zip` | `c061a6ac8259633e40d0bb69d893444ed8e16848cfa15cc3f1a7fff54fcc266c` | PASS |

The v3.8-named archive contains conflicting historical source banners (`3.0-redteam-safe`). Its behavior was used as the reference, while the inconsistency is recorded rather than silently corrected in the historical inventory.

## Historical archaeology result

- 29 meaningful historical differences were classified.
- 0 decisions remain `UNRESOLVED`.
- Decisions: 15 `PRESERVE_WITH_TEST`, 10 `MERGE_OLD_AND_NEW`, 2 `PRESERVE_WITH_COMPATIBILITY_ALIAS`, 1 `RESTORE_OLDER_BEHAVIOR`, and 1 `REPLACE_OLD_WITH_NEW`.
- Older trees were not copied over the v3.9.6 baseline wholesale.
- Restored behavior is tied to explicit implementation files, regression tests, compatibility impact, and residual-risk records.

## Backward-compatibility result

The generated machine-readable comparison is in `docs/compatibility/`.

- Original v3.9.6 paths preserved: **322 / 322**.
- Original v3.9.6 CLI option strings preserved: **300 / 300**.
- Final measured CLI option strings: **330**.
- Original v3.9.6 ordered phases preserved: **124 / 124**.
- Final ordered phases: **129**.
- New working phases: `integration_adapter_proposal`, `osint_api_collectors`, `passive_wireless_inventory`, `safe_plan_execution`, and `session_beacon_import`.
- Original report paths, schema identifiers, and measured configuration keys have no unintentional removals.
- No original phase-order reversal was detected.
- Known breaking changes: none in the measured public path, CLI, phase, output, or schema surface.

The compatibility manifest excludes its own four generated compatibility artifacts, caches, and runtime result directories to avoid self-referential hashes.

## Test result

The original v3.9.6 integration suites passed before modification. After implementation, all 12 available integration suites passed together:

- add-ons
- AI plane
- historical regression fixtures
- v3.9.1 safety
- v3.9.2 reverse/report/confirmation
- v3.9.3 confirmation correctness
- v3.9.4.1 correctness hardening
- v3.9.5 corporate intelligence
- v3.9.6 enterprise control plane
- v3.9.6.1 regression compatibility
- v3.9.7.1 capability depth
- v3.9 safe integration

The unittest-style suites executed **89 named test cases**. The remaining script-style suites also completed their assertion sets and reported PASS. No network service or third-party target was contacted by the automated regression tests; provider behavior used mocks or offline fixtures.

The dedicated historical suite passed 21 fixtures covering:

- curl probe differentials, throttling, timeouts, quoting, and false-positive rejection;
- Nuclei executable/template/workflow handling and installer identity behavior;
- wildcard, soft-404, redirect, JSON catch-all, and response-similarity controls;
- JSON, JSONL, SARIF, nested records, bounded recursion, malformed input, CWE preservation, and deduplication;
- dependency-free reverse-engineering fallback behavior and secret redaction;
- report filenames, qualified posture language, and compatibility aliases.

The v3.9.7.1 capability suite passed 13 tests covering the capability registry, doctor, safe plan rejection controls, session import, RDAP collector, cloud IAM graph, compliance predicates, CI/CD dataflow, deterministic OCSF export, passive wireless import, adapter proposals, CLI compatibility, and phase compatibility.

## Static and package-safety validation

The final source validation checks:

- Python AST parsing;
- JSON and YAML parsing;
- shell syntax with `bash -n`;
- phase uniqueness and module presence;
- canonical profile ordering;
- capability-registry validity;
- absence of symlinks and nested archives;
- absence of runtime caches and collected result files;
- absence of unrestricted `shell=True` or `os.system` in release source outside test fixtures;
- absence of embedded private keys or obvious hard-coded secrets;
- zero-unintentional-removal compatibility status.

Detailed machine-readable results are in `docs/validation/FINAL_STATIC_VALIDATION_v3.9.7.1.json`.

## CLI smoke validation

The following completed successfully from the release tree:

```bash
python3 tbhm.py -h
python3 tbhm.py --list-profiles
python3 tbhm.py --capability-status
python3 tbhm.py --doctor
python3 tbhm.py -y --safe-plan plan.json --safe-plan-dry-run -o <temporary-output>
```

Observed smoke state:

- 15 capabilities registered.
- 11 capabilities available in the validation environment.
- Doctor: PASS with 20 checks; optional missing dependencies were reported without crashing.
- Structured RDAP plan: one dry-run action, zero rejected actions, no shell execution.

Environment availability is not a universal promise: external adapters may be unavailable on another system until their optional executable or package is installed.

## Safety boundaries

No autonomous credential theft, password spraying, phishing, MFA interception, exploitation, arbitrary remote command execution, reverse shell, C2 startup, persistence, lateral movement, DCSync, ticket forgery, pass-the-hash, destructive wireless action, cloud write operation, OT/ICS write operation, or AI-generated arbitrary shell execution was added.

Sensitive domains are limited to safe plans, import/normalization, read-only analysis, approval validation, dry-run representation, policy enforcement, evidence handling, audit logging, and remediation guidance.

## Qualification

Passing offline tests and source validation does not prove that every external executable behaves correctly on every platform, and it does not prove that an assessed target is secure. A run with no confirmed findings must continue to be reported as a coverage-limited result, not as evidence that the target is safe.
