# Strict Evidence, Bug-Bounty Workspace, and Red-Team Campaign Architecture

## Purpose

This build keeps the tested Python control plane and introduces an optional Go
process executor. It changes the security-data model so endpoint liveness,
scanner prose, static indicators, high confidence, and LLM output cannot become
confirmed vulnerabilities by themselves.

## Language architecture

- **Python remains authoritative:** CLI, profile compatibility, scope and policy,
  phase orchestration, evidence normalization, AI, SQLite, finding logic and
  reporting.
- **Go is optional:** `bin/tbhm-go-executor` executes one argv-only job, streams
  full output to the run log, retains bounded tails, enforces timeout and kills
  the Linux process group. If it is absent, Python runs the job.
- **Existing native tools remain native:** TBHM does not rewrite Ghidra, Binwalk,
  Nmap, Nuclei, Semgrep, Frida-family tooling or other specialist engines.
- **C is not used as a framework language:** add a native C module only after a
  benchmark proves a specific packet/parser hot path needs it, with sanitizers,
  fuzzing and process isolation.

## Finding lifecycle

```text
planned test
  -> test execution
  -> observation
  -> candidate hypothesis
  -> supported candidate
  -> versioned assertion evaluation
  -> independent validation attempt
  -> confirmed vulnerability
  -> report / retest / closure
```

A confirmation requires all of the following:

1. A versioned assertion with a test ID and stated invariant.
2. Baseline evidence.
3. Mutation or controlled proof evidence.
4. A negative control.
5. At least two successful proofs from at least two attempts.
6. An explicit verifier method persisted with the finding.

The `findings` table remains for backward compatibility. New typed tables are:

- `test_executions`
- `observations`
- `candidates`
- `validation_attempts`
- `program_policies`
- `identity_contexts`
- `workflow_models`
- `redteam_campaigns`
- `redteam_operations`
- `detection_outcomes`
- `cleanup_actions`

## Bug-bounty workspace

The workspace accepts a reviewed program policy, identity plan, workflow plan,
and HAR. It stores redacted request shape and hashes—not live passwords,
cookies, authorization headers, tokens, multipart bodies or other credentials.
A secure external session provider is referenced by ID at execution time.

A workflow row is ready only when:

- The request exists in the redacted HAR workspace.
- The identity exists and has a session-provider reference.
- The asset is explicitly in scope.
- The HTTP method/action is allowed by the policy.
- The assertion has failure and negative-control conditions.

This phase prepares an execution queue but sends no requests. It can run as a targetless local workflow when these reviewed artifacts are supplied explicitly.

## Red-team lifecycle

The campaign register represents all Enterprise ATT&CK tactic stages plus
exploit validation and physical/social/wireless/OT objectives:

- reconnaissance
- resource development
- initial access
- execution
- persistence
- privilege escalation
- defense evasion
- credential access
- discovery
- lateral movement
- collection
- command and control
- exfiltration
- impact

High-impact operations are forced to `import_only`. A result can influence a
finding only when it matches an approved operation and includes an operator,
authorization and scope references, start/end timestamps, a valid SHA-256,
structured assertion/proof, verified cleanup, and the expected target.

TBHM records prevention, logging, detection, alert routing, analyst response,
response correctness, timing, telemetry gaps, and cleanup actions. Campaign
plans and sanitized results can run as a targetless local import workflow; the
operation target must still match the signed approval and typed campaign row.

## Process capture contract

`Runner.run()` supports:

- `capture_mode="full"`: compatibility mode for phases that parse stdout.
- `capture_mode="tail"`: bounded memory, complete run log.
- `capture_mode="none"`: tiny diagnostic tail, complete log or `stdout_path`.
- `stdout_path` / `stderr_path`: direct parser artifacts without buffering.
- `run_many()`: bounded parallel execution of independent, already-authorized
  jobs.

Existing return-value parsers retain full capture. Calls that ignore output use
bounded tails. Firmware strings stream directly to disk and firmware hashing is
incremental. Reverse-analysis hashes, magic type and bounded entropy samples are
cached in-process using resolved path, size and nanosecond modification time, so
unchanged artifacts are not repeatedly re-read by adjacent phases.

The AI embedding client first probes the loopback model once. Only after a
successful probe does it submit the remaining texts through a bounded worker
pool (default 2, maximum 8). A failure or dimension mismatch regenerates the
whole batch in the deterministic fallback space; remote and fallback vectors
are never mixed.

## Deliberate execution boundary

The platform models and validates red-team exploit and control evidence, but it
does not autonomously generate or launch weaponized exploits, steal credentials,
deploy persistence, disable defenses, establish C2, move laterally, phish users,
change OT state, or exfiltrate real data. Those operations require separately
governed infrastructure and imported, hash-bound, cleanup-verified evidence.
