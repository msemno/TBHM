# TBHM 4.2.2 — owned-account replay and offline isolation

Built on the recovered **4.2.1** distribution; 4.2.0 was retained for comparison.
No original file or phase was removed. There are 452 CLI actions (450 retained,
two added), the same 145 dispatched phases in the same order, and unchanged
SQLite DDL. Argument signatures are preserved; deliberate behavior changes are
listed below. Core dependencies and bundled model weights are unchanged.

## Implemented

- `--api-authz-plan` and `--approve-api-authz`: execute explicitly scoped,
  read-only GET cases using two owned accounts and owned test objects. Credentials
  come from named environment variables. Validate the entire plan first. Each
  case captures an owner baseline, challenger mutation, challenger missing-object
  control, anonymous same-object privacy control and two repeats. All six requests
  share the existing native HTTP request/rate/cooldown policy. Redirects are not
  followed; cookies are cleared between actors. HTTPS is required except numeric
  loopback lab URLs. No write requests or automatic object discovery are added.
- The replay feeds authenticated proof v2, validation attempts, the existing
  finding store, OPERATOR/report generation and execution-backed standards
  accounting. Plans and HAR inventory cannot issue confirmation receipts.
- Access-control proof now rejects non-2xx object responses, non-distinct controls,
  controls returning the protected object, and invalid private-object controls.
  Nested object/owner JSON paths and explicit numeric `owner_value` are supported.
- Linux x86-64 `--offline` installs an inherited seccomp network syscall filter
  across threads and descendants before work starts. Approved offline Runner
  adapters also enter the filter through a wrapper, including the Go executor.
  Socket creation/connections/sends, alternate syscall ABIs, io_uring and relevant
  descriptor/process-injection paths are denied. Unsupported/unavailable isolation
  and inherited socket descriptors fail closed. This is not a filesystem sandbox.
- Delivery snapshots re-sanitize supported text exports and SQLite TEXT cells in
  the backup; secure-delete plus VACUUM removes superseded database text. The live
  run is retained. Signed evidence requiring additional redaction is rejected,
  not silently re-signed. Every sealed file is covered by mutation tests.
- SARIF/HAR and additional text formats join central output sanitization.
- AI run-artifact ingestion rejects symlinks and files outside the run root.
- Evaluation preserves unresolved-only categories, prediction coverage and a
  conservative recall bound alongside the original observed-only metrics.
- Central version, installer messages, SBOM, release manifest and validation
  metadata identify 4.2.2. Executable modes are retained in the ZIP.

## Behavior changes

1. Strict offline denies **all network sockets**, including loopback model HTTP.
   For local source analysis with an explicit local model, use `passive_only`
   without `--offline`. No model is downloaded by this release.
2. Evidence previously accepted through an invalid access-control control can
   demote to unconfirmed on read/revalidation. Records are not deleted.
3. Supported text exports over 16 MiB, non-UTF8 text exports, or signed captures
   containing newly recognized secrets block delivery for review. Opaque binary
   privacy still requires adapter-specific review.

See `docs/research-v4.2.2/VERIFICATION.json` for measured results and
`docs/research-v4.2.2/ROADMAP.md` for remaining gates. Synthetic fixture metrics do
not measure unknown production vulnerabilities, live bounty acceptance or model
quality. Global online child-scanner/browser egress metering remains unresolved.
