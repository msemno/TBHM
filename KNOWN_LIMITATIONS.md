# TBHM 4.2.7: known limitations

This file documents operational boundaries. A passing regression suite is not
evidence that a target has no vulnerabilities or that an external tool works
for every input.

## Coverage and finding status

- Selected phases, available tools, credentials, supplied application artifacts,
  request budgets and program policy determine what can actually execute.
- A phase that was blocked, timed out, exhausted its budget, or failed to parse
  output has incomplete coverage. Zero findings in that phase is not a clean
  security assessment.
- Job completion, finding severity and evidence confidence are separate fields.
  `finished_with_gaps` is an operational state, not a vulnerability type.
- Inspect `execution_ledger.json`, `REPORT_confirmed.md`, `REPORT_leads.md`, and
  the operator review queue. Keep incomplete work visible when reporting results.

## Local models

Ollama availability, a valid embedding vector and observed GPU placement test
connectivity and execution. They do not establish the accuracy of security
reasoning, successful training, or a complete retrieval index.

Runtime model scheduling is opt-in and bounded by the configured dispatcher.
Model advice and reordered phases do not establish exploitability. Confirmation
still needs the applicable evidence contract, identity/target bindings, negative
control and repeat captures. A pending embedding queue remains pending until
coverage is checked; do not replace durable AI state merely to clear a check.

## External scanners and browsers

Each adapter has its own version, applicability and resource constraints.
Python's request counter is not a global traffic limit for every child process.

The installed Dalfox 2.13 adapter can constrain invocation and preserve errors.
It does not patch Dalfox or chromedp internals. A reported allocator panic,
timeout, or absent browser proof leaves that check incomplete. Reflection or a
zero process exit code does not demonstrate JavaScript execution.

No claim of universal external-tool or browser containment is made. Consult the
current adapter diagnostics and use local controlled fixtures for maintenance
tests before resuming a broader campaign.

## Environment and manual work

Windows inference and a Kali VM's Internet connection can fail independently.
A responsive loopback Ollama endpoint does not prove external DNS/NAT health.
Suspend/sleep can interrupt both scans and tunnels; a background launcher does
not keep either host awake.

Authenticated authorization/business-logic checks need controlled accounts and
test objects. Mobile device checks need appropriate app artifacts and devices.
Public source review does not establish private GitHub settings or runner
permissions. Record these as unexecuted when the necessary inputs are absent.

## Release identity

The package manifest detects file drift; it is not an independent signature or
a security certification. Historical release-info and validation files describe
their recorded builds. Keep new test results outside the source checkout and
identify the build and command that actually produced them.
