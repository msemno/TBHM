# Capability Depth Architecture — v3.9.7.1

## Truth model

Every registered capability declares an implementation state (`native`, `adapter`, `import_only`, `proposal_only`, `planned`, or `unavailable`), execution mode, safety class, approval requirement, network behavior, dependencies, schemas, evidence types, phase association, configuration keys, platform support, default state, and failure behavior.

Registry presence does not imply runtime availability or authorization. `--capability-status` calculates availability from the current platform, Python imports, external executables, and required environment-variable presence without displaying secret values.

## Native and bounded operations

The only plan actions that can execute are allowlisted in source. RDAP is implemented in Python. Sherlock, Maigret, and cosign are adapter-backed and require their exact executables. No plan can supply a command, executable, argv array, shell field, or shell fragment.

## Import and proposal boundaries

Session/beacon and wireless capabilities only normalize supplied evidence. Adapter generation only creates an unapproved design proposal. These capabilities cannot activate external products or execute generated commands.

## Evidence and confirmation

New phases preserve source capability, source phase, timestamps, provenance, evidence paths, status, confidence, prerequisites, uncertainty, impact, and remediation where applicable. Imported or static observations remain leads unless independent evidence satisfies the existing confirmation model.

## Local-only invocation

Explicit local inputs such as `--safe-plan`, `--session-evidence`, `--wireless-observations`, and `--adapter-definition` automatically select a narrow local phase subset when no `--phases` value is supplied. This avoids a fake target while preventing the default network profile from running against a placeholder. Active local workflows still require the existing authorization acknowledgment where applicable.
