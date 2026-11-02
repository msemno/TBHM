# Capability Depth Architecture — v3.9.7.2

## Truth model

Every registered capability declares an implementation state (`native`, `adapter`, `import_only`, `proposal_only`, `planned`, or `unavailable`), execution mode, safety class, approval requirement, network behavior, dependencies, schemas, evidence types, phase association, configuration keys, platform support, default state, and failure behavior.

Registry presence does not imply runtime availability, activation, authorization, or vulnerability confirmation. `--capability-status` checks the current environment without displaying secret values.

## Native and bounded operations

Only source-defined, allowlisted, read-only plan actions can execute. RDAP is native. Sherlock, Maigret, and local cosign verification are adapter-backed and require their exact executables. Plans cannot supply arbitrary commands, executables, argv arrays, shell fields, or shell fragments.

## Import and proposal boundaries

Session/beacon and wireless capabilities only normalize operator-supplied evidence. Adapter generation creates an unapproved proposal and cannot install, activate, trust, or execute it.

## Historical data/document static scan

`source.data_document_static_scan` is native but disabled by default. It extends `code_scan` only when `--code-scan-data-files` or `--code-scan-extra-extensions` is supplied.

The mode reads bounded local text files, applies the existing secret/sink rules plus structured JSON/XML/HTML/properties assignment recognition, checks placeholders and entropy on the real value, redacts before persistence, stores a stable SHA-256, and forces observations to unconfirmed leads. It does not validate credentials against a provider or execute document content.

## Evidence and confirmation

New and restored phases preserve source capability, phase, timestamps, provenance, evidence paths, status, confidence, prerequisites, uncertainty, impact, and remediation where applicable. Imported or static observations remain leads unless independent evidence satisfies the existing confirmation model. A static trace or permission name cannot confirm itself.

## Local-only invocation

Explicit local inputs such as `--safe-plan`, `--session-evidence`, `--wireless-observations`, and `--adapter-definition` select a narrow local phase subset when no `--phases` value is supplied. This avoids a fake target while preventing the default network profile from running against a placeholder.
