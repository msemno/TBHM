# CHANGELOG v3.9.4.1 — correctness, scope, evidence, and AI-memory hardening

This maintenance release preserves the v3.9.4 AI Control Plane and the 102-phase
assessment pipeline. It does not add autonomous exploitation or self-modifying
behavior. All source-change proposals remain operator-reviewed and are never
applied automatically.

## AI Control Plane correctness

- Source paths are now the identity of indexed tool documents. A changed file
  replaces its prior document/chunks instead of leaving stale old code
  retrievable beside the new version.
- Chunk IDs are preserved for unchanged symbols and the vector cache updates only
  added/removed rows. One-file changes no longer re-embed the entire tool.
- Every embedding batch is homogeneous. If an Ollama embedding fails or dimensions
  disagree, the complete batch falls back to one deterministic embedding space;
  incompatible caches are rebuilt rather than padded or mixed.
- The source index now includes packaged tests, add-ons, reverse scripts, bundled
  Nuclei templates, payloads, wordlists, profiles, documentation, and source.
- Redacted source snapshots produce bounded real unified diffs for delta review.
- `--ai-propose-delta` creates a pending, non-applying proposal from the actual
  redacted source delta.
- Model-lock configuration is authoritative after initialization.
- Lesson candidates are restricted to the current run.
- Imported resources are extracted and redacted before persistence. Raw copies
  are not stored or included in backups.
- Portable backups include proposal JSON/patches and sanitized resources, exclude
  raw legacy imports, model weights, and rebuildable vector matrices, and restore
  through traversal/link-safe extraction.

## Assessment correctness and safety

- JavaScript and deep-crawl requests are scope-checked before every request and
  every redirect. Passive/zero-rate profiles perform no discovery request.
- Deep crawl records only meaningful 2xx resources as reachable, separates
  401/403 protected routes, ignores 404/5xx for endpoint scoring, and resolves
  relative links against the final redirected URL.
- Registrable-domain handling is IP-safe and covers multi-label public suffixes
  offline without collapsing targets to `co.uk`, `co.id`, `com.my`, and similar.
- Surface correlation consumes source `hosts.txt`/`urls.txt` and enforces target,
  allowlist, and exclusion checks before endpoint persistence.
- Static taint distinguishes sanitized flows from unsanitized static leads.
  Static-only evidence remains SUPPORTED and cannot self-confirm; live route
  reachability is attached before trace classification.
- HTTP proof accepts a denial baseline followed by a successful proof only through
  structured differential fields and an explicit passed negative control.
- Reverse phases propagate a canonical artifact SHA-256 identity; correlation is
  no longer based on evidence-file paths. Dynamic filesystem indicators are
  emitted explicitly.
- Legacy binary review uses boundary-aware short-API detection and normalizes
  same-run capa capabilities as non-confirming leads.
- Failed phases are not marked complete; `--resume` retries them.
- Network findings are scope-gated at the save boundary, and persisted evidence is
  redacted without destroying artifact hashes.
- The authorized red-team profile includes JS analysis, deep crawl, surface
  correlation, and whole-run LLM analysis. Whole-run LLM analysis runs after all
  finding/coverage-producing phases and remains advisory-only.
- `--rate-limit` is clamped by independent framework maximums and cannot turn a
  passive profile active.
- Explicit local-only source/binary/import phase sets can run without a synthetic
  network target.

## Reporting and documentation

- Executive and manager reports include generated time and a narrowly qualified,
  confirmed-evidence posture statement. No fixed severity-to-days remediation
  estimate is invented.
- The methodology audit surfaces authorization/scope/rate/write controls and
  integrates branch/objective coverage artifacts when generated. “Not Tested” is
  never presented as “Safe.”
- Active version metadata is synchronized to
  `3.9.4.1-ai-plane-correctness`.

## Validation

- Existing v3.8–v3.9.4 integration suites remain applicable.
- `integration_test_v3941.py` adds offline regression coverage for AI delta
  replacement, homogeneous embeddings, resource redaction/backup, model lock,
  public-suffix/IP scope, pre-request scope, passive crawl, 404 handling,
  surface-correlation exclusions, static-taint classification, differential HTTP
  proof, artifact correlation, persistence redaction, phase order, local-only
  invocation, and rate ceilings.
