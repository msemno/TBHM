# Historical Source Archaeology — v3.9.7.1

Five supplied releases were independently integrity-tested, extracted, inventoried, hashed, parsed, and compared:

1. v2.16-fixed — curl probes, Nuclei/bootstrap, installer, and regression-restoration reference.
2. v2.21 — source/mobile/interface and false-positive reference.
3. v3.8-expanded — broad safe red-team behavior and adapter reference; its source banner still identifies itself as `3.0-redteam-safe`, so behavior rather than filename was used.
4. v3.9.5 — direct differential reference for corporate-intelligence changes.
5. Original v3.9.6 enterprise-control-plane — authoritative implementation baseline.

The normalized file-lineage comparison found no historical relative source path absent from the original v3.9.6 tree. The meaningful regressions were semantic: rewritten helpers, report contracts, profile ordering, false-positive controls, and fallback behavior. AST comparison produced 3,022 symbol-lineage records and 15 absent symbol names requiring review. All 15 were classified; compatibility wrappers were restored only where they preserve useful behavior or callers.

The complete inventory, hashes, per-version manifests, path matrix, symbol lineage, function decisions, and 29-record decision register are stored in `docs/historical/` and `manifests/`.
