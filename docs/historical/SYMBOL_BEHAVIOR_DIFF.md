# Symbol Behavior Diff

AST comparison covered 3,022 historical symbol records. Fifteen symbol names were absent from the original v3.9.6 tree and required semantic review.

## Reviewed absent symbols

- Reporter helpers `_top_concerns_md`, `_defender_ioc_for`, `_write_html`, `_load_branch_matrix`, and `_branch_status_from_findings`: restored as compatibility helpers around the structured reporter.
- Reverse helpers `import_json` and `static_strings`: restored as bounded compatibility wrappers; the five-stage workflow and shared normalizers remain authoritative.
- Code-security helpers `sev` and `walk`: retained as wrappers; `core.scanner_normalizer` is the preferred implementation.

No private helper was restored merely to increase a symbol count. Each restored name either has historical callers or preserves a documented report/import behavior. Detailed decisions are HIST-0011, HIST-0014, HIST-0015 and HIST-0017.
