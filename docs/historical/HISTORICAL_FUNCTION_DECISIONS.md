# Historical Function Decisions

All 15 absent historical symbol names were semantically classified. The final release restores compatibility wrappers only where useful and keeps strict newer implementations as the source of behavior.

- Reporter compatibility: `PRESERVE_WITH_COMPATIBILITY_ALIAS`.
- Scanner parser compatibility: `REPLACE_OLD_WITH_NEW` plus wrappers and fixtures.
- Reverse fallback compatibility: `MERGE_OLD_AND_NEW`, with no artifact execution.

See `HISTORICAL_DECISION_REGISTER.md` and the offline regression suites for evidence.
