# Historical Source Archaeology — v3.9.7.2

The original v3.9.7.1 archaeology artifacts remain under `docs/historical/` and `manifests/`. v3.9.7.2 adds a second behavior-focused pass against every supplied historical archive, including versions older than the five primary precedence references.

The second pass verified scan rule tables, scanned file classes, provider indicator sets, extension handling, output aliases, fallback identifiers, and offline fixtures—not merely path or symbol presence. It confirmed the five previously reported gaps and found one additional CI/CD syntax gap: the narrower parser did not preserve every inline `pull_request_target` and generic `github.event.*` case from v3.9.6.

All confirmed gaps are classified and implemented in `CHANGELOG-v3.9.7.2.md` and `docs/HISTORICAL_COVERAGE_RESTORATION_v3.9.7.2.md`. No historical source tree replaced the current architecture wholesale.
