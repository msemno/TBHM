# TBHM v3.9.7.3 Lifecycle/Go Safe Upgrade

- Preserved the original 129-phase compatibility order and introduced a 133-phase
  expanded order for current full/red-team profiles.
- Added strict typed test, observation, candidate and validation records.
- Removed confirmation by HIGH confidence, prose keywords, status/liveness or a
  bare verified flag.
- Replaced generic curl verification with liveness observations and structured
  validation queues.
- Added reviewed program-policy, identity, workflow and redacted HAR workspace.
- Added full red-team campaign/tactic records, approval linkage, imported exploit
  validation evidence, detection outcomes and cleanup records.
- Added optional statically linked Go argv-only executor with Python fallback.
- Added bounded output modes, direct artifact streaming, process-group timeout,
  cancellation and bounded parallel tool jobs.
- Changed firmware hashing and strings processing to bounded-memory streaming.
- Added process-local reverse artifact hash/type/entropy caching keyed by file identity, and removed whole-file reads from magic/import triage.
- Added bounded local embedding concurrency after a successful loopback availability probe; fallback remains deterministic and homogeneous.
- Added lifecycle counts to JSON, final and methodology reports.
- Added offline regression tests and example policy/workflow/campaign/result files.
- Added targetless local CLI workflows for reviewed bug-bounty workspaces and campaign evidence imports, avoiding fake network targets.

No autonomous weaponized exploitation, credential theft, persistence, defense
evasion, C2, lateral movement, phishing, destructive action or real-data
exfiltration was added.
