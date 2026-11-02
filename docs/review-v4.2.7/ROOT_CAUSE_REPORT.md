# TBHM 4.2.7: public engineering review

This summary describes source changes and open acceptance goals. Original
engagement-derived analysis is retained privately by the operator. Public
documentation does not distribute those target-linked records or imply that a
scanner observation demonstrated a vulnerability in a named service.

## Changes carried forward in 4.2.7

| Area | Failure class | Implemented direction |
| --- | --- | --- |
| Checkov parsing | Passed results could enter the finding channel | Read failed records with their rule/file relationships |
| njsscan parsing | Diagnostics or unrelated metadata could become findings | Keep matches and parser failures in separate channels |
| Anonymous routes | HTTP success, size or route keywords could imply authorization failure | Preserve response inventory and require evidence for authorization claims |
| Static analysis | Declaration-only signatures and feature presence could imply reachable sinks | Distinguish declarations and inventory from executable behavior |
| API path discovery | Response deviations could be treated as vulnerability proof | Keep uncertainty-aware status and baseline interpretation |
| Inference transport | Target timeouts and small remaining budgets could impair model calls | Separate service budgets, bounded inference timeouts and failure circuits |
| Port scanning | DNS or hostname association could imply network authorization | Require explicit IP/CIDR network scope and a separate packet-rate policy |
| Capability inputs | Missing or compound inputs could be misinterpreted | Record input applicability and reject missing explicit inputs |
| Runtime model control | Planning could be limited to end-of-run advice | Add opt-in bounded priority choices in audited dispatcher windows |
| Compatibility | Explicit model selection or valid workspace dependencies could be lost | Preserve explicit selection and verified local dependency identity |

These are incremental changes. They do not assert that every historical
heuristic, proof class, integration or target methodology has been independently
validated.

## Evidence and authority

Finding severity, evidence confidence and execution coverage are separate.
Scanner output, model advice, a route name or a successful HTTP response cannot
substitute for the required proof contract. Keep negative controls, repeat
captures, identity bindings and target bindings attached to accepted proof.

Model-protocol fixtures establish integration behavior. They are not a study of
the selected real model's reasoning quality. Generation readiness, GPU placement
and retrieval-index completeness are separate operational observations.

## Release validation

Validate the actual source and package you intend to distribute. Use the current
manifest, a fresh offline installation, import/phase checks and the packaged
regression runner. Preserve command, interpreter, result and build information.
Historical validation receipts apply to their recorded source builds.

The publication preparation changes documentation, ignore rules and the public
selection of diagnostic artifacts. It retains runtime Python, Go source,
scanner adapters, pinned dependencies and proof authority. Its validation record
is supplied separately in the preparation kit.

## Open acceptance goals

- Demonstrate scope, semantic action, rate, redirect and cancellation behavior
  for each external scanner/browser combination actually supported.
- Measure the selected real model on independently labeled held-out cases,
  including adversarial evidence and latency limits.
- Expand authenticated actor/role/tenant and business-logic cases with
  controlled accounts and test data.
- Keep budget exhaustion, missing inputs, unavailable tools and deferred
  embeddings visible as incomplete work.
- Establish real mobile/device and browser execution evidence independently
  from static inventory and reflection.
- Verify host/VM sleep, connectivity and reconnection behavior for the actual
  Windows/Kali deployment.

See [known limitations](../../KNOWN_LIMITATIONS.md),
[architecture](ARCHITECTURE.md), [file map](FILE_MAP.md),
[CLI reference](CLI_REFERENCE.md), and the
[installation and operator guide](../UPGRADE-v4.2.7.md).
