# Writer review and open coverage

`WRITER_CANDIDATES.csv` is a static AST call inventory with 2,656 candidate sites.
It deliberately includes possible nonwriters such as generic `run`/`open` calls
and may miss aliased, indirect and native writes. It is not semantic closure.
`all_writers_reviewed` remains false. Legacy and native writer review is open.

The following new paths were reviewed semantically against their tests:

| Producer | Output and sensitive-data handling | Evidence / limitation |
|---|---|---|
| `core/brokered_http.py` | Separate `evidence/brokered_http/ledger.sqlite3`, redacted results JSON, summary observation/log. Response bodies are hashed, not persisted; environment credentials are registered for redaction and not sent to the child | Real native/child, denial, shared quota, cooldown and CLI tests. Decoded accepted-body quota is not a wire quota. Legacy writers are outside this review |
| `scripts/broker_pipe_worker.py` | ID/status-only stdout protocol; discarded stderr; minimal environment and closed inherited descriptors | Socket refusal and actual pipe workflow tested. Fixed packaged worker only; no arbitrary scanner support |
| `core/llm_security_import.py` | Redacted selected metadata/counts, review JSON and informational finding; raw prompts/responses are not copied | Garak/Promptfoo/canonical export tests. User-controlled metadata remains untrusted; labels are not proof |
| `core/learning_corpus_audit.py` | Redacted audit metadata; optional explicitly reviewed sanitized text inside variable-length fenced data cards; hashes in INDEX.json | Permission, hash binding, leakage, fencing and revocation tests. Declared licensing is not independently verified; no unknown-secret guarantee |
| `core/delivery_privacy_audit.py` | Read-only prior snapshot verification; result contains marker names/encodings and paths, not values. Raw/base64 marker values are registered for redaction | Container, malformed/opaque, size-budget, tamper and CLI fail-on-incomplete tests. Unknown formats and budget exhaustion stay incomplete |
| `core/research_input.py` | Bounded local input reader; no artifact writes | Duplicate/nonfinite JSON, depth/size, UTF-8 and symlink handling. No producer lifecycle claim |
| `core/capability_inputs_v423.py` | Parser metadata/routing only; no artifact writes | Default/combined input/explicit phase override tests |

All capability artifacts enter the existing observation/report/sealing pipeline.
New outputs do not grant permission to deliver a live work directory. Deliver
the sealed snapshot, and retain the existing capture-key boundary.

The privacy audit checks supplied canaries in supported raw encodings and bounded
containers. PNG/PDF pixels, encrypted payloads, unknown encodings, unrecognized
binary data and producer lifecycle defects require further work. A canary-free
supported file is not proof of the absence of all credentials or personal data.
No all-sensitive-writers-reviewed or all-formats-private release flag is enabled.
