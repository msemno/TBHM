# Artifact writer coverage

`ARTIFACT_WRITER_COVERAGE.csv` inventories 1,426 static candidate sites/producer
families in this source tree. It includes possible nonwriters and may miss
aliased/native/indirect writes; it is not a claim of complete semantic closure.
Every unreviewed row is visibly `UNVERIFIED`. Scanner-native, browser-generated,
Go/native and opaque/encrypted/PDF/image producer families remain unverified.
`all_sensitive_writers_reviewed` stays false.

| Reviewed new/changed producer | Output / sensitive-data boundary | Validation |
|---|---|---|
| Strict replay | Signed captures via existing API; selected plan assertions, attempts, summary JSON and normal findings. Credentials from env names; registered before captures; captures are redacted and signed; private key stays out of delivery | Real CLI/storage restoration/report/seal tests; missing approval/offline contact zero |
| Broker / pinning | Existing separate ledger; redacted URLs/reasons/digests; no response body persistence except the explicit trusted capture observer. Empty owner-mode dispatch lock file is a coordination artifact | Actual native/isolated child, TLS, DNS changes, concurrency and bounded body tests |
| Evidence graph/operator view | Redacted stored finding facts and bounded selected references; no file reads or network execution from supplied edges | Imported flags refused; only restored receipts identify proof authority; no exploit edge generated |
| Privacy audit | Prior sealed evidence read only; reports marker names/encodings and redacted paths, never marker values. Encoded variants registered for output redaction | UTF-32/URL/hex/HTML/JSON/base64 variants; bounded containers; XZ memory/concatenation refusals |
| Quality evaluator | Selected synthetic labels/outcomes/counts/bounds and source/bundle hashes; no production prompts, model output or credentials | Labeled denominators, abstentions, stage separation, project leakage and paired local evaluation |

Existing snapshot behavior retains live raw run data, creates a sanitized delivery
copy, uses SQLite backup/integrity checks, excludes private keys and rejects signed
evidence requiring further redaction. These producer boundaries remain intact.
The prior audit never re-signs or rewrites immutable evidence.

ZIP/tar/gzip limits remain, BZip2 output is bounded, and XZ limits both output and
decoder memory to 32 MiB. Nested formats use the shared expanded-byte/file/depth
budgets. Unsafe members are not extracted. Concatenated/truncated/oversized XZ,
encrypted/unknown formats and budget exhaustion remain incomplete, not private.
Raw bytes, supported encodings and names are checked; pixels, encrypted semantics,
unknown secrets and producer lifecycle races are not fully covered.

The review records file-level ownership and remaining work. It does not relabel
all legacy writers as reviewed merely because a canary test passed.
