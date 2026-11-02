# Captured proof contract, version 2

`core.proof_contracts.capture_snapshot` is a trusted adapter API for responses
that the adapter actually captured. It accepts a run output directory, test ID,
vulnerability class, role, actor identity label, concrete request and concrete response. It writes a
sanitized capture with a unique ID and returns its relative path, SHA-256 and
run-key HMAC. It hashes the actual request credentials before redaction to bind
identity changes without storing their values. It must not be used to relabel an
untrusted imported record as a live capture.

Both assertion and proof carry `schema: tbhm.proof/2`. The assertion declares
`test_id`, `vulnerability_class`, `failure_conditions` and
`negative_control_conditions`. The proof's `captures` object contains signed
references under `baseline`, `mutation`, `negative_control`, and a `repeats`
array containing at least two distinct captures. Each capture role and test ID
are authenticated. HTTP statuses alone and repeat counters are insufficient.

`access_control` additionally requires `object_id`, `object_path` (default `id`)
and `owner_path` (default `owner`). The owner baseline and other-actor mutation
request the same object. Responses must prove that object's owner and identity;
mutation and owner use distinct captured credential fingerprints. Controls and
repeats bind to the mutation actor. Paths are top-level JSON keys.

`sensitive_data_exposure` requires `private_marker`: a controlled canary present
in the authenticated baseline and anonymous same-resource responses, absent in
the negative control. `open_redirect` requires `redirect_host`: mutation and
repeats must carry actual 3xx Location responses to that controlled host, absent
from the baseline and negative control.

Pass the bundle to `core.assertion_engine.evaluate(..., evidence_root=run_dir)`.
On success `confirmation_fields` produces a process-local receipt. Store the
attempt with `Storage.record_validation_attempt`, link its finding ID, then
update the finding using the resulting fields and validation-attempt ID.
`Storage.all_findings` reloads and validates the stored attempt and captures;
JSON flags alone cannot restore the process-local receipt. The finalizer strips
the private key from delivery, so a recipient can verify file integrity but does
not independently authenticate the scanner's actor labels or capture origin.
A malicious local operator or plugin controlling the key is outside this trust
boundary. Unsupported classes and legacy proof require manual review or a new
reviewed verifier; there is no generic confirmation fallback.

`test_support.py` contains a complete, non-network fixture showing the record
shape; `tests/test_release_v410.py` checks positive and adversarial examples.
