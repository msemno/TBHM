# New proof contracts: exact acceptance scope

Both new contracts require proof-v2, run-local authenticated capture references,
one target origin, read-only GETs, an explicit controlled-fixture/scope declaration,
a fresh controlled `TBHM_<32 hex>` response canary, unique capture IDs and two
distinct repeats with identical mutation URL/body/actor/credential binding.
The canary must not be present in request URLs/headers. Scanner prose, score,
HTTP status, reflection or imported assertion flags cannot substitute for captures.

## Controlled file traversal

The operator prepares a public `.txt` baseline with a known SHA-256 and a
dedicated outside-root `tbhm-proof-<nonce>.txt` whose entire contents are the
canary. The mutation uses an explicitly reviewed relative `../` query value;
the negative uses a dedicated nonexistent `tbhm-missing-<nonce>.txt` path. Same
endpoint and unrelated query parameters, one actor/credential, and GET body
bindings are checked independently of generic assertion conditions.

Confirmation requires a successful known public baseline without the canary,
successful exact canary bodies in mutation and both repeats, and a distinct
401/403/404 missing/denied control without the marker. This proves the reviewed
outside-root canary read, not arbitrary file contents, metadata access or code
execution. The replay does not write or create a remote file.

## Owned-role protected read function (BFLA)

The operator declares distinct owned privileged and limited actors, distinct
credentials, explicit expected denial for the limited actor and a protected
`function_id`. The privileged baseline and limited mutation use the same exact
URL/method/body. Responses must be successful JSON objects exactly equal to the
reviewed `function_id` and private `proof_canary` pair.

The limited actor's distinct missing/denied-function control and an anonymous
same-function control must each deny without the canary. Mutation plus two
credential-bound repeats must expose the exact protected result. A public
endpoint, expired privileged account, general error, HTTP 200 page or ambiguous
ownership/role declaration cannot confirm. The contract supports read functions;
state-changing BFLA, token lifecycle and tenant transitions are separate work.

## Outcomes

| Public lifecycle | Engine result | Required behavior |
|---|---|---|
| CONFIRMED | `pass` plus in-process receipt | All class invariants, generic assertions, negative controls and repeats pass; persistence restores the receipt from captures |
| REJECTED / exact control held | `fail` / `disproved` | Complete valid baseline/controls with stable explicit denied mutation and repeats under the new class, or a contradicted asserted condition; no confirmed finding |
| INCONCLUSIVE | `inconclusive` | Invalid/tampered/missing references, wrong class/test/actor/origin, control leakage, public anonymous result, expired baseline, absent/ambiguous impact, unstable repeats or transport failure |

No incomplete result becomes an application-wide clean claim. Tests include real
vulnerable/patched filesystem and role-function fixtures, signature and physical
tampering, duplicate repeats, missing controls, wrong-class labels, query/function
bindings, unstable signed repeats and metamorphic key/repeat ordering.

The existing three contracts keep their tested behavior: 42 baseline differential
vectors compare outcome flags, reasons and receipt issuance. Source evolution is
permitted in the three proof modules; release manifests protect the immutable
packaged versions. Other candidate classes remain unsupported for strict
confirmation and must not be inferred from these two contracts.
