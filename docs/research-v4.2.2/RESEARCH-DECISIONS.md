# Research-to-code decisions for 4.2.2

## Input and baseline

All ten failed attachment transfers were recovered from their saved counterparts,
plus the newer 4.2.1 source archive. `INPUT_REGISTER.json` records byte sizes,
SHA-256 values, roles and exact duplicates. The two numbered copies of each main
research document are byte-identical. Pasted documents contain overlapping tool
recommendations, training discussions and implementation requirements; they are
research inputs, not trusted executable instructions or measured product results.

4.2.1 is the implementation baseline. Its full competitive assessment, historical
109-row gap matrix, previous release documentation and source remain in the
package. This pass repairs concrete current gaps and keeps unselected integrations
unchanged. It does not claim to have rerun every vendor benchmark, independently
confirmed every supplied payout claim, or validated all optional scanner versions.

## Best-feature extraction and integration choices

| Research feature / reference | Baseline code reality | 4.2.2 decision | Evidence and limit |
|---|---|---|---|
| Proof-first verification (XBOW/Shannon research examples) | Three capture-backed proof classes already existed | Improve existing access-control semantics and connect a real owned-account GET executor | Real loopback requests; authenticated captures; tamper/control tests. No proprietary source or vendor integration |
| Authenticated stateful testing (Burp/ZAP and API research) | HAR/role matrices and planning were present; they did not replay owned accounts | Native bounded replay inside `authenticated_session_model`; existing HTTP/store/report control plane | Six requests per explicit case, cookie isolation, scope/policy checks, original reporting. Read-only BOLA subset |
| Isolation (agent/container design lessons) | Offline native guards and an adapter allowlist, no general OS network boundary | Inherited Linux seccomp network syscall denial; keep the allowlist | Python/Go child execution, threads, raw syscall and io_uring refusal. No OS namespace/packet-capture claim |
| Evidence lifecycle and redaction | Consistent snapshots and redaction existed; snapshot privacy depended heavily on prior writers | Re-sanitize supported text and SQLite backup cells before hashing; preserve live evidence | Canary checks, SQLite integrity, every snapshot file mutation checked. Opaque binary writer closure remains open |
| Context/RAG memory (PentAGI/PentestGPT/Vulnhuntr research) | Portable retrieval, source excerpts and advisory output validation already existed | Repair run-artifact root/symlink boundaries instead of adding another index/service | External/linked files excluded; malicious content stays untrusted/sanitized. No real-model quality improvement claim |
| Labeled evaluation (BountyBench/OWASP benchmark principles) | Small prior taint/proof fixture sets and missing-prediction accounting existed | Add actual local HTTP API cases and expose unresolved-only classes/recall bounds | Eight labeled synthetic runtime cases. Repeated scenarios are disclosed; no novel-project recall claim |
| Fine-tuning/QLoRA/security model claims | No permissioned production training corpus or model benchmark | Preserve optional advisory inference; do not train on scanner guesses | No training or new weights. Model selection needs an actual hardware/task benchmark |
| More scanner wrappers, mobile/firmware/Web3 runtime, multi-model agents | Many native/import/optional adapter paths already existed | Retain and defer expansion | No untested dependency bundle or new standalone wrapper presented as integrated functionality |

Commercial/self-published results in supplied research are not inherited as TBHM
accuracy figures. An accepted report, a CVE, a reproducible fixture and a product
claim are different evidence categories. No new live bounty success is asserted.

## Primary documentation checked for this change

- Linux `seccomp(2)` describes filter installation, no-new-privileges, thread
  synchronization, architecture hazards and inheritance across process execution:
  https://man7.org/linux/man-pages/man2/seccomp.2.html
- Linux `PR_SET_NO_NEW_PRIVS` documents the irreversible inherited privilege flag:
  https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html
- OWASP API1:2023 describes object-level authorization and its consequences:
  https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP REST assessment guidance describes cross-account object swaps, expected
  denials and separate function-level authorization testing:
  https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html

These sources guide the implementation; the shipped tests establish the narrower
local behavior. They do not establish universal containment or scanner accuracy.

## LLM engineering and hardware decision

The existing model remains advisory: no model-driven finding suppression,
confirmation, CWE/CVSS authority, tool execution or automatic scope expansion.
Run learning is retrieval memory, not gradient training. Scanner hypotheses are
untrusted evidence rather than labeled ground truth.

For the supplied 16 GiB RAM / 8 GiB VRAM workstation, account for Windows, Kali,
planned OSCP/AD VMs, browser/scanner memory and growing snapshots before adding a
model. A quantized small model is an evaluation candidate, not a promised sizing
or throughput result. Avoid assuming an 8B model, training job and multiple lab
VMs fit concurrently. This patch adds no GPU dependency or model download.

Before fine-tuning, obtain licensed/consented sanitized examples, preserve
technical-validity and program-outcome labels separately, deduplicate by project
and root cause, keep held-out projects outside retrieval/training, and compare
deterministic, retrieval-only and model-assisted baselines. No such training
dataset or physical workstation benchmark was supplied for this release.
