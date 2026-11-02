# Reverse Engineering, Exploitability Assessment, and Reporting — v3.9.2

## Design basis

TBHM follows an iterative hybrid methodology: low-cost static triage informs deeper static review; controlled dynamic evidence validates or rejects static hypotheses; correlated evidence is then converted into a finding with explicit confirmation status. The orchestrator uses established platforms instead of attempting to replace Ghidra, IDA Pro, Radare2/Rizin, debuggers, instrumentation frameworks, and sandboxes.

## Quick start

Static triage only:

```bash
./tbhm.py -d binary-review.local -y \
  --binary-path ./sample.bin \
  --phases reverse_triage,exploitability_assessment,report
```

Full installed static backends:

```bash
./tbhm.py -d binary-review.local -y \
  --binary-path ./sample.bin \
  --reverse-tooling --reverse-static \
  --reverse-backends auto \
  --phases reverse_triage,reverse_static_analysis,reverse_correlation,local_llm_triage,exploitability_assessment,report
```

Import controlled dynamic/sandbox evidence:

```bash
./tbhm.py -d binary-review.local -y \
  --binary-path ./sample.bin \
  --reverse-dynamic-results ./sandbox-export \
  --reverse-verification-manifest ./verification.json \
  --reverse-symbolic-results ./symbolic-export \
  --local-llm \
  --phases reverse_triage,reverse_static_analysis,reverse_dynamic_evidence,reverse_symbolic_analysis,reverse_correlation,local_llm_triage,exploitability_assessment,report
```

Bounded angr structural analysis:

```bash
./tbhm.py -d binary-review.local -y \
  --binary-path ./sample.bin \
  --reverse-symbolic \
  --reverse-symbolic-timeout 300 \
  --reverse-symbolic-max-functions 500 \
  --phases reverse_triage,reverse_symbolic_analysis,reverse_correlation,exploitability_assessment,report
```

## Dynamic-evidence verification manifest

Imported debugger/sandbox text is not trusted merely because it contains a crash marker. To confirm controlled runtime proof, supply a JSON manifest that binds the exact evidence SHA-256 to an explicit review decision:

```json
{
  "evidence": [
    {
      "sha256": "64-hex-character digest",
      "controlled": true,
      "reproduced": true,
      "approved": true,
      "verification_method": "clean-snapshot cyclic-pattern reproduction",
      "reviewer": "authorized analyst",
      "scope_reference": "ROE-2026-001",
      "timestamp": "2026-07-17T12:00:00Z"
    }
  ]
}
```

Without a matching entry, even a controlled-crash-looking log remains an unconfirmed lead.

## Confirmation states

### CONFIRMED

Requires an explicit successful verifier or controlled proof and reproducible evidence. For a memory-corruption finding, this may be a repeatable controlled crash with instruction-pointer or equivalent control evidence. For a web/API issue, it may be a successful independent request demonstrating an authorization or integrity boundary violation.

### SUPPORTED

The evidence is strong and non-hedged, but explicit verifier metadata or an independent repeat is incomplete. It remains outside the strict confirmed-only report.

### UNCONFIRMED

Scanner output, imports, decompiled patterns, suspicious strings, LLM observations, and external reports without independent reproduction remain leads.

## Report field contract

Every finding receives:

- summary;
- confirmation and exploitability status;
- proof of concept;
- confirmed reproduction steps or remaining validation steps;
- attack prerequisites;
- possible access path and access outcome;
- evidence and confirmation reasons;
- security impact;
- remediation;
- retest criteria.

The final report always separates confirmed, supported, and unconfirmed records.

## Reverse tools and integration modes

| Tool family | TBHM integration | Execution boundary |
|---|---|---|
| file/readelf/objdump/nm/FLOSS/capa | direct bounded static subprocess | no artifact execution |
| Ghidra | headless analysis + exporter script | static only |
| IDA Pro | licensed batch mode + IDAPython exporter | static only |
| Radare2/Rizin | JSON CLI commands | static only |
| Binary Ninja/Hopper/PeStudio/DIE | import operator export | external/operator-managed |
| GDB/WinDbg/x64dbg/Frida | import logs/JSON | run separately in isolated lab |
| CAPE/Cuckoo/ANY.RUN/Hybrid/Joe/VT | import reports | external sandbox |
| QEMU/Unicorn/DynamoRIO/PIN | import traces | external controlled execution |
| angr | bounded structural CFG/function analysis | no concrete exploit synthesis |
| Triton/Unicorn symbolic results | import JSON/SARIF | no payload synthesis |
| MCP servers | not enabled | future review only; no autonomous tool control |

## Local-model sizing for the user's laptop

For Kali Linux on an ASUS TUF Gaming A16 with 16 GB RAM and an 8 GB RTX 5050, TBHM retains the conservative profile:

- 4B cybersecurity model;
- Q4_K_M quantization;
- 4096-token context;
- one parallel request;
- sequential scanners and model inference;
- GPU preferred, CPU fallback.

Do not run Ghidra, multiple heavy scanners, angr, a browser, and local LLM inference concurrently on 16 GB system RAM. The reverse phases are ordered and bounded to reduce memory pressure.

## Evidence handling

- Hash every input artifact and imported evidence file.
- Preserve the original scanner/debugger/sandbox output.
- Redact secrets before report and LLM processing.
- Record tool, phase, timestamp, source path, and verification method.
- Use clean-snapshot repeatability before confirming runtime behavior.
- Never treat the model's narrative as proof.
