# TBHM v3.9.7.5 Reverse-Engineering Capability Status

## Capability matrix

| Capability | Status in v3.9.7.5 | Evidence/output |
|---|---|---|
| Universal normalized reverse IR | Implemented for Ghidra, R2/Rizin, angr and generic imports | `REVERSE_IR_INDEX.json`, normalized per-artifact IR |
| Ghidra decompiler/high P-code export | Implemented exporter; requires a separately installed Ghidra runtime | decompiled C, high P-code, functions, blocks, refs, types/variables where recovered |
| Interprocedural native taint | Implemented as bounded fixed-point analysis | `REVERSE_TAINT_INDEX.json`, function summaries and explainable flows |
| JavaScript → Java/Kotlin → JNI → native correlation | Implemented as static cross-language correlation | `REVERSE_CROSS_LANGUAGE_INDEX.json` |
| TBHM disposable container sandbox | Implemented and explicitly gated | `REVERSE_SANDBOX_INDEX.json`, command/policy/result provenance |
| TBHM disposable QEMU overlay lifecycle | Implemented base-image/overlay/serial lifecycle | QEMU command, overlay path and captured output |
| Dynamic event to function mapping | Implemented for normalized addresses and ASLR rebasing | `REVERSE_DYNAMIC_MAPPING.json` |
| Symbolic/concolic input generation | Implemented through the bounded angr helper; external angr runtime required | symbolic JSON and generated test input |
| Fuzz harness generation | Implemented as reviewable libFuzzer-style proposals | harness source, dictionary and manifest |
| Crash reproduction and minimization | Implemented only through the locked-down container runner | deduplicated crashes and minimized reproducer evidence |
| Function-level binary comparison | Implemented over normalized IR | changed/matched/unmatched function records |
| Campaign artifact deduplication | Implemented with a SHA-256/SQLite content-addressed store | campaign database and reuse summaries |
| UEFI analysis | Static managed workflow; deeper parsing depends on installed UEFI tools | family inventory and tool outputs |
| Kernel/driver analysis | Static PE/ELF/kext metadata and optional installed-tool adapters | driver inventory and observations |
| Mobile analysis | Static APK/AAB/IPA/DEX inventory and optional JADX/apkanalyzer/aapt | mobile family records and framework hints |
| Protocol analysis | PCAP/PCAPNG headers plus optional bounded tshark export | protocol inventory and packet summary |
| Hardware evidence | Managed schemas and static metadata for UART/JTAG/SWD/CAN/USB/memory traces | hardware evidence inventory |
| EMBA mode | Static/SBOM host mode; emulation/full sandbox-image gated | `EMBA_RUN.json`, `EMBA_IMPORT_SUMMARY.json` |
| Packaging verification | Implemented for trees and ZIPs | package verification JSON and manifest checks |
| Complete JS usefulness analysis | Implemented for all discovered candidates up to explicit hard bounds | `JS_USEFULNESS_INDEX.json`, CSV, recovered-source evidence |

## Important precision boundaries

### Taint analysis

The engine is interprocedural and uses fixed-point function summaries, but it is
bounded and conservative. It does not claim complete path sensitivity, perfect
pointer-alias recovery, full field sensitivity, or guaranteed resolution of
indirect calls. These limitations are written into the result itself.

### Cross-language analysis

The WebView/JNI layer correlates static bridge names, Java/Kotlin methods, native
declarations, JNI names and normalized native functions. Reflection, generated
bindings, encrypted bundles, dynamic registration and heavily obfuscated code can
remain unresolved. Runtime instrumentation can be imported and mapped to improve
confidence.

### Symbolic/concolic analysis

TBHM builds bounded angr jobs and accepts explicit reachability targets. State,
solver, input-size and timeout limits prevent unlimited path exploration. A
concrete generated input is a test case, not proof of deployed exploitability.

### Sandboxing

No arbitrary artifact is launched by default. Container and QEMU execution
require explicit options and authorization. Container images and VM base images
must already exist locally and are never pulled by TBHM. Network is disabled by
default. The QEMU lifecycle does not yet provide a general guest-agent protocol
for automatically copying arbitrary jobs into every operating system image.

### EMBA

Host execution is restricted to static/SBOM profiles. EMBA emulation/full must go
through an already-present locked-down sandbox image. Some upstream emulation
features may require privileges incompatible with the strict policy; TBHM fails
closed rather than silently weakening isolation. A reviewed purpose-built image
is therefore required for operational emulation.

### Managed families

UEFI, drivers, mobile, protocol and hardware evidence now have first-class family
records and bounded static adapters. This does not imply universal semantic
recovery for every vendor format, kernel build, obfuscator, protocol or physical
hardware interface.

## External runtime dependencies not bundled

Ghidra, angr, EMBA, Podman/Docker, QEMU, UEFIExtract,
`uefi-firmware-parser`, JADX, Android build tools and tshark remain separately
installed projects. TBHM records readiness and degrades to import/static modes
when they are unavailable.

## Confirmation states

The reverse pipeline preserves the distinction between:

1. observation;
2. lead;
3. static path supported;
4. runtime behavior observed;
5. confirmed;
6. confirmed in deployed context;
7. disproved/not applicable;
8. unknown due to missing evidence.
