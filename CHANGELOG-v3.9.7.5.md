# TBHM v3.9.7.5 — Universal Deep Reverse, JavaScript Intelligence, and Verified Packaging

v3.9.7.5 is an additive upgrade over v3.9.7.4 FULL. It retains every historical
phase, CLI option, source path and public top-level Python symbol found in the
v3.9.7.3 and v3.9.7.4 baselines. Static analysis remains the default. Runtime
execution, symbolic input generation, crash reproduction and EMBA emulation are
explicitly gated and do not run on the analyst host by default.

## Normalized reverse-engineering IR

- Adds `core/reverse_ir.py` and the `reverse_ir_analysis` phase.
- Normalizes Ghidra, Radare2/Rizin, IDA/generic and angr evidence into
  `tbhm.reverse-ir/1.0` records.
- The Ghidra exporter now records decompiled C, high P-code, function ranges,
  parameters, locals, callers/callees, basic blocks, strings and data references.
- Adds stable per-function fingerprints for later correlation and diffing.
- Tool-specific failures and missing fields remain explicit; they are not filled
  with invented values.

## Interprocedural taint and cross-language tracing

- Adds a bounded fixed-point native IR taint engine with source, sink and
  sanitizer models.
- Propagates parameter/return summaries across resolved direct calls.
- Models common source APIs that write attacker-controlled bytes through buffer
  arguments, plus LOAD/STORE and conservative pointer-memory propagation.
- Records unresolved indirect calls and field-insensitive aliasing as uncertainty.
- Adds JavaScript/WebView bridge, Java/Kotlin method, JNI declaration and native
  function correlation.
- Cross-language output marks browser-controlled arguments and links native taint
  paths where normalized IR evidence is available.

This is an operational, explainable bounded analysis engine. It is not described
as a mathematically complete alias-, path-, context- and field-sensitive proof
system, and static paths do not automatically confirm exploitability.

## TBHM-owned sandbox and dynamic mapping

- Adds a disposable container runner using Podman or Docker with:
  - `--pull=never`;
  - network disabled by default;
  - read-only root filesystem;
  - all Linux capabilities dropped;
  - `no-new-privileges`;
  - an unprivileged guest UID;
  - CPU, memory, PID and time limits;
  - explicit read-only artifact mounts.
- Adds QEMU lifecycle management using a temporary qcow2 overlay over a read-only
  base image, no networking and serial-only evidence capture.
- Adds static-to-dynamic event mapping, including ASLR module-base rebasing.
- Runtime actions require `--confirm-isolated-execution` and explicit local
  images/commands. Images are never downloaded automatically.

## Symbolic, concolic, fuzzing and crash analysis

- Extends the angr helper with bounded CFG, symbolic and concolic modes.
- Supports find/avoid addresses, stdin or argv input, printable-byte constraints,
  seed files and trace-guided concolic replay.
- Writes concrete benign test inputs only; it does not generate shellcode,
  persistence or weaponized payloads.
- Adds automatic libFuzzer-style harness proposals, seed dictionaries and review
  manifests for ranked parser functions.
- Adds crash-stack normalization, deduplication and delta minimization.
- Optional crash reproduction/minimization runs only inside the locked-down
  container path and preserves the baseline crash signature.

## Binary diff and campaign artifact store

- Adds exact, name-based and fuzzy function matching over normalized IR.
- Reports changed functions, security-relevant token deltas and unmatched code.
- Adds a SQLite content-addressed campaign store keyed by SHA-256.
- Deduplicates identical artifacts across campaigns, projects, products and
  versions and stores provenance/observation links.

## Managed artifact-family analysis

- Adds bounded family detection and static workflows for:
  - UEFI/firmware capsules and firmware volumes;
  - Windows PE drivers, Linux kernel modules and macOS kext bundles;
  - Android APK/AAB, iOS IPA, DEX and mobile framework hints;
  - PCAP/PCAPNG protocol captures;
  - UART, JTAG/SWD, logic-analyzer, CAN, USB, memory and register evidence.
- Optional adapters use installed tools such as UEFIExtract,
  `uefi-firmware-parser`, JADX/apkanalyzer/aapt, tshark, rabin2 and objdump.
- Tool absence produces an explicit readiness limitation instead of fabricated
  analysis.

## Complete JavaScript intelligence

- Katana output, ParamSpider output, ZAP JSON/XML/HAR/SARIF imports, ZAP AJAX
  spider URLs and crawler inventories are merged into one canonical candidate
  set.
- Every unique in-scope JavaScript candidate is analyzed by default and receives a result record: analyzed, inaccessible or explicitly skipped for scope/size/error policy. An optional nonzero `--js-max-files` value can impose an operator-selected count cap.
- Content analysis covers endpoints, parameters, GraphQL operations, auth/cloud
  indicators, WebSockets, feature flags, secret candidates and browser
  source-to-sink paths.
- Source maps are recovered from remote references and inline data URIs.
- Original source files in `sourcesContent` are analyzed and fed back into the
  endpoint/parameter inventories.
- Safety bounds never silently discard work: candidates, maps or recovered
  sources beyond limits receive explicit skipped records.
- Outputs include JSON, CSV, per-file evidence, recovered sources and a usefulness
  classification explaining whether each file contained actionable signals.

## EMBA and external firmware tools

- EMBA static/SBOM modes can run from an explicitly supplied local installation.
- EMBA emulation/full modes no longer run on the analyst host. They require both
  `--confirm-isolated-execution` and an already-present container image supplied
  with `--emba-sandbox-image`.
- RouterSploit remains static catalog/result-import only; exploit, credential,
  scanner and payload modules are never launched by TBHM.
- FirmAE, FIRMADYNE, FAT, FACT, QEMU and related external evidence remain
  provenance-preserving imports unless a separately gated adapter is selected.

## Package verification

- Adds `--verify-package` and `package_verification`.
- Verifies ZIP CRCs, safe member paths, duplicate entries, symlink policy,
  compression ratios and total uncompressed size.
- Verifies embedded release-manifest hashes, sizes, executable modes and complete
  inventory coverage.
- Source-tree verification checks symlinks, manifest completeness and Python
  compilation.

## Compatibility and safety

- No v3.9.7.3 or v3.9.7.4 phase, CLI option, packaged source path or public
  top-level Python symbol was removed in the audited source tree.
- One intentional safety tightening replaces the older confirmation-only EMBA
  host-emulation path: emulation/full now requires a prepared sandbox image.
- Imported findings, CVE strings, crashes and static paths remain observations or
  leads until their preconditions and deployed impact are reproduced.
