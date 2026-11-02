# TBHM v3.9.7.4 Reverse-Engineering Capability Status

## Implemented and operational in this release

- Dependency-free binary fallback: hashes, entropy, strings, endpoints, secret
  markers and dangerous API indicators.
- Ghidra, IDA, Radare2/Rizin, capa and FLOSS static adapters when installed.
- Bounded angr CFG/function inventory.
- Imported debugger, sandbox, Frida, QEMU and symbolic evidence with provenance.
- Firmware/container identification beyond fixed header-only detection.
- Recursive extraction with unblob/binwalk and SquashFS fallbacks.
- Confined rootfs audit, ELF inventory, hardening, accounts, keys, services,
  permissions, web/CGI, package/SBOM, update-chain and attack-surface evidence.
- Binary prioritization for expensive static/symbolic follow-up.
- EMBA explicit static execution and report import.
- EMBA emulation gate requiring explicit isolated-execution confirmation.
- RouterSploit static module catalog and result import without module execution.
- Generic FirmAE/FIRMADYNE/FAT/FACT/QEMU evidence import.
- Artifact hashes, evidence indexes, confirmation separation and standalone
  reporting.

## Partially implemented

- Artifact graph: firmware/rootfs/files are linked, but a universal campaign
  graph across every platform and project type is not complete.
- Source/sink reasoning: dangerous API and same-file web/CGI leads exist, but
  full context-sensitive interprocedural taint is not complete.
- Dynamic analysis: evidence import and explicitly gated EMBA integration exist,
  but TBHM does not yet own a universal disposable-VM sandbox controller.
- Symbolic analysis: bounded CFG inventory exists; path solving and benign input
  synthesis are not complete.
- Component intelligence: package/SBOM inventory exists; exact CVE applicability,
  backported-patch detection and reachability are not automatically proven.
- Update analysis: static write/verification evidence exists; cryptographic
  signature behavior, rollback and deployed boot-chain enforcement still need
  controlled validation.

## Still roadmap work

- Universal normalized decompiler IR including p-code/IL, variables, types,
  indirect calls and branch predicates.
- Context-sensitive interprocedural taint across native, managed, JavaScript,
  JNI/PInvoke and firmware script boundaries.
- Full-system sandbox orchestration with snapshots, outbound deny, syscall/API
  tracing and static-to-dynamic address mapping.
- Symbolic/concolic reachability, bounded input synthesis and path summaries.
- Fuzz harness generation, corpus management, crash minimization and duplicate
  stack triage.
- Function-level version matching, patch-diff intelligence and product-family
  campaign dashboards.
- Dedicated UEFI, kernel/driver, protocol, mobile and hardware-in-the-loop packs.
- Hardware evidence schemas for UART, JTAG/SWD, logic analyzer, CAN, USB and
  memory/register traces.

## Safety model

- Static only by default.
- No artifact is launched on the analyst host by reverse phases.
- RouterSploit is catalog/import-only.
- Imported tool output never confirms a vulnerability by itself.
- EMBA starts only through `--emba`; its emulation profile additionally requires
  `--confirm-isolated-execution` and a disposable analysis environment.
