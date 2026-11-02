# TBHM Universal Reverse-Engineering Platform
## Complete Architecture Gap Analysis, Capability Specification, and Multi-Project Implementation Roadmap

**Target reviewed:** TBHM v3.9.7.3-installer-stability  
**Document type:** Engineering specification and implementation roadmap  
**Scope:** Universal reverse engineering across firmware, native binaries, mobile applications, managed code, drivers, bootloaders, packages, protocols, hardware dumps, and large multi-project research programs  
**Intended use:** Authorized security research, internal assessment, product security, vulnerability validation, malware triage in controlled environments, and repeatable reverse-engineering workflows

---

# 1. Purpose of this document

This document replaces the earlier firmware-focused roadmap.

The earlier document used one router image as the main example. That was too narrow. TBHM is intended to support hundreds of different projects, targets, operating systems, architectures, formats, and analysis goals. The correct design is therefore not a collection of special-case checks for one `.bin` image. It is a **universal reverse-engineering platform** with:

- artifact-aware dispatch;
- recursive extraction and normalization;
- architecture-aware static analysis;
- controlled dynamic execution;
- source-to-sink data-flow analysis;
- symbolic and concolic analysis;
- fuzzing and harness generation;
- version and patch-diff analysis;
- protocol and file-format analysis;
- strong evidence correlation;
- strict confirmation states;
- scalable project and campaign management;
- reproducible reports.

The senior-confirmed findings from previous projects should be treated as **gold regression cases**, not as the boundaries of the design. The system must be capable of discovering the same classes of weaknesses across unrelated products and formats without hardcoding one vendor, model, filesystem, architecture, or endpoint.

---

# 2. Executive assessment

TBHM currently has a useful reverse-engineering **triage and evidence-import layer**, but it is not yet a complete reverse-engineering or vulnerability-discovery platform.

The present implementation provides:

- artifact hashing;
- limited magic recognition;
- printable-string extraction;
- URL, IP, secret-marker, and suspicious-import matching;
- shallow metadata collection through Radare2/Rizin, Ghidra, IDA, `file`, `readelf`, `objdump`, `nm`, FLOSS, and capa when available;
- bounded angr CFG enumeration;
- import of externally generated debugger, sandbox, mobile, and symbolic-analysis output;
- generic finding normalization;
- correlation by artifact identity and phase presence;
- final reporting with confirmation-state separation.

The present implementation does not provide a complete automated path from:

```text
unknown artifact
    -> correct format and family identification
    -> nested extraction and unpacking
    -> semantic component inventory
    -> attack-surface reconstruction
    -> deep decompilation
    -> attacker-input modeling
    -> source-to-sink proof
    -> controlled runtime validation
    -> confirmed vulnerability
```

The most important architectural problem is that the reverse branch is currently **tool-oriented** rather than **artifact- and evidence-oriented**.

For example, the current system asks:

```text
Is Radare2 installed?
Did Ghidra produce functions?
Does the binary contain "system"?
Does an imported log contain "segfault"?
```

A mature reverse-engineering platform must ask:

```text
What kind of artifact is this?
What contains or launches it?
Which trust boundaries feed it?
What inputs can an attacker control?
Which parsers, handlers, state machines, privileges, and sinks process those inputs?
What validation, canonicalization, authorization, cryptography, or memory-safety controls exist?
Can the path be reproduced in a controlled runtime?
What exact evidence proves or disproves the vulnerability?
```

---

# 3. Universal scope

TBHM should support the following artifact families as first-class targets.

## 3.1 Native applications and libraries

- Linux ELF executables and shared objects
- Windows PE/COFF executables and DLLs
- macOS Mach-O applications, frameworks, dylibs, and universal binaries
- static libraries and object files
- Go binaries
- Rust binaries
- C and C++ binaries
- stripped vendor binaries
- statically linked utilities
- command-line applications
- desktop GUI applications
- server daemons
- proprietary agents and services

## 3.2 Firmware and embedded systems

- router firmware
- camera and DVR/NVR firmware
- printers
- industrial and OT devices
- access points
- smart-home devices
- medical-device firmware
- automotive ECU images
- baseband and modem images
- UEFI/BIOS images
- bootloaders
- Linux-based embedded firmware
- RTOS firmware
- bare-metal MCU dumps
- NAND, NOR, SPI flash, EEPROM, and eMMC dumps
- update packages and recovery images
- extracted root filesystems
- device-tree blobs
- kernel modules
- web-management assets
- vendor protocols

## 3.3 Mobile applications

- Android APK
- Android App Bundle
- DEX
- ODEX and VDEX
- ART/OAT
- Android native libraries
- iOS IPA
- iOS Mach-O
- Objective-C and Swift metadata
- Flutter applications
- React Native applications
- Xamarin/.NET MAUI applications
- Cordova and WebView applications
- mobile SDKs
- embedded certificates and configuration

## 3.4 Managed and bytecode platforms

- .NET assemblies
- Java JAR/WAR/EAR
- JVM bytecode
- Kotlin bytecode
- Python bytecode
- Node.js and Electron applications
- JavaScript bundles
- WebAssembly
- Lua bytecode
- PHP bytecode where available
- JVM and CLR native interop components

## 3.5 Kernels, drivers, and privileged components

- Windows kernel drivers
- Linux kernel modules
- macOS kernel extensions and DriverKit components
- device drivers
- hypervisor modules
- filesystem drivers
- filter drivers
- network drivers
- IOCTL and device-control interfaces
- eBPF programs
- privileged system services
- boot components

## 3.6 Installers, packages, and software distribution

- MSI
- MSIX
- NSIS
- Inno Setup
- InstallShield
- DEB
- RPM
- AppImage
- Snap
- Flatpak
- DMG
- PKG
- Docker/OCI images
- VM appliances
- update bundles
- browser extensions
- VSIX and IDE plugins
- package-manager artifacts
- signed and unsigned update packages

## 3.7 Protocols and data formats

- packet captures
- proprietary binary protocols
- serial protocols
- USB protocols
- Bluetooth and BLE
- CAN bus
- Modbus
- DNP3
- OPC UA
- RTSP
- MQTT
- vendor discovery protocols
- custom RPC
- shared-memory IPC
- named pipes
- Unix sockets
- D-Bus
- COM/RPC
- custom file formats
- document parsers
- archive formats
- media codecs
- configuration formats

## 3.8 Hardware-oriented evidence

- UART logs
- JTAG dumps
- SWD dumps
- logic-analyzer traces
- SPI flash captures
- boot logs
- memory dumps
- crash dumps
- core dumps
- minidumps
- kernel dumps
- register traces
- power-analysis exports
- fault-injection evidence

## 3.9 Controlled malware and suspicious-code analysis

- packed binaries
- loaders
- droppers
- persistence modules
- malicious documents
- shellcode
- encrypted configurations
- command-and-control configuration
- process-injection behavior
- anti-debugging and anti-VM behavior

Execution of untrusted artifacts must remain isolated, approval-gated, and disabled by default.

---

# 4. Current source-level baseline

The following observations come from the supplied TBHM v3.9.7.3 source.

## 4.1 Limited artifact recognition

`core/reverse_utils.py` currently recognizes a small list of magic values:

- ELF
- PE
- Mach-O
- ZIP-like containers
- Android DEX
- WebAssembly

It does not have a generalized format registry or recursive type-detection engine.

## 4.2 Non-semantic file selection

`iter_files()` walks files and stops after reaching a count limit. It does not rank files by:

- executability;
- network exposure;
- privilege;
- startup use;
- references from manifests or scripts;
- import risk;
- parser behavior;
- endpoint references;
- update or authentication relevance.

This can consume the analysis budget on unimportant files.

## 4.3 Small fixed sink list

`SUSPICIOUS_IMPORTS` is useful as a starting point, but it is a small cross-platform string list. It does not model:

- full API families;
- architecture-specific wrappers;
- custom vendor wrappers;
- sanitizers;
- source APIs;
- privilege transitions;
- protocol handlers;
- file operations;
- cryptographic misuse;
- IPC boundaries;
- kernel APIs;
- managed-code equivalents.

## 4.4 Strings are treated as evidence without context

String extraction can identify clues, but it does not establish:

- code references;
- handler ownership;
- reachability;
- data flow;
- validation;
- privilege;
- attack preconditions;
- runtime behavior.

## 4.5 Static backends are metadata-heavy

The Radare2/Rizin path exports general information, functions, imports, symbols, strings, sections, and a call graph. The Ghidra exporter is primarily function/call/import metadata. It does not preserve a rich intermediate representation for vulnerability reasoning.

## 4.6 Symbolic analysis is structural

The supplied angr helper runs `CFGFast`, enumerates functions, and records limited mitigation data. It explicitly does not synthesize inputs or prove vulnerable paths.

## 4.7 Dynamic analysis is import-only

`reverse_dynamic_evidence.py` imports externally generated logs and reports. It does not:

- launch a sandbox;
- configure an emulator;
- attach a debugger;
- trace system calls;
- instrument APIs;
- generate runtime test cases;
- map dynamic events back to decompiled functions.

## 4.8 Correlation is shallow

The current correlation layer mostly associates evidence through artifact hashes and phase presence. It does not maintain a universal semantic graph of:

```text
input
 -> parser
 -> state
 -> function
 -> data transformation
 -> validation
 -> sink
 -> runtime event
 -> impact
```

## 4.9 Mobile reverse analysis is adapter-oriented

The mobile branch can run or import several tools, but it does not yet provide one normalized Android/iOS program model that connects:

- manifests;
- exported components;
- Java/Kotlin methods;
- native libraries;
- WebViews;
- deep links;
- IPC;
- secrets;
- runtime instrumentation;
- data flow.

## 4.10 Firmware containers stop at inventory

This was confirmed by running v3.9.7.3 against a real TP-Link 841 v11 image (SquashFS 4.0/LZMA rootfs, MIPS uImage). The firmware path is inventory-only:

- `core/reverse_utils.py::magic_type()` matches eight fixed magic prefixes (ELF, PE, Mach-O ×3, ZIP-like, DEX, WebAssembly). A vendor firmware header matches none of them, so the image is classified `unknown` even when the host `file` command identifies it correctly.
- `phases/firmware_reverse_safe.py` performs SHA-256 hashing, a `binwalk` signature scan, `strings`, and a fixed `PATTERNS` keyword count. It emits one LOW control finding when any keyword is present.
- Extraction is gated behind `--firmware-extract`; without it, `binwalk -e` never runs. Even with it, TBHM shells out to `binwalk` and does not validate, carve by offset, or catalog the result.
- There is no offset-based partition carving, no `unsquashfs`/`sasquatch` fallback, and no post-extraction pass over the rootfs. Because the rootfs is compressed, `strings`, `objdump`, and `nm` on the container yield almost nothing, and `reverse_triage` never sees the ELF binaries inside.

The net effect: on a firmware container the tool produces an extraction-preparation scan, not an analysis. Every capability that depends on reaching the rootfs (accounts, services, web/CGI, component inventory, hardening) is therefore unreached, not merely incomplete. Section 46 records the confirmed gaps and maps each to the roadmap capability that closes it.

---

# 5. Core design principles

## 5.1 Artifact first, tool second

The platform must identify the artifact and required analysis strategy before choosing tools.

Incorrect:

```text
Run every available reverse tool against every file.
```

Correct:

```text
Identify artifact family
 -> identify container relationships
 -> select compatible analyzers
 -> prioritize high-value components
 -> run bounded analysis
 -> normalize evidence
```

## 5.2 Evidence graph, not flat findings

Every observation must become a node or edge in an evidence graph.

Examples of nodes:

- artifact
- embedded artifact
- process
- service
- endpoint
- parameter
- protocol field
- function
- basic block
- string
- import
- source
- sanitizer
- sink
- file
- registry key
- configuration value
- credential
- certificate
- update package
- driver IOCTL
- runtime event
- test case
- finding

Examples of edges:

- contains
- extracts-to
- imports
- calls
- references
- reads
- writes
- listens-on
- receives
- transforms
- validates
- authenticates
- authorizes
- passes-to
- launches
- loads
- flashes
- decrypts
- signs
- verifies
- reproduces
- confirms
- disproves

## 5.3 Separate observation from vulnerability

A dangerous function, old version, weak algorithm, exposed string, or crash marker is not automatically a vulnerability.

Required states:

1. Observation
2. Lead
3. Static path supported
4. Runtime behavior observed
5. Confirmed
6. Confirmed in deployed context
7. Disproved
8. Not applicable
9. Unknown due to insufficient evidence

## 5.4 Controlled execution

No untrusted artifact should execute on the analyst host.

Execution must use:

- disposable VM;
- emulator;
- container with appropriate isolation;
- seccomp;
- namespaces;
- network isolation;
- snapshot or overlay;
- resource quotas;
- timeout;
- audit logging;
- explicit authorization.

## 5.5 Reproducibility

Every result must record:

- artifact hash;
- parent artifact hash;
- extraction chain;
- tool version;
- command line;
- environment;
- analysis profile;
- timestamps;
- output hashes;
- parser version;
- analyst decisions;
- confirmation evidence.

## 5.6 Scale without losing depth

The platform must support both:

- one deep manual project;
- hundreds of projects in a campaign.

This requires caching, deduplication, job scheduling, resumption, shared signature databases, and project-level policy profiles.

---

# 6. Universal end-to-end workflow

```text
1. Engagement and project creation
2. Artifact intake and chain of custody
3. Hashing and deduplication
4. Artifact-family identification
5. Recursive extraction and unpacking
6. Normalized artifact graph creation
7. Semantic inventory
8. Attack-surface reconstruction
9. Prioritization
10. Static analysis
11. Decompilation and intermediate representation
12. Data-flow and control-flow analysis
13. Version, library, and patch comparison
14. Dynamic execution or emulation where authorized
15. Runtime instrumentation
16. Symbolic/concolic analysis
17. Fuzzing and harness generation
18. Vulnerability-specific validation
19. Cross-evidence correlation
20. Analyst review
21. Confirmation classification
22. Reporting
23. Retest and regression storage
```

Each step must be independently resumable.

---

# 7. Project and campaign architecture

The current reverse features are mostly run-oriented. A large research program needs a higher-level model.

## 7.1 Entities

```text
Campaign
  -> Project
      -> Product
          -> Version
              -> Artifact
                  -> Embedded artifact
                  -> Analysis run
                  -> Evidence
                  -> Finding
                  -> Retest
```

## 7.2 Campaign capabilities

- compare hundreds of projects;
- deduplicate identical libraries;
- identify reused vulnerable components;
- identify shared credentials or keys;
- identify common vendor SDK code;
- compare patches across product versions;
- track which findings recur across a product line;
- search all decompiled functions and strings;
- maintain a reusable function-signature database;
- maintain a corpus of confirmed and disproved patterns.

## 7.3 Content-addressed storage

Artifacts and evidence should be stored by SHA-256:

```text
store/sha256/ab/cd/<full-hash>/
```

Benefits:

- no duplicate analysis;
- exact provenance;
- easy version comparison;
- reproducible evidence;
- campaign-scale reuse.

## 7.4 Job scheduler

Required worker classes:

- lightweight triage worker;
- extraction worker;
- decompiler worker;
- dynamic sandbox worker;
- symbolic-analysis worker;
- fuzzing worker;
- GPU-assisted model worker;
- report worker.

Each worker must publish:

- capabilities;
- tool versions;
- supported architectures;
- resource limits;
- health status.

---

# 8. Universal artifact registry

Replace the hardcoded magic list with a plugin-based registry.

## 8.1 Handler contract

Every artifact handler should define:

```python
class ArtifactHandler:
    handler_id: str
    supported_magic: list[bytes]
    supported_extensions: list[str]
    supported_mime_types: list[str]
    confidence_priority: int

    def identify(path, context) -> IdentificationResult: ...
    def extract(path, workspace, context) -> list[ArtifactRecord]: ...
    def inventory(path, context) -> InventoryResult: ...
    def recommend_phases(record, context) -> list[str]: ...
```

## 8.2 Identification inputs

Use multiple signals:

- magic bytes;
- file command;
- MIME;
- extension;
- entropy;
- section layout;
- container metadata;
- architecture headers;
- manifest contents;
- embedded strings;
- signatures;
- external classifiers.

## 8.3 Identification result

```json
{
  "artifact_id": "sha256:...",
  "family": "android_apk",
  "format": "zip",
  "subtype": "apk",
  "architecture": ["arm64-v8a", "armeabi-v7a"],
  "confidence": 0.99,
  "handlers": ["zip", "android_apk"],
  "recommended_phases": [
    "container_extract",
    "android_manifest",
    "dex_analysis",
    "native_library_analysis"
  ]
}
```

## 8.4 Required handlers

At minimum:

- ELF
- PE/COFF
- Mach-O
- archive/ZIP
- APK/AAB
- IPA
- DEX/OAT/VDEX
- JAR/WAR/EAR
- .NET assembly
- WebAssembly
- Python bytecode
- JavaScript/Electron
- firmware generic
- UEFI/BIOS
- U-Boot/uImage/FIT
- SquashFS
- CramFS
- JFFS2
- UBI/UBIFS
- ext filesystems
- Android boot image
- kernel image
- Linux kernel module
- Windows driver
- packet capture
- memory dump
- crash dump
- Docker/OCI image
- MSI and common installers
- document/archive formats
- raw flash dump

---

# 9. Recursive extraction and unpacking framework

## 9.1 Universal extraction interface

```python
class Extractor:
    extractor_id: str
    supported_families: list[str]
    requires_isolation: bool

    def probe(record, context) -> ProbeResult: ...
    def extract(record, workspace, context) -> ExtractionResult: ...
    def validate(result, context) -> ValidationResult: ...
```

## 9.2 Recursive behavior

The engine must:

- extract containers;
- identify extracted children;
- recurse to a configured depth;
- avoid cycles;
- hash every child;
- preserve parent-child offsets;
- stop on duplicate hashes;
- enforce size and count limits;
- detect decompression bombs;
- prevent path traversal;
- prevent symlink escapes;
- record failures and fallbacks.

## 9.3 Extractor families

- 7-Zip
- libarchive
- Unblob
- Binwalk
- firmware-specific carvers
- Sasquatch
- UBIREADER
- Jefferson
- cpio
- tar
- gzip
- xz/lzma
- zstd
- Android unpackers
- MSI tools
- NSIS/Inno extractors
- DMG/PKG tools
- OCI layer extraction
- PyInstaller extractors
- Electron ASAR
- UPX
- common packer unpackers
- custom vendor package plugins

## 9.4 Validation

Extraction success must not be inferred from exit code alone.

Validate:

- output exists;
- output file count is plausible;
- extracted types are recognizable;
- filesystem superblock matches;
- no unsafe paths escaped;
- hashes are recorded;
- decompressed size is within policy;
- parent offsets are preserved.

---

# 10. Semantic inventory layer

Every artifact family needs a semantic inventory.

## 10.1 Native binary inventory

- architecture;
- endianness;
- ABI;
- compiler;
- language hints;
- entry point;
- imports;
- exports;
- sections;
- resources;
- symbols;
- debug data;
- signatures;
- mitigations;
- linked libraries;
- strings;
- embedded files;
- TLS callbacks;
- constructors;
- exception handlers;
- privileges and manifest requirements.

## 10.2 Firmware inventory

- vendor and model;
- partition map;
- bootloader;
- kernel;
- root filesystem;
- services;
- startup chain;
- accounts;
- permissions;
- web interface;
- update mechanism;
- certificates;
- hardware interfaces;
- device-tree;
- kernel modules;
- protocol daemons.

## 10.3 Android inventory

- package name;
- SDK levels;
- permissions;
- exported activities, services, receivers, and providers;
- intent filters;
- deep links;
- network security configuration;
- backup flags;
- debuggable flag;
- WebViews;
- native libraries;
- DEX classes;
- signing certificate;
- embedded endpoints and secrets;
- Flutter/React Native bridges.

## 10.4 iOS inventory

- bundle identifiers;
- entitlements;
- URL schemes;
- associated domains;
- ATS settings;
- keychain groups;
- Objective-C classes/selectors;
- Swift metadata;
- native frameworks;
- embedded provisioning profiles;
- jailbreak and anti-debug checks;
- dynamic library loading.

## 10.5 Windows inventory

- PE metadata;
- Authenticode;
- imports/exports;
- services;
- COM registrations;
- scheduled tasks;
- drivers;
- manifests;
- installer actions;
- registry writes;
- named pipes;
- RPC interfaces;
- update mechanisms.

## 10.6 Managed-code inventory

- assemblies;
- packages;
- namespaces;
- methods;
- reflection;
- native interop;
- serialization;
- resources;
- configuration;
- dynamic loading;
- dependency versions.

---

# 11. Attack-surface reconstruction

The tool must reconstruct **interfaces**, not only files.

## 11.1 Interface types

- network ports;
- HTTP endpoints;
- RPC methods;
- IPC endpoints;
- device files;
- IOCTLs;
- exported mobile components;
- deep links;
- file parsers;
- update handlers;
- plugin interfaces;
- command-line options;
- environment variables;
- registry keys;
- configuration files;
- hardware debug interfaces;
- boot consoles;
- USB endpoints;
- Bluetooth characteristics;
- CAN message IDs;
- protocol message types.

## 11.2 Attack-surface record

```json
{
  "interface_id": "http:/diagnostic/ping",
  "artifact_id": "sha256:...",
  "interface_type": "http_endpoint",
  "authentication": "unknown",
  "privilege_context": "root",
  "inputs": [
    {
      "name": "host",
      "type": "string",
      "source": "query"
    }
  ],
  "handler_functions": ["0x4012a0"],
  "risk_tags": ["command_execution", "network_input"]
}
```

## 11.3 Cross-layer linking

Examples:

```text
Android exported activity
 -> Java method
 -> JNI bridge
 -> native function
 -> file-write sink
```

```text
Windows named pipe
 -> service dispatcher
 -> parser
 -> impersonation call
```

```text
Firmware HTTP form
 -> native web handler
 -> NVRAM write
 -> startup script
 -> command execution
```

---

# 12. Binary prioritization engine

Deep analysis is expensive. The platform must rank artifacts and functions.

## 12.1 Artifact ranking signals

- network-facing;
- privileged;
- startup-loaded;
- parses attacker-controlled data;
- implements authentication;
- handles updates;
- handles cryptographic material;
- uses unsafe memory functions;
- contains process-launch APIs;
- contains file-system sinks;
- handles archive extraction;
- driver or kernel context;
- externally reachable;
- unique vendor code;
- stripped and complex;
- changed between versions;
- referenced by confirmed findings;
- high code centrality.

## 12.2 Function ranking signals

- references interface strings;
- called from parser dispatch;
- calls dangerous sinks;
- performs privilege changes;
- copies user input;
- performs cryptography;
- writes to executable or protected locations;
- controls update or boot behavior;
- contains suspicious arithmetic;
- has complex loops;
- has many callers;
- changed in a security patch;
- reachable from exported entry points.

## 12.3 Ranking output

```json
{
  "function": "sub_140012340",
  "score": 94,
  "reasons": [
    "reachable from named-pipe dispatcher",
    "calls CreateProcessW",
    "processes caller-controlled string",
    "service runs as LocalSystem"
  ]
}
```

---

# 13. Deep static-analysis layer

## 13.1 Required normalized intermediate representation

Tool-specific JSON is not enough. TBHM needs a common IR.

Entities:

- function;
- basic block;
- instruction;
- p-code/IL operation;
- call site;
- variable;
- parameter;
- global;
- string;
- memory region;
- branch condition;
- source;
- sink;
- sanitizer;
- type;
- structure;
- vtable;
- class;
- exception edge.

## 13.2 Backend adapters

- Ghidra
- IDA Pro
- Binary Ninja
- Radare2
- Rizin
- angr
- LLVM tooling
- RetDec
- JADX
- apktool/smali
- ILSpy/dnSpy
- CFR/FernFlower
- Hopper where available
- specialized firmware and driver tools

## 13.3 Ghidra exporter requirements

The current exporter must be expanded to preserve:

- decompiled C;
- high P-code;
- parameters;
- local variables;
- stack offsets;
- inferred types;
- string references;
- data references;
- callers;
- callees;
- indirect calls;
- switch tables;
- basic blocks;
- branch conditions;
- global accesses;
- sink call arguments;
- source APIs;
- decompiler warnings;
- function signatures;
- namespaces/classes;
- structure definitions.

## 13.4 Type recovery

Support:

- debug symbols;
- DWARF;
- PDB;
- RTTI;
- Objective-C metadata;
- Swift metadata;
- Go metadata;
- Rust symbols;
- vtable recovery;
- function signature databases;
- library prototypes;
- header packs;
- vendor SDK signatures.

## 13.5 Function identification

- function hashes;
- fuzzy hashes;
- mnemonic hashes;
- control-flow hashes;
- Ghidra Function ID;
- FLIRT-like signatures;
- library matching;
- cross-version matching;
- common compiler runtime detection.

---

# 14. Source, sink, and sanitizer knowledge base

The current small suspicious-import dictionary should become an extensible knowledge system.

## 14.1 Model fields

```json
{
  "api": "system",
  "platform": "posix",
  "role": "sink",
  "vulnerability_classes": ["command_injection"],
  "arguments": {
    "command": 0
  },
  "shell_interpretation": true,
  "severity_modifier": "high"
}
```

## 14.2 Source families

- network input;
- HTTP parameters;
- RPC input;
- IPC messages;
- command-line input;
- environment variables;
- file content;
- untrusted archive entries;
- mobile intents;
- deep links;
- clipboard;
- USB;
- Bluetooth;
- serial;
- CAN;
- device IOCTL input;
- user-mode pointers;
- configuration from writable storage;
- database records;
- cloud responses;
- update packages.

## 14.3 Sink families

- command/process execution;
- code loading;
- dynamic evaluation;
- unsafe memory copy;
- format strings;
- allocation arithmetic;
- file read/write/delete;
- privilege changes;
- authentication decisions;
- cryptographic verification;
- network connections;
- deserialization;
- database queries;
- registry and service configuration;
- kernel memory access;
- flash writes;
- firmware boot transfer;
- native bridges.

## 14.4 Sanitizer families

- strict parsers;
- length checks;
- allowlists;
- canonicalization;
- path boundary checks;
- escaping;
- encoding;
- signature verification;
- certificate validation;
- authentication checks;
- authorization checks;
- range checks;
- integer overflow checks;
- safe wrappers;
- parameterized APIs;
- fixed argument arrays.

## 14.5 Wrapper discovery

The platform must learn custom wrappers.

Example:

```text
vendor_exec_command()
 -> snprintf()
 -> system()
```

Once identified, `vendor_exec_command` becomes a command sink for the project and possibly for all products using the same SDK.

---

# 15. Interprocedural data-flow and taint analysis

This is a critical missing capability.

## 15.1 Requirements

- interprocedural;
- context-sensitive where practical;
- field-sensitive for structures;
- pointer-aware;
- call-graph aware;
- architecture-aware;
- tracks registers and stack arguments;
- models common libraries;
- models custom wrappers;
- records uncertainty;
- supports backward and forward slicing;
- links native and managed layers;
- supports callbacks and indirect calls.

## 15.2 Output

```json
{
  "source": {
    "type": "http_parameter",
    "name": "filename",
    "function": "parse_request"
  },
  "sink": {
    "type": "file_open",
    "api": "fopen",
    "function": "download_handler"
  },
  "path": [
    "parse_request",
    "copy_parameter",
    "build_path",
    "download_handler"
  ],
  "transformations": [
    "url_decode",
    "snprintf"
  ],
  "sanitizers": [],
  "confidence": 0.87
}
```

## 15.3 Path classification

- source and sink in same function;
- source reaches wrapper;
- source reaches sink;
- sanitizer present;
- sanitizer incomplete;
- path depends on unresolved indirect call;
- path dynamically observed;
- path confirmed.

## 15.4 Multi-language flow

Examples:

```text
JavaScript bridge
 -> Java method
 -> JNI
 -> native C++
 -> system()
```

```text
C# named-pipe server
 -> P/Invoke
 -> native DLL
 -> file write
```

```text
HTML endpoint
 -> proprietary template engine
 -> native web daemon
 -> shell script
```

---

# 16. Control-flow and state-machine analysis

Many vulnerabilities are logic or protocol-state problems rather than simple taint paths.

Required features:

- function CFG;
- interprocedural call graph;
- state variable discovery;
- dispatch-table recovery;
- protocol opcode mapping;
- switch-table recovery;
- authentication-state transitions;
- update-state transitions;
- error-path analysis;
- privilege-state transitions;
- initialization ordering;
- race-window identification.

Applications:

- authentication bypass;
- secure-boot bypass;
- protocol command authorization;
- WPS lockout;
- license checks;
- recovery-mode access;
- file-parser state confusion;
- IPC impersonation;
- update rollback;
- business-logic flaws.

---

# 17. Dynamic-analysis platform

## 17.1 Execution modes

- process sandbox;
- container;
- disposable VM;
- user-mode emulation;
- full-system emulation;
- mobile emulator;
- physical lab device;
- hardware-in-the-loop;
- debugger attach;
- instrumentation attach;
- crash-dump import.

## 17.2 Standard evidence

- process tree;
- command line;
- loaded modules;
- system calls;
- API calls;
- network flows;
- DNS;
- file operations;
- registry operations;
- IPC;
- privileges;
- environment;
- crashes;
- memory maps;
- heap events;
- coverage;
- screenshots where relevant;
- request/response captures;
- device logs.

## 17.3 Platform instrumentation

### Linux and embedded

- strace
- ltrace
- GDB
- rr where supported
- eBPF/BCC
- auditd
- QEMU traces
- Frida
- DynamoRIO
- Valgrind
- sanitizers

### Windows

- WinDbg
- x64dbg
- Process Monitor
- ETW
- API Monitor
- Frida
- DynamoRIO
- Application Verifier
- Driver Verifier
- Time Travel Debugging
- kernel debugging

### Android

- ADB
- logcat
- Frida
- Objection
- JADX correlation
- emulator snapshots
- native GDB/lldb
- Binder tracing
- network interception

### iOS

- LLDB
- Frida
- simulator/device logs
- Objective-C runtime tracing
- network tracing
- filesystem and keychain observation

## 17.4 Dynamic-to-static mapping

Every runtime event should map back to:

- module;
- function;
- address;
- decompiled function;
- source/sink model;
- test case;
- request;
- finding.

---

# 18. Emulation and virtualization orchestration

## 18.1 CPU and OS emulation

Support:

- QEMU user mode;
- QEMU system mode;
- Unicorn;
- FirmAE;
- FIRMADYNE;
- EMBA emulation;
- Android Emulator;
- iOS Simulator where legally and technically possible;
- Wine for selected Windows behavior;
- DOS/legacy emulators;
- MCU emulation frameworks where available.

## 18.2 Architecture selection

Automatic mapping:

- MIPS/MIPSEL;
- ARM/Thumb;
- AArch64;
- x86/x64;
- PowerPC;
- RISC-V;
- AVR;
- Xtensa;
- SPARC;
- SuperH.

## 18.3 Emulation fallback strategy

```text
full-system emulator
    -> pre-extracted rootfs
    -> user-mode service emulation
    -> single-function emulation
    -> imported external evidence
```

## 18.4 Environment repair

Embedded programs often require:

- NVRAM stubs;
- device files;
- fake interfaces;
- configuration files;
- shared libraries;
- expected paths;
- kernel modules;
- hardware responses.

The platform should record all shims. A shim must never silently alter the security result.

---

# 19. Symbolic and concolic analysis

The current angr path is CFG inventory. A full capability needs separate analysis modes.

## 19.1 Modes

- reachability;
- path constraints;
- input synthesis;
- branch solving;
- crash reproduction;
- protocol-state exploration;
- file-format exploration;
- function-level symbolic execution;
- concolic replay from runtime traces.

## 19.2 Bounded safety controls

- function allowlist;
- address range;
- timeout;
- memory limit;
- state limit;
- solver query limit;
- loop bounding;
- path prioritization;
- no automatic weaponization.

## 19.3 Use cases

- reach command sink;
- reach file-open sink;
- bypass authentication branch;
- prove integer overflow;
- produce parser-crash input;
- reach dangerous IOCTL path;
- identify required protocol fields;
- validate checksum or signature branches;
- generate a minimal non-destructive test case.

## 19.4 Function summaries

Cache summaries for common libraries and reused functions to scale across projects.

---

# 20. Fuzzing and harness generation

## 20.1 Fuzzing families

- coverage-guided fuzzing;
- grammar-based fuzzing;
- mutation fuzzing;
- protocol fuzzing;
- file-format fuzzing;
- API fuzzing;
- kernel-driver fuzzing;
- mobile IPC fuzzing;
- hardware-protocol fuzzing.

## 20.2 Engines

- AFL++
- libFuzzer
- honggfuzz
- WinAFL
- Syzkaller
- boofuzz
- Peach-compatible workflows
- Jazzer
- SharpFuzz
- libprotobuf-mutator
- custom QEMU/unicorn harnesses

## 20.3 Harness generation

The tool should identify parser entry points and generate proposed harnesses:

- input buffer;
- input length;
- initialization;
- required globals;
- cleanup;
- environment stubs;
- corpus seeds;
- dictionary tokens.

Generated harnesses remain proposals until reviewed.

## 20.4 Crash triage

- deduplicate by stack hash;
- minimize input;
- reproduce;
- map to function;
- classify memory corruption;
- identify mitigations;
- record exploitability indicators;
- separate crash from security impact.

---

# 21. Differential and version-analysis engine

This is essential for hundreds of projects.

## 21.1 Comparison modes

- old version vs new version;
- vulnerable vs patched;
- vendor build vs upstream;
- debug vs release;
- product A vs product B;
- firmware family comparison;
- library reuse across vendors;
- current tool version vs historical tool version.

## 21.2 Function matching

- exact hashes;
- fuzzy hashes;
- CFG similarity;
- mnemonic similarity;
- decompiler similarity;
- string-reference similarity;
- import-call pattern;
- function signature;
- BinDiff/Diaphora/Ghidra Version Tracking imports.

## 21.3 Security diff

Identify:

- new validation;
- removed validation;
- changed authentication;
- added bounds checks;
- changed signature verification;
- changed key material;
- newly reachable code;
- removed privileges;
- vulnerable function copied into another product.

## 21.4 Patch intelligence

A known security patch should become a reusable detector:

```text
vulnerable pattern
patched pattern
required preconditions
affected architectures
confidence
```

---

# 22. Deobfuscation, unpacking, and anti-analysis

## 22.1 Detection

- high entropy;
- packed sections;
- self-modifying code;
- import resolution at runtime;
- API hashing;
- control-flow flattening;
- opaque predicates;
- string encryption;
- virtualization;
- anti-debugging;
- anti-VM;
- timing checks;
- jailbreak/root detection;
- certificate pinning;
- loader stubs.

## 22.2 Unpacking workflow

```text
detect packer
 -> select unpacker
 -> controlled execution
 -> dump memory image
 -> rebuild imports
 -> identify original entry point
 -> re-run static analysis
```

## 22.3 Deobfuscation

- constant folding;
- dead-code removal;
- string decryption;
- API hash resolution;
- control-flow normalization;
- Java/Android deobfuscation;
- .NET deobfuscation;
- JavaScript unpacking;
- Flutter symbol recovery where possible.

All transformations must preserve provenance.

---

# 23. Cryptography and secrets analysis

## 23.1 Cryptographic inventory

- algorithms;
- modes;
- key sizes;
- IV/nonce handling;
- random-number generation;
- certificate validation;
- signature verification;
- key derivation;
- password hashing;
- key storage;
- hardcoded keys;
- custom crypto;
- obfuscation mistaken for encryption.

## 23.2 Weakness detectors

- ECB;
- static IV;
- nonce reuse;
- weak RNG;
- hardcoded symmetric key;
- embedded private key;
- disabled certificate verification;
- hostname-verification bypass;
- weak password KDF;
- reversible credential storage;
- unauthenticated encryption;
- checksum used as signature;
- insecure key derivation;
- fixed salt;
- shared fleet credential.

## 23.3 Credential assessment

Support:

- `/etc/shadow`;
- Windows credential artifacts in authorized offline evidence;
- mobile secure-storage artifacts;
- application databases;
- configuration files;
- custom hash schemes.

Optional offline password testing must be:

- explicit;
- authorized;
- bounded;
- local;
- non-networked;
- independently verified by recomputation;
- reported separately from live authentication.

---

# 24. Vulnerability-analysis engines

The following should be independent reusable detectors, not firmware-specific scripts.

## 24.1 Command injection

Sources:

- HTTP;
- RPC;
- IPC;
- file content;
- mobile intents;
- configuration;
- protocol fields;
- command line.

Sinks:

- shell execution;
- process launch through a shell;
- script interpreters;
- vendor wrappers.

Required proof:

- attacker input reaches command construction;
- shell interpretation exists;
- validation is absent or bypassable;
- runtime evidence where necessary.

## 24.2 Path traversal and arbitrary file access

Detect:

- user-controlled path fragments;
- archive extraction paths;
- upload destinations;
- download handlers;
- backup/restore names;
- log viewers;
- plugin paths;
- symbolic-link issues;
- canonicalization failures;
- root-boundary failures.

Distinguish:

- read;
- write;
- delete;
- rename;
- overwrite;
- executable placement.

## 24.3 Memory corruption

Detect and validate:

- stack overflow;
- heap overflow;
- out-of-bounds read/write;
- use-after-free;
- double free;
- integer overflow;
- signedness bugs;
- truncation;
- format strings;
- uninitialized memory;
- null dereference;
- race-driven lifetime bugs;
- type confusion.

Evidence should combine:

- decompiler path;
- length relationships;
- allocation size;
- copy size;
- crash;
- sanitizer report;
- instruction-pointer or controlled-write indicators.

## 24.4 Authentication and access control

- hardcoded credentials;
- universal credentials;
- hidden accounts;
- authentication bypass;
- default passwords;
- insecure recovery;
- fail-open logic;
- client-side-only checks;
- role confusion;
- insecure token validation;
- missing authorization on IPC/RPC;
- privileged endpoint exposure.

## 24.5 Update and supply-chain security

- unsigned update;
- signature not verified;
- signature checked after write;
- rollback;
- model/version bypass;
- insecure transport;
- mutable update metadata;
- plugin/update DLL hijacking;
- installer custom-action abuse;
- insecure package verification;
- boot-chain gap.

## 24.6 Deserialization and object loading

- Java serialization;
- .NET BinaryFormatter and equivalents;
- pickle;
- YAML unsafe loading;
- PHP object serialization;
- custom object decoders;
- native plugin loading;
- dynamic class loading.

## 24.7 SQL and query injection in compiled or managed applications

- string-built queries;
- ORM raw query paths;
- embedded databases;
- local privileged services;
- mobile content-provider queries.

## 24.8 Cryptographic misuse

Use the crypto inventory and data flow to prove:

- attacker influence;
- key reuse;
- missing verification;
- weak storage;
- protocol impact.

## 24.9 Race conditions and TOCTOU

- check then use;
- temporary files;
- update replacement;
- symlink races;
- privilege changes;
- concurrent state transitions;
- lock omissions.

## 24.10 IPC and RPC vulnerabilities

- unauthenticated named pipes;
- permissive socket permissions;
- unsafe D-Bus methods;
- COM/RPC exposure;
- insecure Binder interfaces;
- weak message validation;
- confused deputy;
- impersonation errors.

## 24.11 Driver and kernel vulnerabilities

- IOCTL inventory;
- user-pointer validation;
- buffer size validation;
- access-control flags;
- privileged device permissions;
- arbitrary read/write primitives;
- race conditions;
- object lifetime;
- MDL mapping;
- copy-to/from-user logic;
- kernel callback registration;
- insecure firmware loading.

## 24.12 Mobile-specific vulnerabilities

- exported components;
- intent redirection;
- deep-link abuse;
- insecure WebView bridges;
- JavaScript interfaces;
- insecure local storage;
- backup exposure;
- certificate pinning weaknesses;
- native library issues;
- keychain misuse;
- custom URL scheme hijacking;
- insecure inter-app communication;
- biometric fallback logic.

## 24.13 File-parser vulnerabilities

- length-field mismatch;
- integer overflow;
- nested recursion;
- decompression bombs;
- malformed metadata;
- unchecked offsets;
- parser differential;
- archive traversal;
- codec bugs.

## 24.14 Protocol vulnerabilities

- missing authentication;
- command authorization;
- state confusion;
- replay;
- downgrade;
- length validation;
- malformed packet handling;
- amplification;
- information disclosure;
- unsafe command dispatch.

## 24.15 Privilege and persistence weaknesses

- writable service binary;
- DLL search-order hijacking;
- insecure PATH;
- launch agent/service abuse;
- scheduled-task modification;
- startup-script writes;
- plugin path abuse;
- boot environment modification;
- kernel module loading.

---

# 25. Platform-specific analysis packs

Universal core logic should be extended through platform packs.

## 25.1 Linux/ELF pack

- ELF parsing;
- glibc/uClibc/musl recognition;
- systemd/init;
- capabilities;
- SUID/SGID;
- namespaces;
- seccomp;
- dynamic linker;
- RPATH;
- shell and command wrappers;
- core dumps;
- package metadata.

## 25.2 Windows/PE pack

- PE parsing;
- services;
- registry;
- Authenticode;
- COM/RPC;
- named pipes;
- ETW;
- drivers and IOCTLs;
- UAC manifests;
- installers;
- DLL search paths;
- PDB support.

## 25.3 macOS/iOS pack

- Mach-O;
- code signing;
- entitlements;
- Objective-C;
- Swift;
- XPC;
- launchd;
- sandbox profiles;
- Keychain;
- URL schemes;
- frameworks and dylibs.

## 25.4 Android pack

- manifest;
- DEX;
- native libraries;
- Binder;
- intents;
- providers;
- WebViews;
- network security config;
- signing;
- emulator instrumentation.

## 25.5 Firmware/embedded pack

- vendor containers;
- filesystem extraction;
- rootfs;
- bootloader;
- kernel;
- services;
- web management;
- hardware interfaces;
- update chain;
- emulation;
- vendor protocols.

## 25.6 Managed-code pack

- .NET;
- JVM;
- Python bytecode;
- JavaScript/Electron;
- WebAssembly;
- deserialization;
- reflection;
- dynamic loading;
- dependency inventory.

## 25.7 Driver/kernel pack

- Windows drivers;
- Linux modules;
- IOCTL;
- syscall hooks;
- user-kernel boundaries;
- memory safety;
- privilege boundaries;
- debugger integration.

## 25.8 Protocol pack

- PCAP import;
- field inference;
- message clustering;
- state-machine recovery;
- dissector generation;
- grammar generation;
- replay and mutation in isolated labs.

---

# 26. Hardware and physical reverse-engineering integration

TBHM should not attempt to replace specialized hardware tools, but it should normalize their evidence.

## 26.1 Inputs

- UART logs;
- JTAG/SWD exports;
- flash dumps;
- chip-off images;
- logic-analyzer captures;
- CAN captures;
- USB captures;
- BLE captures;
- boot traces;
- register dumps.

## 26.2 Hardware profile

Record:

- processor;
- flash type;
- memory;
- debug ports;
- pinout;
- voltage;
- boot mode;
- secure-boot state;
- readout protection;
- fuse state;
- device identifiers.

## 26.3 Correlation

```text
physical flash region
 -> firmware partition
 -> extracted binary
 -> decompiled function
 -> runtime service
 -> confirmed vulnerability
```

---

# 27. Evidence and confirmation model

## 27.1 Evidence types

- raw artifact;
- extracted artifact;
- tool output;
- decompiler output;
- pseudocode;
- p-code/IL;
- call graph;
- data-flow path;
- system-call trace;
- API trace;
- request/response;
- packet capture;
- debugger log;
- crash dump;
- memory dump;
- screenshot;
- analyst note;
- senior validation;
- physical-device observation;
- retest evidence.

## 27.2 Confirmation rules

### Observation

Example:

```text
The binary imports system().
```

### Lead

Example:

```text
A network-facing handler and system() exist in the same binary.
```

### Static path supported

Example:

```text
A decompiler path shows request data reaching a command buffer, but runtime reachability is not tested.
```

### Runtime behavior observed

Example:

```text
The handler executes and calls /bin/sh, but attacker control over the final command is incomplete.
```

### Confirmed

Example:

```text
A controlled input reaches the sink and produces an independently verifiable harmless effect.
```

### Confirmed in deployed context

Example:

```text
Network exposure, authentication, privilege, and impact are verified on the intended deployment.
```

### Senior-confirmed external evidence

A senior’s confirmation can be recorded as valid evidence when accompanied by:

- finding identifier;
- artifact hash;
- reproduction method;
- environment;
- evidence file;
- reviewer;
- date;
- scope reference;
- confirmation decision.

The system should import this as a reviewed confirmation record rather than losing it because the original automated run did not reproduce it.

---

# 28. Analyst workbench

A universal platform needs an analyst interface, not only command output.

## 28.1 Work queues

- artifacts needing identification;
- failed extraction;
- high-priority binaries;
- unresolved indirect calls;
- source-to-sink leads;
- crashes needing triage;
- findings awaiting confirmation;
- senior-reviewed evidence;
- retests.

## 28.2 Function view

For each prioritized function:

- decompiled code;
- disassembly;
- P-code/IL;
- callers;
- callees;
- strings;
- data references;
- sources;
- sinks;
- sanitizers;
- dynamic hits;
- version diff;
- analyst annotations.

## 28.3 Finding evidence view

Show the complete chain:

```text
artifact
 -> interface
 -> source
 -> function path
 -> sink
 -> test case
 -> runtime evidence
 -> impact
 -> confirmation
```

---

# 29. AI-assisted analysis boundary

The local AI layer can improve prioritization but must never be the source of confirmation.

## 29.1 Appropriate uses

- summarize decompiled functions;
- propose names;
- explain protocols;
- cluster similar functions;
- suggest candidate sources/sinks;
- propose validation plans;
- compare versions;
- generate analyst checklists;
- identify missing evidence;
- draft reports from verified evidence.

## 29.2 Prohibited conclusions without evidence

The AI must not independently mark as confirmed:

- exploitability;
- authentication bypass;
- arbitrary code execution;
- key recovery;
- path traversal;
- memory control;
- signature bypass;
- live network exposure.

## 29.3 Retrieval corpus

Index:

- tool documentation;
- public specifications;
- architecture manuals;
- API models;
- CWE patterns;
- analyst notes;
- confirmed internal findings;
- disproved patterns;
- vendor SDK signatures;
- prior version diffs.

---

# 30. Tool adapter architecture

## 30.1 Adapter types

- identifier;
- extractor;
- static analyzer;
- decompiler;
- dynamic sandbox;
- debugger;
- symbolic engine;
- fuzzer;
- protocol analyzer;
- hash assessor;
- normalizer;
- verifier;
- reporter.

## 30.2 Adapter contract

```json
{
  "adapter_id": "ghidra_headless",
  "adapter_type": "decompiler",
  "supported_families": ["ELF", "PE", "Mach-O", "raw_binary"],
  "supported_architectures": ["x86", "x86_64", "ARM", "AArch64", "MIPS", "PowerPC"],
  "execution_mode": "static",
  "required_tools": ["analyzeHeadless"],
  "output_schema": "tbhm.reverse.ir.v1",
  "health_test": "fixtures/elf_x64",
  "resource_class": "heavy"
}
```

## 30.3 Capability truth

An adapter is available only if:

- executable exists;
- dependencies exist;
- rules/signatures exist;
- license requirements are satisfied;
- fixture test succeeds;
- output validates against schema;
- supported architecture matches the artifact.

---

# 31. Installer and doctor redesign

The current doctor checks many general requirements, but reverse capabilities require deeper health tests.

## 31.1 Required checks

### Identification

- parse ELF, PE, Mach-O, APK, firmware, and archive fixtures.

### Extraction

- extract ZIP;
- extract SquashFS;
- extract JFFS2;
- extract UBI;
- unpack APK;
- unpack common installer;
- block malicious traversal fixture.

### Ghidra

- run headless import;
- export IR;
- export decompiled code;
- validate schema.

### Radare2/Rizin

- run analysis;
- export JSON;
- verify function and string references.

### Capa

- rules present;
- fixture analysis works;
- supported format reported.

### FLOSS

- supported format test;
- unsupported format reported truthfully.

### angr

- load fixture;
- CFG test;
- bounded reachability test.

### QEMU

- architecture emulator present;
- execute harmless fixture;
- capture trace.

### Mobile

- JADX;
- apktool;
- ADB;
- Frida compatibility;
- emulator availability.

### Windows

- PE parser;
- optional sandbox connector;
- debugger import parser.

### Password assessment

- John/Hashcat modes;
- known test hash verification.

### Fuzzing

- compile fixture;
- execute harness;
- capture coverage;
- triage known crash.

## 31.2 Doctor output

```json
{
  "capability": "reverse.dataflow.command_injection",
  "available": false,
  "reasons": [
    "Ghidra IR exporter is metadata-only",
    "source/sink engine not installed"
  ],
  "partial_capabilities": [
    "sink string detection",
    "call graph export"
  ]
}
```

---

# 32. Normalized schemas

## 32.1 Artifact schema

```json
{
  "artifact_id": "sha256:...",
  "path": "...",
  "family": "ELF",
  "subtype": "shared_object",
  "parent_id": "sha256:...",
  "offset": 1234,
  "architecture": "MIPS32",
  "endianness": "little",
  "size": 100000,
  "provenance": {}
}
```

## 32.2 Function schema

```json
{
  "artifact_id": "sha256:...",
  "function_id": "0x401000",
  "name": "handle_request",
  "callers": [],
  "callees": [],
  "strings": [],
  "sources": [],
  "sinks": [],
  "sanitizers": [],
  "decompiled_ref": "...",
  "dynamic_hits": []
}
```

## 32.3 Test-case schema

```json
{
  "test_id": "TC-001",
  "finding_id": "F-001",
  "environment_id": "vm-snapshot-12",
  "input": {},
  "expected_safe_behavior": "...",
  "observed_behavior": "...",
  "evidence_hashes": [],
  "destructive": false,
  "approved": true
}
```

## 32.4 Confirmation schema

```json
{
  "finding_id": "F-001",
  "status": "confirmed",
  "reviewer": "senior analyst",
  "scope_reference": "ROE-...",
  "artifact_hash": "...",
  "evidence": [],
  "reproduction": [],
  "limitations": []
}
```

---

# 33. Reporting requirements

## 33.1 Report layers

- executive report;
- technical report;
- reverse-engineering appendix;
- evidence manifest;
- project comparison;
- campaign dashboard;
- retest report.

## 33.2 Every vulnerability should include

- title;
- severity;
- CVSS with assumptions;
- CWE;
- affected artifacts and versions;
- interface;
- attack prerequisites;
- source-to-sink path;
- static evidence;
- dynamic evidence;
- confirmation state;
- steps to reproduce without private tooling where possible;
- impact;
- remediation;
- retest criteria;
- evidence hashes;
- limitations.

## 33.3 Exclusions

Do not report as confirmed solely because of:

- dangerous import;
- old version;
- suspicious string;
- scanner finding;
- AI conclusion;
- crash without security impact;
- endpoint name;
- weak mitigation;
- default value without runtime use;
- unverified CVE match.

---

# 34. Scale and performance

## 34.1 Caching

Cache by:

- artifact hash;
- tool version;
- analysis configuration;
- backend;
- architecture;
- signature database version.

## 34.2 Incremental analysis

When only one component changes:

- reuse extraction;
- reuse unchanged decompilation;
- analyze changed functions;
- rerun affected detectors;
- regenerate report delta.

## 34.3 Resource policy

Profiles:

- quick triage;
- standard;
- deep static;
- dynamic;
- symbolic;
- fuzzing;
- full research;
- batch campaign.

## 34.4 Failure isolation

One failed adapter must not terminate the project. Record:

- failure stage;
- command;
- exit code;
- logs;
- fallback;
- untested capabilities.

---

# 35. Security and safety controls

## 35.1 Default behavior

- static only;
- no execution;
- no external network;
- no credential reuse;
- no destructive payloads;
- no firmware flashing;
- no live device changes.

## 35.2 Approval gates

Separate approval for:

- execution;
- network access;
- authentication testing;
- password assessment;
- state-changing requests;
- reboot;
- update installation;
- kernel-driver loading;
- hardware write;
- fuzzing;
- crash generation.

## 35.3 Isolation

- non-root where possible;
- disposable VM;
- snapshots;
- read-only mounts;
- outbound deny;
- resource limits;
- secret redaction;
- evidence encryption;
- audit logs.

---

# 36. Proposed universal phases

```text
project_initialize
artifact_intake
artifact_identification
artifact_deduplication
container_recursive_extract
artifact_graph_build
semantic_inventory
attack_surface_map
artifact_prioritization

native_binary_triage
native_decompile
native_ir_normalize
native_dataflow
native_dynamic
native_symbolic
native_fuzz

firmware_identify
firmware_unpack
firmware_rootfs
firmware_boot_chain
firmware_service_map
firmware_web_map
firmware_protocol_map
firmware_update_chain
firmware_emulation

android_manifest
android_dex
android_native
android_ipc
android_dynamic

ios_metadata
ios_native
ios_ipc
ios_dynamic

dotnet_analysis
jvm_analysis
script_bundle_analysis
wasm_analysis

driver_surface
driver_static
driver_dynamic

protocol_inference
protocol_state_machine
protocol_fuzz

crypto_inventory
credential_assessment
component_inventory
cve_applicability

version_diff
patch_diff
family_correlation

reverse_evidence_correlation
reverse_confirmation
reverse_report
campaign_report
```

---

# 37. Proposed CLI structure

Avoid hundreds of unrelated flat options. Use profiles and namespaces.

## 37.1 Project

```text
--project PATH
--campaign NAME
--product NAME
--product-version VALUE
--artifact PATH
--artifact-list PATH
--resume
```

## 37.2 Analysis profile

```text
--reverse-profile triage
--reverse-profile standard
--reverse-profile deep-static
--reverse-profile dynamic
--reverse-profile fuzz
--reverse-profile full
```

## 37.3 Artifact handling

```text
--extract-recursive
--extract-max-depth N
--extract-max-size-mb N
--handler HANDLER
--rootfs PATH
```

## 37.4 Static analysis

```text
--decompiler auto
--decompiler ghidra
--decompiler ida
--decompiler rizin
--dataflow
--control-flow
--string-xrefs
--type-recovery
--function-signatures
```

## 37.5 Dynamic analysis

```text
--dynamic
--sandbox auto
--emulator auto
--network none
--snapshot NAME
--runtime-timeout N
--runtime-authorized
```

## 37.6 Symbolic and fuzzing

```text
--symbolic
--symbolic-function ADDRESS
--symbolic-goal ADDRESS
--fuzz
--fuzz-target FUNCTION
--fuzz-engine aflpp
--fuzz-budget N
```

## 37.7 Credential analysis

```text
--credential-audit
--offline-hash-test
--wordlist PATH
--rules PATH
--candidate-corpus PATH
--password-budget-seconds N
```

## 37.8 Validation

```text
--validation-plan
--validation-manifest PATH
--import-senior-confirmation PATH
--safe-runtime-tests
```

---

# 38. Universal regression corpus

The test corpus must include positive and negative fixtures.

## 38.1 Native binaries

- ELF x86/x64;
- ARM;
- MIPS;
- PE;
- Mach-O;
- Go;
- Rust;
- stripped and unstripped;
- statically linked;
- packed.

## 38.2 Vulnerability fixtures

- confirmed command injection;
- safe fixed-argument execution;
- confirmed path traversal;
- safe canonicalized path;
- stack overflow;
- integer overflow;
- format string;
- use-after-free;
- insecure deserialization;
- auth bypass;
- weak crypto;
- signed update;
- unsigned update;
- safe and unsafe IOCTL.

## 38.3 Firmware

- SquashFS;
- JFFS2;
- UBIFS;
- UEFI;
- RTOS;
- raw MCU;
- multiple architectures;
- known web-management vulnerability;
- known protocol vulnerability;
- safe negative images.

## 38.4 Mobile

- OWASP MAS crackmes;
- InjuredAndroid;
- DIVA;
- native JNI fixtures;
- iOS crackmes;
- safe negative applications.

## 38.5 Driver and kernel

- HackSys Extreme Vulnerable Driver;
- safe driver fixtures;
- Linux vulnerable modules;
- Syzkaller test cases.

## 38.6 Protocol

- vulnerable parser;
- safe parser;
- state-machine bypass;
- malformed length;
- replay protection;
- authenticated command dispatch.

## 38.7 Senior-confirmed internal corpus

Every senior-confirmed finding should become:

- a sanitized fixture or evidence bundle;
- an expected result;
- a negative-control counterpart;
- a regression test;
- a documented confirmation state.

---

# 39. Acceptance criteria

## 39.1 Identification

- correct family for at least 95% of supported fixtures;
- no silent “unknown” when a supported handler exists;
- conflicting classifiers are reported.

## 39.2 Extraction

- nested artifacts extracted safely;
- traversal and symlink attacks blocked;
- parent-child provenance complete;
- fallback used automatically.

## 39.3 Static analysis

- architecture and ABI correct;
- prioritized functions decompiled;
- strings linked to functions;
- imports and wrappers modeled;
- output schema valid.

## 39.4 Data flow

- positive command-injection fixture detected;
- safe command wrapper not falsely confirmed;
- path traversal positive detected;
- canonicalized negative suppressed;
- evidence path explainable.

## 39.5 Dynamic

- controlled environment created;
- behavior captured;
- events mapped to static functions;
- timeout and rollback work;
- no external traffic unless approved.

## 39.6 Confirmation

- senior confirmation import works;
- automated leads remain leads;
- confirmed report contains reproducible evidence;
- disproved findings remain recorded.

## 39.7 Scale

- resume interrupted campaign;
- deduplicate identical components;
- reuse cached analysis;
- compare product versions;
- produce campaign-level component and vulnerability views.

---

# 40. Implementation roadmap

## Phase 0 — Correct the data model

Deliver:

- project/campaign entities;
- artifact graph;
- evidence graph;
- universal schemas;
- confirmation records;
- content-addressed storage.

This is the foundation. Do not add many more isolated scanners before it exists.

## Phase 1 — Universal identification and extraction

Deliver:

- plugin registry;
- recursive extraction;
- safe unpacking;
- artifact-family dispatch;
- provenance;
- fallback engines.

## Phase 2 — Semantic inventory and prioritization

Deliver:

- per-platform inventories;
- attack-surface map;
- service/interface discovery;
- artifact and function ranking.

## Phase 3 — Deep static IR

Deliver:

- upgraded Ghidra exporter;
- Radare2/Rizin normalization;
- JADX/ILSpy/JVM adapters;
- function, string, call, and data references;
- type recovery.

## Phase 4 — Universal source/sink engine

Deliver:

- knowledge base;
- wrapper discovery;
- interprocedural data flow;
- command injection;
- path traversal;
- file access;
- crypto;
- authorization;
- memory-copy modeling.

## Phase 5 — Dynamic and emulation plane

Deliver:

- sandbox controller;
- QEMU;
- mobile emulator;
- Windows/Linux runtime connectors;
- system/API tracing;
- static-to-dynamic address mapping.

## Phase 6 — Symbolic and fuzzing plane

Deliver:

- bounded reachability;
- input synthesis;
- harness proposals;
- fuzz execution;
- crash triage;
- minimization.

## Phase 7 — Differential and campaign intelligence

Deliver:

- version diff;
- function matching;
- patch detection;
- shared-component analysis;
- product-family dashboards.

## Phase 8 — Specialized packs

Deliver:

- firmware;
- Android/iOS;
- Windows drivers;
- Linux kernel;
- protocols;
- UEFI;
- hardware evidence.

## Phase 9 — Analyst workbench and reporting

Deliver:

- evidence graph UI;
- function workbench;
- confirmation review;
- senior-validation import;
- standalone technical reports;
- campaign reports.

---

# 41. Priority matrix

| Priority | Capability | Reason |
|---|---|---|
| P0 | Artifact/evidence graph | All later capabilities require stable relationships and provenance |
| P0 | Recursive identification and extraction | Prevents analysis of the wrong container layer |
| P0 | Deep normalized IR | Required for defensible reverse findings |
| P0 | Source/sink/sanitizer model | Required for actual vulnerability paths |
| P1 | Semantic inventories | Builds context across many project types |
| P1 | Attack-surface reconstruction | Connects interfaces to code |
| P1 | Dynamic isolation and tracing | Confirms runtime behavior |
| P1 | Senior-confirmation import | Preserves externally validated truth |
| P2 | Symbolic/concolic | Deep path validation |
| P2 | Fuzzing and harness generation | Finds parser and memory bugs |
| P2 | Version/patch diff | High value across product families |
| P2 | Credential and crypto workflows | Common across firmware, apps, and services |
| P3 | Hardware integrations | Important but specialized |
| P3 | Full campaign UI | Needed after core evidence model is stable |

---

# 42. What must not happen

The rebuilt system must not:

- assume every input is firmware;
- assume every firmware uses SquashFS;
- assume every binary is ELF;
- assume every project is network-facing;
- equate an import with a vulnerability;
- equate an old version with an applicable CVE;
- equate a crash with exploitability;
- equate a hash with a recovered password;
- equate a client-side value with live authentication;
- hide failed tools;
- call a capability available only because an executable exists;
- execute artifacts on the host;
- auto-confirm AI conclusions;
- lose senior-confirmed evidence;
- produce thousands of flat low-value findings without context.

---

# 43. Target end state

The final TBHM reverse-engineering platform should behave like this:

```text
The user creates a project and supplies one or hundreds of artifacts.

TBHM identifies each artifact, safely extracts nested content, builds an
artifact graph, and chooses the correct analysis packs.

It inventories interfaces, privileges, components, credentials, protocols,
update paths, and execution relationships.

It prioritizes high-value artifacts and functions, produces rich decompiler
IR, traces attacker-controlled inputs to security-sensitive sinks, and
distinguishes complete and incomplete paths.

Where authorized, it creates a controlled runtime, records behavior, maps
events back to static code, performs bounded symbolic exploration or fuzzing,
and generates reproducible evidence.

It imports senior-confirmed validation as first-class evidence.

It reports only what the evidence supports, preserves leads for analyst review,
and scales the same logic across firmware, desktop software, mobile apps,
drivers, protocols, managed code, and future project types.
```

That is the universal design required for hundreds of different reverse-engineering projects.

---

# 44. Source files reviewed for the current-state assessment

- `core/reverse_utils.py`
- `phases/reverse_triage.py`
- `phases/reverse_static_analysis.py`
- `phases/reverse_dynamic_evidence.py`
- `phases/reverse_symbolic_analysis.py`
- `phases/reverse_correlation.py`
- `phases/reverse_engineering_tooling.py`
- `phases/firmware_reverse_safe.py`
- `core/sbom.py`
- `core/doctor.py`
- `core/tool_catalog.py`
- `install.sh`
- `phases/mobile_scan.py`
- `phases/mobile_reverse_extended.py`
- `scripts/reverse/angr_triage.py`
- `scripts/ghidra/ExportTbhmAnalysis.java`
- `docs/REVERSE_ENGINEERING_AND_REPORTING_v3.9.2.md`

---

# 45. Final engineering directive

Do not implement this roadmap as one enormous phase or one script.

Implement it as:

```text
stable schemas
 + artifact handlers
 + analysis adapters
 + reusable evidence graph
 + platform packs
 + vulnerability detectors
 + controlled validation
 + regression corpus
```

Every new capability must include:

- schema;
- adapter contract;
- health test;
- positive fixture;
- negative fixture;
- timeout;
- failure behavior;
- provenance;
- confirmation rule;
- report mapping.

This approach allows TBHM to grow across hundreds of unrelated projects without becoming a collection of brittle, vendor-specific checks.

---

# 46. Firmware case study — TP-Link 841 v11 (validated against v3.9.7.3)

This section records a concrete validation run used to confirm the current-state assessment against source, not a hypothetical. It grounds sections 4.10, 9, 10.2, and 25.5 in a real artifact.

## 46.1 Artifact under test

```text
File:        sportix9_up_boot.bin  (TP-Link WR841 v11 image)
Size:        4,063,744 bytes
SHA-256:     e047c5aef648761faf52c7967e6f472c80accc5132ec3a982251a0ec128ab66a
Kernel area: offset 0x200,     size 849,707 bytes
Rootfs area: offset 0x100000,  size 2,883,584 bytes
SquashFS:    offset 0x120200,  SquashFS 4.0, LZMA, 602 inodes
uImage:      legacy MIPS Linux uImage header at offset 0x39c0
Rootfs hash: b5c69a5d4ad7c4da92ec8718abc6811a84b0db803c218a18491035dbff7d32d7
```

The important property: this is a firmware container, not an ELF. The correct order is inspect, extract, then analyze the ELF binaries inside the extracted filesystem individually.

## 46.2 Observed behavior of the current tool

Running the firmware and reverse phases on the raw image reproduced exactly what the source predicts:

- `file` identified the TP-Link image; TBHM `magic_type()` reported `unknown`.
- Raw `strings` returned little, because the rootfs is LZMA-compressed.
- `objdump` and `nm` could not process the container.
- No static-backend output was produced without Ghidra/Radare2 installed.
- The only substantive signal was high entropy.
- Symbolic analysis was unsuitable for the raw container.

The first TBHM run is therefore an inventory and extraction-preparation scan. Real findings only appear after the rootfs is extracted and individual ELF binaries (BusyBox, the web server) are handed to the reverse phases.

## 46.3 Confirmed gaps mapped to roadmap capability

Each row was confirmed by reading v3.9.7.3 source. The right-hand column is the section/phase that already specifies the fix, so this is a validation of the roadmap, not new scope.

| Confirmed gap (v3.9.7.3) | Current behavior in source | Closed by |
|---|---|---|
| Firmware format recognition | `magic_type()` returns `unknown`; no vendor-header parser | §4.1, §8 artifact registry; `firmware_identify` |
| Partition carving | No offset-based kernel/rootfs carving | §9 extraction; `firmware_unpack` |
| SquashFS-aware workflow | `binwalk` shelled out; result not validated or cataloged | §9.2–9.4; `firmware_unpack` |
| Vendor SquashFS fallback | No `unsquashfs`/`sasquatch` path anywhere in `phases/` or `core/` | §9.3 extractor families |
| Rootfs recursive analysis | No pass over `/etc`, init scripts, or web roots after extraction | §10.2 firmware inventory; `firmware_rootfs` |
| ELF prioritization | `iter_files()` is count/size-bounded with no ranking | §4.2, §12; `artifact_prioritization` |
| Binary hardening | No `checksec`-style NX/PIE/RELRO/canary check in any phase | §25.1 Linux/ELF pack |
| Accounts and permissions | No `/etc/passwd`, `/etc/shadow`, SUID/SGID, world-writable audit | §24.4; §10.2 |
| Service mapping | No init/service/port reconstruction | `firmware_service_map` |
| Web/CGI source review | Not connected to extracted web roots | §24.1; `firmware_web_map` |
| Component inventory + SBOM | `core/sbom.py` exists but is wired only into `code_scan`/`code_intel`, not firmware | §36 `component_inventory`; §24.5 |
| CVE correlation | No component-version-to-CVE workflow for firmware | §36 `cve_applicability` |
| Update verification | No signature/rollback/update-chain assessment | §24.5; `firmware_update_chain` |
| Full-system emulation | `reverse_dynamic_evidence.py` is import-only; TBHM never executes | §17, §18; `firmware_emulation` |
| QEMU binary execution | QEMU listed as an evidence *source*, not a runner | §17.3, §18.2 |
| Fuzzing/harness | No native harness generation or fuzzing | §20 |
| Hardware validation | No UART/JTAG/SPI/boot validation | §26 |

## 46.4 Doctor coverage gap

`install.sh` installs `qemu-user`, `radare2`, `file`, `binutils`, and `gdb`, and the optional-tool report lists `file readelf objdump nm r2 rizin analyzeHeadless capa floss gdb frida qemu-x86_64`. The firmware workflow depends on tools the current doctor does not check: `binwalk`, `unsquashfs`, `sasquatch`, `checksec`, and the MIPS QEMU variants (`qemu-mips-static`, `qemu-mipsel-static`). Section 31.1 already requires identification, extraction, and QEMU checks; the doctor should enumerate these firmware-specific tools so a missing extractor is surfaced before a scan, not during it.

---

# 47. Interim firmware operator workflow

Until sections 9, 10.2, 18, and the `firmware_*` phases exist, firmware assessment is a manual sequence with TBHM used on the extracted ELF binaries rather than the container. This is the validated order for the case-study image and the reference for the eventual automated pipeline.

```text
TBHM raw firmware scan        (inventory / extraction-prep only)
        v
Carve and extract SquashFS    (binwalk -Me, or dd + unsquashfs/sasquatch)
        v
Manual rootfs review          (accounts, init/services, web/CGI, keys, SUID)
        v
TBHM on selected ELF binaries (BusyBox, web server — not the container)
        v
Ghidra / Radare2 / checksec
        v
EMBA static + SBOM scan
        v
FirmAE or EMBA emulation      (isolated VM)
        v
TBHM scan of the emulated web service
        v
Import QEMU / FirmAE / GDB evidence into TBHM (reverse_dynamic_evidence)
        v
Manual confirmation and final report
```

Operator notes tied to the source:

- Run TBHM on the container only to inventory it. Do not point Ghidra or angr at the compressed image; select the ELF binaries after extraction.
- Extraction processes untrusted filesystem metadata. Carve and extract in a disposable VM, and use root only for the isolated extraction command, never for the whole run.
- When `unsquashfs` rejects a vendor-modified SquashFS, fall back to `sasquatch`.
- Determine architecture and endianness from `readelf -h` before choosing `qemu-mips-static` versus `qemu-mipsel-static`; do not assume.
- Emulate only inside an isolated VM with the emulated service kept off the LAN and the internet.
- Runtime evidence (kernel/service logs, process list, strace, GDB output, PCAPs, crash logs) is imported back through `reverse_dynamic_evidence`; a crash is confirmed only with a controlled instruction-pointer marker and a matching SHA-256-bound verification manifest entry.

For a precise gap review after an extraction-plus-BusyBox/web-server run, the four files that carry the most signal are `elf-inventory.txt`, `startup-services.txt`, `reverse_static_index.json`, and `REPORT_final.md`.
