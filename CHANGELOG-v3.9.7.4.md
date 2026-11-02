# TBHM v3.9.7.4 — Universal Reverse and Firmware Reliability Update

v3.9.7.4 preserves the complete v3.9.7.3 scanner and adds a safer, deeper
firmware/reverse-engineering plane. The release remains static by default.
External execution and emulation are never inferred from tool availability.

## Regression corrections

- Resolves firmware paths before changing an extractor working directory, so
  relative image paths continue to work.
- Preserves binwalk root-mode compatibility when the installed binwalk exposes
  `--run-as`, without invoking sudo or opening an interactive prompt.
- Validates extractor return codes and filesystem structure before accepting an
  extracted rootfs; a failed `unsquashfs` attempt now continues to `sasquatch`.
- Confines firmware symlinks to the extracted root. Absolute firmware links are
  interpreted inside the firmware filesystem and host-path escapes are rejected.
- Uses tri-state hardening results. Missing or invalid `readelf` output is
  reported as unknown instead of “all mitigations missing.”
- Separates private keys, public keys, certificates, and unknown PEM files.
- Removes shell comments and requires an executable-looking statement before a
  service is described as a startup candidate.
- Ignores interpreter shebangs when looking for web/CGI command-execution sinks.
- Adds dedicated duplicate-UID0, SGID and world-writable evidence.
- Makes firmware and extracted-rootfs scans true local-only workflows; no fake
  web target is required.

## Firmware identification and extraction

- Bounded container scanning beyond the first 4 KiB for SquashFS, JFFS2, UBI,
  CramFS, TRX, uImage, Android boot images, FDT and vendor markers.
- Validated extraction chain:
  1. unblob with structured report;
  2. binwalk recursive extraction;
  3. offset carving plus unsquashfs;
  4. sasquatch fallback.
- Structured extraction provenance with commands, return codes, validation and
  failure details.
- ELF class, architecture, endianness, type and qemu-user recommendation.

## Rootfs intelligence

- Confined account and shadow review, including empty fields, root hashes,
  interactive UID0 accounts and duplicate UID0 identities.
- Private-key, public-key and certificate classification.
- Init/service statement inventory with referenced-vs-started separation.
- SUID, SGID and world-writable inventory.
- Web/CGI inventory and bounded static command-sink leads.
- Package database parsing for dpkg, opkg and apk.
- CycloneDX-compatible firmware component/SBOM output without claiming CVE
  applicability from version strings alone.
- Static firmware update-chain inventory that distinguishes flash/write actions
  from local signature/checksum-verification markers.
- Ranked ELF priority list for deeper Ghidra/radare2/angr analysis.
- Static attack-surface map and content-derived bounded artifact graph.

## External firmware adapters

### EMBA

- `--emba` explicitly starts an installed EMBA scan against `--firmware`.
- Default behavior selects the static profile.
- `--emba-emulation` additionally requires `--confirm-isolated-execution`.
- `--emba-results` imports an existing report without starting EMBA.
- EMBA CVE references and security topics remain leads until exact component,
  reachability and runtime impact are independently verified.

### RouterSploit

- `--routersploit-catalog` statically parses a local RouterSploit module tree,
  records module categories, metadata, CVE references and file hashes.
- `--routersploit-results` imports operator-reviewed output as unconfirmed leads.
- TBHM never imports or executes RouterSploit Python modules and never launches
  exploit, credential, scanner, generic-attack or payload modules.

### Additional evidence sources

- Generic evidence import recognizes FirmAE, FIRMADYNE, Firmware Analysis
  Toolkit, FACT, QEMU, unblob, Binwalk, Ghidra, PANDA and avatar-family exports.
- Tool catalog entries were added or corrected for unblob, EMBA, RouterSploit,
  FACT, FirmAE, FIRMADYNE, Firmware Analysis Toolkit, Qiling and avatar².

## Doctor and installer

- Main `--doctor` now checks firmware extractors, qemu-user variants, EMBA,
  RouterSploit source readiness and both current/historical tool catalogs.
- Optional reverse installation adds archive/decompression helpers and installs
  unblob through apt or an isolated Python environment when available.
- EMBA and RouterSploit remain operator-managed because their environments and
  risk boundaries require explicit analyst control.

## New evidence files

- `FIRMWARE_EXTRACTION_PROVENANCE.json`
- `FIRMWARE_ROOTFS_INDEX.json`
- `FIRMWARE_ARTIFACT_GRAPH.json`
- `FIRMWARE_ATTACK_SURFACE.json`
- `FIRMWARE_COMPONENT_INVENTORY.json`
- `FIRMWARE_SBOM.cdx.json`
- `FIRMWARE_UPDATE_CHAIN.json`
- `FIRMWARE_BINARY_PRIORITIES.json`
- `FIRMWARE_TOOL_READINESS.json`
- `FIRMWARE_TOOLING_INDEX.json`
- `EMBA_IMPORT_SUMMARY.json`
- `ROUTERSPLOIT_CATALOG.json`
- `ROUTERSPLOIT_RESULTS_IMPORT.json`

## Confirmation boundary

An import, dangerous API, old component, public exploit module, CVE string,
startup reference, missing compiler mitigation or crash is not automatically a
confirmed vulnerability. Static and imported records remain observations,
leads or supported paths until the complete authorized source-to-sink and
runtime evidence supports confirmation.
