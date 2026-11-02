# TBHM v3.9.7.4 — Firmware analysis: identification, extraction, rootfs audit

Closes the firmware-container gaps confirmed against v3.9.7.4 source (roadmap
§4.10, §46). Everything added is static and read-only: no firmware is executed,
chrooted into, emulated, or flashed by TBHM.

## core/reverse_utils.py (new helpers, dependency-free)
- `container_type()` / `identify()` — recognize firmware and container formats
  (SquashFS, uImage, TRX, JFFS2, UBI, CramFS, XZ, Android boot, FDT) and vendor
  images (TP-Link/D-Link/Netgear/U-Boot). A vendor image is no longer `unknown`.
- `find_offsets()` — locate an embedded filesystem for offset-based carving.
- `is_elf()` / `elf_header_info()` — pure-bytes ELF header parse (class,
  endianness, machine, type) with the matching qemu-user binary, resolving the
  MIPS-vs-mipsel question without assumptions.
- `parse_hardening()` / `hardening_gaps()` — checksec-equivalent (NX, PIE,
  RELRO, canary, stripped, RPATH/RUNPATH, FORTIFY) parsed from readelf text; no
  external checksec dependency.

## phases/firmware_reverse_safe.py (extended; original behavior preserved)
- Container identification finding (was: `unknown`).
- Opt-in extraction (`--firmware-extract`): binwalk `-Me`, then offset-based
  SquashFS carve with `unsquashfs` and a `sasquatch` fallback.
- Static root-filesystem audit: ELF inventory with architecture/endianness and
  dominant-arch/QEMU recommendation; binary hardening per ELF (network-facing
  binaries prioritized); account review (`/etc/passwd`, `/etc/shadow`: root
  shells, empty passwords, duplicate UID 0, shipped root hash); private-key and
  TLS/SSH key material; insecure services at boot (telnetd/tftpd/ftpd/UPnP/SNMP…)
  from init scripts; SUID/SGID/world-writable enumeration; web/CGI command-
  execution leads. Writes `FIRMWARE_ROOTFS_INDEX.json` + summaries.
- New `--firmware-rootfs PATH` to audit an already-extracted tree directly
  (matches the manual extract-then-analyze workflow).

## phases/diagnostics.py, install.sh
- Doctor/installer now surface binwalk, unsquashfs, sasquatch, checksec, and the
  MIPS/ARM `qemu-*-static` variants, with install hints. `INSTALL_REVERSE_TOOLING`
  now also pulls `binwalk`, `squashfs-tools`, and `qemu-user-static`.

## Safety
Extraction parses untrusted filesystem metadata and should run in a disposable
VM. The rootfs audit is read-only. Findings are static leads until confirmed with
controlled runtime evidence imported through `reverse_dynamic_evidence`.

---

The final consolidated release record is `CHANGELOG-v3.9.7.4.md`. It includes
regression corrections, EMBA/RouterSploit adapters, SBOM, update-chain review,
binary prioritization, safety boundaries and validation details.
