# TBHM v3.9.7.4 Final Reverse-Engineering Upgrade Review

## Final verdict

`TBHM-v3.9.7.4-universal-reverse` is a validated additive upgrade over
v3.9.7.3. The final ZIP preserves every historical source/data capability,
repairs all confirmed firmware regressions from the earlier candidate, adds a
safer firmware-analysis layer, and introduces explicit third-party adapter
boundaries.

## Release identity

- Release: `3.9.7.4-universal-reverse`
- Archive: `TBHM-v3.9.7.4-universal-reverse.zip`
- Archive size: `1,791,918 bytes`
- Archive SHA-256: `d38ccf2867e3b3ee530957f162368cfc205243d1cc6534fba19bb1ed71506b71`
- Manifest SHA-256: `eb2dce378239e30aa02f335877f4a02068acf07b270a9786bfcc961090df7e4b`
- Manifest-listed files: 407
- Clean release files including the manifest: 408

## Backward compatibility

- Historical CLI options: 319/319 retained
- Current CLI options: 332
- Historical phases: 129/129 retained
- Current phases: 130
- Historical source/data files removed: 0
- Modified historical files: 34
- New release files: 13

The update intentionally omits generated Python bytecode caches. Those are not
capabilities or release source files.

## Confirmed regressions corrected

1. Relative firmware paths are resolved before changing the extraction working
   directory.
2. Binwalk root compatibility is retained when the installed version supports
   the acknowledgement option.
3. Extractor return codes and rootfs structure are validated before success.
4. `sasquatch` can run after a failed `unsquashfs` attempt.
5. Firmware-controlled symlinks cannot read files outside the extracted root.
6. Public certificates are separated from private keys and SSH public keys.
7. Comment-only service references are not reported as boot-started services.
8. Failed hardening tooling produces `unknown`, not invented missing controls.
9. Firmware images, extracted root filesystems and binaries run locally without
   a fabricated network target.
10. Version, doctor, reports, installer, catalogs and manifest now identify
    v3.9.7.4 consistently.

## Reverse-engineering additions

### Firmware core

- bounded firmware/container recognition beyond header-only matching;
- extraction provenance and validated fallback chain;
- safe rootfs traversal;
- ELF inventory, architecture and QEMU recommendation;
- accounts, duplicate UID 0, password-hash and empty-field review;
- private key, certificate and public-key separation;
- service/startup semantics;
- SUID, SGID and world-writable evidence;
- web/CGI command-execution leads without auto-confirmation;
- package/component inventory and CycloneDX-compatible SBOM;
- static update-chain verification/write evidence;
- attack-surface candidates and ranked binaries for deeper analysis.

### External adapters

- EMBA static execution is explicit and report import is supported.
- EMBA emulation requires a second isolated-execution confirmation gate.
- RouterSploit is static-catalog and result-import only. TBHM never imports or
  launches its exploit, credential, scanner, payload or generic modules.
- FirmAE, FIRMADYNE, Firmware Analysis Toolkit, FACT, QEMU and similar evidence
  can be normalized from operator-provided result directories.
- Unblob is included as the preferred recursive extraction adapter where
  installed, with bounded fallbacks.

## Validation result

The final exact ZIP was extracted into a new directory and revalidated:

- ZIP integrity and path-safety checks: PASS
- 407/407 manifest hashes and executable declarations: PASS
- Python compilation: PASS
- shell syntax: PASS
- CLI help and doctor identity: PASS
- JSON/YAML parsing: PASS
- all 15 integration scripts: PASS
- 149 named regression tests: PASS

## Important remaining work

This release does not claim to complete the entire universal roadmap. Major
remaining engineering work includes:

- universal normalized p-code/IL/decompiler IR;
- context-sensitive interprocedural source-to-sink analysis;
- a TBHM-owned disposable-VM sandbox and static/dynamic address mapping;
- symbolic/concolic path solving and benign input synthesis;
- fuzz harness generation, corpus management and crash minimization;
- function-level version/patch intelligence and campaign-scale reuse;
- dedicated UEFI, kernel/driver, protocol, mobile and hardware-evidence packs.

## External-tool validation limitation

The optional large third-party environments were not installed and executed
end-to-end in this build container. Their command construction, result parsing,
failure isolation and approval gates were tested with fixtures/mocks. Actual
EMBA/FirmAE/FIRMADYNE operation still depends on a correctly prepared isolated
analyst environment. RouterSploit module execution is intentionally absent.
