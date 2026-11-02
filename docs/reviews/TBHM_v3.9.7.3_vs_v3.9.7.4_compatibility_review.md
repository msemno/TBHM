# TBHM v3.9.7.3 → v3.9.7.4 Compatibility and Regression Review

## Executive verdict

**Status: NOT READY to publish as v3.9.7.4 yet.**

The proposed v3.9.7.4 archive is substantially additive:

- No v3.9.7.3 file was removed.
- No historical CLI option was removed.
- No top-level function was removed from the modified Python modules.
- All bundled historical/integration test scripts completed successfully.
- The existing firmware hashing, binwalk signature scan, strings extraction, keyword inventory, and reporting behavior remains present.

However, there are **two confirmed cases where v3.9.7.3 can work and v3.9.7.4 can fail**:

1. **Relative firmware paths during extraction**
   - v3.9.7.3 runs binwalk from the caller's current directory.
   - v3.9.7.4 changes `cwd` to the evidence extraction directory but still passes the original relative path.
   - Example generated command: `binwalk -Me fw.bin` with `cwd=<output>/extracted`.
   - `fw.bin` is then resolved inside the extraction directory instead of the original working directory.

2. **Binwalk extraction while TBHM is run as root**
   - v3.9.7.3 explicitly invokes `binwalk -e --run-as=root`.
   - v3.9.7.4 invokes `binwalk -Me` without `--run-as=root`.
   - Binwalk installations that require explicit root acknowledgement may refuse extraction.

The update also has several new defects that do not represent lost v3 behavior, but still block a trustworthy release.

---

## Files reviewed

### Archives

| Archive | SHA-256 | Files | Uncompressed size |
|---|---|---:|---:|
| `TBHM-v3.9.7.3-installer-stability(3).zip` | `c047a8f15a04f295a891dc2f2c7c3d48813409e30f980092a3fea302d6c9f5c7` | 395 | 8,165,553 bytes |
| `TBHM-v3.9.7.4-firmware-analysis.zip` | `7b444163236b2dc55f11f67c84c05d3df40b397a012c27e7878cc5abd58bde09` | 396 | 8,202,489 bytes |

Both ZIPs were checked for absolute paths and `..` traversal entries. No unsafe ZIP member paths were found.

### Roadmap documents

| Document | SHA-256 |
|---|---|
| `TBHM_Universal_Reverse_Engineering_Architecture_and_Roadmap(1).md` | `1c251e1648a0b9b481ef6b22ec92ce0e1a78c5732860a5f98a20c4020d4d85f9` |
| `TBHM_Universal_Reverse_Engineering_Architecture_and_Roadmap (2).md` | `22961dcebe5bb86692d34bca18359613fed1c5dab8eb7437c52d8044f3917bad` |

The second roadmap retains the first roadmap and adds the validated firmware-container assessment, TP-Link case study, doctor coverage gap, and interim operator workflow.

---

## Structural comparison

### File-level result

- Common files: **395**
- Identical common files: **390**
- Modified common files: **5**
- New files in v3.9.7.4: **1**
- Removed files: **0**

### Modified files

| File | Approximate line change | Purpose |
|---|---:|---|
| `core/reverse_utils.py` | +218 / -0 | Firmware/container identification, ELF parsing, hardening parsing |
| `install.sh` | +3 / -1 | Firmware extraction and QEMU packages/reporting |
| `phases/diagnostics.py` | +12 / -0 | Firmware tool readiness entries |
| `phases/firmware_reverse_safe.py` | +493 / -11 | Extraction and rootfs audit |
| `tbhm.py` | +4 / -0 | `--firmware-rootfs` option |

### New file

- `CHANGELOG-v3.9.7.4-firmware.md`

The archive still uses the top-level directory name:

`TBHM-v3.9.7.3-installer-stability`

---

## Backward-compatibility result

### Preserved

- All v3.9.7.3 archive files are present in v3.9.7.4.
- All **319** historical CLI flags are retained.
- v3.9.7.4 adds one flag: `--firmware-rootfs`.
- Existing phases and profiles were not deleted.
- Existing reverse fallback logic remains present.
- Existing firmware hashing, binwalk scan, strings extraction, pattern counting, finding generation, and summary writing remain present.
- File permissions on changed executable files remain intact.

### Test result

- Python compilation of the complete v3.9.7.4 source tree: **PASS**
- All 14 bundled integration/regression scripts: **PASS**
- Historical CLI retention tests: **PASS**
- Historical phase retention tests: **PASS**
- Installer isolation/stability tests: **PASS**
- Reverse fallback tests: **PASS**

This means the broad v3.9.7.3 scanner was not accidentally deleted or replaced.

---

# Confirmed regressions: v3.9.7.3 can do this, v3.9.7.4 may not

## R-01 — Relative firmware path breaks after changing extraction working directory

**Severity:** High  
**File:** `phases/firmware_reverse_safe.py`, around lines 97–109

v3.9.7.3:

```text
binwalk -e --run-as=root fw.bin
cwd: unchanged
```

v3.9.7.4:

```text
binwalk -Me fw.bin
cwd: <TBHM output>/redteam/12_firmware_reverse/extracted
```

The path is checked before the working directory changes, but is not converted to an absolute path before binwalk runs.

### Impact

A command that worked in v3.9.7.3 can fail in v3.9.7.4:

```bash
./tbhm.py ... --firmware firmware.bin --firmware-extract
```

### Required correction

Resolve the path before passing it to any subprocess:

```python
fw = Path(firmware).expanduser().resolve()
```

Also use the resolved path in `_extract()`.

---

## R-02 — Explicit root extraction compatibility was removed

**Severity:** Medium  
**File:** `phases/firmware_reverse_safe.py`, around line 104

v3.9.7.3 uses:

```text
binwalk -e --run-as=root
```

v3.9.7.4 uses:

```text
binwalk -Me
```

### Impact

When TBHM is run as root in an isolated firmware-analysis VM, binwalk versions that enforce root acknowledgement may reject extraction.

### Required correction

Do not silently remove the old behavior. Detect effective UID and add the supported acknowledgement only when needed, or run extraction under a dedicated unprivileged user. Record the exact decision in evidence.

---

# Release-blocking v3.9.7.4 defects

## B-01 — The archive is still internally v3.9.7.3

**Severity:** High

The following remain `3.9.7.3-installer-stability`:

- `tbhm.py::VERSION`
- CLI banner
- `core/reporter.py::VERSION`
- `core/ai_plane/__init__.py::__version__`
- `core/doctor.py` release output
- installer heading and messages
- installer helper release metadata
- OCSF metadata
- reverse phase JSON versions
- report text and SARIF semantic version
- release manifest name and release field
- archive root directory
- README and validation documentation
- bundled tests

Running:

```bash
python3 tbhm.py --doctor
```

still reports:

```json
"release": "3.9.7.3-installer-stability"
```

### Impact

- Reports generated by the proposed v3.9.7.4 identify themselves as v3.9.7.3.
- Evidence provenance is ambiguous.
- Installation can overwrite or mix with a v3.9.7.3 tree.
- Compatibility tests pass partly because they still assert v3.9.7.3.

### Required correction

Perform a synchronized release bump across runtime, reports, doctor, installer, manifests, metadata exports, documentation, tests, and archive root name.

---

## B-02 — Release manifest is stale and invalid for the archive

**Severity:** High

`RELEASE_MANIFEST-v3.9.7.3.json` contains stale size/hash records for all five modified files:

- `core/reverse_utils.py`
- `install.sh`
- `phases/diagnostics.py`
- `phases/firmware_reverse_safe.py`
- `tbhm.py`

It also omits:

- `CHANGELOG-v3.9.7.4-firmware.md`

### Impact

A manifest-based integrity or release verification process will report the update as modified, inconsistent, or tampered.

### Required correction

Create a new `RELEASE_MANIFEST-v3.9.7.4.json` after all changes and tests are final. Do not reuse the v3.9.7.3 manifest.

---

## B-03 — Rootfs audit follows symlinks outside the extracted firmware tree

**Severity:** Critical  
**File:** `phases/firmware_reverse_safe.py`, especially account and init-file reads

A controlled fixture created:

```text
rootfs/etc/passwd -> /temporary/outside-passwd
```

The rootfs audit read the external file and included its user in `accounts.json`.

The risk exists because fixed paths and init files are read with normal `Path.is_file()` / `read_text()` behavior without rejecting symlinks or verifying resolved-path containment.

### Impact

A malicious firmware filesystem can cause TBHM to:

- read analyst-host files;
- copy host-derived content into evidence;
- produce findings based on host data rather than firmware data;
- violate the claimed extracted-rootfs trust boundary.

Absolute firmware symlinks are also interpreted using the host root instead of firmware-root semantics.

### Required correction

Implement a safe rootfs accessor that:

1. rejects unsafe symlinks by default;
2. resolves relative links inside the firmware root only;
3. remaps absolute firmware links to the extracted root;
4. verifies `resolved_path` remains under the canonical root;
5. records skipped unsafe links.

Run extraction and audit inside a disposable, unprivileged sandbox even after this fix.

---

## B-04 — Failed `unsquashfs` can be treated as successful extraction

**Severity:** High  
**File:** `phases/firmware_reverse_safe.py`, around lines 87–93

The return code from `unsquashfs` and `sasquatch` is ignored.

A controlled runner returned failure from `unsquashfs` but created an empty destination directory. v3.9.7.4 immediately returned that empty directory as a rootfs and never attempted the `sasquatch` fallback.

### Impact

- Empty or partial extraction can be reported as a successful rootfs audit.
- The intended vendor-SquashFS fallback may never run.
- A report can incorrectly show zero findings because the wrong or empty tree was audited.

### Required correction

Require:

- `rc == 0`;
- a valid filesystem marker set;
- a plausible minimum file count;
- no extraction escape;
- output created during the current attempt;
- successful validation before returning.

Delete or isolate the destination between extractor attempts.

---

## B-05 — Public certificates are reported as embedded private keys

**Severity:** High  
**File:** `phases/firmware_reverse_safe.py`, around lines 254–284

Every `.pem` file is treated as private key material before its content is examined.

A controlled public CA certificate named `ca.pem` generated the High finding:

`Private key / TLS-SSH key material embedded in firmware`

### Impact

High-severity false positives and incorrect fleet-wide impersonation claims.

### Required correction

Classify content, not extension:

- `BEGIN ... PRIVATE KEY` → private key candidate
- `BEGIN CERTIFICATE` → public certificate inventory
- SSH public-key formats → public key inventory
- unknown `.pem` → observation requiring parsing

Do not emit a High private-key finding based only on `.pem`.

---

## B-06 — Service names in comments are reported as services started at boot

**Severity:** Medium  
**File:** `phases/firmware_reverse_safe.py`, around lines 288–321

The service audit concatenates init files and searches for a service-name word anywhere in the text.

A fixture containing only:

```sh
# telnetd disabled and never started
```

was reported as:

`Insecure service started by firmware init: telnetd`

### Required correction

Strip comments and parse executable statements. Distinguish:

- installed/present;
- referenced;
- enabled;
- started;
- conditional startup;
- disabled/commented.

The current evidence supports “referenced,” not “started.”

---

## B-07 — Hardening tool failures become false “all mitigations missing” findings

**Severity:** Medium  
**Files:** `core/reverse_utils.py`, `phases/firmware_reverse_safe.py`

The five `readelf` return codes are ignored. Empty output is parsed as:

- no NX;
- no PIE;
- no RELRO;
- no canary.

This can turn a corrupt ELF, unsupported input, or tool failure into a High-confidence hardening finding.

### Required correction

Use tri-state values:

- `true`
- `false`
- `unknown`

Only report a missing mitigation when the parser has valid supporting output. Save tool failure separately as an analysis limitation.

Shared libraries should also not receive a generic “no PIE” executable finding.

---

# Important incomplete integrations

## I-01 — `--firmware-rootfs` does not activate the phase in most profiles

The new CLI flag is registered, but it is not included in dynamic phase insertion logic.

Profiles without `firmware_reverse_safe` include:

- `authorized_full`
- `authorized_safe`
- `quick_recon`
- `passive_only`
- `forensic_recheck`

Therefore, supplying `--firmware-rootfs` under those profiles does not guarantee that the new audit runs.

### Required correction

When any of the following is supplied, insert `firmware_reverse_safe` before reporting:

- `--firmware`
- `--firmware-extract`
- `--firmware-rootfs`

---

## I-02 — The main `--doctor` command does not check firmware tools

The scan-phase diagnostics list was extended, but `python3 tbhm.py --doctor` uses `core/doctor.py`, which was not changed.

The main doctor does not surface:

- `binwalk`
- `unsquashfs`
- `sasquatch`
- `checksec`
- `qemu-mipsel-static`
- `qemu-mips-static`
- `qemu-arm-static`

This does not satisfy the roadmap’s doctor requirement.

---

## I-03 — Duplicate UID 0 is detected but not reported

`duplicate_uid0` is populated in `accounts.json`, but no dedicated finding is created.

The generic interactive-root-shell finding does not clearly communicate that multiple account names map to UID 0.

---

## I-04 — SGID and world-writable files are not fully surfaced

The audit collects SGID and world-writable files in `FIRMWARE_ROOTFS_INDEX.json`, but only writes `suid-files.txt`.

Missing evidence outputs:

- `sgid-files.txt`
- `world-writable-files.txt`

No finding or prioritization is generated for dangerous world-writable startup/configuration files.

---

## I-05 — Container recognition scans only the first 4 KiB by default

A generic image with SquashFS magic after byte 4096 remains `unknown`, unless a vendor marker appears near the beginning.

The TP-Link example may work through vendor text, but generic containers with embedded filesystems farther into the image are still missed by `identify()`.

Identification and extraction currently use different scan depths.

---

## I-06 — Extraction validation and provenance remain incomplete

The roadmap requires extraction validation and parent/child provenance. v3.9.7.4 still does not fully record:

- extractor return code in the rootfs index;
- chosen offset and partition map as structured data;
- carved-image hash;
- extracted-tree hash/manifest;
- child artifact hashes;
- extractor/tool version;
- validation status;
- stale-output protection;
- multiple-rootfs selection rationale.

The first shallow directory containing `etc/` or `bin/` is selected, which can choose the wrong partition when multiple filesystems exist.

---

## I-07 — The universal roadmap is not implemented by this update

The update improves firmware identification, extraction fallback, ELF inventory, and several rootfs checks. It does **not** implement the complete roadmap, including:

- universal artifact registry;
- recursive normalized artifact graph;
- semantic attack-surface reconstruction;
- interprocedural taint analysis;
- controlled dynamic execution;
- symbolic input synthesis;
- fuzzing/harness generation;
- firmware SBOM and CVE applicability;
- update-chain/signature/rollback analysis;
- full-system emulation orchestration;
- hardware validation.

The v3.9.7.4 changelog should describe this as an incremental firmware static-analysis update, not closure of the complete reverse-engineering roadmap.

---

# What v3.9.7.4 adds successfully

Subject to the corrections above, the update adds useful capability:

- firmware/container signatures;
- vendor hints;
- embedded SquashFS offset search;
- ELF class, architecture, endianness, and QEMU recommendation;
- rootfs ELF inventory;
- bounded hardening review;
- passwd/shadow inventory;
- key-file inventory;
- init/service references;
- SUID/SGID/world-writable collection;
- web/CGI command-execution leads;
- direct `--firmware-rootfs` input;
- firmware tooling installer/diagnostic visibility in the scan phase.

The design remains static and does not execute or emulate firmware.

---

# Required v3.9.7.4 release gate

Do not publish until all items below pass:

1. Resolve firmware paths before changing subprocess `cwd`.
2. Restore safe root/binwalk compatibility.
3. Validate extractor return codes and outputs; correctly run fallbacks.
4. Confine every rootfs read to the extracted tree.
5. Separate private keys, public keys, and certificates.
6. Parse service startup semantics instead of raw word presence.
7. Treat hardening results as true/false/unknown and check tool return codes.
8. Auto-insert the firmware phase for all firmware input flags.
9. Add firmware tools to the actual `--doctor` path.
10. Emit duplicate-UID0, SGID, and world-writable evidence correctly.
11. Synchronize every version and archive name to v3.9.7.4.
12. Regenerate the release manifest after final changes.
13. Add dedicated v3.9.7.4 tests for all new code and every regression above.
14. Re-run the complete historical suite.

---

# Final answer to the comparison question

**Most v3.9.7.3 functionality is retained.** No old file, phase, public top-level function, or historical CLI flag was removed, and the historical test suite passes.

**But v3.9.7.4 currently loses two practical extraction behaviors from v3.9.7.3:**

- relative firmware paths can break because extraction changes `cwd`;
- root binwalk extraction no longer includes the explicit root acknowledgement.

Because of those regressions, the stale release identity/manifest, unsafe symlink handling, and extraction false-success issue, the uploaded update should be treated as a **development candidate**, not the final v3.9.7.4 release.
