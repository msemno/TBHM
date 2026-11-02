# TBHM v3.9.7.5 Validation Record

## Source validation completed

- Complete Python AST parse and bytecode compilation: passed.
- JSON parsing: passed.
- YAML parsing: passed.
- Shell syntax validation with `bash -n`: passed.
- `tbhm.py --help`: passed.
- `tbhm.py --doctor`: release identity correct; zero required failures.
- Local binary reverse dry-run phase selection: passed.
- Local managed-family dry-run phase selection: passed.
- Katana/ParamSpider/ZAP/JS phase-plan dry run: passed.

## Regression suites

All bundled integration scripts pass, including:

- historical compatibility and phase/CLI retention;
- AI-plane and safe-plan boundaries;
- installer isolation and dependency handling;
- v3.9.7.4 firmware extraction/rootfs regressions;
- v3.9.7.5 normalized IR and taint;
- WebView/JNI/native correlation;
- ASLR dynamic mapping;
- harness generation;
- crash deduplication and sandbox minimization;
- function-level diffing;
- campaign artifact deduplication;
- mobile/protocol family handling;
- package manifest/inventory verification;
- complete JS candidate and source-map processing;
- EMBA static/emulation safety gates.

## External-runtime validation boundary

The build environment does not contain every optional third-party runtime. Source
contracts, parsers, fixtures, command construction, evidence normalization,
readiness reporting and failure isolation were tested. A separately installed and
licensed/authorized environment is still required for full operational runs of
Ghidra, angr, EMBA, QEMU, UEFIExtract, JADX/Android tooling and tshark.

EMBA emulation/full is intentionally fail-closed: confirmation without a prepared
sandbox image is refused, and images are never pulled automatically.

## Release-package gate

The final package must additionally pass, from a clean extraction:

1. embedded manifest hash, size, executable-mode and complete-inventory checks;
2. ZIP CRC, member-path, duplicate, symlink and compression-policy checks;
3. complete Python compilation;
4. all bundled integration scripts;
5. comparison against v3.9.7.3 and v3.9.7.4 with no historical phase or CLI removal.

The final external verification report records the archive SHA-256 and clean-ZIP
results after packaging, avoiding circular modification of the package itself.
