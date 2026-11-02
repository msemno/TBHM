# TBHM v3.9.7.4 Backward-Compatibility Report

**Baseline:** `TBHM-v3.9.7.3-installer-stability`  
**Candidate:** `TBHM-v3.9.7.4-universal-reverse`

## Result

v3.9.7.4 is an additive update over v3.9.7.3:

- all 319 historical primary CLI options are present;
- all 129 historical ordered phases are present;
- the update adds 13 CLI options and one phase;
- no historical source, configuration, profile, template, payload, wordlist or
  documentation file is removed;
- historical public symbols and structured catalog identifiers remain covered
  by regression tests;
- all 15 bundled integration scripts pass.

A generated `.pyc` cache from the older extracted tree is intentionally not
shipped. Generated caches are not release capabilities.

## Regressions corrected from the earlier v3.9.7.4 candidate

- relative firmware paths are resolved before extraction changes directory;
- binwalk root compatibility is retained when supported;
- failed or empty extraction cannot be silently accepted as a root filesystem;
- rootfs symlinks cannot escape into the analyst host;
- certificates are not classified as private keys by filename alone;
- comment-only service references are not reported as active startup commands;
- unavailable hardening evidence is represented as `unknown` rather than as a
  missing protection;
- local firmware and binary workflows no longer require a fabricated target;
- runtime, installer, report, doctor and manifest identities are synchronized to
  v3.9.7.4.

## Additions

- safer recursive firmware extraction and provenance;
- rootfs component/SBOM, update-chain, attack-surface and prioritization output;
- explicit EMBA static/import adapter with a separate emulation approval gate;
- RouterSploit static catalog and result-import adapter with no module execution;
- generic external firmware-tool evidence import;
- expanded doctor and tool-catalog coverage;
- dedicated v3.9.7.4 regression suite.
