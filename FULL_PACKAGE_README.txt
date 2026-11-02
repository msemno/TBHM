TBHM 4.2.5 FULL SOURCE DISTRIBUTION
Archive root: TBHM-4.2.5
Start: bash install.sh --offline
Run: ./tbhm --help
Current guide: docs/UPGRADE-v4.2.5.md
Release validation: RELEASE_VALIDATION.json

Historical package note (retained):

TBHM v3.9.7.5 FULL PACKAGE
============================

Release: 3.9.7.5-universal-deep-reverse
Archive root: TBHM-v3.9.7.5-FULL

This is the complete source release. It contains the scanner, all historical and
current phases, profiles, templates, payload/wordlist data, reverse-engineering
modules, complete JavaScript intelligence, installer, tests, roadmaps, validation
and compatibility records.

Key documents:
- README.md
- CHANGELOG-v3.9.7.5.md
- VALIDATION-v3.9.7.5.md
- docs/REVERSE_ENGINEERING_STATUS_v3.9.7.5.md
- docs/JS_INTELLIGENCE_v3.9.7.5.md
- docs/PACKAGING_VERIFICATION_v3.9.7.5.md
- docs/compatibility/BACKWARD_COMPATIBILITY_REPORT_v3.9.7.5.md

Integrity:
- RELEASE_MANIFEST-v3.9.7.5.json is the authoritative complete inventory.
- FULL_PACKAGE_SHA256SUMS.txt is supplemental and intentionally excludes itself
  and RELEASE_MANIFEST-v3.9.7.5.json to avoid checksum recursion.
- The external TBHM-v3.9.7.5-FULL.zip.sha256 file verifies the final archive.

Safety:
- Static analysis is the default.
- Runtime actions require explicit authorization and isolation confirmation.
- Container/VM images must already exist locally and are not pulled by TBHM.
- RouterSploit is catalog/import-only.
- EMBA host mode is static/SBOM only; emulation/full is sandbox-image gated.
