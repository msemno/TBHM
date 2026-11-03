# Repository map — where to read the code

This is a guided map of **known release components** rather than a fabricated full tree. The verified source tree on Kali is the authority. Use `docs/review-v4.2.7/FILE_MAP.md` for the original detailed file inventory.

```text
TBHM/
├── README.md                         Portfolio landing page / quickstart
├── docs/portfolio/                   Learning, architecture and publication docs
├── docs/UPGRADE-v4.2.7.md            Operator and installation reference
├── docs/PROOF-v2.md                  Proof verifier contract
├── docs/review-v4.2.7/              Current release engineering review
├── core/                             Core security logic (example: code_patterns.py)
├── knowledge/                        Runtime/analysis contract data
├── manifests/                        Historical versioned manifests
├── tests/                            Regression, transport and evidence tests
├── scripts/                          Release validation and test runner
├── tooling/go_executor/              Optional Go executor source
├── vendor/wheels/                    Pinned offline Python dependencies
├── vendor/licenses/                  Bundled dependency notices
├── install.sh                        Offline-capable installer
├── tbhm                              CLI entrypoint
├── requirements.lock                 Locked dependencies
├── RELEASE_MANIFEST-v4.2.7.json     Package integrity inventory
├── SBOM.cdx.json                     Software bill of materials
├── runtime.json                      Recorded runtime metadata
├── NOTICE.md                         Existing source-rights notice
├── KNOWN_LIMITATIONS.md              Operational gaps and caveats
└── THIRD_PARTY_NOTICES.md            Third-party attribution
```

The tree is **illustrative and selective**: it does not attempt to list the 1,232 manifest entries or guess every source path.

## Read a capability from the inside out

1. Look up the feature in [release history](RELEASE_HISTORY.md) or `docs/review-v4.2.7/CLI_REFERENCE.md`.
2. Use `docs/review-v4.2.7/FILE_MAP.md` to locate implementation and its adapter.
3. Find related regression cases in `tests/` and the relevant integration tests.
4. Check the negative control: what *should not* be reported or allowed?
5. Check `execution_ledger.json` and delivery artifacts for a run: what actually executed?
6. Distinguish implemented integration from test-backed behavior and from real-target evidence.

## Avoid a cosmetic mass refactor

Do not move hundreds of historical source, wheels, test, manifest and provenance files merely to make the tree resemble a smaller portfolio. Paths and executable bits are part of the signed-off *local integrity inventory* (hashes, not signatures). Such renames can break import paths, test fixtures and release packaging. Organize the **documentation and navigation first**. Treat source restructuring as a separate engineering change with regression and migration work.
