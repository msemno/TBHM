# Install and upgrade TBHM 4.2.5

Preserve the original 4.2.4 folder/archive and the portable AI home. Extract this release into a separate directory.

The bundled runtime targets Linux x86-64, glibc >= 2.27 and Python 3.12. The core is installed from the same hash-locked bundled wheels; no dependency, model weight or training framework has been added. Do not replace Kali's system Python or install into global site-packages.

```bash
cd TBHM-4.2.5
bash install.sh --offline --python /path/to/python3.12
./tbhm --version
./tbhm --help
```

If `python3.12` is already available, omit the `--python` argument. A different interpreter version is refused. Provisioning an absent Python 3.12 interpreter is a separate workstation operation; its installer is not bundled.

Back up the AI home with the old release **before** first opening it in 4.2.5:

```bash
/path/to/TBHM-4.2.4/tbhm --ai-backup
```

Use the same `--ai-home DIR` or `TBHM_AI_HOME` in the new release. Opening the store adds schema version 6 without changing existing table DDL, IDs, lessons, mistakes, documents, runs or audit records. The run database schema is unchanged. `--ai-migrate` also refreshes the legacy source index; scenario-only maintenance needs no model or vector index.

Rollback: stop all TBHM processes, keep a copy of the upgraded AI home, restore the pre-upgrade consistent AI-home backup, and run the preserved 4.2.4 release. Do not replace a live SQLite file while its WAL is open. The regression suite upgrades a real packaged version-5 database, verifies every old table definition and retained rows, and verifies restoration of the pre-upgrade copy.

For the approximately 6 GB Kali guest, keep interactive scanning separate from learning evaluation. The learning queue permits one inference worker per store and checks for at least 256 MiB available RAM, 64 MiB free disk and bounded process count before inference. Queue capacity is 32 per project; retry is explicit and limited to three claims. These are preflight safeguards, not a hard OS memory quota. Existing scanner resource controls remain active.

Scanner-only and retrieval-only use work without an LLM. A local model is contacted only for an explicitly approved `run_job` operation; failures remain recorded and do not modify findings or stop an active scan. Offline learning commands refuse model contact. No GPU access, Windows-host loopback reachability or CUDA passthrough is assumed. An authenticated remote host companion is deferred; remote model endpoints are not enabled by this release.

Validation commands:

```bash
.venv/bin/python scripts/run_tests.py --workers 1
.venv/bin/python scripts/validate_v4_release.py
.venv/bin/python scripts/check_release_v425.py
.venv/bin/python scripts/check_done.py
```

The last command checks the entire future scanner roadmap and is expected to fail for this incremental release. The preceding release-specific gate must pass. The recorded environment is Linux/Python 3.12, not an instrumented VMware Kali guest; real guest model latency/RAM/VRAM remain unverified.
