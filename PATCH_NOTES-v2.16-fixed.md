# TBHM v2.16-fixed Patch Notes

Patched from `TBHM-v2.16-Updated.zip` using `TBHM-v2.15.zip` as the regression reference.

## Restored from v2.15 into v2.16

- `probe_webdav` restored to `core/curl_probes.py` and added back to `run_all()`.
- `probe_admin_bypass` restored to test `X-Original-URL` / `X-Rewrite-URL` admin routing bypass.
- `probe_range_overflow` restored as a safe indicator for Apache Range-header DoS pattern.
- `probe_server_status` restored with body validation for `/server-status`, `/server-info`, `/.env`, and `/.git/config`.

## Fixed v2.16 curl probe regressions

- Fixed `probe_method_override`; v2.16 treated a plain `405 Method Not Allowed` as vulnerable. It now only flags when the response references the injected fake `DEBUG` method.
- Strengthened `probe_sensitive_files`; it now uses `GET` with body validation instead of relying on `HEAD` status only.
- Added `/server-info` and stronger confirmation for `/.env`, `/.git/config`, `/actuator/env`, `phpinfo`, and config files.

## Fixed nuclei automation

- `phases/nuclei_extended.py` now resolves official nuclei template root explicitly.
- Fixed fragile `-w workflows/` relative path. It now uses the absolute official `workflows` directory when present and falls back to tags when workflows are missing.
- Added useful logging for failed/no-template sweeps instead of silent failures.
- `phases/vuln_scan.py` now self-heals templates and explicitly passes the discovered template root to nuclei.
- `phases/custom_nuclei.py` now uses the shared runner/logging and reports stderr when no output is created.
- `core/bootstrap.py` now builds bundled TBHM templates automatically if missing/empty and searches multiple nuclei template locations.
- `phases/diagnostics.py` now reports official template root, official template count, and bundled custom-template count.

## Fixed install automation

- Fixed Go tool-name detection for modules ending in `/v2` or `/v3`; installer no longer checks for a fake `v2` command and now correctly handles tools like `dalfox` and `ffuf`.
- Added a guard for the common `httpx` confusion so ProjectDiscovery `httpx` is installed when the existing binary is not usable for TBHM.
- Installer now counts nuclei templates across common locations, not only `~/nuclei-templates`.
- Installer now builds bundled custom templates if the `tbhm` template directory is missing or empty.

## Validation performed

- Python compile check passed for the full project.
- `tbhm.py --help` works.
- `tbhm.py -d example.com -y --dry-run --only-nuclei --no-bootstrap` works.
- Bundled custom nuclei templates rebuilt successfully: 22 YAML templates.
- YAML parse validation passed for all bundled templates.
- ZIP integrity test passed.
