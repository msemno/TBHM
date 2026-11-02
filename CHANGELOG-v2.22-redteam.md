# TBHM v2.22-redteam changelog

## Added

- New `authorized_redteam` profile.
- New enterprise red-team CLI flags:
  - `--redteam`
  - `--corp-cidr`, `--corp-cidrs-file`
  - `--dc-ip`, `--dc-ips-file`
  - `--ad-domain`, `--ad-user`, `--ad-password-env`
  - `--wireless-interface`
  - `--firmware`, `--firmware-extract`
  - `--ai-endpoints-file`
- New safe red-team phases:
  - `redteam_governance`
  - `internal_network_safe`
  - `ad_identity_safe`
  - `iot_cctv_safe`
  - `wireless_physical_soc`
  - `firmware_reverse_safe`
  - `ai_redteam_safe`
  - `redteam_final_summary`
- New helper module `core/redteam_utils.py`.
- New docs: `docs/REDTEAM_v2.22.md` and `WHAT_TBHM_v2.22_REDTEAM_TESTS.md`.

## Changed

- Existing default `authorized_safe` / `authorized_full` behavior stays clean: enterprise red-team phases only run when using `--profile authorized_redteam` or `--redteam`.
- Legal/safety banner now explicitly says no credential theft or persistence.
- Diagnostics checks now include LDAP, wireless inventory, and firmware static-review tools.

## Safety boundary

This upgrade adds coverage and evidence tracking for realistic red-team branches, but it does not automate malware, persistence, credential theft, EDR bypass, destructive exploitation, denial-of-service, unsafe RF actions, or real data exfiltration.
