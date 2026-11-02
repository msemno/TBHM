# TBHM v3.0-redteam-safe Changelog

This v3 package is built from `TBHM-v2_24-redteam-safe` as the base and integrates the practical parts of `tbhm_v2_24_addons` directly into the real TBHM phase model.

## What changed

### New integrated add-on package

Added `tbhm_addons/`:

- `logging_core.py` — structured multi-channel logging.
- `mod_sqli.py` — detection-only SQL injection verifier.
- `mod_net_ad.py` — read-only network + AD attack-surface review.
- `mod_service_primitive.py` — Windows service ACL/path primitive review.
- `adapter.py` — original generic add-on adapter kept for standalone/import compatibility.

### New native TBHM phases

Added these real phase modules under `phases/`:

- `add_sqli`
- `add_net_ad`
- `add_service_primitive`
- `addons_common`

The new phases convert add-on results into native TBHM findings, evidence files, and final reports.

### Phase-order integration

`PHASE_ORDER` now includes:

- `add_service_primitive` after `internal_network_safe`.
- `add_net_ad` after `ad_identity_safe`.
- `add_sqli` after `injections`.

`add_net_ad` and `add_service_primitive` are treated as enterprise red-team phases and are automatically filtered out unless you use `--profile authorized_redteam`, `--redteam`, or explicit `--phases`.

### New CLI flags

```bash
--no-addons
--addon-sqli-target URL
--addon-sqli-max-urls N
--addon-sqli-delay SECONDS
--addon-sqli-time-delay SECONDS
--addon-sqli-sqlmap
--addon-sqli-no-tls-verify
--ad-base-dn DN
--ad-ldaps
--addon-nmap-timing TEMPLATE
--svc-prove-writable
```

### Safety boundaries preserved

- ADD-SQLI is detection-only; it does not dump DB data.
- ADD-NETAD is read-only; it does not request roastable tickets, crack, relay, DCSync, dump credentials, move laterally, or persist.
- ADD-SVCPRIM does not drop executable payloads or restart services. Optional proof writes only a temporary inert `.txt` marker and only when both `--svc-prove-writable` and `--allow-writes` are supplied.

## Main example commands

### Web/API with focused SQLi verifier

```bash
python3 tbhm.py -u https://target.example/path?id=1 \
  --profile authorized_safe -y \
  --phases add_sqli \
  --addon-sqli-target 'https://target.example/path?id=1'
```

### Full authorized red-team with add-ons

```bash
export TBHM_AD_PASSWORD='READ_ONLY_AD_PASSWORD_HERE'
python3 tbhm.py -d company.local \
  --profile authorized_redteam -y --redteam \
  --corp-cidr 10.10.0.0/16 \
  --dc-ip 10.10.10.10 \
  --ad-domain company.local \
  --ad-user readonly@company.local
```

### Run only the deeper AD add-on

```bash
export TBHM_AD_PASSWORD='READ_ONLY_AD_PASSWORD_HERE'
python3 tbhm.py -d company.local \
  --profile authorized_redteam -y --redteam \
  --phases add_net_ad \
  --corp-cidr 10.10.0.0/16 \
  --dc-ip 10.10.10.10 \
  --ad-domain company.local \
  --ad-user readonly@company.local
```

### Run Windows service primitive review locally on a Windows host

```powershell
python tbhm.py -d company.local --profile authorized_redteam -y --redteam --phases add_service_primitive
```

Optional inert proof, only with explicit write approval:

```powershell
python tbhm.py -d company.local --profile authorized_redteam -y --redteam --phases add_service_primitive --allow-writes --svc-prove-writable
```
