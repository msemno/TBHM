"""
Phase: cloud_inventory_safe   (v3.3)   [--cloud-profiles aws,gcp,azure]

Read-only multi-cloud inventory. It runs only LIST/DESCRIBE style commands (never
create/modify/delete) using whatever cloud CLIs are installed and already
authenticated (aws/gcloud/az). If no CLI/creds are present it consumes a provided
inventory JSON (--live-inventory), so it degrades gracefully and stays useful for
the iac_drift phase.

Nothing is provisioned or changed. All commands are read-only enumeration.
"""
from __future__ import annotations

import json
import shutil
import os
from pathlib import Path

# read-only enumeration commands per provider
_AWS_CMDS = [
    ("s3", ["aws", "s3api", "list-buckets", "--output", "json"]),
    ("ec2", ["aws", "ec2", "describe-instances", "--output", "json"]),
    ("iam-users", ["aws", "iam", "list-users", "--output", "json"]),
    ("iam-roles", ["aws", "iam", "list-roles", "--output", "json"]),
    ("lambda", ["aws", "lambda", "list-functions", "--output", "json"]),
]
_GCP_CMDS = [
    ("compute", ["gcloud", "compute", "instances", "list", "--format=json"]),
    ("buckets", ["gcloud", "storage", "buckets", "list", "--format=json"]),
    ("iam", ["gcloud", "projects", "get-iam-policy", "--format=json"]),
]
_AZ_CMDS = [
    ("vm", ["az", "vm", "list", "-o", "json"]),
    ("storage", ["az", "storage", "account", "list", "-o", "json"]),
    ("roles", ["az", "role", "assignment", "list", "-o", "json"]),
]
_PROVIDER_CMDS = {"aws": ("aws", _AWS_CMDS), "gcp": ("gcloud", _GCP_CMDS),
                  "azure": ("az", _AZ_CMDS), "az": ("az", _AZ_CMDS)}


def run(ctx):
    profiles = (getattr(ctx.args, "cloud_profiles", None) or "").strip()
    live = getattr(ctx.args, "live_inventory", None)
    if not profiles and not live:
        return

    out_dir = ctx.output / "cloud_inventory"
    out_dir.mkdir(exist_ok=True)
    inventory = {"resources": []}

    if profiles:
        for prov in [p.strip().lower() for p in profiles.split(",") if p.strip()]:
            cli, cmds = _PROVIDER_CMDS.get(prov, (None, []))
            if not cli or not shutil.which(cli):
                ctx.log("WARN", "cloud_inventory_safe",
                        f"{prov}: CLI '{cli}' not installed — skipping (provide --live-inventory)")
                continue
            for label, cmd in cmds:
                cmd = list(cmd)
                if prov == 'gcp':
                    project = getattr(ctx.args, 'gcp_project', None) or os.environ.get('TBHM_GCP_PROJECT')
                    if not project or not __import__('re').fullmatch(r'[a-z][a-z0-9-]{4,62}', project):
                        ctx.log('WARN', 'cloud_inventory_safe', 'GCP inventory requires an explicit --gcp-project or TBHM_GCP_PROJECT')
                        ledger = getattr(ctx, 'execution_ledger', None)
                        if ledger:
                            ledger.record(kind='dependency', status='blocked', reason='explicit GCP project missing or invalid')
                        break
                    if label == 'iam':
                        cmd.insert(3, project)
                    cmd += ['--project', project, '--quiet']
                rc, out, err = ctx.runner.run(cmd, timeout=120, log_name=f"cloud_{prov}_{label}")
                if rc == 0 and out.strip():
                    (out_dir / f"{prov}_{label}.json").write_text(out)
                    try:
                        data = json.loads(out)
                        inventory["resources"].append({"type": f"{prov}:{label}",
                                                        "raw_count": _count(data)})
                    except Exception:
                        pass
            ctx.log("OK", "cloud_inventory_safe", f"{prov}: read-only enumeration done")

    if live and Path(live).is_file():
        try:
            inventory["provided"] = json.loads(Path(live).read_text())
        except Exception:
            pass

    (out_dir / "cloud_inventory.json").write_text(json.dumps(inventory, indent=2))
    ctx.log("OK", "cloud_inventory_safe",
            f"cloud inventory written ({len(inventory['resources'])} enumerations) "
            f"→ cloud_inventory.json (feed --live-inventory to iac_drift)")


def _count(data):
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in ("Buckets", "Reservations", "Users", "Roles", "Functions", "value"):
            if isinstance(data.get(k), list):
                return len(data[k])
    return 0
