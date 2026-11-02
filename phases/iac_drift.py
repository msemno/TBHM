"""
Phase: iac_drift   (v3.2)   [--terraform-state PATH --live-inventory PATH]

Read-only Infrastructure-as-Code drift detection. Attackers love "ClickOps" —
resources created by hand in the cloud console that never went through CI/CD and
so escape IaC security review. This phase compares committed Terraform state
against a live cloud inventory and flags:

  * shadow resources  - live but not in IaC (manual/ClickOps),
  * ghost resources    - in IaC but not live (drift/decommissioned),
  * both directions summarised for the report.

It parses a terraform.tfstate JSON and a live inventory JSON. It performs NO
cloud API calls itself (that needs credentials); supply the live inventory from
cloud_recon output or a read-only `aws/gcloud/az ... list` dump. Nothing is
modified.
"""
from __future__ import annotations

import json
from pathlib import Path


def _load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def _tfstate_resources(state):
    """Yield (type, id/name) tuples from a terraform.tfstate."""
    out = set()
    if not isinstance(state, dict):
        return out
    for res in state.get("resources", []):
        rtype = res.get("type", "")
        for inst in res.get("instances", []):
            attrs = inst.get("attributes", {}) or {}
            ident = attrs.get("id") or attrs.get("arn") or attrs.get("name") \
                or attrs.get("bucket") or res.get("name", "")
            if ident:
                out.add((rtype, str(ident)))
    return out


def _live_resources(inv):
    """Accept a flexible live inventory: list of {type,id} or {resources:[...]}."""
    out = set()
    items = inv.get("resources", inv) if isinstance(inv, dict) else inv
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict):
                rtype = it.get("type") or it.get("resource_type") or ""
                ident = it.get("id") or it.get("arn") or it.get("name") or ""
                if ident:
                    out.add((str(rtype), str(ident)))
    return out


def run(ctx):
    tf = getattr(ctx.args, "terraform_state", None)
    live = getattr(ctx.args, "live_inventory", None)
    if not tf and not live:
        return  # silent skip

    out_dir = ctx.output / "iac_drift"
    out_dir.mkdir(exist_ok=True)

    state = _load_json(tf) if tf else None
    inv = _load_json(live) if live else None
    if state is None or inv is None:
        ctx.log("WARN", "iac_drift",
                "need both --terraform-state and --live-inventory (valid JSON) — skipping")
        return

    iac = _tfstate_resources(state)
    real = _live_resources(inv)
    iac_ids = {i for _, i in iac}
    real_ids = {i for _, i in real}

    shadow = sorted([r for r in real if r[1] not in iac_ids])   # live, not in IaC
    ghost = sorted([r for r in iac if r[1] not in real_ids])    # IaC, not live

    result = {"iac_resources": len(iac), "live_resources": len(real),
              "shadow_resources": [{"type": t, "id": i} for t, i in shadow],
              "ghost_resources": [{"type": t, "id": i} for t, i in ghost]}
    (out_dir / "iac_drift.json").write_text(json.dumps(result, indent=2))

    for t, i in shadow[:60]:
        ctx.save_finding({
            "phase": "iac_drift", "severity": "MEDIUM", "confidence": "MEDIUM",
            "title": f"Shadow cloud resource (ClickOps): {t} {i}",
            "target": i, "url": "",
            "description": f"{t} '{i}' exists live but is absent from committed IaC. It bypassed "
                           f"CI/CD security review and may be misconfigured or unmonitored.",
            "evidence": f"live-only :: {t} {i}",
            "impact": "Unreviewed, drift-prone resources are a common source of exposure.",
            "remediation": "Import into IaC or decommission; enforce IaC-only provisioning.",
            "cwe": "CWE-16", "mrs_score": 55,
        })

    ctx.log("OK", "iac_drift",
            f"IaC={len(iac)} live={len(real)} | shadow={len(shadow)} ghost={len(ghost)} "
            f"→ iac_drift.json")
