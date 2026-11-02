"""Human approval gate for intrusive operator-layer integrations.

The gate never grants authority itself.  It only validates an operator-supplied
engagement manifest and exposes a narrow yes/no decision to phases.  Missing,
expired or malformed manifests fail closed.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_REQUIRED = {"engagement_id", "authorized_actions", "expires_at", "approved_by"}


def load_manifest(path: str | Path | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"approval manifest not found: {p}")
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        if yaml is None:
            raise ValueError("PyYAML is required for YAML approval manifests")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("approval manifest must be an object")
    missing = sorted(_REQUIRED - set(data))
    if missing:
        raise ValueError("approval manifest missing: " + ", ".join(missing))
    expires = _parse_time(str(data.get("expires_at")))
    if expires <= datetime.now(timezone.utc):
        raise ValueError("approval manifest is expired")
    if not isinstance(data.get("authorized_actions"), list):
        raise ValueError("authorized_actions must be a list")
    data["_expires_at"] = expires.isoformat()
    return data


def _parse_time(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _host(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or value.split("/")[0].split(":")[0]).strip("[]").lower()


def _target_allowed(target: str, allowed_value: str) -> bool:
    target_host = _host(target)
    allowed = str(allowed_value or "").strip().lower()
    if not target_host or not allowed:
        return False
    # CIDRs are exact network authorizations; an IP target must belong to it.
    try:
        network = ipaddress.ip_network(allowed, strict=False)
        return ipaddress.ip_address(target_host) in network
    except ValueError:
        pass
    allowed_host = _host(allowed)
    try:
        return ipaddress.ip_address(target_host) == ipaddress.ip_address(allowed_host)
    except ValueError:
        pass
    # A domain authorization covers that domain and its subdomains only.
    return target_host == allowed_host or target_host.endswith("." + allowed_host)


def approved(manifest: dict, action: str, target: str = "") -> tuple[bool, str]:
    if not manifest:
        return False, "no valid engagement approval manifest"
    actions = {str(x).strip().lower() for x in manifest.get("authorized_actions", [])}
    wanted = str(action).strip().lower()
    if wanted not in actions and "*" not in actions:
        return False, f"action '{action}' is not authorized"
    if target:
        allowed = [str(x).strip() for x in manifest.get("targets", []) if str(x).strip()]
        if allowed and not any(_target_allowed(target, item) for item in allowed):
            return False, f"target '{target}' is not listed in the approval manifest"
    return True, "approved by operator-supplied engagement manifest"


def summary(manifest: dict) -> dict:
    if not manifest:
        return {"valid": False}
    return {
        "valid": True,
        "engagement_id": manifest.get("engagement_id"),
        "approved_by": manifest.get("approved_by"),
        "expires_at": manifest.get("_expires_at") or manifest.get("expires_at"),
        "authorized_actions": manifest.get("authorized_actions", []),
        "targets": manifest.get("targets", []),
        "stop_conditions": manifest.get("stop_conditions", []),
        "cleanup_required": bool(manifest.get("cleanup_required", True)),
    }
