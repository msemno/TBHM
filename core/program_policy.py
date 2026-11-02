"""Machine-readable bug-bounty / engagement policy evaluation.

The operator supplies a reviewed policy. TBHM does not scrape changing program
pages at execution time. Explicit exclusions win, unclear scope fails closed,
and method/action/rate restrictions are ceilings rather than permissions TBHM
can grant itself.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

_LIST_FIELDS = {
    "included_assets", "excluded_assets", "eligible_vulnerability_types",
    "ineligible_vulnerability_types", "prohibited_actions", "allowed_http_methods",
}
_VULN_ALIASES = (
    {"idor", "bola", "broken_object_level_authorization", "cwe_639"},
    {"bopla", "mass_assignment", "broken_object_property_level_authorization", "cwe_915"},
    {"bfla", "broken_function_level_authorization", "cwe_285"},
    {"xss", "cross_site_scripting", "cwe_79"},
    {"sqli", "sql_injection", "cwe_89"},
    {"ssrf", "server_side_request_forgery", "cwe_918"},
    {"path_traversal", "directory_traversal", "cwe_22"},
    {"command_injection", "os_command_injection", "cwe_78"},
)


def load(path: str | Path | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"program policy not found: {p}")
    text = p.read_text(encoding="utf-8", errors="ignore")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        if yaml is None:
            raise ValueError("PyYAML is required for YAML program policies")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("program policy must be an object")
    data.setdefault("policy_id", p.stem)
    data.setdefault("included_assets", [])
    data.setdefault("excluded_assets", [])
    data.setdefault("eligible_vulnerability_types", [])
    data.setdefault("ineligible_vulnerability_types", [])
    data.setdefault("prohibited_actions", [])
    data.setdefault("allowed_http_methods", ["GET", "HEAD", "OPTIONS"])
    data.setdefault("max_requests_per_second", 1)
    for key in _LIST_FIELDS:
        if not isinstance(data.get(key), list):
            raise ValueError(f"program policy field {key} must be a list")
    if data.get("allowed_actions") is not None and not isinstance(data.get("allowed_actions"), list):
        raise ValueError("program policy field allowed_actions must be a list")
    try:
        rate = float(data.get("max_requests_per_second"))
    except (TypeError, ValueError):
        raise ValueError("max_requests_per_second must be numeric")
    import math
    if not math.isfinite(rate) or rate < 0 or rate > 100000:
        raise ValueError("max_requests_per_second is outside the allowed range")
    data["max_requests_per_second"] = rate
    data["allowed_http_methods"] = sorted({str(x).upper() for x in data["allowed_http_methods"]})
    return data


def _parsed(value: str):
    raw = str(value or "").strip()
    return urlparse(raw if "://" in raw else "//" + raw)


def _host(value: str) -> str:
    raw = str(value or "").strip()
    try:
        parsed = _parsed(raw)
        return (parsed.hostname or raw.split("/")[0].split(":")[0]).strip("[]").lower()
    except Exception:
        return raw.split("/")[0].split(":")[0].strip("[]").lower()


def _host_matches(value: str, pattern: str) -> bool:
    host = _host(value)
    pat = str(pattern or "").strip().lower()
    if not host or not pat:
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(pat, strict=False)
    except ValueError:
        pass
    p_host = _host(pat)
    if pat.startswith("*."):
        suffix = pat[2:]
        return host.endswith("." + suffix)
    if "*" in pat or "?" in pat:
        return fnmatch.fnmatch(host, pat)
    return host == p_host


def _matches_asset(value: str, rule) -> bool:
    if isinstance(rule, str):
        return _host_matches(value, rule)
    if not isinstance(rule, dict):
        return False
    pattern = str(rule.get("pattern") or rule.get("host") or rule.get("asset") or "")
    if not _host_matches(value, pattern):
        return False
    parsed = _parsed(value)
    schemes = {str(x).lower() for x in (rule.get("schemes") or [])}
    if schemes and str(parsed.scheme or "").lower() not in schemes:
        return False
    ports = {int(x) for x in (rule.get("ports") or []) if str(x).isdigit()}
    if ports:
        try:
            port = parsed.port
        except ValueError:
            return False
        if port is None:
            port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
        if port not in ports:
            return False
    paths = [str(x) for x in (rule.get("paths") or rule.get("path_patterns") or [])]
    if paths and not any(fnmatch.fnmatch(parsed.path or "/", pattern) for pattern in paths):
        return False
    return True


def _rule_label(rule) -> str:
    if isinstance(rule, str):
        return rule
    try:
        return json.dumps(rule, sort_keys=True, default=str)
    except Exception:
        return str(rule)


def evaluate_asset(policy: dict, asset: str) -> dict:
    excluded = [x for x in policy.get("excluded_assets", []) if _matches_asset(asset, x)]
    if excluded:
        return {"decision": "out_of_scope", "reason": f"matched exclusion: {_rule_label(excluded[0])}",
                "policy_id": policy.get("policy_id", "")}
    included = [x for x in policy.get("included_assets", []) if _matches_asset(asset, x)]
    if included:
        return {"decision": "in_scope", "reason": f"matched inclusion: {_rule_label(included[0])}",
                "policy_id": policy.get("policy_id", "")}
    return {"decision": "unclear", "reason": "asset did not match an explicit inclusion",
            "policy_id": policy.get("policy_id", "")}


def _action_match(wanted: str, rule: str) -> bool:
    return fnmatch.fnmatch(wanted, str(rule or "").lower().strip())


def evaluate_action(policy: dict, action: str, *, method: str = "") -> dict:
    wanted = str(action or "").lower().strip()
    prohibited = [str(x).lower().strip() for x in policy.get("prohibited_actions", [])]
    if wanted and any(_action_match(wanted, x) for x in prohibited):
        return {"allowed": False, "reason": f"action prohibited by policy: {wanted}"}
    allowlist = [str(x).lower().strip() for x in (policy.get("allowed_actions") or [])]
    if wanted and allowlist and not any(_action_match(wanted, x) for x in allowlist):
        return {"allowed": False, "reason": f"action not present in policy allowlist: {wanted}"}
    if method:
        allowed = {str(x).upper() for x in policy.get("allowed_http_methods", [])}
        if str(method).upper() not in allowed:
            return {"allowed": False, "reason": f"HTTP method {method.upper()} is not allowlisted"}
    return {"allowed": True, "reason": "no policy prohibition matched"}


def _norm_vuln(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _vuln_match(value: str, rule: str) -> bool:
    wanted = _norm_vuln(value)
    candidate = _norm_vuln(rule)
    if candidate == "*" or wanted == candidate:
        return True
    wanted_tokens = set(wanted.split("_"))
    candidate_tokens = set(candidate.split("_"))
    if candidate and (candidate in wanted or (candidate_tokens and candidate_tokens <= wanted_tokens)):
        return True
    for group in _VULN_ALIASES:
        if candidate in group and any(alias == wanted or alias in wanted for alias in group):
            return True
    return False


def evaluate_vulnerability(policy: dict, vuln_type: str) -> dict:
    excluded = [str(x) for x in policy.get("ineligible_vulnerability_types", [])]
    included = [str(x) for x in policy.get("eligible_vulnerability_types", [])]
    if any(_vuln_match(vuln_type, rule) for rule in excluded):
        return {"eligible": False, "reason": "explicitly ineligible"}
    if included and not any(_vuln_match(vuln_type, rule) for rule in included):
        return {"eligible": None, "reason": "not listed as eligible; manual program review required"}
    return {"eligible": True, "reason": "eligible under supplied policy"}


def summary(policy: dict) -> dict:
    if not policy:
        return {"loaded": False}
    return {
        "loaded": True,
        "policy_id": policy.get("policy_id"),
        "program_name": policy.get("program_name"),
        "included_assets": len(policy.get("included_assets", [])),
        "excluded_assets": len(policy.get("excluded_assets", [])),
        "max_requests_per_second": policy.get("max_requests_per_second"),
        "reviewed_at": policy.get("reviewed_at"),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
