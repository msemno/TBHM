"""
Profile loader. Profiles live in profiles/*.yaml.

A profile defines the safety envelope and tuning for a scan. Hard limits
(K1 in the design doc) are ALWAYS applied on top — profiles can only loosen
within bounds, never disable safety.
"""
from __future__ import annotations
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


class ProfileError(Exception):
    pass


# Hard floors / ceilings that cannot be overridden by any profile.
# These come from Section 8 of the design doc (Constitutional AI for the tool).
HARD_LIMITS = {
    # Concurrency caps — profile can request lower, never higher
    "max_global_rps": 50,
    "max_per_target_rps": 20,
    "max_per_endpoint_rps": 5,
    "max_workers": 100,

    # Payload classes that are NEVER allowed regardless of profile
    "forbidden_payload_substrings": [
        "DROP TABLE", "drop table",
        "TRUNCATE", "truncate",
        "DELETE FROM", "delete from",
        "rm -rf", "format c:",
        "shutdown", "reboot",
        ":(){:|:&};:",  # fork bomb
        "/etc/shadow",   # actual exfil targets — not for read attempts
    ],
    "forbidden_methods_unless_explicit": ["DELETE", "PUT"],

    # Data exfiltration limits
    "max_records_per_idor_test": 3,   # don't enumerate users — prove with 2-3
    "max_response_kb_to_store": 2048, # 2MB per response

    # Always cleanup test data
    "auto_cleanup_test_uploads": True,

    # Scope enforcement
    "require_explicit_scope": True,   # for active profiles
}


# Built-in profile defaults so the tool works even if YAML is missing.
BUILTIN_DEFAULTS = {
    "passive_only": {
        "name": "passive_only",
        "description": "Zero-touch reconnaissance only (DNS, crt.sh, GitHub dorks). Safe for any target.",
        "rate_limit": {"global_rps": 0, "per_target_rps": 0},
        "active_probes": False,
        "send_payloads": False,
        "phases_enabled": ["recon", "discovery", "secrets_misc"],
        "nuclei": {"severity": [], "tags": []},
    },
    "authorized_safe": {
        "name": "authorized_safe",
        "description": "Default bug-bounty scan. Active probing with conservative rate limits.",
        "rate_limit": {"global_rps": 10, "per_target_rps": 5, "per_endpoint_rps": 1},
        "active_probes": True,
        "send_payloads": True,
        "payload_classes": ["time_blind", "oob", "reflection", "differential"],
        "nuclei": {"severity": ["critical", "high", "medium"], "tags": ["cve", "exposure", "misconfig", "takeover"]},
        "sqlmap": {"enabled": True, "level": 2, "risk": 1, "max_time": 60},
        "max_subdomains": 2000,
        "katana_depth": 2,
    },
    "authorized_full": {
        "name": "authorized_full",
        "description": "Full pentest. Requires explicit Statement-of-Work. Aggressive but still bounded by hard limits.",
        "rate_limit": {"global_rps": 30, "per_target_rps": 15, "per_endpoint_rps": 3},
        "active_probes": True,
        "send_payloads": True,
        "payload_classes": ["*"],
        "nuclei": {"severity": ["critical", "high", "medium", "low"],
                   "tags": ["cve", "exposure", "misconfig", "takeover", "intrusive", "fuzz"]},
        "sqlmap": {"enabled": True, "level": 3, "risk": 2, "max_time": 180},
        "max_subdomains": 10000,
        "katana_depth": 4,
    },
    "forensic_recheck": {
        "name": "forensic_recheck",
        "description": "Re-validate previously-found bugs only. Minimal traffic. Good for fix verification.",
        "rate_limit": {"global_rps": 2, "per_target_rps": 1, "per_endpoint_rps": 1},
        "active_probes": True,
        "send_payloads": True,
        "only_check_known": True,
        "phases_enabled": ["verify", "report"],
    },
}


def list_profiles(profiles_dir: Path) -> dict:
    """Return name → profile metadata for all available profiles."""
    out = dict(BUILTIN_DEFAULTS)
    if yaml and profiles_dir.is_dir():
        for f in profiles_dir.glob("*.yaml"):
            try:
                with open(f) as fp:
                    data = yaml.safe_load(fp) or {}
                data.setdefault("name", f.stem)
                out[data["name"]] = data
            except Exception:
                pass
    return out


def load_profile(profiles_dir: Path, name: str) -> dict:
    """
    Load a profile by name. YAML file in profiles/ wins over built-in default.
    Hard limits are always merged on top — they take precedence.
    """
    profiles = list_profiles(profiles_dir)
    if name not in profiles:
        available = ", ".join(profiles.keys())
        raise ProfileError(f"unknown profile '{name}'. Available: {available}")
    profile = dict(profiles[name])
    # Enforce hard ceilings on rate limits
    rl = profile.setdefault("rate_limit", {})
    rl["global_rps"]      = min(rl.get("global_rps",      10), HARD_LIMITS["max_global_rps"])
    rl["per_target_rps"]  = min(rl.get("per_target_rps",  5),  HARD_LIMITS["max_per_target_rps"])
    rl["per_endpoint_rps"]= min(rl.get("per_endpoint_rps",1),  HARD_LIMITS["max_per_endpoint_rps"])
    profile["hard_limits"] = HARD_LIMITS
    return profile
