"""
Intensity overlays applied on top of safety profile.

Profile = WHAT'S SAFE (rate limits, forbidden payloads, scope)
Intensity = HOW HARD WE GO (wordlist size, scanner timeouts, depth)

These are orthogonal. You can have:
  - authorized_safe + --quick  (gentle quick scan)
  - authorized_safe + --deep   (thorough but still bounded by safety)
  - authorized_full + --insane (deepest, only for sanctioned pentest)
"""
from __future__ import annotations


INTENSITIES = {
    "quick": {
        "name": "quick",
        "description": "~10-20 min. Minimal recon, critical/high nuclei only.",
        "subdomain_wordlist": "subdomains_small",        # top 5K
        "max_subdomains_brute": 5000,
        "katana_depth": 1,
        "katana_timeout": 60,
        "content_wordlist": "content_quickhits",
        "nuclei_severity": ["critical", "high"],
        "nuclei_tags_extra": [],
        "sqlmap_enabled": False,
        "screenshot_enabled": False,
        "port_scan": "top100",                            # nmap top-100
        "use_masscan": False,
        "nikto_enabled": False,
        "jaeles_enabled": False,
        "wapiti_enabled": False,
        "max_alive_hosts_to_scan": 50,
    },
    "standard": {
        "name": "standard",
        "description": "1-3 hours. Default. Balanced coverage.",
        "subdomain_wordlist": "subdomains_medium",        # top 20K
        "max_subdomains_brute": 20000,
        "katana_depth": 2,
        "katana_timeout": 300,
        "content_wordlist": "content_common",
        "nuclei_severity": ["critical", "high", "medium"],
        "nuclei_tags_extra": ["takeover", "cve"],
        "sqlmap_enabled": True,
        "screenshot_enabled": True,
        "port_scan": "top1000",                           # naabu top-1000 or nmap top-1000
        "use_masscan": False,
        "nikto_enabled": False,
        "jaeles_enabled": True,
        "wapiti_enabled": False,
        "max_alive_hosts_to_scan": 200,
    },
    "deep": {
        "name": "deep",
        "description": "6-12 hours. Heavy recon + most scanners.",
        "subdomain_wordlist": "subdomains_large",         # top 110K
        "max_subdomains_brute": 110000,
        "katana_depth": 3,
        "katana_timeout": 900,
        "content_wordlist": "content_raft_med",
        "nuclei_severity": ["critical", "high", "medium", "low"],
        "nuclei_tags_extra": ["cve", "exposure", "misconfig", "takeover", "fuzz"],
        "sqlmap_enabled": True,
        "screenshot_enabled": True,
        "port_scan": "top5000",
        "use_masscan": True,
        "nikto_enabled": True,
        "jaeles_enabled": True,
        "wapiti_enabled": True,
        "max_alive_hosts_to_scan": 1000,
    },
    "insane": {
        "name": "insane",
        "description": "12-48 hours. Maximum coverage. Only with authorized_full + SoW.",
        "subdomain_wordlist": "subdomains_huge",          # 1M+
        "max_subdomains_brute": 1000000,
        "katana_depth": 5,
        "katana_timeout": 3600,
        "content_wordlist": "content_raft_lg",
        "nuclei_severity": ["critical", "high", "medium", "low", "info"],
        "nuclei_tags_extra": ["cve", "exposure", "misconfig", "takeover", "fuzz", "intrusive"],
        "sqlmap_enabled": True,
        "screenshot_enabled": True,
        "port_scan": "all",                               # all 65535
        "use_masscan": True,
        "nikto_enabled": True,
        "jaeles_enabled": True,
        "wapiti_enabled": True,
        "max_alive_hosts_to_scan": 10000,
    },
}


def apply(profile: dict, intensity_name: str) -> dict:
    """Merge intensity into profile. Returns the modified profile."""
    if intensity_name not in INTENSITIES:
        return profile
    intensity = INTENSITIES[intensity_name]
    profile["_intensity"] = intensity_name
    profile["intensity"] = intensity

    # Apply tunables to existing profile fields, respecting safety caps
    profile.setdefault("nuclei", {})
    profile["nuclei"]["severity"] = intensity["nuclei_severity"]
    existing_tags = profile["nuclei"].get("tags", [])
    profile["nuclei"]["tags"] = sorted(set(existing_tags + intensity["nuclei_tags_extra"]))

    profile.setdefault("sqlmap", {})
    profile["sqlmap"]["enabled"] = (intensity["sqlmap_enabled"] and
                                     profile["sqlmap"].get("enabled", False))

    profile["katana_depth"] = min(intensity["katana_depth"],
                                   profile.get("katana_depth", 2))
    profile["max_subdomains"] = min(intensity["max_subdomains_brute"],
                                     profile.get("max_subdomains", 2000))
    return profile


def get(profile: dict, key: str, default=None):
    """Safe lookup into the active intensity config inside a profile."""
    return profile.get("intensity", {}).get(key, default)
