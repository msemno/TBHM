"""
SecLists integration helper.

Locates SecLists wordlists at standard paths and falls back to bundled
wordlists in TBHM-v2/wordlists/ if SecLists isn't installed.

Common SecLists install locations:
  /usr/share/seclists                    (Kali, Parrot)
  /usr/share/wordlists/seclists          (some Debian setups)
  /opt/SecLists                          (manual git clone)
  ~/SecLists                             (user-level git clone)
  /usr/local/share/seclists              (brew on macOS Intel)
  /opt/homebrew/share/seclists           (brew on macOS Apple Silicon)
"""
from __future__ import annotations
import os
from pathlib import Path

# Search order for the SecLists root
_SECLISTS_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/usr/share/wordlists/seclists",
    "/usr/share/wordlists/SecLists",
    "/opt/SecLists",
    "/opt/seclists",
    "/usr/local/share/seclists",
    "/usr/local/share/SecLists",
    "/opt/homebrew/share/seclists",
    "/opt/homebrew/share/SecLists",
    str(Path.home() / "SecLists"),
    str(Path.home() / "tools" / "SecLists"),
]


def _find_seclists_root() -> Path | None:
    # Allow override via env
    env = os.environ.get("SECLISTS")
    if env and Path(env).is_dir():
        return Path(env)
    for c in _SECLISTS_CANDIDATES:
        p = Path(c)
        # SecLists has a distinctive top-level structure
        if p.is_dir() and (p / "Discovery").is_dir():
            return p
    return None


SECLISTS_ROOT = _find_seclists_root()
TBHM_ROOT = Path(__file__).resolve().parent.parent
TBHM_WL_DIR = TBHM_ROOT / "wordlists"


# ──────────────────────────────────────────────────────────────────────────────
# Map of logical wordlist name → (relative SecLists path, fallback file)
# Each phase asks for what it needs by name; the helper resolves to a real path.
# ──────────────────────────────────────────────────────────────────────────────
_WORDLIST_MAP = {
    # Subdomain DNS brute force
    "subdomains_small":  ("Discovery/DNS/subdomains-top1million-5000.txt",   "subdomains.txt"),
    "subdomains_medium": ("Discovery/DNS/subdomains-top1million-20000.txt",  "subdomains.txt"),
    "subdomains_large":  ("Discovery/DNS/subdomains-top1million-110000.txt", "subdomains.txt"),
    "subdomains_huge":   ("Discovery/DNS/n0kovo_subdomains_huge.txt",        "subdomains.txt"),

    # Content / directory discovery
    "content_common":    ("Discovery/Web-Content/common.txt",                None),
    "content_quickhits": ("Discovery/Web-Content/quickhits.txt",             None),
    "content_raft_med":  ("Discovery/Web-Content/raft-medium-directories.txt", None),
    "content_raft_lg":   ("Discovery/Web-Content/raft-large-directories.txt",  None),
    "content_dirlist":   ("Discovery/Web-Content/directory-list-2.3-medium.txt", None),
    "content_big":       ("Discovery/Web-Content/big.txt",                   None),

    # API / objects
    "api_endpoints":     ("Discovery/Web-Content/api/api-endpoints.txt",     "api_endpoints.txt"),
    "api_objects":       ("Discovery/Web-Content/api/objects.txt",           "api_endpoints.txt"),
    "api_actions":       ("Discovery/Web-Content/api/actions.txt",           None),

    # Parameters
    "params_burp":       ("Discovery/Web-Content/burp-parameter-names.txt",  "params_common.txt"),
    "params_top":        ("Discovery/Web-Content/api/api-endpoints.txt",     "params_common.txt"),

    # Backups / sensitive files
    "backups":           ("Discovery/Web-Content/Common-DB-Backups.txt",     None),

    # Fuzzing payloads
    "xss_jhaddix":       ("Fuzzing/XSS/XSS-Jhaddix.txt",                    "xss_basic.txt"),
    "xss_bypass":        ("Fuzzing/XSS/XSS-BurpSuite-RX-Hacker.txt",        "xss_basic.txt"),
    "xss_polyglots":     ("Fuzzing/Polyglots/XSS_Polyglots.txt",            "xss_basic.txt"),
    "sqli_generic":      ("Fuzzing/SQLi/Generic-SQLi.txt",                  "sqli_basic.txt"),
    "sqli_auth_bypass":  ("Fuzzing/SQLi/quick-SQLi.txt",                    "sqli_basic.txt"),
    "lfi_linux":         ("Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",     "lfi_basic.txt"),
    "lfi_windows":       ("Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",   "lfi_basic.txt"),
    "lfi_jhaddix":       ("Fuzzing/LFI/LFI-Jhaddix.txt",                    "lfi_basic.txt"),
    "ssrf_urls":         ("Fuzzing/SSRF/SSRF-URLs.txt",                     "ssrf_basic.txt"),
    "ssrf_burp":         ("Fuzzing/SSRF/SSRF.txt",                          "ssrf_basic.txt"),
    "redirect":          ("Fuzzing/open-redirect/Open-Redirect-payloads.txt", "redirect_basic.txt"),
    "command_injection": ("Fuzzing/command-injection-commix.txt",            None),
    "xxe":               ("Fuzzing/XXE-Fuzzing.txt",                         None),

    # Web shells
    "web_shells":        ("Web-Shells/FuzzDB/php-cmd.txt",                   None),
}


def get(name: str) -> Path | None:
    """
    Return absolute path to a wordlist by logical name.
    Tries SecLists first, then bundled fallback. Returns None if neither exists.
    """
    if name not in _WORDLIST_MAP:
        return None
    rel, fallback = _WORDLIST_MAP[name]
    if SECLISTS_ROOT:
        candidate = SECLISTS_ROOT / rel
        if candidate.is_file():
            return candidate
    if fallback:
        fb = TBHM_WL_DIR / fallback
        if fb.is_file():
            return fb
    return None


def get_or_warn(name: str, ctx_log_fn=None) -> Path | None:
    """get() but logs a warning if missing."""
    p = get(name)
    if p is None and ctx_log_fn:
        ctx_log_fn("WARN", "seclists",
                   f"wordlist '{name}' not found (install SecLists for full coverage)")
    return p


def status() -> dict:
    """Return diagnostic info about SecLists availability."""
    return {
        "seclists_root": str(SECLISTS_ROOT) if SECLISTS_ROOT else None,
        "available": SECLISTS_ROOT is not None,
        "fallback_dir": str(TBHM_WL_DIR),
    }


def list_available() -> dict[str, str]:
    """Return name → resolved path for all available wordlists."""
    out = {}
    for name in _WORDLIST_MAP:
        p = get(name)
        if p:
            out[name] = str(p)
    return out
