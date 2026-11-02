"""
core/bootstrap.py  —  v2.11

Self-healing setup layer. The #1 reason "nuclei finds nothing" is that the
official template repo was never downloaded, so nuclei runs against an empty
template set. The #2 reason is SecLists missing, so content_discovery falls
back to the tiny bundled wordlists.

This module DETECTS those gaps and FIXES them automatically:

  ensure_nuclei_templates()  -> runs `nuclei -update-templates` if the template
                                store is empty or stale; returns template count.
  ensure_seclists()          -> locates SecLists; clones a shallow copy if absent.
  ensure_custom_templates()  -> resolves the bundled TBHM custom template dir.
  bootstrap_all()            -> runs all of the above, returns a status dict.

Everything is best-effort and network-failure-tolerant: if a download can't
happen (offline, no git, etc.) the scan still proceeds, just degraded — and the
diagnostics phase reports exactly what's missing.

Nothing here is destructive. We only ADD templates / wordlists.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover - requirements include PyYAML
    yaml = None

# Where nuclei stores its templates by default (v3 uses ~/nuclei-templates,
# but the path is also recorded in the nuclei config). We probe both.
DEFAULT_NUCLEI_TEMPLATE_DIRS = [
    Path.home() / "nuclei-templates",
    Path.home() / ".local" / "nuclei-templates",
    Path.home() / ".config" / "nuclei" / "templates",
    Path.home() / ".config" / "nuclei-templates",
    Path("/usr/share/nuclei-templates"),
    Path("/opt/nuclei-templates"),
]

SECLISTS_CANDIDATES = [
    Path("/usr/share/seclists"),
    Path("/usr/share/SecLists"),
    Path("/opt/SecLists"),
    Path.home() / "SecLists",
]

# Bundled custom templates ship inside the repo at nuclei-templates/tbhm/
REPO_ROOT = Path(__file__).resolve().parent.parent
CUSTOM_TEMPLATE_DIR = REPO_ROOT / "nuclei-templates" / "tbhm"


# ──────────────────────────────────────────────────────────────────────────────
def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _template_is_valid(path: Path) -> bool:
    """Validate a candidate template without executing nuclei or making network calls."""
    try:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            return False
        text = path.read_text(encoding="utf-8", errors="strict")
        if yaml is None:
            # Conservative fallback: require the two mandatory top-level markers.
            return bool(re.search(r"(?m)^id\s*:\s*\S+", text) and re.search(r"(?m)^info\s*:\s*$", text))
        value = yaml.safe_load(text)
        return isinstance(value, dict) and bool(value.get("id")) and isinstance(value.get("info"), dict)
    except Exception:
        return False


def _valid_template_count(root: Path, limit: int = 100_000) -> int:
    count = 0
    try:
        candidates = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
    except Exception:
        return 0
    for path in candidates[:max(0, min(int(limit), 100_000))]:
        if _template_is_valid(path):
            count += 1
    return count


def nuclei_template_count() -> int:
    """Best-effort count of usable installed nuclei templates."""
    if not _have("nuclei"):
        return -1
    # Count only structurally usable templates. A directory containing malformed
    # YAML must not be reported as a healthy template store.
    best = 0
    for d in DEFAULT_NUCLEI_TEMPLATE_DIRS:
        if d.is_dir():
            best = max(best, _valid_template_count(d))
    if best:
        return best
    # Fallback: ask nuclei to list templates. A non-zero exit is not success.
    try:
        r = subprocess.run(["nuclei", "-tl", "-silent"],
                           capture_output=True, text=True, timeout=30, check=False)
        if r.returncode != 0:
            return 0
        return len([line for line in r.stdout.splitlines() if line.strip()])
    except Exception:
        return 0


def ensure_nuclei_templates(log=None, force=False, min_count=1000) -> dict:
    """
    Make sure nuclei has a healthy template store. Downloads/updates if empty
    or below `min_count`. Returns {installed, count, action}.
    """
    def _log(level, msg):
        if log:
            log(level, "bootstrap", msg)

    if not _have("nuclei"):
        _log("WARN", "nuclei not installed — cannot manage templates (run install.sh)")
        return {"installed": False, "count": -1, "action": "skip-no-nuclei"}

    count = nuclei_template_count()
    if count >= min_count and not force:
        _log("OK", f"nuclei templates healthy ({count} present)")
        return {"installed": True, "count": count, "action": "already-ok"}

    # Need to (re)download.
    flag = "-update-templates" if not force else "-update-templates"
    _log("INFO", f"nuclei templates low ({count}). Running nuclei {flag} …")
    update_error = ""
    try:
        result = subprocess.run(["nuclei", flag, "-silent"],
                                capture_output=True, text=True, timeout=900, check=False)
        if result.returncode != 0:
            update_error = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()[:500]
            _log("WARN", f"nuclei template update exited {result.returncode}: {update_error}")
    except subprocess.TimeoutExpired:
        update_error = "timeout"
        _log("WARN", "nuclei -update-templates timed out (slow network). Re-run --setup later.")
    except Exception as e:
        update_error = str(e)
        _log("WARN", f"nuclei template update failed: {e}")

    new_count = nuclei_template_count()
    if new_count > count:
        _log("OK", f"nuclei templates updated: {count} → {new_count}")
        return {"installed": True, "count": new_count, "action": "updated"}
    _log("WARN", f"nuclei templates still low ({new_count}). "
                 f"Check network or run 'nuclei -update-templates' manually.")
    return {"installed": True, "count": new_count, "action": "update-failed", "error": update_error}


def find_seclists() -> Path | None:
    for p in SECLISTS_CANDIDATES:
        if p.is_dir():
            return p
    return None


def ensure_seclists(log=None, clone_to="/opt/SecLists") -> dict:
    """Locate SecLists; shallow-clone it if absent and git is available."""
    def _log(level, msg):
        if log:
            log(level, "bootstrap", msg)

    found = find_seclists()
    if found:
        _log("OK", f"SecLists present at {found}")
        return {"present": True, "path": str(found), "action": "already-ok"}

    if not _have("git"):
        _log("WARN", "SecLists missing and git not installed — using bundled wordlists only.")
        return {"present": False, "path": None, "action": "skip-no-git"}

    # Try the system path first, fall back to the user's home if not writable.
    target = Path(clone_to)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not os.access(target.parent, os.W_OK):
            target = Path.home() / "SecLists"
    except Exception:
        target = Path.home() / "SecLists"

    _log("INFO", f"Cloning SecLists (shallow) to {target} … (this can take a minute)")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/danielmiessler/SecLists.git", str(target)],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        _log("WARN", "SecLists clone timed out. Re-run --setup on a faster link.")
        return {"present": False, "path": None, "action": "clone-timeout"}
    except Exception as e:
        _log("WARN", f"SecLists clone failed: {e}")
        return {"present": False, "path": None, "action": "clone-failed"}

    if (target / "Discovery").is_dir() or any(target.glob("*")):
        _log("OK", f"SecLists ready at {target}")
        return {"present": True, "path": str(target), "action": "cloned"}
    return {"present": False, "path": None, "action": "clone-empty"}


def ensure_custom_templates(log=None) -> dict:
    """Resolve/build the bundled TBHM custom template directory."""
    def _log(level, msg):
        if log:
            log(level, "bootstrap", msg)

    builder = CUSTOM_TEMPLATE_DIR.parent / "_build_templates.py"
    if (not CUSTOM_TEMPLATE_DIR.is_dir() or not any(CUSTOM_TEMPLATE_DIR.rglob("*.yaml"))) and builder.exists():
        _log("INFO", "building bundled TBHM custom templates")
        try:
            subprocess.run(["python3", str(builder)], capture_output=True, text=True, timeout=60)
        except Exception as e:
            _log("WARN", f"custom template build failed: {e}")

    if CUSTOM_TEMPLATE_DIR.is_dir():
        n = sum(1 for _ in CUSTOM_TEMPLATE_DIR.rglob("*.yaml"))
        if n:
            _log("OK", f"TBHM custom templates: {n} at {CUSTOM_TEMPLATE_DIR}")
            return {"present": True, "path": str(CUSTOM_TEMPLATE_DIR), "count": n}
        _log("WARN", f"custom template dir exists but has no YAML templates: {CUSTOM_TEMPLATE_DIR}")
        return {"present": False, "path": str(CUSTOM_TEMPLATE_DIR), "count": 0}
    _log("WARN", f"custom template dir missing: {CUSTOM_TEMPLATE_DIR}")
    return {"present": False, "path": str(CUSTOM_TEMPLATE_DIR), "count": 0}


def nuclei_templates_root() -> Path | None:
    """Return the official template directory with the most valid templates."""
    best = None
    best_count = 0
    for directory in DEFAULT_NUCLEI_TEMPLATE_DIRS:
        if not directory.is_dir():
            continue
        count = _valid_template_count(directory)
        if count > best_count:
            best = directory
            best_count = count
    return best


def bootstrap_all(log=None, force=False) -> dict:
    """Run every ensure_* step. Safe to call at the start of any scan."""
    return {
        "nuclei_templates": ensure_nuclei_templates(log=log, force=force),
        "seclists":         ensure_seclists(log=log),
        "custom_templates": ensure_custom_templates(log=log),
    }
