"""
Phase: supply_chain_review   (v3.2)

Static, read-only supply-chain review over any supplied source tree/repos. It
extends the existing SBOM work in code_scan/code_intel with three supply-chain
specific checks:

  1. Dependency confusion  - internal-looking package names that are NOT scoped
     and could be shadowed by a public package of the same name.
  2. Typosquatting          - dependencies whose names are a 1-2 edit distance
     from a popular package (common squat target).
  3. Lockfile integrity     - manifest declares deps but no lockfile is present
     (unpinned installs), or git/http(s) direct dependencies.

No installs, no network resolution, no execution. Runs when code input exists.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from core import code_intel as CI

# small popular-package list used only as typosquat reference anchors
_POPULAR = {
    "npm": ["react", "lodash", "express", "axios", "chalk", "commander",
            "request", "moment", "debug", "async", "webpack", "babel", "next",
            "dotenv", "colors", "jsonwebtoken", "mongoose", "bcrypt"],
    "pip": ["requests", "numpy", "pandas", "flask", "django", "urllib3",
            "boto3", "pyyaml", "cryptography", "jinja2", "setuptools", "pillow"],
}
_INTERNAL_HINT = re.compile(r"(?i)(internal|corp|private|acme|company|\binc\b|core-|-internal)")


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _gather_roots(ctx):
    roots = []
    cd = getattr(ctx.args, "code_dir", None)
    if cd and Path(cd).is_dir():
        roots.append(Path(cd))
    # reuse any repos code_intel/code_scan already cloned
    for base in ("source_code_full/_repos", "code/_repos"):
        p = ctx.output / base
        if p.is_dir():
            roots += [d for d in p.iterdir() if d.is_dir()]
    return roots


def _parse_manifests(root: Path):
    """Return (ecosystem, name, spec, manifest_file, has_lockfile)."""
    deps = []
    root = Path(root)
    npm_lock = any((root / f).exists() for f in
                   ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"))
    pip_lock = any((root / f).exists() for f in
                   ("Pipfile.lock", "poetry.lock", "requirements.lock"))
    for f in root.rglob("*"):
        if (f.is_symlink() or not f.is_file() or f.name.lower() not in {'package.json', 'requirements.txt'}
                or any(part in {'.git', 'node_modules', '.venv', 'vendor'} for part in f.relative_to(root).parts)
                or f.stat().st_size > 1_000_000):
            continue
        name = f.name.lower()
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        if name == "package.json":
            try:
                data = json.loads(text)
            except Exception:
                continue
            for section in ("dependencies", "devDependencies"):
                for pkg, spec in (data.get(section) or {}).items():
                    deps.append(("npm", pkg, str(spec), str(f), npm_lock))
        elif name == "requirements.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$", line)
                if m:
                    deps.append(("pip", m.group(1), (m.group(2) or "").strip(),
                                 str(f), pip_lock))
    return deps


def run(ctx):
    roots = _gather_roots(ctx)
    if not roots:
        return  # silent skip — no code input

    out_dir = ctx.output / "supply_chain"
    out_dir.mkdir(exist_ok=True)
    ctx.log("INFO", "supply_chain_review", "━━━ dependency confusion / typosquat / integrity ━━━")

    all_deps = []
    for r in roots:
        all_deps += _parse_manifests(r)

    confusion, typosquat, integrity, local_inventory = [], [], [], []
    for eco, pkg, spec, mf, lock in all_deps:
        local = _local_dependency(eco, pkg, spec, mf, roots)
        if local:
            local_inventory.append(local)
            continue
        low = pkg.lower()
        # 1. dependency confusion: internal-looking, unscoped npm name
        if eco == "npm" and not pkg.startswith("@") and _INTERNAL_HINT.search(pkg):
            confusion.append({"ecosystem": eco, "package": pkg, "manifest": mf,
                              "why": "internal-looking unscoped npm name; a public "
                                     "package of the same name could shadow it"})
        # 2. typosquat: near-miss of a popular package (but not an exact match)
        for pop in _POPULAR.get(eco, []):
            if low != pop and _edit_distance(low, pop) == 1:
                typosquat.append({"ecosystem": eco, "package": pkg, "manifest": mf,
                                  "near": pop,
                                  "why": f"1 edit from popular package '{pop}'"})
                break
        # 3. integrity: git/http direct dependency, or no lockfile
        if re.search(r"(?i)(git\+|https?://|github:|file:)", spec):
            integrity.append({"ecosystem": eco, "package": pkg, "manifest": mf,
                              "spec": spec, "why": "non-registry direct dependency source"})
        elif not lock:
            integrity.append({"ecosystem": eco, "package": pkg, "manifest": mf,
                              "spec": spec, "why": "no lockfile present — unpinned install"})

    result = {"dependencies_seen": len(all_deps),
              "resolved_local_dependencies": local_inventory,
              "dependency_confusion": confusion,
              "typosquatting": typosquat,
              "integrity": integrity}
    (out_dir / "supply_chain_review.json").write_text(json.dumps(result, indent=2))

    for c in confusion:
        ctx.save_finding({
            "phase": "supply_chain_review", "severity": "MEDIUM", "confidence": "LOW",
            "title": f"Dependency confusion risk: {c['package']}",
            "target": c["manifest"], "url": "",
            "description": c["why"] + ". If this package is resolved from a public "
                           "registry, an attacker can publish a malicious same-name package.",
            "evidence": f"{c['manifest']} :: {c['package']}",
            "impact": "Malicious code execution in build/runtime via a substituted package.",
            "remediation": "Scope internal packages (@org/name), pin a private registry, "
                           "and enable install-time scope/registry allow-lists.",
            "cwe": "CWE-1195.001".replace("1195.001", "1195"), "mrs_score": 55,
        })
    for t in typosquat:
        ctx.save_finding({
            "phase": "supply_chain_review", "severity": "MEDIUM", "confidence": "LOW",
            "title": f"Possible typosquat dependency: {t['package']} (near {t['near']})",
            "target": t["manifest"], "url": "",
            "description": t["why"] + ". Confirm this is the intended package.",
            "evidence": f"{t['manifest']} :: {t['package']}",
            "impact": "Installing a squatted package can execute attacker code.",
            "remediation": f"Verify the package name; you may have meant '{t['near']}'.",
            "cwe": "CWE-1195", "mrs_score": 50,
        })
    for it in integrity[:40]:
        ctx.save_finding({
            "phase": "supply_chain_review", "severity": "LOW", "confidence": "LOW",
            "title": f"Dependency integrity: {it['package']} ({it['why']})",
            "target": it["manifest"], "url": "",
            "description": it["why"] + f" (spec: {it['spec'] or 'n/a'}).",
            "evidence": f"{it['manifest']} :: {it['package']} {it['spec']}",
            "impact": "Unpinned/non-registry dependencies weaken reproducibility and supply-chain integrity.",
            "remediation": "Commit a lockfile, pin versions, and prefer registry sources with integrity hashes.",
            "cwe": "CWE-1104", "mrs_score": 30,
        })

    ctx.log("OK", "supply_chain_review",
            f"{len(all_deps)} deps | confusion={len(confusion)} typosquat={len(typosquat)} "
            f"integrity={len(integrity)} → supply_chain_review.json")


def _local_dependency(ecosystem, name, spec, manifest, roots):
    """Recognize verified in-tree package links, not arbitrary file: strings.

    A missing/escaping link or a remote dependency remains a review candidate.
    Test and CI manifests remain analyzed; nothing is excluded by repository role.
    """
    if ecosystem != 'npm' or not spec.startswith(('file:', 'link:', 'workspace:')):
        return None
    containing = next((Path(r).resolve() for r in roots
                       if Path(manifest).resolve().is_relative_to(Path(r).resolve())), None)
    if containing is None:
        return None
    if spec.startswith(('file:', 'link:')):
        target = (Path(manifest).parent / spec.split(':', 1)[1]).resolve()
        candidates = [target / 'package.json'] if target.is_relative_to(containing) else []
    else:
        if not ((containing/'pnpm-workspace.yaml').is_file() or _has_workspaces(containing/'package.json')):
            return None
        candidates = [p for p in containing.rglob('package.json')
                      if not any(x in {'.git', 'node_modules', '.venv', 'vendor'} for x in p.relative_to(containing).parts)][:5000]
    for candidate in candidates:
        if (candidate.is_symlink() or not candidate.is_file() or
                not candidate.resolve().is_relative_to(containing) or candidate.stat().st_size > 1_000_000):
            continue
        try:
            data = json.loads(candidate.read_text())
        except (ValueError, OSError):
            continue
        if isinstance(data, dict) and data.get('name') == name:
            return {'package': name, 'manifest': manifest, 'spec': spec,
                    'resolved_manifest': str(candidate), 'classification': 'local_workspace_inventory',
                    'runtime_security_validated': False}
    return None


def _has_workspaces(path):
    try:
        value = json.loads(path.read_text())
        return isinstance(value, dict) and bool(value.get('workspaces'))
    except (ValueError, OSError):
        return False
