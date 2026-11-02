"""
Phase: code_scan   (v2.17)

Static analysis of a target's open-source code (the Filen approach: the SDK/web
repo holds the real endpoints and sometimes secrets). Give it a local directory
or a list of git repos; it clones, walks the tree, and runs the shared pattern
engine for secrets, endpoints, and dangerous sinks.

Extracted endpoints are written to <output>/code/endpoints.txt and hosts to
<output>/code/hosts.txt so api_fuzz / recon can consume them — turning "guess the
route" into "read the route from source".

Optional bonus tools if installed: semgrep (--config auto) and gitleaks. The
built-in engine always runs regardless.

Inputs (any of):
  --code-dir PATH         scan an already-downloaded source tree
  --code-repos URL,URL    clone these git repos and scan them
  --code-repos-file PATH  file with one git repo URL per line
Skips silently if no code input is provided.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import os
from pathlib import Path

from core import code_patterns as CP
from core.git_intake import repository_name, clone_repository
from core.evidence_redaction import redact_text


def _extension_set(raw: str | None) -> set[str]:
    """Normalize an explicit comma-separated text-extension allowlist."""
    out = set()
    for item in str(raw or "").split(","):
        value = item.strip().lower()
        if not value:
            continue
        if not value.startswith("."):
            value = "." + value
        if re.fullmatch(r"\.[a-z0-9][a-z0-9._+-]{0,15}", value):
            out.add(value)
    return out


def _secret_token(value: str) -> str:
    text = str(value or "")
    quoted = re.search(r"(['\"])([^'\"]{6,})\1", text)
    return quoted.group(2) if quoted else text


def _redact_secret_match(value: str, candidate: str | None = None) -> tuple[str, str]:
    """Return a readable redaction and stable hash without persisting the secret."""
    text = str(value or "")
    token = str(candidate) if candidate is not None else _secret_token(text)
    digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()
    if len(token) <= 8:
        masked = "[redacted]"
    else:
        masked = f"{token[:3]}…{token[-3:]}"
    token_pos = text.find(token) if token else -1
    if token_pos >= 0:
        redacted = text[:token_pos] + masked + text[token_pos + len(token):]
    else:
        quoted = re.search(r"(['\"])([^'\"]{6,})\1", text)
        if quoted:
            redacted = text[:quoted.start(2)] + masked + text[quoted.end(2):]
        else:
            redacted = masked
    return redacted[:240], digest


def _save_secret(ctx, secret: dict, rel: str, *, data_file_opt_in: bool = False) -> bool:
    title = f"Hardcoded secret in source: {secret['type']}"
    confidence = "MEDIUM" if "Generic" in secret["type"] else "HIGH"
    severity = secret["severity"]
    evidence = f"{rel}:{secret['line']}  {secret['match']}"
    extra = {}
    if data_file_opt_in:
        # Reuse the production placeholder/entropy/checksum gate on the real value
        # before redaction, then retain surviving records as static leads only.
        from core import fp_filters
        token = str(secret.get("candidate") or _secret_token(secret["match"]))
        probe = {"phase": "code_scan", "title": title, "type": secret["type"], "target": rel, "evidence": f"{rel}:{secret['line']}  {token}", "confidence": confidence}
        dummy, _reason = fp_filters.is_dummy_secret(probe, min_entropy=float(getattr(ctx.args, "secret_min_entropy", 3.0) or 3.0), ctx="data")
        if dummy:
            return False
        redacted, digest = _redact_secret_match(secret["match"], token)
        evidence = f"{rel}:{secret['line']}  {redacted} [sha256:{digest[:16]}…]"
        severity = "LOW" if "Generic" in secret["type"] else "MEDIUM"
        confidence = "LOW" if "Generic" in secret["type"] else "MEDIUM"
        extra = {
            "data_file_opt_in": True,
            "secret_fp_prechecked": True,
            "secret_value_sha256": digest,
            "finding_class": "lead",
            "status": "lead",
            "verified": False,
            "confirmation_basis": "Static pattern plus placeholder/entropy screening only; value was redacted before persistence.",
            "unconfirmed_assumptions": "The value is live, reachable, in production use, and grants access.",
        }
    saved = ctx.save_finding({
        "phase": "code_scan",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "target": rel,
        "url": "",
        "description": f"{secret['type']} found in {rel}:{secret['line']}. "
                       f"Hardcoded credentials in committed source or operational data may be exposed to anyone with repository or artifact access.",
        "evidence": evidence,
        "impact": "Credential exposure if the candidate is live and authorized for a real service; verify safely and rotate.",
        "remediation": "Remove from source/data, rotate the credential, load from an approved secret manager, and add a regression check.",
        "mrs_score": {"HIGH": 80, "MEDIUM": 55, "LOW": 35}.get(severity, 35),
        **extra,
    })
    return saved is not None


def _save_sink(ctx, sink: dict, rel: str, *, data_file_opt_in: bool = False) -> bool:
    saved = ctx.save_finding({
        "phase": "code_scan",
        "severity": "LOW",
        "confidence": "LOW",
        "title": f"Dangerous code pattern: {sink['type']}",
        "target": rel,
        "url": "",
        "description": f"{sink['type']} at {rel}:{sink['line']}. Review-grade static observation; confirm whether executable code and user-controlled input reach this sink.",
        "evidence": f"{rel}:{sink['line']}  {sink['match']}",
        "impact": "Potential injection, execution, deserialization, cryptographic, or transport weakness only when the snippet is executable and reachable.",
        "remediation": "Validate reachability and input flow; remove or harden the dangerous API and add a focused regression test.",
        "mrs_score": 25,
        "data_file_opt_in": bool(data_file_opt_in),
        "finding_class": "lead",
        "status": "lead",
        "verified": False,
        "confirmation_basis": "Static pattern only.",
    })
    return saved is not None


def _gather_repos(ctx):
    repos = []
    raw = getattr(ctx.args, "code_repos", None)
    if raw:
        repos += [r.strip() for r in raw.split(",") if r.strip()]
    rfile = getattr(ctx.args, "code_repos_file", None)
    if rfile and Path(rfile).is_file():
        repos += [l.strip() for l in Path(rfile).read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(repos))


def _clone(ctx, repos, dest: Path):
    cloned = []
    for url in repos:
        if getattr(ctx.args, 'offline', False):
            ctx.log('WARN', 'code_intake', 'offline mode: repository cloning blocked; use --code-dir')
            continue
        try:
            name = repository_name(url)
        except ValueError as exc:
            ctx.log('WARN', 'code_scan', redact_text(f'repository rejected: {exc}'))
            continue
        target = dest / name
        if target.exists():
            cloned.append(target)
            continue
        ctx.log("INFO", "code_scan", redact_text(f"cloning {url} (shallow)…"))
        try:
            token = os.environ.get(getattr(ctx.args, 'github_token_env', None) or '', '')
            clone_repository(url, target, token)
            if target.exists():
                cloned.append(target)
        except Exception as e:
            ctx.log("WARN", "code_scan", redact_text(f"clone failed {url}: {e}"))
    return cloned


def run(ctx):
    code_dir = getattr(ctx.args, "code_dir", None)
    repos = _gather_repos(ctx)
    if not code_dir and not repos:
        return  # nothing to scan — silent skip

    out_dir = ctx.output / "code"
    out_dir.mkdir(exist_ok=True)
    roots = []
    if code_dir and Path(code_dir).is_dir():
        roots.append(Path(code_dir))
    if repos:
        roots += _clone(ctx, repos, out_dir / "_repos")
    if not roots:
        ctx.log("WARN", "code_scan", "no source available to scan")
        return

    ctx.log("INFO", "code_scan", f"━━━ scanning {len(roots)} source tree(s) ━━━")

    # v2.18: recover original source from any shipped source maps first, then scan
    # the recovered tree alongside the originals.
    from core import sourcemaps, sbom
    from tempfile import TemporaryDirectory
    private_recovery = TemporaryDirectory(prefix="tbhm-source-recovery-")
    for root in list(roots):
        try:
            rec_dir = Path(private_recovery.name) / root.name
            n_rec = sourcemaps.reconstruct_dir(root, rec_dir, redact=False)
            if n_rec:
                roots.append(rec_dir)
                ctx.log("OK", "code_scan",
                        f"source maps: recovered {n_rec} original file(s) from {root.name} → {rec_dir}")
        except Exception as e:
            ctx.log("WARN", "code_scan", f"sourcemap recovery failed for {root.name}: {e}")

    all_urls, all_paths, all_hosts = set(), set(), set()
    n_secret = n_sink = files_scanned = 0
    data_candidates = data_scanned = data_filtered = 0
    scan_historical_data = bool(getattr(ctx.args, "code_scan_data_files", False))
    extra_full_scan_ext = _extension_set(getattr(ctx.args, "code_scan_extra_extensions", None))

    for root in roots:
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            if any(part in CP.SKIP_DIRS for part in f.parts):
                continue
            if f.suffix.lower() in CP.SKIP_EXT or CP.is_minified(f.name):
                continue
            suf = f.suffix.lower()
            historical_data = suf in getattr(CP, "HISTORICAL_DATA_EXT", getattr(CP, "ENDPOINT_EXT", set()))
            full_data_scan = (historical_data and scan_historical_data) or suf in extra_full_scan_ext
            opt_in_full_scan = full_data_scan and suf not in CP.SCAN_EXT
            endpoint_only = historical_data and not full_data_scan
            if suf not in CP.SCAN_EXT and not endpoint_only and not full_data_scan:
                continue
            try:
                if f.stat().st_size > 2_000_000:   # skip huge files
                    continue
                text = f.read_text(errors="ignore")
            except Exception:
                continue
            files_scanned += 1
            rel = str(f.relative_to(root.parent if root.parent else root))

            # Manifest/document files remain endpoint-only by default. Operators
            # can explicitly restore the v2.21 secret/sink breadth; surviving
            # observations are prefiltered, redacted, and forced to static leads.
            if historical_data:
                data_candidates += 1
            if endpoint_only:
                ep = CP.find_endpoints(text)
                all_urls.update(ep["urls"])
                all_paths.update(ep["paths"])
                all_hosts.update(ep["hosts"])
                continue

            if full_data_scan and historical_data:
                data_scanned += 1

            secrets = CP.find_secrets(text, rel)
            if opt_in_full_scan and hasattr(CP, "find_structured_data_secrets"):
                secrets += CP.find_structured_data_secrets(text, rel)
            seen_secrets = set()
            for secret in secrets:
                identity = (secret.get("type"), secret.get("line"), secret.get("candidate") or secret.get("match"))
                if identity in seen_secrets:
                    continue
                seen_secrets.add(identity)
                if _save_secret(ctx, secret, rel, data_file_opt_in=opt_in_full_scan):
                    n_secret += 1
                elif full_data_scan and historical_data:
                    data_filtered += 1

            for sink in CP.find_sinks(text, rel):
                if _save_sink(ctx, sink, rel, data_file_opt_in=opt_in_full_scan):
                    n_sink += 1

            ep = CP.find_endpoints(text)
            all_urls.update(ep["urls"])
            all_paths.update(ep["paths"])
            all_hosts.update(ep["hosts"])

    # Persist extracted endpoints for api_fuzz / recon consumption.
    if all_paths:
        (out_dir / "endpoints.txt").write_text("\n".join(sorted(all_paths)))
    if all_urls:
        (out_dir / "urls.txt").write_text("\n".join(sorted(all_urls)))
    if all_hosts:
        (out_dir / "hosts.txt").write_text("\n".join(sorted(all_hosts)))

    # Optional external SAST/secret tools.
    _run_optional_tools(ctx, roots, out_dir)

    # v2.18: SBOM + known-CVE lookup via OSV.dev.
    try:
        comps = []
        for root in roots:
            comps += sbom.parse_dependencies(root)
        # de-dup
        uniq = {(c["name"], c["version"], c["ecosystem"]): c for c in comps}
        comps = list(uniq.values())
        if comps:
            (out_dir / "sbom.cyclonedx.json").write_text(
                json.dumps(sbom.cyclonedx(comps), indent=2))
            if getattr(ctx.args, 'allow_external_enrichment', False) and not getattr(ctx.args, 'offline', False):
                comps = sbom.query_osv(comps)
                osv_state = 'requested'
            else:
                osv_state = 'not_requested'
                ctx.log('INFO', 'sbom', 'OSV lookup disabled; local SBOM generated without publishing dependency metadata')
            vuln_comps = [c for c in comps if c.get("vulns")]
            for c in vuln_comps:
                ids = ", ".join(v["id"] for v in c["vulns"][:6])
                ctx.save_finding({
                    "phase": "code_scan",
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "title": f"Vulnerable dependency: {c['name']} {c['version']} ({len(c['vulns'])} CVE)",
                    "target": c.get("file", ""), "url": "",
                    "description": f"{c['name']}@{c['version']} ({c['ecosystem']}) has known advisories: "
                                   f"{ids}. Reachability not verified — confirm the vulnerable code path "
                                   f"is actually invoked before rating.",
                    "evidence": "; ".join(f"{v['id']}: {v['summary']}" for v in c["vulns"][:3])[:400],
                    "impact": "Depends on the specific CVE and whether the vulnerable function is reachable.",
                    "remediation": "Upgrade to a fixed version; check the advisory for the patched release.",
                    "references": [f"https://osv.dev/vulnerability/{v['id']}" for v in c["vulns"][:5]],
                    "cwe": "CWE-1104",
                    "mrs_score": 70,
                })
            ctx.log("OK", "code_scan",
                    f"SBOM: {len(comps)} components → sbom.cyclonedx.json | "
                    f"{len(vuln_comps)} with returned advisory matches (OSV lookup: {osv_state})")
    except Exception as e:
        ctx.log("WARN", "code_scan", f"SBOM/CVE step failed: {e}")

    ctx.log("OK", "code_scan",
            f"code_scan: {files_scanned} files | {n_secret} secrets | {n_sink} sinks | "
            f"{len(all_paths)} API paths + {len(all_hosts)} hosts extracted | "
            f"data/doc full-scan {data_scanned}/{data_candidates}, filtered {data_filtered} "
            f"→ {out_dir/'endpoints.txt'}")
    if all_paths:
        ctx.log("INFO", "code_scan",
                f"feed these into api_fuzz:  --api-wordlist {out_dir/'endpoints.txt'}")


def _run_optional_tools(ctx, roots, out_dir):
    if ctx.runner.has("gitleaks"):
        from core import fp_filters
        for root in roots:
            try:
                rep = out_dir / f"gitleaks_{root.name}.json"
                ctx.runner.run(["gitleaks", "detect", "-s", str(root),
                                "--report-path", str(rep), "--no-banner"],
                               timeout=300, log_name="gitleaks", capture_mode="tail")
                # v3.5: don't trust gitleaks output raw — it fires on git SHAs,
                # plugin IDs, dataset labels, and placeholders. Validate every hit
                # through the same example/checksum/path gate before it counts.
                if rep.exists():
                    real, filtered = fp_filters.validate_gitleaks_report(rep)
                    if filtered:
                        (out_dir / f"gitleaks_{root.name}.filtered.json").write_text(
                            json.dumps(filtered, indent=2))
                    for it in real:
                        ctx.save_finding({
                            "phase": "code_secrets",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "title": f"[gitleaks] {it.get('RuleID','secret')}",
                            "target": it.get("File", ""),
                            "url": "",
                            "description": f"gitleaks matched rule {it.get('RuleID')} "
                                           f"at {it.get('File')}:{it.get('StartLine')}. "
                                           f"Validated past the FP gate — confirm the value "
                                           f"is live before reporting.",
                            "evidence": f"{it.get('File')}:{it.get('StartLine')}  "
                                        f"[value withheld — see repo]",
                            "impact": "Credential exposure if the value is live; verify and rotate.",
                            "remediation": "Remove from source, rotate, load from a secret manager.",
                            "cwe": "CWE-798",
                            "mrs_score": 60,
                        })
                    ctx.log("OK", "code_scan",
                            f"gitleaks {root.name}: {len(real)} kept / "
                            f"{len(filtered)} filtered as noise")
            except Exception as e:
                ctx.log("WARN", "code_scan", f"gitleaks parse failed: {e}")
    if ctx.runner.has("semgrep"):
        for root in roots:
            try:
                rep = out_dir / f"semgrep_{root.name}.json"
                ctx.runner.run(["semgrep", "--config", str(Path(__file__).resolve().parents[1] / "tooling" / "semgrep-native.yaml"), "--json",
                                "-o", str(rep), str(root)],
                               timeout=900, log_name="semgrep", capture_mode="tail")
                ctx.log("INFO", "code_scan", f"semgrep results: {rep}")
            except Exception:
                pass
