"""Unified safe code-security orchestration (v3.9 additive update).

Preserves the v3.8 default adapter set and adds optional read-only adapters for
language SAST, SCA, secrets, SBOM, and IaC/container linting. Build-dependent or
cloud-coupled products remain import-only so the phase never uploads source or
changes the repository without an explicit external workflow.
"""
from __future__ import annotations

import json
from pathlib import Path

from core import redteam_utils as RT
from core.scanner_normalizer import iter_result_files, parse_file, save_items


DEFAULT_TOOLS = "bandit,njsscan,gitleaks,trivy,grype,checkov,terrascan,tfsec"
IMPORT_ONLY = {
    "codeql", "sonarqube", "spotbugs", "pmd", "snyk", "ggshield",
    "gitguardian", "mega-linter", "defectdojo", "fortify", "veracode",
    "checkmarx", "coverity",
}


def sev(value):
    """v3.8 severity-normalization compatibility helper."""
    normalized = str(value or "INFO").upper()
    return {
        "ERROR": "HIGH", "WARN": "MEDIUM", "WARNING": "MEDIUM",
        "MODERATE": "MEDIUM", "CRITICAL": "CRITICAL", "HIGH": "HIGH",
        "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO",
    }.get(normalized, "INFO")


def emit(ctx, title, severity, target, evidence, source, cwe="CWE-20"):
    """v3.8 compatibility emitter; scanner evidence remains non-confirming."""
    normalized = sev(severity)
    ctx.save_finding({
        "phase": "code_security_tooling", "severity": normalized,
        "confidence": "MEDIUM", "title": str(title)[:180],
        "target": str(target), "url": "",
        "description": f"Code-security result normalized from {source}. Reachability, exploitability, and dependency usage require validation.",
        "evidence": str(evidence)[:2200],
        "impact": "May represent vulnerable code, dependency risk, an exposed secret, or insecure infrastructure configuration.",
        "remediation": "Validate and remediate in source or dependency configuration, rotate exposed secrets, add regression tests, and rerun CI checks.",
        "cwe": str(cwe or "CWE-20"),
        "mrs_score": 70 if normalized in {"HIGH", "CRITICAL"} else 45,
    })


def walk(ctx, value, source, path=""):
    """v3.8 recursive JSON compatibility normalizer."""
    count = 0
    if isinstance(value, dict):
        title = (value.get("title") or value.get("name") or value.get("rule_id") or
                 value.get("test_name") or value.get("VulnerabilityID") or
                 value.get("check_id") or value.get("Description"))
        severity = value.get("severity") or value.get("Severity") or value.get("issue_severity") or value.get("level")
        target = value.get("Target") or value.get("file") or value.get("filename") or value.get("path") or value.get("File") or path
        if title and (severity or any(key in value for key in ("CVE", "VulnerabilityID", "line_number", "StartLine", "Secret", "Match"))):
            emit(ctx, title, severity or "INFO", target, json.dumps(value, ensure_ascii=False), source, value.get("cwe") or value.get("CWE") or "CWE-20")
            count += 1
        for key, child in value.items():
            count += walk(ctx, child, source, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            count += walk(ctx, child, source, f"{path}/{index}")
    return count


def import_file(ctx, path):
    """v3.8 JSON/JSONL import compatibility entry point."""
    file = Path(path)
    try:
        if file.suffix.lower() == ".jsonl":
            return sum(walk(ctx, json.loads(line), file.stem) for line in file.read_text(errors="ignore").splitlines() if line.strip())
        return walk(ctx, json.loads(file.read_text(errors="ignore")), file.stem)
    except Exception:
        return 0


def _write_stdout(dest: Path, stdout: str) -> Path | None:
    if stdout and stdout.strip():
        dest.write_text(stdout, encoding="utf-8", errors="ignore")
        return dest
    return dest if dest.exists() else None


def _run_simple(ctx, name: str, src: Path, out: Path) -> list[Path]:
    dest = out / f"{name}.json"
    result_files: list[Path] = []

    if name == "bandit":
        cmd = ["bandit", "-r", str(src), "-f", "json", "-o", str(dest)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_bandit", capture_mode="tail")
    elif name == "njsscan":
        cmd = ["njsscan", "--json", "-o", str(dest), str(src)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_njsscan", capture_mode="tail")
    elif name == "gitleaks":
        cmd = ["gitleaks", "detect", "--source", str(src), "--report-format", "json",
               "--report-path", str(dest), "--no-banner"]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_gitleaks", capture_mode="tail")
    elif name == "trivy":
        cmd = ["trivy", "fs", "--format", "json", "--output", str(dest), str(src)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_trivy", capture_mode="tail")
    elif name == "grype":
        cmd = ["grype", f"dir:{src}", "-o", "json", "--file", str(dest)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_grype", capture_mode="tail")
    elif name == "checkov":
        cmd = ["checkov", "-d", str(src), "-o", "json", "--output-file-path", str(out)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_checkov", capture_mode="tail")
        # Checkov may create results_json.json rather than the requested name.
        result_files.extend(p for p in out.glob("*.json") if "checkov" in p.name or "results_json" in p.name)
    elif name == "terrascan":
        cmd = ["terrascan", "scan", "-d", str(src), "-o", "json"]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=3600, log_name="code_security_terrascan")
        _write_stdout(dest, stdout)
    elif name == "tfsec":
        cmd = ["tfsec", str(src), "--format", "json", "--out", str(dest)]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_tfsec", capture_mode="tail")
    elif name == "semgrep":
        dest = out / "semgrep.sarif"
        cmd = [
            "semgrep", "scan", "--config", str(Path(__file__).resolve().parents[1] / "tooling" / "semgrep-native.yaml"), "--metrics=off",
            "--disable-version-check", "--sarif", "--output", str(dest), str(src),
        ]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_semgrep", capture_mode="tail")
    elif name == "ruff":
        cmd = ["ruff", "check", "--select", "S", "--output-format", "json", str(src)]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=1800, log_name="code_security_ruff")
        _write_stdout(dest, stdout)
    elif name == "brakeman":
        cmd = ["brakeman", "-p", str(src), "-f", "json", "-o", str(dest), "--no-pager"]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_brakeman", capture_mode="tail")
    elif name == "gosec":
        cmd = ["gosec", "-fmt=json", f"-out={dest}", "./..."]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_gosec", cwd=src, capture_mode="tail")
    elif name == "eslint":
        cmd = ["eslint", "--no-config-lookup", "--config", str(Path(__file__).resolve().parents[1] / "tooling" / "eslint.config.mjs"), "-f", "json", "-o", str(dest), "."]
        ctx.runner.run(cmd, timeout=3600, log_name="code_security_eslint", cwd=src, capture_mode="tail")
    elif name == "trufflehog":
        dest = out / "trufflehog.jsonl"
        cmd = ["trufflehog", "filesystem", "--no-update", "--no-verification", "--json", str(src)]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=3600, log_name="code_security_trufflehog")
        _write_stdout(dest, stdout)
    elif name in {"detect-secrets", "detect_secrets"}:
        name = "detect-secrets"
        dest = out / "detect-secrets.json"
        cmd = ["detect-secrets", "scan", "--all-files", str(src)]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=3600, log_name="code_security_detect_secrets")
        _write_stdout(dest, stdout)
    elif name == "syft":
        cmd = ["syft", f"dir:{src}", "-o", "json"]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=3600, log_name="code_security_syft")
        _write_stdout(dest, stdout)
    elif name == "safety":
        # Safety CLI syntax differs across major versions; the legacy check path
        # is widely available and is kept best-effort/read-only.
        cmd = ["safety", "check", "--json"]
        rc, stdout, _ = ctx.runner.run(cmd, timeout=1800, log_name="code_security_safety", cwd=src)
        _write_stdout(dest, stdout)
    elif name in {"dependency-check", "dependency_check"}:
        executable = "dependency-check" if ctx.runner.has("dependency-check") else "dependency-check.sh"
        cmd = [executable, "--scan", str(src), "--format", "JSON", "--out", str(out)]
        ctx.runner.run(cmd, timeout=7200, log_name="code_security_dependency_check", capture_mode="tail")
        report = out / "dependency-check-report.json"
        if report.exists():
            result_files.append(report)
    elif name == "hadolint":
        findings = []
        dockerfiles = [p for p in src.rglob("*") if p.is_file() and
                       (p.name == "Dockerfile" or p.name.lower().startswith("dockerfile."))]
        for index, dockerfile in enumerate(dockerfiles[:200]):
            rc, stdout, _ = ctx.runner.run(
                ["hadolint", "-f", "json", str(dockerfile)],
                timeout=120, log_name=f"code_security_hadolint_{index}",
            )
            if stdout.strip():
                try:
                    parsed = json.loads(stdout)
                    if isinstance(parsed, list):
                        findings.extend(parsed)
                except Exception:
                    continue
        dest.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    else:
        return []

    if dest.exists():
        result_files.append(dest)
    # Stable deduplication while preserving order.
    seen = set()
    unique = []
    for file in result_files:
        key = str(file.resolve())
        if key not in seen and file.exists():
            seen.add(key)
            unique.append(file)
    return unique


def _tool_available(ctx, name: str) -> bool:
    aliases = {
        "detect_secrets": "detect-secrets",
        "dependency_check": "dependency-check",
    }
    executable = aliases.get(name, name)
    if executable == "dependency-check":
        return ctx.runner.has("dependency-check") or ctx.runner.has("dependency-check.sh")
    return ctx.runner.has(executable)


def run(ctx):
    if not (getattr(ctx.args, "code_security_tooling", False) or
            getattr(ctx.args, "code_security_results", None)):
        return

    out = RT.evidence_dir(ctx, "28_code_security_tooling")
    total = 0
    src_raw = getattr(ctx.args, "code_dir", None)
    enabled = [x.strip().lower() for x in str(
        getattr(ctx.args, "code_security_tools", DEFAULT_TOOLS) or DEFAULT_TOOLS
    ).split(",") if x.strip()]
    executed = []
    skipped = []

    if getattr(ctx.args, "code_security_tooling", False) and src_raw and Path(src_raw).is_dir():
        src = Path(src_raw).resolve()
        for name in enabled:
            if name in IMPORT_ONLY:
                skipped.append({"tool": name, "reason": "import-only: build/service/cloud coupling"})
                ctx.log("INFO", "code_security_tooling", f"{name} is import-only; provide --code-security-results")
                continue
            if not _tool_available(ctx, name):
                skipped.append({"tool": name, "reason": "not installed"})
                ctx.log("WARN", "code_security_tooling", f"{name} not installed; skipped")
                continue
            files = _run_simple(ctx, name, src, out)
            tool_count = 0
            for file in files:
                items = parse_file(file, name)
                _record_diagnostics(ctx, file, name)
                tool_count += save_items(ctx, "code_security_tooling", items, name)
            total += tool_count
            executed.append({"tool": name, "outputs": [str(f) for f in files], "normalized": tool_count})
    elif getattr(ctx.args, "code_security_tooling", False):
        ctx.log("WARN", "code_security_tooling", "--code-security-tooling requires a valid --code-dir")

    results_path = getattr(ctx.args, "code_security_results", None)
    imported = []
    if results_path:
        for file in iter_result_files(results_path):
            source = file.stem
            items = parse_file(file, source)
            _record_diagnostics(ctx, file, source)
            count = save_items(ctx, "code_security_tooling", items, source)
            total += count
            imported.append({"file": str(file), "normalized": count})

    summary_json = {
        "normalized_observations": total,
        "default_tools_preserved": DEFAULT_TOOLS,
        "selected_tools": enabled,
        "executed": executed,
        "skipped": skipped,
        "imported": imported,
        "live_read_only_tools": [
            "bandit", "njsscan", "gitleaks", "trivy", "grype", "checkov",
            "terrascan", "tfsec", "semgrep", "ruff", "brakeman", "gosec",
            "eslint", "trufflehog(no verification)", "detect-secrets", "syft",
            "safety", "dependency-check", "hadolint",
        ],
        "import_only_tools": sorted(IMPORT_ONLY),
        "safety": {
            "repository_writes": False,
            "secret_live_verification": False,
            "source_upload": False,
            "scanner_findings_are_leads": True,
        },
    }
    (out / "code_security_tooling_summary.json").write_text(json.dumps(summary_json, indent=2), encoding="utf-8")
    RT.write_md(out / "CODE_SECURITY_TOOLING_SUMMARY.md", "Unified Code Security Tooling Summary", [
        ("Status", f"{total} code-security observation(s) normalized."),
        ("Preserved v3.8 defaults", DEFAULT_TOOLS),
        ("Additional live adapters", "Semgrep, Ruff, Brakeman, Gosec, ESLint, TruffleHog with verification disabled, detect-secrets, Syft, Safety, OWASP Dependency-Check and Hadolint."),
        ("Import-only platforms", "CodeQL, SonarQube, SpotBugs, PMD, Snyk, GitGuardian/ggshield, Mega-Linter, DefectDojo, Fortify, Veracode, Checkmarx and Coverity can be normalized from JSON/JSONL/SARIF."),
        ("Executed", json.dumps(executed, ensure_ascii=False) if executed else "None"),
        ("Skipped", json.dumps(skipped, ensure_ascii=False) if skipped else "None"),
        ("Safety", "All live adapters scan only the local --code-dir. No repository changes, pull requests, cloud source upload, dependency upgrades, or third-party secret verification are performed. Imported scanner observations remain leads."),
    ])
    ctx.log("OK", "code_security_tooling", f"{total} code-security observation(s) normalized")


def _record_diagnostics(ctx, path, source):
    from core.scanner_normalizer import scanner_diagnostics
    diagnostics = scanner_diagnostics(path, source)
    if not diagnostics:
        return
    destination = Path(path).with_name(Path(path).stem + '_diagnostics.json')
    # Imported input files are read-only. Write receipts into this run only.
    out = RT.evidence_dir(ctx, '28_code_security_tooling')
    (out / destination.name).write_text(json.dumps(diagnostics, indent=2)+'\n')
    for item in diagnostics:
        if getattr(ctx, 'execution_ledger', None):
            ctx.execution_ledger.record(kind='scanner_diagnostic', status='parser-error',
                tool=source, reason=item['reason'], source_path=item.get('path', ''))
    ctx.log('WARN', 'code_security_tooling',
            f'{source}: {len(diagnostics)} parser diagnostic(s); affected coverage incomplete')
