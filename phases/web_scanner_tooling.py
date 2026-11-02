"""Web scanner orchestration/import adapter with URL/JavaScript feedback."""
from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from core import redteam_utils as RT

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def emit(ctx, title, sev, url, evidence, source):
    sev = str(sev or "INFO").upper(); sev = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO"
    ctx.save_finding({
        "phase": "web_scanner_tooling", "severity": sev, "confidence": "MEDIUM",
        "title": f"{source}: {title}"[:180], "target": url, "url": url,
        "description": "Imported automated web-scanner result. TBHM verification phases should confirm it before final acceptance.",
        "evidence": evidence[:1800], "impact": "Varies by scanner rule and reachable application behavior.",
        "remediation": "Reproduce, fix the root cause, and retest with both the source scanner and TBHM verification.",
        "cwe": "CWE-20", "mrs_score": 50,
    })


def _urls(value) -> set[str]:
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, str) and key.lower() in {"url", "uri", "href", "requesturl", "responseurl", "@name"}:
                found.update(m.group(0).rstrip(".,);]") for m in URL_RE.finditer(child))
            found.update(_urls(child))
    elif isinstance(value, list):
        for child in value: found.update(_urls(child))
    elif isinstance(value, str):
        found.update(m.group(0).rstrip(".,);]") for m in URL_RE.finditer(value))
    return found


def import_file_count(ctx, path: Path) -> int:
    """Backward-compatible wrapper: pre-v4 import_file returned only the count.
    v4 import_file returns (count, urls); this preserves the old int contract.
    """
    count, _urls = import_file(ctx, path)
    return count


def import_file(ctx, path: Path) -> tuple[int, set[str]]:
    count, urls = 0, set()
    if path.suffix.lower() in (".json", ".sarif"):
        try: data = json.loads(path.read_text(errors="ignore"))
        except Exception: return 0, set()
        urls.update(_urls(data))
        for site in data.get("site", []) if isinstance(data, dict) else []:
            site_url = site.get("@name", "")
            if site_url: urls.add(site_url)
            for alert in site.get("alerts", []):
                instances = alert.get("instances") if isinstance(alert.get("instances"), list) else []
                alert_urls = [row.get("uri", "") for row in instances if isinstance(row, dict) and row.get("uri")]
                for alert_url in alert_urls: urls.add(alert_url)
                emit(ctx, alert.get("name", "finding"), str(alert.get("riskdesc", "INFO")).split()[0],
                     alert_urls[0] if alert_urls else site_url, json.dumps(alert), "ZAP"); count += 1
        for run in data.get("runs", []) if isinstance(data, dict) else []:
            for result in run.get("results", []):
                loc = (((result.get("locations") or [{}])[0].get("physicalLocation") or {}).get("artifactLocation", {}).get("uri", ""))
                if loc.startswith(("http://", "https://")): urls.add(loc)
                emit(ctx, result.get("ruleId", "finding"), result.get("level"), loc, json.dumps(result), "SARIF"); count += 1
    elif path.suffix.lower() == ".xml":
        try: root = ET.parse(path).getroot()
        except Exception: return 0, set()
        for element in root.iter():
            for value in list(element.attrib.values()) + ([element.text] if element.text else []):
                if value: urls.update(m.group(0).rstrip(".,);]") for m in URL_RE.finditer(str(value)))
        for alert in root.findall(".//alertitem"):
            uri = alert.findtext("uri") or ""
            if uri: urls.add(uri)
            emit(ctx, alert.findtext("alert") or "finding", {"3":"HIGH","2":"MEDIUM","1":"LOW","0":"INFO"}.get(alert.findtext("riskcode"), "INFO"),
                 uri, ET.tostring(alert, encoding="unicode"), "ZAP"); count += 1
        for item in root.findall(".//ReportItem"):
            emit(ctx, item.get("pluginName", "Nessus item"), item.get("risk_factor") or "INFO", item.get("port", ""),
                 ET.tostring(item, encoding="unicode"), "Nessus"); count += 1
    elif path.suffix.lower() in {".txt", ".log", ".har"}:
        try:
            text = path.read_text(errors="ignore")
            if path.suffix.lower() == ".har": urls.update(_urls(json.loads(text)))
            else: urls.update(m.group(0).rstrip(".,);]") for m in URL_RE.finditer(text))
        except Exception: pass
    return count, urls


def _merge(path: Path, values: set[str]):
    existing = set(path.read_text(errors="ignore").splitlines()) if path.is_file() else set()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(existing | values)) + ("\n" if existing or values else ""), encoding="utf-8")


def run(ctx):
    if not (getattr(ctx.args, "web_scanner_tooling", False) or getattr(ctx.args, "web_scanner_results", None)): return
    out = RT.evidence_dir(ctx, "22_web_scanner_tooling")
    count, discovered = 0, set()
    if getattr(ctx.args, "web_scanner_tooling", False) and ctx.runner.has("zap-baseline.py"):
        alive = ctx.runner.read_lines(ctx.output / "recon" / "alive.txt")
        for index, url in enumerate(alive[:int(getattr(ctx.args, "zap_max_targets", 5))]):
            dest = out / f"zap_{index}.json"
            command = ["zap-baseline.py", "-t", url, "-J", str(dest), "-I"]
            if getattr(ctx.args, "zap_ajax_spider", True): command.append("-j")
            ctx.runner.run(command, timeout=int(getattr(ctx.args, "zap_timeout", 1800)), log_name=f"zap_baseline_{index}", capture_mode="tail")
            if dest.exists():
                n, urls = import_file(ctx, dest); count += n; discovered.update(urls)
    results = getattr(ctx.args, "web_scanner_results", None)
    if results:
        root = Path(results)
        files = [root] if root.is_file() else root.rglob("*") if root.is_dir() else []
        for file in files:
            if file.is_file() and file.suffix.lower() in (".json", ".sarif", ".xml", ".txt", ".log", ".har"):
                n, urls = import_file(ctx, file); count += n; discovered.update(urls)
    scope = getattr(ctx, "scope", None)
    if scope is not None: discovered = {u for u in discovered if scope.allows(u)}
    js_urls = {u for u in discovered if urlparse(u).path.lower().endswith((".js", ".mjs")) or ".js?" in u.lower() or ".mjs?" in u.lower()}
    _merge(ctx.output / "recon" / "zap_urls.txt", discovered)
    _merge(ctx.output / "recon" / "javascript.txt", js_urls)
    RT.write_md(out / "WEB_SCANNER_TOOLING_SUMMARY.md", "Web Scanner Tooling Summary", [
        ("Status", f"{count} result(s) normalized."), ("Discovered URLs", str(len(discovered))),
        ("JavaScript candidates", str(len(js_urls))),
        ("Compatibility", "Imports ZAP JSON/XML/HAR, SARIF and Nessus-style evidence; discovered JS URLs feed the dedicated complete JavaScript analysis phase."),
        ("Preservation", "Native nuclei, audit, injection, deep_scan, access-control and verify phases are unchanged."),
    ])
    ctx.log("OK", "web_scanner_tooling", f"{count} scanner result(s), {len(discovered)} URL(s), {len(js_urls)} JS candidate(s)")
