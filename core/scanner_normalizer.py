"""Shared scanner result normalizer for additive source-security adapters.

The normalizer intentionally emits observations/leads. It does not claim that a
scanner record is exploitable without independent validation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


SEVERITY_MAP = {
    "FATAL": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "ERROR": "MEDIUM",
    "HIGH": "HIGH",
    "IMPORTANT": "HIGH",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "NOTE": "LOW",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "NONE": "INFO",
}


def severity(value) -> str:
    raw = str(value or "INFO").strip().upper()
    # Common numeric linter levels: 2=error, 1=warning, 0=off. They do not
    # prove exploitability, so keep them below HIGH; finding_class still marks
    # every imported adapter observation as a lead.
    if raw in {"2", "ERRORLEVEL"}:
        return "MEDIUM"
    if raw == "1":
        return "LOW"
    if raw == "0":
        return "INFO"
    return SEVERITY_MAP.get(raw, "INFO")


def _first(mapping: dict, *keys, default=""):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _cwe_from(value) -> str:
    if isinstance(value, list):
        value = " ".join(str(x) for x in value)
    match = re.search(r"CWE[-_: ]?(\d+)", str(value or ""), re.I)
    return f"CWE-{match.group(1)}" if match else ""


def _sarif(data: dict, source: str, limit: int = 5000) -> list[dict]:
    items = []
    for run in data.get("runs", []) if isinstance(data, dict) else []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules = {str(r.get("id")): r for r in driver.get("rules", []) if r.get("id")}
        for result in run.get("results", []) or []:
            if len(items) >= limit:
                return items
            rid = str(result.get("ruleId") or "scanner-result")
            rule = rules.get(rid, {})
            message = ((result.get("message") or {}).get("text") or
                       ((rule.get("shortDescription") or {}).get("text")) or rid)
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = ((loc.get("artifactLocation") or {}).get("uri") or "")
            region = loc.get("region") or {}
            props = result.get("properties") or {}
            tags = (rule.get("properties") or {}).get("tags") or []
            items.append({
                "title": f"{source}: {rid}",
                "severity": severity(result.get("level") or props.get("severity")),
                "target": artifact,
                "line": region.get("startLine", ""),
                "evidence": message,
                "rule": rid,
                "cwe": _cwe_from(tags or props.get("cwe") or rule),
                "source": source,
                "source_path": artifact,
                "raw": result,
            })
    return items


def _generic_walk(value, source: str, path: str = "",
                  out: list[dict] | None = None, limit: int = 5000,
                  depth: int = 0, max_depth: int = 32,
                  seen_objects: set[int] | None = None) -> list[dict]:
    """Bounded recursive extraction for heterogeneous scanner records."""
    if out is None:
        out = []
    if seen_objects is None:
        seen_objects = set()
    if len(out) >= limit or depth > max(1, min(int(max_depth), 128)):
        return out
    if isinstance(value, (dict, list)):
        object_id = id(value)
        if object_id in seen_objects:
            return out
        seen_objects.add(object_id)
    if isinstance(value, dict):
        title = _first(
            value,
            "title", "name", "rule_id", "ruleId", "check_id", "test_name",
            "VulnerabilityID", "vulnerability_id", "Description", "description",
            "message", "Match", "DetectorName", "check_name", "rule_name",
            "rule_description", "warning_type", "type", "code", "RuleID",
        )
        sev = _first(value, "severity", "Severity", "issue_severity", "level", "risk")
        if not sev and any(k in value for k in ("Secret", "DetectorName", "hashed_secret", "warning_type", "check_id", "code")):
            sev = "MEDIUM"
        target = _first(
            value,
            "Target", "target", "file", "filename", "path", "File", "location",
            "resource", "ArtifactName", default=path,
        )
        line = _first(value, "line", "line_number", "Line", "StartLine", "start_line")
        cwe = _cwe_from(_first(value, "cwe", "CWE", "cwes", "Cwe", default=""))
        evidence = _first(
            value,
            "message", "Message", "description", "Description", "Match", "Secret",
            "code", "snippet", "Details", "detail", default="",
        )
        signal_keys = {
            "CVE", "VulnerabilityID", "vulnerability_id", "line_number", "StartLine",
            "Secret", "Match", "rule_id", "ruleId", "check_id", "DetectorName",
            "hashed_secret", "warning_type", "code", "RuleID",
        }
        if title and (sev or signal_keys.intersection(value.keys())):
            out.append({
                "title": f"{source}: {str(title)[:140]}",
                "severity": severity(sev),
                "target": str(target),
                "line": line,
                "evidence": str(evidence or json.dumps(value, ensure_ascii=False, default=str))[:2200],
                "rule": str(_first(value, "rule_id", "ruleId", "check_id", "VulnerabilityID", "code", "RuleID", default="")),
                "cwe": cwe,
                "source": source,
                "source_path": path,
                "raw": value,
            })
        for key, child in value.items():
            if len(out) >= limit:
                break
            _generic_walk(child, source, f"{path}/{key}", out, limit, depth + 1, max_depth, seen_objects)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if len(out) >= limit:
                break
            _generic_walk(child, source, f"{path}/{index}", out, limit, depth + 1, max_depth, seen_objects)
    return out


def _njsscan(data: dict, source: str, limit: int) -> list[dict]:
    """Keep rule/location relationships; parser errors are coverage failures.

    One candidate per rule retains every bounded occurrence. Metadata without
    a real file match cannot become a finding (including redacted rules).
    """
    items = []
    for section in ('nodejs', 'templates'):
        rules = data.get(section) or {}
        if not isinstance(rules, dict):
            continue
        for rule, result in rules.items():
            if len(items) >= limit:
                return items
            if not isinstance(result, dict):
                continue
            files = result.get('files') or []
            if not isinstance(files, list):
                continue
            matches = [f for f in files[:5000] if isinstance(f, dict)
                       and isinstance(f.get('file_path'), str) and f['file_path'].strip()
                       and isinstance(f.get('match_lines'), list) and f['match_lines']
                       and type(f['match_lines'][0]) is int and f['match_lines'][0] > 0]
            if not matches:
                continue
            meta = result.get('metadata') or {}
            if not isinstance(meta, dict):
                meta = {}
            first = matches[0]
            items.append({'title': f'{source}: {rule}', 'source': source, 'rule': rule,
                          'severity': severity(meta.get('severity')), 'target': first['file_path'],
                          'source_path': first['file_path'], 'line': first['match_lines'][0],
                          'cwe': _cwe_from(meta.get('cwe')),
                          'evidence': str(meta.get('description') or rule),
                          'occurrences': matches, 'raw': result})
    return items


def scanner_diagnostics(path, source):
    """Diagnostics are separate from vulnerabilities and remain visible."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return [{'kind': 'parser-error', 'reason': 'Malformed or unreadable scanner JSON'}]
    if 'njsscan' in str(source).lower() and isinstance(data, dict):
        return [{'kind': 'parser-error', 'reason': str(e.get('message', 'Scanner parse error'))[:500],
                 'path': str(e.get('path', ''))} for e in data.get('errors', [])
                if isinstance(e, dict)]
    return []


def _checkov(data, source, limit):
    """Checkov's passed/skipped checks are inventory, never vulnerabilities."""
    documents = data if isinstance(data, list) else [data]
    items = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        results = document.get('results') or {}
        if not isinstance(results, dict):
            continue
        for result in results.get('failed_checks', []) or []:
            if len(items) >= limit:
                return items
            if (not isinstance(result, dict) or
                    (result.get('check_result') or {}).get('result') != 'FAILED'):
                continue
            target = result.get('file_abs_path') or result.get('file_path')
            rule = result.get('check_id')
            if not isinstance(target, str) or not target or not isinstance(rule, str) or not rule:
                continue
            lines = result.get('file_line_range') or []
            items.append({'title': f'{source}: {rule}', 'source': source, 'rule': rule,
                'target': target, 'source_path': target, 'line': lines[0] if lines else '',
                'severity': severity(result.get('severity') or 'LOW'), 'cwe': '',
                'evidence': str(result.get('check_name') or rule), 'raw': result})
    return items


def parse_json_value(data, source: str, max_items: int = 5000) -> list[dict]:
    items: list[dict] = []
    # SARIF has a well-defined result structure. Running the generic recursive
    # parser over the same document duplicates each result and can lose the
    # rule/location relationship, so use only the dedicated SARIF parser.
    if ('checkov' in source.lower() or
            isinstance(data, dict) and 'check_type' in data and 'results' in data or
            isinstance(data, list) and any(isinstance(d, dict) and 'check_type' in d and 'results' in d for d in data)):
        items.extend(_checkov(data, source, max_items))
    elif isinstance(data, dict) and ('njsscan' in source.lower() or 'njsscan_version' in data):
        items.extend(_njsscan(data, source, max_items))
    elif isinstance(data, dict) and isinstance(data.get("runs"), list):
        items.extend(_sarif(data, source, max_items))
    else:
        items.extend(_generic_walk(data, source, limit=max_items))
    # Deduplicate within one imported file.
    seen = set()
    deduped = []
    for item in items:
        key = (item.get("title"), item.get("target"), str(item.get("line")), item.get("evidence"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def parse_file(path: str | Path, source: str | None = None, max_items: int = 5000) -> list[dict]:
    p = Path(path)
    source = source or p.stem
    suffix = p.suffix.lower()
    max_items = max(0, min(int(max_items), 50_000))
    try:
        if p.stat().st_size > 100_000_000:
            return []
    except OSError:
        return []

    out: list[dict] = []
    if suffix == ".jsonl":
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except Exception:
                        continue
                    out.extend(parse_json_value(value, source, max_items=max(0, max_items - len(out))))
                    if len(out) >= max_items:
                        break
        except Exception:
            return []
        seen = set()
        deduped = []
        for item in out:
            key = (item.get("title"), item.get("target"), str(item.get("line")), item.get("evidence"))
            if key in seen:
                continue
            seen.add(key); deduped.append(item)
        return deduped[:max_items]

    try:
        data = json.loads(p.read_text(errors="ignore"))
    except Exception:
        return []
    return parse_json_value(data, source, max_items=max_items)


def iter_result_files(path: str | Path) -> Iterable[Path]:
    p = Path(path)
    candidates = [p] if p.is_file() else p.rglob("*") if p.is_dir() else []
    for file in candidates:
        if (file.is_file() and file.suffix.lower() in {".json", ".jsonl", ".sarif"}
                and file.stat().st_size <= 100_000_000):
            yield file


def save_items(ctx, phase: str, items: list[dict], source: str,
               extra_fields: dict | None = None) -> int:
    count = 0
    for item in items:
        sev = severity(item.get("severity"))
        target = item.get("target", "")
        line = item.get("line", "")
        evidence = f"{target}:{line} {item.get('evidence', '')}".strip()
        finding = {
            "phase": phase,
            "severity": sev,
            "confidence": "MEDIUM",
            "title": f"Scanner observation candidate — {item.get('title', source)}"[:180],
            "target": target,
            "url": "",
            "description": (
                f"Read-only result normalized from {source}. This is a scanner observation, "
                "not proof of exploitability. Validate source reachability, runtime behavior, "
                "affected versions, and compensating controls before reporting it as confirmed."
            ),
            "evidence": evidence[:2400],
            "impact": "Potential code, dependency, secret, or configuration risk; impact depends on validation.",
            "remediation": "Validate the observation, remediate the underlying issue, add a regression test, and rerun the relevant scanner.",
            "cwe": item.get("cwe") or "",
            "mrs_score": 70 if sev in {"CRITICAL", "HIGH"} else 45,
            "scanner_source": source,
            "scanner_rule": item.get("rule", ""),
            "scanner_occurrences": item.get("occurrences", []),
            "status": "lead",
            "finding_class": "lead",
            "validation_required": "Imported scanner observation requires independent verification.",
        }
        if extra_fields:
            finding.update(extra_fields)
        finding_id = ctx.save_finding(finding)
        if finding_id is not None:
            count += 1
    return count
