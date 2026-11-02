"""Reverse-engineering compatibility phase (v3.9.3-restore).

Retained for v3.8 command compatibility AND restored to perform the original
bounded, dependency-free static checks on a supplied --binary-path, which the
v3.9.2 refactor accidentally dropped (the native reverse_static_analysis phase
requires Ghidra/IDA/radare2 to be installed; this phase must still produce
findings when those heavy tools are absent).

What this phase does, in order:
  1. If --binary-path is supplied: for each artifact (bounded by count/size),
     compute SHA-256/MD5, sample entropy, magic type; extract printable
     strings; derive URL/IP/secret-marker/suspicious-import indicators; emit
     bounded, deduplicated findings. Every secret-marker candidate is passed
     through the same fp_filters gate used everywhere else, so documented
     example/placeholder strings never resurface here.
  2. If --reverse-results is supplied: normalize JSON/JSONL/SARIF exports.
  3. Always writes a migration summary pointing at the native workflow.

Safety: the supplied artifact is NEVER executed. This is pure static read.
It reuses core.reverse_utils and core.code_patterns primitives so behaviour is
consistent with the rest of the tool and adds no third-party dependency.
"""
from __future__ import annotations

import json
from pathlib import Path

from core import redteam_utils as RT
from core import reverse_utils as RU
from core import code_patterns as CP
from core import fp_filters as FP
from core.scanner_normalizer import iter_result_files, parse_file, save_items


def emit(ctx, title, sev, target, ev, source):
    """v3.8 compatibility entry point; emits a non-confirming static lead."""
    ctx.save_finding({
        "phase": "reverse_engineering_tooling",
        "severity": str(sev or "INFO").upper() if str(sev or "INFO").upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO",
        "confidence": "MEDIUM",
        "title": str(title)[:180],
        "target": str(target),
        "url": "",
        "description": f"Static reverse-engineering observation from {source}. Dynamic execution was not performed.",
        "evidence": str(ev)[:2200],
        "impact": "May indicate unsafe capabilities, embedded secrets, insecure transport, dangerous imports, or vulnerable components.",
        "remediation": "Confirm reachability and business impact, remove secrets, harden the build, update components, and rerun analysis.",
        "cwe": "CWE-912",
        "mrs_score": 55,
    })


def import_json(ctx, path):
    """v3.8 compatibility normalizer backed by the current shared parser."""
    file = Path(path)
    return save_items(ctx, "reverse_engineering_tooling", parse_file(file, file.stem), file.stem)


def static_strings(ctx, path):
    """v3.8 compatibility static string review with current redaction gates."""
    file = Path(path)
    try:
        strings = RU.extract_strings(file, minimum=8, max_strings=5000)
    except Exception:
        return 0
    indicators = RU.indicators(strings)
    count = 0
    for url in indicators.get("urls", [])[:50]:
        if str(url).lower().startswith("http://"):
            emit(ctx, "Plaintext HTTP endpoint embedded", "MEDIUM", file, url, "built-in static strings")
            count += 1
    for item in indicators.get("suspicious_imports", [])[:40]:
        emit(ctx, "Process execution capability string", "MEDIUM", file, item.get("name", item), "built-in static strings")
        count += 1
    for candidate in RU.secret_candidates(strings)[:60]:
        value = str(candidate.get("value") or "")
        fake = {"evidence": value, "title": "embedded credential-like string", "target": str(file)}
        try:
            dummy, _reason = FP.is_dummy_secret(fake)
            if dummy:
                continue
        except Exception:
            pass
        emit(ctx, "Embedded credential-like string", "HIGH", file, "[REDACTED secret candidate]", "built-in static strings")
        count += 1
    return count


def _capa_items(path: Path, binary: Path) -> list[dict]:
    """Normalize same-run capa capabilities as bounded, non-confirming leads."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return []
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, dict):
        return []
    items = []
    for key, value in rules.items():
        if len(items) >= 500:
            break
        if not isinstance(value, dict) or not value.get("matches"):
            continue
        meta = value.get("meta") if isinstance(value.get("meta"), dict) else {}
        name = str(meta.get("name") or key)[:180]
        namespace = str(meta.get("namespace") or "")
        description = str(meta.get("description") or "Capability matched by capa static analysis.")
        count = len(value.get("matches") or {}) if isinstance(value.get("matches"), dict) else 1
        items.append({
            "title": f"capa capability: {name}",
            "severity": "LOW",
            "target": str(binary),
            "line": "",
            "evidence": f"{description} namespace={namespace or 'n/a'} match_groups={count}",
            "rule": str(key),
            "cwe": "",
        })
    return items


def _static_binary_review(ctx, out) -> int:
    """Original bounded static checks on --binary-path. Returns findings count."""
    bpath = getattr(ctx.args, "binary_path", None)
    if not bpath:
        return 0
    artifacts = list(RU.iter_files(
        bpath,
        getattr(ctx.args, "reverse_max_files", 50),
        getattr(ctx.args, "reverse_max_file_mb", 200),
    ))
    if not artifacts:
        RT.write_md(out / "BINARY_NOT_FOUND.md", "Binary Static Review — No Artifact", [
            ("Reason", f"--binary-path '{bpath}' matched no readable file within bounds."),
            ("Bounds", "reverse_max_files / reverse_max_file_mb apply."),
        ])
        return 0

    findings = 0
    index = []
    for binary in artifacts:
        stem = RU.safe_stem(binary)
        h = RU.hashes(binary)
        artifact_id = f"sha256:{h.get('sha256', '')}" if h.get("sha256") else ""
        ent = RU.sample_entropy(binary)
        mtype = RU.magic_type(binary)
        strings = RU.extract_strings(binary, minimum=8, max_strings=5000)
        ind = RU.indicators(strings)

        # v3.9.3 fix B: also detect dangerous APIs shorter than the string floor
        # (gets/system/popen/strcpy/WinExec/...) by scanning raw bytes.
        seen_imports = {i["name"] for i in ind.get("suspicious_imports", [])}
        ind["suspicious_imports"].extend(RU.raw_short_imports(binary, already=seen_imports))

        # v3.9.3 fix A: pull secret candidates WITH their value so the real value
        # (not the "[REDACTED]" label) is what the FP gate judges. Value stays in
        # memory only; evidence is stored redacted.
        secret_cands = RU.secret_candidates(strings)

        # v3.9.3 fix C: optional capa run when capa is installed and reverse
        # tooling is enabled (matches the old legacy behaviour).
        capa_out = None
        capa_observations = 0
        if getattr(ctx.args, "reverse_tooling", False) and ctx.runner.has("capa"):
            dest = out / f"{stem}.capa.json"
            try:
                rc, stdout, stderr = ctx.runner.run(
                    ["capa", "-j", str(binary)], timeout=900,
                    log_name=f"reverse_capa_{stem}")
                if rc == 0 and stdout.strip():
                    dest.write_text(stdout, encoding="utf-8")
                    capa_out = str(dest)
                    # Same-run output must not remain evidence-only. Normalize
                    # matched capabilities immediately as static leads, carrying
                    # the canonical artifact identity for later correlation.
                    capa_observations = save_items(
                        ctx, "reverse_engineering_tooling", _capa_items(dest, binary),
                        "capa", extra_fields={"artifact_id": artifact_id})
                    findings += capa_observations
            except Exception:
                capa_out = None
                capa_observations = 0

        record = {
            "binary": str(binary), "artifact_id": artifact_id,
            "sha256": h.get("sha256"), "md5": h.get("md5"),
            "entropy": round(ent, 2), "type": mtype,
            "string_count": len(strings),
            "urls": ind["urls"], "ips": ind["ips"],
            "secret_markers": ind["secret_markers"],
            "suspicious_imports": ind["suspicious_imports"],
            "capa_output": capa_out,
            "capa_observations_normalized": capa_observations,
            "execution_performed": False,
        }
        index.append(record)
        RU.write_json(out / f"{stem}.static.json", record)

        # 1) inventory finding (INFO) — always useful for the report/manifest
        ctx.save_finding({
            "phase": "reverse_engineering_tooling", "severity": "INFO", "confidence": "HIGH",
            "title": f"Binary static inventory: {binary.name}",
            "target": str(binary), "url": "", "artifact_id": artifact_id,
            "description": f"{mtype}; SHA-256 {h.get('sha256','?')}; entropy {ent:.2f}; "
                           f"{len(strings)} strings; {len(ind['urls'])} URL(s), "
                           f"{len(ind['ips'])} IP(s), {len(ind['suspicious_imports'])} suspicious import(s).",
            "evidence": f"{binary.name}: sha256={h.get('sha256','?')} type={mtype} entropy={ent:.2f}",
            "impact": "Baseline static metadata for the supplied artifact.",
            "remediation": "N/A — informational inventory.",
            "cwe": "", "mrs_score": 10, "verified": True,
            "verified_at": RT.now_iso() if hasattr(RT, "now_iso") else None,
        })
        findings += 1

        # 2) plaintext endpoints embedded in the binary (LOW — lead for follow-up)
        for url in ind["urls"][:50]:
            if url.lower().startswith("http://"):
                ctx.save_finding({
                    "phase": "reverse_engineering_tooling", "severity": "LOW", "confidence": "MEDIUM",
                    "title": f"Cleartext HTTP endpoint in binary: {binary.name}",
                    "target": str(binary), "url": "", "artifact_id": artifact_id,
                    "description": f"Binary references a cleartext HTTP endpoint: {url}",
                    "evidence": f"{binary.name}: {url}",
                    "impact": "Cleartext transport can expose data in transit / enable MITM.",
                    "remediation": "Use HTTPS; pin certificates where appropriate.",
                    "cwe": "CWE-319", "mrs_score": 30,
                })
                findings += 1

        # 3) suspicious process-execution / network imports (LOW — capability lead)
        for imp in ind["suspicious_imports"][:40]:
            ctx.save_finding({
                "phase": "reverse_engineering_tooling", "severity": "LOW", "confidence": "LOW",
                "title": f"Dangerous API import in binary: {imp['name']} ({binary.name})",
                "target": str(binary), "url": "", "artifact_id": artifact_id,
                "description": f"Binary imports/references {imp['name']}: {imp['reason']}. "
                               f"Capability lead only — confirm reachability via the native reverse workflow.",
                "evidence": f"{binary.name}: {imp['name']}",
                "impact": imp["reason"],
                "remediation": "Review the call site; ensure inputs to this API are not attacker-controlled.",
                "cwe": imp.get("cwe", ""), "mrs_score": 20,
            })
            findings += 1

        # 4) embedded secrets — v3.9.3 fix A: judge the REAL value with the fp
        #    gate (so a live-looking key survives and an example key is dropped),
        #    then store only the redacted form.
        for cand in secret_cands[:60]:
            # v3.9.3: judge by VALUE only. First screen the clean value directly
            # (we already have it, no re-parsing) against the shared placeholder/
            # example/entropy checks, so a binary named "sample.bin" or a value
            # like EXAMPLE_PLACEHOLDER is handled the same as anywhere else — but
            # web test/doc PATH suppression is NOT applied to a supplied binary.
            fake = {"evidence": f"x = \"{cand['value']}\"",
                    "title": "Hardcoded secret: Generic"}
            dummy, why = FP.is_dummy_secret(fake)
            if dummy:
                continue
            pseudo = {
                "phase": "reverse_engineering_tooling",
                "title": f"Hardcoded secret in binary: {binary.name}",
                "target": "binary://artifact",   # neutral: no test/doc path signal
                "confidence": "MEDIUM",
                "evidence": f"binary://artifact: {cand['label']}={cand['value']}",
            }
            action, reason, _tier = FP.assess(pseudo)
            if action == "drop":
                continue
            ctx.save_finding({
                "phase": "reverse_engineering_tooling",
                "severity": "MEDIUM" if action == "keep" else "LOW",
                "confidence": "MEDIUM" if action == "keep" else "LOW",
                "title": f"Hardcoded secret in binary: {binary.name}",
                "target": str(binary), "url": "", "artifact_id": artifact_id,
                "description": f"A secret ({cand['label']}) was found in the binary. "
                               f"Value redacted here; validate whether it is live before reporting "
                               f"(consider --validate-secrets).",
                # stored evidence is REDACTED — real value never persisted
                "evidence": f"{binary.name}: {cand['redacted']}",
                "impact": "Embedded credential exposure if the value is live.",
                "remediation": "Remove from the binary; load secrets at runtime from a secret store; rotate.",
                "cwe": "CWE-798", "mrs_score": 45,
            })
            findings += 1

    RU.write_json(out / "reverse_static_index.json", index)
    return findings


def run(ctx):
    if not (getattr(ctx.args, "reverse_tooling", False)
            or getattr(ctx.args, "reverse_results", None)
            or getattr(ctx.args, "binary_path", None)):
        return
    out = RT.evidence_dir(ctx, "25_reverse_engineering_tooling_legacy")

    # 1) restored: bounded dependency-free static review of the supplied binary
    static_findings = _static_binary_review(ctx, out)

    # 2) retained: normalize any supplied JSON/JSONL/SARIF exports
    import_count = 0
    supplied = getattr(ctx.args, "reverse_results", None)
    default_artifact_id = ""
    supplied_artifacts = list(RU.iter_files(
        getattr(ctx.args, "binary_path", None),
        getattr(ctx.args, "reverse_max_files", 50),
        getattr(ctx.args, "reverse_max_file_mb", 200),
    ))
    if len(supplied_artifacts) == 1:
        default_artifact_id = RU.artifact_id(supplied_artifacts[0])
    if supplied:
        for result in iter_result_files(supplied):
            import_count += save_items(
                ctx, "reverse_engineering_tooling",
                parse_file(result, result.stem), result.stem,
                extra_fields={"artifact_id": default_artifact_id} if default_artifact_id else None)

    RT.write_md(out / "REVERSE_ENGINEERING_TOOLING_SUMMARY.md", "Reverse Engineering Adapter", [
        ("Static binary findings", str(static_findings)),
        ("Normalized observations", str(import_count)),
        ("Native workflow", "reverse_triage -> reverse_static_analysis -> reverse_dynamic_evidence -> reverse_symbolic_analysis -> reverse_correlation"),
        ("Compatibility", "Runs bounded static checks on --binary-path even when Ghidra/IDA/radare2 are absent; also normalizes generic JSON/JSONL/SARIF exports."),
        ("Safety", "The supplied artifact is never executed."),
    ])
    ctx.log("OK", "reverse_engineering_tooling",
            f"static binary findings: {static_findings}; normalized {import_count} legacy observation(s)")
