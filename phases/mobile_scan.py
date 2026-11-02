"""
Phase: mobile_scan   (v2.17)

Mobile app analysis. Mobile apps are the richest source of hardcoded API keys,
Firebase/S3 URLs, and backend endpoints — they ship the credentials inside the
binary. This phase extracts that surface.

Inputs (any of):
  --apk PATH         Android package (.apk)
  --ipa PATH         iOS package (.ipa)
  --mobile-src PATH  mobile app source tree (open-source app)
Skips silently if none provided.

Approach (degrades gracefully by available tooling):
  APK:
    - unzip; run `strings` on classes*.dex + resources.arsc + assets → secrets/endpoints
    - AndroidManifest.xml is binary AXML: parsed via `aapt dump xmltree` if present,
      else `apktool`, else string-grep fallback. Flags exported components,
      debuggable, allowBackup, cleartext traffic, and deep-link schemes.
  IPA:
    - unzip; locate Payload/*.app; scan Info.plist (plutil if present, else strings)
      and the Mach-O binary strings → secrets/endpoints; flag ATS exceptions and
      URL schemes.
  Source tree:
    - walk files through the shared pattern engine (same as code_scan).

Extracted endpoints/hosts are written to <output>/mobile/ for api_fuzz/recon.
"""
from __future__ import annotations

import plistlib
import re
import subprocess
import zipfile
import json
import hashlib

from core.safe_archive import safe_extract_zip
from pathlib import Path

from core import code_patterns as CP
from core.android_manifest import application_booleans, manifest_inventory

_STRINGS_MIN = 6


def _strings(path: Path, minlen: int = _STRINGS_MIN) -> str:
    """Extract printable strings from a binary, using `strings` if available."""
    import shutil
    if shutil.which("strings"):
        try:
            r = subprocess.run(["strings", "-n", str(minlen), str(path)],
                               capture_output=True, text=True, timeout=120)
            return r.stdout
        except Exception:
            pass
    # Pure-python fallback.
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return "\n".join(out)


def _emit(ctx, finding):
    ctx.save_finding(finding)


def run(ctx):
    apk = getattr(ctx.args, "apk", None)
    ipa = getattr(ctx.args, "ipa", None)
    src = getattr(ctx.args, "mobile_src", None)
    out_dir = ctx.output / "mobile"
    out_dir.mkdir(exist_ok=True)
    supplied = {'apk': apk, 'ipa': ipa, 'mobile_src': src}
    receipt = {'schema': 'tbhm.mobile-capability/1', 'inputs': {},
               'dynamic_device_testing_executed': False}
    for kind, value in supplied.items():
        exists = bool(value) and (Path(value).is_dir() if kind == 'mobile_src' else Path(value).is_file())
        receipt['inputs'][kind] = {'status': 'provided' if exists else 'missing' if value else 'not_requested',
                                  'static_analysis_attempted': False}
    (out_dir/'capability_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    missing = [kind for kind, state in receipt['inputs'].items() if state['status'] == 'missing']
    if missing:
        raise ValueError('Explicit mobile input missing: '+', '.join(missing))
    if not (apk or ipa or src):
        ctx.log('INFO', 'mobile_scan', 'No app artifact/source supplied; mobile testing not requested.')
        return

    urls, paths, hosts = set(), set(), set()

    if apk and Path(apk).is_file():
        receipt['inputs']['apk']['static_analysis_attempted'] = True
        (out_dir/'capability_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        _scan_apk(ctx, Path(apk), out_dir, urls, paths, hosts)
    if ipa and Path(ipa).is_file():
        receipt['inputs']['ipa']['static_analysis_attempted'] = True
        (out_dir/'capability_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        _scan_ipa(ctx, Path(ipa), out_dir, urls, paths, hosts)
    if src and Path(src).is_dir():
        receipt['inputs']['mobile_src']['static_analysis_attempted'] = True
        (out_dir/'capability_receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        _scan_source(ctx, Path(src), urls, paths, hosts)

    if paths:
        (out_dir / "endpoints.txt").write_text("\n".join(sorted(paths)))
    if urls:
        (out_dir / "urls.txt").write_text("\n".join(sorted(urls)))
    if hosts:
        (out_dir / "hosts.txt").write_text("\n".join(sorted(hosts)))
    ctx.log("OK", "mobile_scan",
            f"mobile_scan: {len(paths)} API paths + {len(hosts)} hosts extracted → {out_dir}")


def _scan_text_blob(ctx, text, label, urls, paths, hosts):
    for s in CP.find_secrets(text, label):
        _emit(ctx, {
            "phase": "mobile_scan",
            "severity": s["severity"],
            "confidence": "MEDIUM" if "Generic" in s["type"] else "HIGH",
            "title": f"Hardcoded secret in mobile app: {s['type']}",
            "target": label, "url": "",
            "description": f"{s['type']} embedded in {label}. Mobile binaries are trivially "
                           f"unpacked, so shipped credentials are effectively public.",
            "evidence": s["match"],
            "impact": "Credential exposure; verify if live and rotate.",
            "remediation": "Never ship secrets in the app; proxy through a backend.",
            "mrs_score": {"HIGH": 80, "MEDIUM": 55, "LOW": 35}.get(s["severity"], 40),
        })
    ep = CP.find_endpoints(text)
    urls.update(ep["urls"]); paths.update(ep["paths"]); hosts.update(ep["hosts"])


def _scan_apk(ctx, apk, out_dir, urls, paths, hosts):
    ctx.log("INFO", "mobile_scan", f"━━━ APK: {apk.name} ━━━")
    work = out_dir / "_apk" / apk.stem
    work.mkdir(parents=True, exist_ok=True)
    try:
        report = safe_extract_zip(apk, work)
        if not report.safe:
            ctx.log("WARN", "mobile_scan", f"APK extraction rejected {len(report.rejected)} unsafe member(s): {report.rejected[:5]}")
        if report.truncated:
            ctx.log("WARN", "mobile_scan", f"APK extraction hit a safety cap; {report.extracted} file(s) extracted")
        if report.extracted == 0:
            ctx.log("WARN", "mobile_scan", "APK produced no safe extractable members")
            return
    except Exception as e:
        ctx.log("WARN", "mobile_scan", f"cannot unzip APK: {e}")
        return

    # 1) strings on dex + resources + assets
    blob = []
    for pat in ("classes*.dex", "resources.arsc"):
        for f in work.glob(pat):
            blob.append(_strings(f))
    for f in (work / "assets").rglob("*") if (work / "assets").is_dir() else []:
        if f.is_file() and f.suffix.lower() in CP.SCAN_EXT:
            try:
                blob.append(f.read_text(errors="ignore"))
            except Exception:
                pass
    _scan_text_blob(ctx, "\n".join(blob), f"{apk.name}:dex/resources", urls, paths, hosts)

    # 2) AndroidManifest analysis
    _analyze_manifest(ctx, apk, work)


def _analyze_manifest(ctx, apk, work):
    manifest = work / "AndroidManifest.xml"
    text = ""
    # aapt gives clean xmltree from the original APK (binary AXML).
    import shutil
    if shutil.which("aapt"):
        try:
            r = subprocess.run(["aapt", "dump", "xmltree", str(apk), "AndroidManifest.xml"],
                               capture_output=True, text=True, timeout=60)
            text = r.stdout if r.returncode == 0 else ''
        except Exception:
            pass
    if not text and shutil.which("aapt2"):
        try:
            r = subprocess.run(["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
                               capture_output=True, text=True, timeout=60)
            text = r.stdout if r.returncode == 0 else ''
        except Exception:
            pass
    if not text and manifest.exists():
        # Decoded XML can be parsed directly. Raw AXML strings are not boolean
        # proof; without a working decoder those declarations stay unknown.
        if manifest.stat().st_size <= 2_000_000:
            text = manifest.read_text(errors='replace')

    if not text:
        _record_manifest(ctx, '', str(apk))
        ctx.log("INFO", "mobile_scan", "manifest unreadable (install aapt for full analysis)")
        return

    findings = []
    low = text.lower()
    settings = application_booleans(text)
    if settings['debuggable'] is True:
        findings.append(("HIGH", "Debuggable application",
                         "android:debuggable=true ships a debuggable build — allows runtime tampering and data extraction."))
    if settings['allowBackup'] is True:
        findings.append(("LOW", "Backup allowed",
                         "android:allowBackup=true declares backup enabled; platform version and policy determine actual extraction."))
    if settings['usesCleartextTraffic'] is True:
        findings.append(("MEDIUM", "Cleartext traffic allowed",
                         "usesCleartextTraffic=true declares cleartext permitted; review networkSecurityConfig and verify actual runtime traffic."))
    inventory = _record_manifest(ctx, text, str(apk))
    exported = sum(c['exposure'] == 'exported_by_declaration' and
                   c['review'] == 'exported_without_declared_permission_review_required'
                   for c in inventory['components'])
    if exported:
        findings.append(("INFO", f"{exported} exported component(s) without declared permissions",
                         "Static review candidates. Exported components can be intentional; runtime authorization and data access are unverified."))
    # Deep link schemes.
    schemes = set(re.findall(r'scheme[^\n]*"([a-z][a-z0-9+.\-]*)"', text, re.I))
    schemes -= {"http", "https", "package"}
    if schemes:
        findings.append(("INFO", f"Deep-link schemes: {', '.join(sorted(schemes)[:8])}",
                         "Custom URL schemes are attack surface — test deep-link handling for auth bypass / parameter injection."))

    for sev, title, desc in findings:
        _emit(ctx, {
            "phase": "mobile_scan", "severity": sev, "confidence": "MEDIUM",
            "title": f"Android manifest: {title}", "target": apk.name, "url": "",
            "description": desc, "evidence": f"AndroidManifest.xml ({apk.name})",
            "impact": desc, "remediation": "Harden the manifest; restrict exported components and disable debug/cleartext in release builds.",
            "mrs_score": {"HIGH": 70, "MEDIUM": 45, "LOW": 30, "INFO": 20}.get(sev, 25),
        })


def _scan_ipa(ctx, ipa, out_dir, urls, paths, hosts):
    ctx.log("INFO", "mobile_scan", f"━━━ IPA: {ipa.name} ━━━")
    work = out_dir / "_ipa" / ipa.stem
    work.mkdir(parents=True, exist_ok=True)
    try:
        report = safe_extract_zip(ipa, work)
        if not report.safe:
            ctx.log("WARN", "mobile_scan", f"IPA extraction rejected {len(report.rejected)} unsafe member(s): {report.rejected[:5]}")
        if report.truncated:
            ctx.log("WARN", "mobile_scan", f"IPA extraction hit a safety cap; {report.extracted} file(s) extracted")
        if report.extracted == 0:
            ctx.log("WARN", "mobile_scan", "IPA produced no safe extractable members")
            return
    except Exception as e:
        ctx.log("WARN", "mobile_scan", f"cannot unzip IPA: {e}")
        return
    apps = list((work / "Payload").glob("*.app")) if (work / "Payload").is_dir() else []
    blob = []
    for app in apps:
        # Info.plist
        plist = app / "Info.plist"
        if plist.exists():
            try:
                pl = plistlib.loads(plist.read_bytes())
                blob.append(str(pl))
                # ATS exceptions
                ats = pl.get("NSAppTransportSecurity", {})
                if ats.get("NSAllowsArbitraryLoads"):
                    _emit(ctx, {"phase": "mobile_scan", "severity": "MEDIUM", "confidence": "HIGH",
                                "title": "iOS ATS disabled (NSAllowsArbitraryLoads)", "target": ipa.name, "url": "",
                                "description": "App Transport Security disabled — allows plaintext HTTP connections.",
                                "evidence": "Info.plist NSAppTransportSecurity",
                                "impact": "MITM / plaintext interception risk.",
                                "remediation": "Remove NSAllowsArbitraryLoads; scope exceptions narrowly.",
                                "mrs_score": 45})
                # URL schemes
                for url_t in pl.get("CFBundleURLTypes", []):
                    for sch in url_t.get("CFBundleURLSchemes", []):
                        _emit(ctx, {"phase": "mobile_scan", "severity": "INFO", "confidence": "MEDIUM",
                                    "title": f"iOS URL scheme: {sch}", "target": ipa.name, "url": "",
                                    "description": "Custom URL scheme — test deep-link handling.",
                                    "evidence": f"CFBundleURLSchemes: {sch}", "impact": "Deep-link attack surface.",
                                    "remediation": "Validate deep-link inputs; prefer universal links.",
                                    "mrs_score": 20})
            except Exception:
                blob.append(_strings(plist, 4))
        # Mach-O binary strings (executable named like the app)
        for f in app.iterdir():
            if f.is_file() and not f.suffix:
                blob.append(_strings(f))
    if not apps:
        # Just string the whole thing.
        for f in work.rglob("*"):
            if f.is_file():
                blob.append(_strings(f))
                break
    _scan_text_blob(ctx, "\n".join(blob), f"{ipa.name}:binary/plist", urls, paths, hosts)


def _scan_source(ctx, root, urls, paths, hosts):
    ctx.log("INFO", "mobile_scan", f"━━━ mobile source: {root} ━━━")
    n = 0
    for f in root.rglob("*"):
        if f.is_symlink() or not f.is_file() or any(p in CP.SKIP_DIRS for p in f.parts):
            continue
        if f.name == 'AndroidManifest.xml' and f.stat().st_size <= 2_000_000:
            # Source manifests participate in the same inventory as APK XML.
            _record_manifest(ctx, f.read_text(errors='replace'), str(f.relative_to(root)))
        if f.suffix.lower() in CP.SKIP_EXT or CP.is_minified(f.name):
            continue
        if f.suffix.lower() not in CP.SCAN_EXT:
            continue
        try:
            if f.stat().st_size > 2_000_000:
                continue
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        n += 1
        rel = str(f.relative_to(root))
        _scan_text_blob(ctx, text, rel, urls, paths, hosts)
    ctx.log("INFO", "mobile_scan", f"scanned {n} mobile source files")


def _record_manifest(ctx, text, label):
    result = manifest_inventory(text)
    if hasattr(ctx, 'output'):
        out = ctx.output/'mobile'; out.mkdir(exist_ok=True)
        key = hashlib.sha256(label.encode()).hexdigest()[:12]
        result['source'] = label
        (out/f'manifest_{key}.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
        if result['status'] != 'complete' and getattr(ctx, 'execution_ledger', None):
            ctx.execution_ledger.record(kind='artifact', status='partial', artifact=f'mobile/manifest_{key}.json', reason='component inventory incomplete; decoded XML required')
    return result
