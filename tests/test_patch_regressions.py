"""Regression tests for the v4.0.0-unified-safe patch set (2026-08).

Each test pins a specific bug that was fixed so it cannot silently return.
Run: python3 -m pytest tests/test_patch_regressions.py -q
  or: python3 tests/test_patch_regressions.py   (falls back to a plain runner)
"""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


# ── Bug 1: open-redirect must compare the Location HOST, not substring ──────────
def _redirect_host():
    src = open(os.path.join(ROOT, "phases/injections.py")).read()
    m = re.search(r"def _redirect_host\(.*?(?=\ndef _open_redirect)", src, re.S)
    ns = {}; exec("from urllib.parse import urlparse\n" + m.group(0), ns)
    return ns["_redirect_host"]

def test_open_redirect_host_parsing():
    f = _redirect_host()
    # real redirects -> attacker host
    assert f("https://evil.example.com/") == "evil.example.com"
    assert f("//evil.example.com/") == "evil.example.com"
    # F11: without // this is a relative path, not a URL authority.
    assert f("evil.example.com/x") == ""
    # false positives that must NOT resolve to the attacker host
    assert f("/redirect?next=https://evil.example.com") == ""       # on-site
    # suffix trick: real host is the full name, NOT evil.example.com, so the
    # open-redirect check (which compares == "evil.example.com") will not fire.
    assert f("https://evil.example.com.target.com/") == "evil.example.com.target.com"
    assert f("https://evil.example.com.target.com/") != "evil.example.com"
    assert f("/account/login") == ""


# ── Bug 2: injections payload must survive backslash/group-ref chars ────────────
def test_injection_payload_no_regex_corruption():
    import re as _re
    def new(url, param, pl):
        return _re.sub(rf"({_re.escape(param)}=)[^&]*", lambda m: m.group(1) + pl, url, count=1)
    url = "https://h/item?id=1&x=2"
    for pl in [r"..\..\win.ini", r"\1\1", r"\g<0>", r"../../etc/passwd", "' OR '1'='1"]:
        got = new(url, "id", pl).split("id=")[1].split("&")[0]
        assert got == pl, f"payload corrupted: {pl!r} -> {got!r}"
    # ensure the live file actually uses the lambda form, not rf"\1{...}"
    src = open(os.path.join(ROOT, "phases/injections.py")).read()
    assert 'rf"\\1{' not in src, "interpolated re.sub replacement still present"


# ── Bug 3: subzy/takeover banner -> LEAD; CVE never downgraded; normals untouched ─
def _to_finding():
    from phases.nuclei_extended import _to_finding
    return _to_finding


def test_takeover_downgrade_and_cve_guard():
    f = _to_finding()
    # banner takeover (any severity) -> LOW / LEAD / text validation
    r = f({"template-id":"subzy","matched-at":"https://x.me",
           "info":{"name":"T","severity":"high","tags":"takeover,dns"},
           "extracted-results":["There isn't a GitHub Pages site here."]}, "takeover", 85)
    assert r["severity"] == "LOW" and r["finding_class"] == "lead"
    assert isinstance(r["validation_required"], str) and r["validation_required"] != "True"
    # MEDIUM takeover also downgraded
    r = f({"template-id":"azure-takeover","matched-at":"https://x.me",
           "info":{"name":"T","severity":"medium","tags":"takeover"}}, "takeover", 85)
    assert r["severity"] == "LOW" and r["finding_class"] == "lead"
    # CVE severity is retained; a match without captured exchange remains a lead
    r = f({"template-id":"CVE-2023-1","matched-at":"https://x.me",
           "info":{"name":"RCE","severity":"critical","tags":"cve,takeover"}}, "cves", 85)
    assert r["severity"] == "CRITICAL" and r["finding_class"] == "lead"
    # A normal match also needs captured evidence before support classification
    r = f({"template-id":"cors","matched-at":"https://x.me",
           "info":{"name":"CORS","severity":"medium","tags":"misconfig"}}, "x", 85)
    assert r["finding_class"] == "lead" and r["evidence_capture_status"] == "missing-http-exchange"


# ── Bug 4: --resume always-rerun set covers downstream DB-reading phases ─────────
def test_resume_rerun_set():
    src = open(os.path.join(ROOT, "tbhm.py")).read()
    m = re.search(r"_ALWAYS_RERUN_ON_RESUME = \{(.*?)\}", src, re.S)
    body = m.group(1)
    for ph in ["report","evidence_finalize","dashboard","fp_review","attack_path",
               "compliance_coverage","coverage_map","vulnerability_intelligence_enrichment"]:
        assert f'"{ph}"' in body, f"{ph} missing from resume rerun set"


# ── Bug 5: llm_local falls back to /api/generate on /api/chat 400 ───────────────
def test_llm_generate_fallback_exists():
    src = open(os.path.join(ROOT, "core/llm_local.py")).read()
    assert "_generate_fallback" in src
    assert "/api/generate" in src
    assert "status_code == 400" in src


# ── Bug B (the one that regressed twice): scope must NOT allow-all w/o includes ──
def test_scope_no_allowlist_denies_external():
    from core.scope import Scope
    from core import targets as T
    class Ctx:
        def __init__(s, scope, domains): s.scope=scope; s.targets=domains; s.scope_excludes=[]
    # NO --scope file => Scope([],[]); target is api.example.com only
    c = Ctx(Scope([], []), ["api.example.com"])
    assert T.target_scope_allows(c, "api.example.com") is True
    assert T.target_scope_allows(c, "v2.api.example.com") is True
    assert T.target_scope_allows(c, "admin.example.com") is False
    assert T.target_scope_allows(c, "example.com") is False
    assert T.target_scope_allows(c, "google.com") is False        # the regression
    # WITH an allowlist it is authoritative
    c = Ctx(Scope(["api.example.com"], []), ["api.example.com"])
    assert T.target_scope_allows(c, "api.example.com") is True
    assert T.target_scope_allows(c, "google.com") is False


# ── smart_crawl must use the CENTRAL scope authority, not its own _in_scope ──────
def test_smart_crawl_uses_central_scope():
    src = open(os.path.join(ROOT, "phases/smart_crawl.py")).read()
    # the crawl loop and headless pass must both call target_scope_allows
    assert "target_scope_allows(ctx, url)" in src, "HTTP loop not routed to central scope"
    assert "target_scope_allows(ctx, u)" in src, "headless pass not routed to central scope"
    # and it must NOT still gate the loop on the old root-domain _in_scope
    assert "if not _in_scope(url, root_domains" not in src, "old _in_scope gate still active"
    # behavioral: crawler decision == engine decision for a sibling the allowlist denies
    import sys; sys.path.insert(0, ROOT)
    from core.scope import Scope
    from core import targets as T
    class Ctx:
        def __init__(s): s.scope=Scope(["api.example.com"],[]); s.targets=["api.example.com"]; s.scope_excludes=[]
    c=Ctx()
    assert T.target_scope_allows(c,"https://api.example.com/x") is True
    assert T.target_scope_allows(c,"https://admin.example.com/x") is False   # old crawler said True
    assert T.target_scope_allows(c,"https://google-analytics.com/x") is False


# ── Exact vs wildcard scope typing (core/scope.py) ──────────────────────────────
def test_scope_exact_vs_wildcard_typing():
    import sys; sys.path.insert(0, ROOT)
    from core.scope import Scope
    # =exact : host only, no subdomains, no apex
    ex = Scope(["=api.example.com"], [])
    assert ex.allows("api.example.com") is True
    assert ex.allows("v2.api.example.com") is False
    assert ex.allows("example.com") is False
    assert ex.allows("api.example.com.evil.com") is False
    # *.wildcard : subdomains yes, apex NO (HackerOne semantics) — unchanged
    wc = Scope(["*.example.com"], [])
    assert wc.allows("api.example.com") is True
    assert wc.allows("example.com") is False
    # bare : subdomain-inclusive (apex + subs) — unchanged / backward compatible
    bare = Scope(["example.com"], [])
    assert bare.allows("example.com") is True
    assert bare.allows("api.example.com") is True
    assert bare.allows("example.com.evil.com") is False
    # existing glob forms unchanged
    assert Scope(["static*.twilio.com"], []).allows("static1.twilio.com") is True
    assert Scope(["*.sip.*.twilio.com"], []).allows("foo.sip.us1.twilio.com") is True
    assert Scope(["*.sip.*.twilio.com"], []).allows("sip.twilio.com") is False
    # exact composes with wildcard and propagates through the shared authority
    from core import targets as T
    class Ctx:
        def __init__(s): s.scope=Scope(["=api.example.com"],[]); s.targets=["api.example.com"]; s.scope_excludes=[]
    c=Ctx()
    assert T.target_scope_allows(c, "https://api.example.com/x") is True
    assert T.target_scope_allows(c, "https://v2.api.example.com/x") is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception as e:
            failed += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
