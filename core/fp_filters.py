"""
core/fp_filters.py   (v3.5)

Central false-positive gate applied to EVERY finding at save time, plus helpers
code_scan / code_intel use to keep noise out of the report in the first place.

Grounded in observed real FPs from the Anthropic-targets run:
  * AWS docs example key AKIAIOSFODNN7EXAMPLE flagged HIGH in *Tests.cs
  * ghp_XXXX... placeholder flagged HIGH inside sanitizer.ts (the redactor itself)
  * jwt.io demo JWT (sub=1234567890) flagged HIGH in test fixtures
  * pickle.loads / os.system / innerHTML matched in test, bench, docs, and in the
    scanner's OWN pattern-definition files (security-guidance/hooks/patterns.py)
  * gitleaks generic/sourcegraph rule matched 40-hex git SHAs / plugin IDs in
    marketplace.json manifests (2242 hits from one file)
  * dataset column names (BLS_percent_women_2019) matched generic-api-key
  * synthetic [chain] findings with no verified underlying primitive

Design: conservative. DROPS clear noise and DOWNGRADES borderline items to
"lead" (kept, out of the confirmed report). Every drop carries a reason and is
archived by the caller — nothing is silently deleted.
"""
from __future__ import annotations

import binascii
import math
import re

# ── path context ─────────────────────────────────────────────────────────────
_TEST_DOC_SEGMENTS = re.compile(
    r"(?i)(^|[/\\.])("
    r"tests?|__tests__|__mocks__|mocks?|fixtures?|testdata|test_data|"
    r"examples?|samples?|demos?|docs?|documentation|"
    r"vendor|node_modules|third_party|3rdparty|migrations|"
    r"\.claude|\.github|\.vscode|\.idea|storybook|\.storybook|e2e|cypress|"
    r"benchmarks?|bench|spec|specs|winogenerated|datasets?|eval|evals"
    r")([/\\.]|$)"
)
_TEST_DOC_FILENAME = re.compile(
    r"(?i)("
    r"[._-]tests?\.[a-z0-9]+$|tests?\.[a-z0-9]+$|"
    r"[._-]specs?\.[a-z0-9]+$|"
    r"\.(test|spec)\.[a-z0-9]+$|"
    r"\.(example|sample|dist|tmpl|template|golden|mock)$"
    r")"
)
_NONCODE_FILE = re.compile(
    r"(?i)("
    r"(^|[/\\])(license|licence|copying|notice|changelog|changes|history|"
    r"readme|contributing|authors|code_of_conduct|security)([._-][^/\\]*)?$|"
    r"\.(md|markdown|rst|txt|adoc)$"
    r")"
)
_DATA_MANIFEST_FILE = re.compile(
    r"(?i)("
    r"\.(json|jsonl|ndjson|csv|tsv|parquet|lock|sum)$|"
    r"(^|[/\\])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|"
    r"gemfile\.lock|cargo\.lock|poetry\.lock|go\.sum|\.stats\.yml|"
    r"marketplace\.json)$"
    r")"
)
_SECURITY_TOOLING_FILE = re.compile(
    r"(?i)(sanitiz|redact|scrubb?|pattern|detector|detect_|signatures?|"
    r"secret[_-]?scan|gitleaks|trufflehog|lint|linter|rules?|allowlist|"
    r"denylist|blocklist|security[_-]?guidance)"
)


def path_context(path: str) -> str:
    """Return 'test_doc' | 'noncode' | 'data' | 'security_tooling' | 'prod'."""
    p = str(path or "")
    fname = re.split(r"[/\\]", p)[-1] if p else ""
    if _SECURITY_TOOLING_FILE.search(fname):
        return "security_tooling"
    if _NONCODE_FILE.search(p):
        return "noncode"
    if _DATA_MANIFEST_FILE.search(p):
        return "data"
    if _TEST_DOC_FILENAME.search(fname) or _TEST_DOC_SEGMENTS.search(p):
        return "test_doc"
    return "prod"


# ── dummy / placeholder / example secrets ────────────────────────────────────
_DUMMY_LITERALS = {
    "secret", "password", "changeme", "change_me", "your_secret", "your-secret",
    "your_api_key", "yourapikey", "example", "test", "testing", "test_key",
    "testkey", "dummy", "placeholder", "redacted", "xxxxxx", "foobar", "foo",
    "bar", "123456", "abc123", "some_password", "somepassword", "invalid",
    "invalid_api_key", "invalid_key", "rotated-key", "ak-replace", "ak-match",
    "sk-prod-abc123", "my-secret-key", "my_secret", "mysecret", "s3cr3t",
    "password123", "admin", "root", "null", "none", "undefined", "sample",
    "aws_secret_access_key", "akiaiosfodnn7example",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
    "test-api-key-123456789", "your_access_token", "your-token", "access_token",
    "oidc-federation-2026-04-01", "whsec_c2vjcmv0cg==",
}
_EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}
_DUMMY_PATTERNS = re.compile(
    r"(?i)(^|[^a-z0-9])("
    r"your[_-]?|example|placeholder|change[_-]?me|dummy|sample|redacted|"
    r"test[_-]?|fake[_-]?|mock[_-]?|invalid|replace|rotated|x{4,}|<[^>]+>|"
    r"\.\.\.|todo|fixme|foobar|abc123|000000|sk[_-]test[_-]|sk-prod-)"
)
_ALL_PLACEHOLDER = re.compile(
    r"^(?:(.)\1{7,}|x{6,}|0{6,}|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\})$", re.I)
_HEX40 = re.compile(r"^[0-9a-f]{40}$", re.I)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_IDX = {c: i for i, c in enumerate(_B62)}


def _b62_decode(s: str) -> int:
    n = 0
    for c in s:
        if c not in _B62_IDX:
            return -1
        n = n * 62 + _B62_IDX[c]
    return n


def github_token_valid_checksum(token: str) -> bool:
    """True if a classic GitHub PAT's trailing 6-char base62 CRC32 checks out.
    Placeholders like ghp_XXXX... and ghp_0000... fail this."""
    m = re.match(r"^(gh[pousr]|github_pat)_([0-9A-Za-z]{30,})$", token)
    if not m:
        return True
    body = m.group(2)
    if len(body) < 36:
        return True
    payload, checksum = body[:-6], body[-6:]
    got = _b62_decode(checksum)
    if got < 0:
        return False
    want = binascii.crc32(payload.encode()) % (62 ** 6)
    return got == want


def _extract_secret_value(finding: dict) -> str:
    """Best-effort pull of the literal secret value from a finding.
    Handles quoted values, TBHM's 'path:line  VALUE' format, and assignments."""
    ev = finding.get("evidence", "") or finding.get("match", "") or ""
    m = re.search(r"""["']([^"']{3,200})["']""", ev)
    if m:
        return m.group(1)
    m = re.search(r":\d+\s+(\S{3,200})\s*$", ev)
    if m:
        return m.group(1)
    m = re.search(r"[:=]\s*([^\s'\";]{4,200})", ev)
    if m:
        return m.group(1)
    m = re.search(r"(\S{12,200})\s*$", ev)
    return m.group(1) if m else ""


def is_dummy_secret(finding: dict, min_entropy: float = 3.0,
                    ctx: str = "prod") -> tuple[bool, str]:
    val = _extract_secret_value(finding)
    if not val:
        return False, ""
    raw = val.strip().strip("'\"")
    low = raw.lower()
    title = (finding.get("title", "") + finding.get("type", "")).lower()

    if raw in _EXAMPLE_KEYS or low in _DUMMY_LITERALS:
        return True, f"known example/placeholder value ('{raw[:24]}')"
    if _ALL_PLACEHOLDER.match(raw):
        return True, f"all-placeholder token ('{raw[:24]}')"
    if _DUMMY_PATTERNS.search(raw):
        return True, f"placeholder-pattern value ('{raw[:24]}')"
    b64 = re.search(r"([A-Za-z0-9+/]{6,}={0,2})$", raw)
    if b64:
        try:
            import base64
            dec = base64.b64decode(b64.group(1) + "===", validate=False).decode("utf-8", "ignore").strip().lower()
            if dec in _DUMMY_LITERALS or dec in ("secret", "password", "token"):
                return True, f"base64 of dummy word ('{dec[:16]}')"
        except Exception:
            pass
    if re.match(r"^(gh[pousr]|github_pat)_", raw) and not github_token_valid_checksum(raw):
        return True, "GitHub token checksum invalid (placeholder/fake)"
    if raw.startswith("eyJ"):
        try:
            import base64, json as _json
            parts = raw.split(".")
            if len(parts) >= 2:
                pad = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = _json.loads(base64.urlsafe_b64decode(pad))
                if str(payload.get("sub")) in ("1234567890", "0", "test"):
                    return True, "demo JWT (sub=1234567890)"
        except Exception:
            pass
    if ctx == "data" and (_HEX40.match(raw) or _HEX64.match(raw)):
        return True, f"git-SHA/identifier in manifest, not a credential ('{raw[:12]}')"
    ent = _entropy(raw)
    generic = "generic" in title or "assignment" in title
    floor = min_entropy if generic else max(2.0, min_entropy - 0.8)
    if ent < floor:
        return True, f"low-entropy value ({ent:.1f} bits < {floor:.1f})"
    return False, ""


# ── verification / chain helpers ─────────────────────────────────────────────
_CONFIRMED_MARKERS = ("curl-verified", "reproduced", "verified live", "200 + schema",
                      "introspection enabled", "verified", "response_raw")


# v3.9.3: runtime proof must reflect a SUCCESSFUL, boundary-crossing response.
# A 401/403 means the control held; 404 means nothing is there; 5xx is an error.
# None of those prove a vulnerability, so they must NOT count as runtime proof.
# Success = 2xx, or a 3xx redirect (often still a real reachable resource).
_LIVE_PROBE_RE = re.compile(
    r"(?i)\b(get|post|put|delete|patch|head|options)\b.*?"
    r"(->|=>|\u2192|:)\s*(2\d{2}|3\d{2})\b"      # METHOD ... -> 2xx/3xx only
)
_HTTP_STATUS_RE = re.compile(
    r"(?i)(http/\d\.\d\s+(2\d{2}|3\d{2})|status[=:]\s*(2\d{2}|3\d{2})|\u2192\s*(2\d{2}|3\d{2})\s*\(len)")
# Explicit denial/error markers that must never be read as proof, even if some
# other 2xx-looking number appears elsewhere in the same evidence string.
_DENIAL_RE = re.compile(
    r"(?i)(\b(401|403|404|405|429|5\d{2})\b|unauthori[sz]ed|forbidden|"
    r"access denied|not found|blocked by waf|challenge)")


def _structured_differential_proof(finding: dict) -> bool:
    """Accept a denial baseline only when a separately structured proof succeeds.

    A denial token anywhere in free-form evidence remains ambiguous.  Callers can
    instead store baseline/proof statuses plus a passed negative control either
    at the finding root or under ``verification``/``differential``.
    """
    candidates = [finding]
    for key in ("verification", "differential", "runtime_proof"):
        value = finding.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    for data in candidates:
        try:
            baseline = int(data.get("baseline_status"))
            proof = int(data.get("proof_status"))
        except (TypeError, ValueError):
            continue
        negative_ok = data.get("negative_control_passed") is True
        delta = str(data.get("expected_delta") or data.get("observed_delta") or "").strip()
        if baseline in {401, 403, 404} and 200 <= proof < 400 and negative_ok and delta:
            return True
    return False


def _has_runtime_proof(finding: dict) -> bool:
    if finding.get("verified") is True or finding.get("verified_at"):
        return True
    if finding.get("response_raw"):
        return True
    # live validation of a credential counts as proof
    val = finding.get("validation") or {}
    if isinstance(val, dict) and val.get("state") == "live":
        return True
    ev = (finding.get("evidence", "") or "")
    evl = ev.lower()
    if any(m in evl for m in _CONFIRMED_MARKERS) and "candidate" not in evl:
        return True
    if _structured_differential_proof(finding):
        return True
    # v3.9.3: live-probe evidence proves reachability ONLY on a success status,
    # and only when the same evidence does not also carry a denial/error marker
    # (a mixed "302 -> 403" chain is not proof of access).
    if (_LIVE_PROBE_RE.search(ev) or _HTTP_STATUS_RE.search(ev)):
        # a success token is present; reject if a denial token co-occurs on the
        # decisive part of the evidence.
        if _DENIAL_RE.search(ev):
            # success AND denial both present — ambiguous, not proof.
            return False
        return True
    return False




def _has_vulnerability_proof(finding: dict) -> bool:
    """Strict security-boundary proof used for promotion/correlation gates.

    ``_has_runtime_proof`` is retained as a historical observation helper for
    compatibility tests.  A response body or HTTP success status is not enough
    here: structured controls or an explicit legacy verifier are required.
    """
    if _structured_differential_proof(finding):
        return True
    if finding.get("verified") is not True:
        return False
    from core.finding_class import classify
    return classify(finding) == "confirmed"



# ── the gate ─────────────────────────────────────────────────────────────────
_KEYWORD_BRANCH_TITLES = ("[code_payments]", "[code_ai_api]", "[code_webhooks]",
                          "[code_uploads]", "[code_admin]", "[code_cloud]",
                          "[code_mobile_api]", "payment/pricing", "webhook receiver",
                          "file upload handler", "ai/llm integration", "cloud/iam",
                          "mobile api surface", "admin surface", "[code_auth]",
                          "without visible auth", "sensitive route")
_SINK_MARKERS = ("dangerous code pattern:", "[code_injection]", "os command injection",
                 "insecure deserialization", "code injection candidate")


def _target_path(finding: dict) -> str:
    return str(finding.get("target", "") or finding.get("file", "")
               or finding.get("path", "") or finding.get("url", ""))


def assess(finding: dict, *, min_entropy: float = 3.0,
           secret_confidence: str = "medium",
           extra_ignores=None) -> tuple[str, str, str]:
    """Return (action, reason, tier). action in {keep,downgrade,drop}."""
    phase = (finding.get("phase", "") or "").lower()
    title = (finding.get("title", "") or "").lower()
    path = _target_path(finding)
    ctx = path_context(path)
    conf = (finding.get("confidence", "") or "").upper()

    if extra_ignores:
        pl = path.lower()
        for pat in extra_ignores:
            pat = pat.strip().lower().rstrip("/")
            if pat and pat in pl:
                return "drop", f"matches ignore pattern '{pat}'", "triage"

    is_secret = ("secret" in phase or "secret" in title or "hardcoded" in title
                 or "credential" in title)
    is_keyword_branch = any(k in title for k in _KEYWORD_BRANCH_TITLES)
    is_sink = any(k in title for k in _SINK_MARKERS)
    is_chain = ("[chain]" in title or "attack_path" in phase
                or phase == "lateral_movement_paths")

    # 0. synthetic chains require a verified underlying primitive
    if is_chain and not _has_vulnerability_proof(finding):
        return "downgrade", "synthetic chain with no verified hop (verified_at null)", "lead"

    # 1. self-referential security-tooling files
    if ctx == "security_tooling" and (is_secret or is_sink):
        return "drop", f"self-referential security-tooling file ({path.split('/')[-1]})", "triage"

    # Explicit v2.21-compatible data/document scanning is opt-in. The caller
    # pre-validates and redacts secret values before persistence. Preserve these
    # observations only as static leads; never let the opt-in confirm itself.
    if finding.get("data_file_opt_in") is True:
        if is_secret:
            if finding.get("secret_fp_prechecked") is not True:
                dummy, why = is_dummy_secret(finding, min_entropy=min_entropy, ctx="data")
                if dummy:
                    return "drop", why, "triage"
            return "downgrade", "explicit data/document scan: prechecked static secret lead", "lead"
        if is_sink or phase in ("code_intel", "code_scan"):
            return "downgrade", "explicit data/document scan: static sink lead without reachability proof", "lead"

    # 2. data / manifest files
    if ctx == "data":
        if is_secret:
            dummy, why = is_dummy_secret(finding, min_entropy=min_entropy, ctx=ctx)
            if dummy:
                return "drop", why, "triage"
            if "generic" in title or conf in ("LOW", "MEDIUM"):
                return "drop", "generic secret rule in data/manifest file (git-SHA/ID likely)", "triage"
        if is_keyword_branch or is_sink:
            return "drop", "keyword/sink match in data/manifest file", "triage"

    # 3. non-code / doc files
    if ctx == "noncode":
        if is_secret or is_keyword_branch or is_sink or phase in ("code_intel", "code_scan"):
            return "drop", f"non-code/doc file ({path.split('/')[-1]})", "triage"

    # 4. test / mock / docs / bench / dataset
    if ctx == "test_doc":
        if is_secret:
            return "drop", "secret in test/mock/docs/bench path", "triage"
        if is_keyword_branch:
            return "drop", "keyword match in test/mock/docs path", "triage"
        if is_sink or phase in ("code_intel", "code_scan"):
            return "downgrade", "code finding in test/mock/docs path", "lead"

    # 5. dummy / example / low-entropy / bad-checksum secrets anywhere
    if is_secret:
        dummy, why = is_dummy_secret(finding, min_entropy=min_entropy, ctx=ctx)
        if dummy:
            return "drop", why, "triage"
        if secret_confidence == "high":
            if "generic" in title or conf == "LOW":
                return "downgrade", "secret-confidence=high: generic/low secret -> lead", "lead"

    # 6. SAST sinks in production without taint/reachability proof.  A
    # deterministic source-to-sink trace may be explicitly classified as
    # SUPPORTED by code_intel.  Preserve that high-confidence support while
    # keeping it out of CONFIRMED; generic sink hits remain review-grade leads.
    supported_static_methods = {
        "static-taint-dataflow",
        "static-taint-plus-route-reachability",
    }
    is_supported_static = (
        str(finding.get("finding_class") or "").lower() == "supported"
        and str(finding.get("verification_method") or "").lower()
        in supported_static_methods
        and finding.get("verified") is not True
    )
    if is_sink and not _has_vulnerability_proof(finding) and not is_supported_static:
        return "downgrade", "SAST sink without taint/reachability proof (review-grade lead)", "lead"

    # 7. keyword-only handler branches with LOW confidence
    if is_keyword_branch and conf == "LOW":
        return "downgrade", "keyword-only code lead (no taint/reachability proof)", "lead"

    return "keep", "", finding.get("tier", "")


# ── gitleaks result validator ────────────────────────────────────────────────
def validate_gitleaks_report(path):
    """Parse a gitleaks JSON report -> (real, filtered) applying the same gates."""
    import json
    from pathlib import Path
    real, filtered = [], []
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return real, filtered
    if not isinstance(data, list):
        return real, filtered
    for item in data:
        secret = (item.get("Secret") or "").strip()
        file = item.get("File") or ""
        rule = item.get("RuleID") or ""
        pseudo = {
            "phase": "code_secrets",
            "title": f"gitleaks: {rule}",
            "target": file,
            "confidence": "MEDIUM",
            "evidence": f"{file}:{item.get('StartLine','?')}  {secret}",
        }
        ctx = path_context(file)
        dummy, why = is_dummy_secret(pseudo, ctx=ctx)
        if ctx in ("test_doc", "noncode", "data", "security_tooling") or dummy:
            item["_filtered_reason"] = why or f"{ctx} path"
            filtered.append(item)
        else:
            real.append(item)
    return real, filtered


def load_ignore_patterns(args, roots=None):
    """Merge --ignore-patterns-file and any .tbhmignore in the code roots."""
    from pathlib import Path
    pats = []
    ipf = getattr(args, "ignore_patterns_file", None)
    if ipf and Path(ipf).is_file():
        pats += [l.strip() for l in Path(ipf).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    for r in (roots or []):
        ti = Path(r) / ".tbhmignore"
        if ti.is_file():
            pats += [l.strip() for l in ti.read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
    sil = getattr(args, "secret_ignore_list", None)
    if sil and Path(sil).is_file():
        pats += [l.strip() for l in Path(sil).read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
    return pats
