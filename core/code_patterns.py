"""
core/code_patterns.py   (v2.17)

Pure-Python static scanning primitives shared by code_scan and mobile_scan.
No external tools required (semgrep/gitleaks are used as a bonus when present).

Three jobs:
  find_secrets(text, path)  -> hardcoded credentials / keys / tokens
  find_endpoints(text)      -> URLs, API paths, hostnames (feeds api_fuzz)
  find_sinks(text, path)    -> dangerous code patterns (SAST-lite, review-grade)

Designed for low false positives: secret regexes are provider-specific where
possible; generic assignments require a keyword + a quoted value of real length.
"""
from __future__ import annotations

import math
import re

# ── Secrets ───────────────────────────────────────────────────────────────────
# name -> (compiled regex, severity, redact?)
_SECRET_DEFS = [
    ("AWS Access Key ID",        r"\bAKIA[0-9A-Z]{16}\b",                              "HIGH"),
    ("AWS Secret Access Key",    r"(?i)aws_secret[_a-z]*\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "HIGH"),
    ("Google API Key",           r"\bAIza[0-9A-Za-z_\-]{35}\b",                        "HIGH"),
    ("Google OAuth Token",       r"\bya29\.[0-9A-Za-z_\-]+",                           "HIGH"),
    ("GitHub Token",             r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b",        "HIGH"),
    ("GitHub Fine-grained PAT",  r"\bgithub_pat_[0-9A-Za-z_]{60,}\b",                  "HIGH"),
    ("Slack Token",              r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",                 "HIGH"),
    ("Slack Webhook",            r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",  "MEDIUM"),
    ("Stripe Secret Key",        r"\b(sk|rk)_live_[0-9A-Za-z]{24,}\b",                 "HIGH"),
    ("Stripe Test Key",          r"\b(sk|rk)_test_[0-9A-Za-z]{24,}\b",                 "LOW"),
    ("Private Key Block",        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----", "HIGH"),
    ("JWT",                      r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "MEDIUM"),
    ("Twilio API Key",           r"\bSK[0-9a-fA-F]{32}\b",                             "HIGH"),
    ("Twilio Account SID",       r"\bAC[0-9a-fA-F]{32}\b",                             "MEDIUM"),
    ("SendGrid API Key",         r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b",    "HIGH"),
    ("Mailgun Key",              r"\bkey-[0-9a-f]{32}\b",                              "MEDIUM"),
    ("Firebase Database URL",    r"https://[a-z0-9\-]+\.firebaseio\.com",              "MEDIUM"),
    ("Firebase Cloud Messaging", r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}",      "HIGH"),
    ("Heroku API Key",           r"(?i)heroku[a-z0-9_ ]*[:=]\s*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "HIGH"),
    ("npm Token",                r"\bnpm_[0-9A-Za-z]{36}\b",                           "HIGH"),
    ("Square Access Token",      r"\bsq0atp-[0-9A-Za-z_\-]{22}\b",                     "HIGH"),
    ("PayPal Braintree Token",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", "HIGH"),
    ("Generic Secret Assignment",
     r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
     "MEDIUM"),
]
_SECRETS = [(name, re.compile(rx), sev) for name, rx, sev in _SECRET_DEFS]

# Values that look like secrets but are placeholders -> drop.
_PLACEHOLDER = re.compile(
    r"(?i)(your[_-]?|example|placeholder|changeme|xxxx|<.*>|\.\.\.|dummy|test[_-]?key|sample|redacted|insert|todo|fixme|foobar|abcdef123|000000)",
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n/len(s)) * math.log2(n/len(s)) for n in counts.values())


# v3.5: shared, structural non-secret screen applied to EVERY match (not just
# generic assignments). Catches AWS/JWT docs examples, XXXX placeholders, and
# checksum-failing GitHub tokens at the source so they never become findings.
_EXAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}
_ALLX = re.compile(r"(?i)^(?:x{6,}|0{6,}|(.)\1{7,})$")


def _is_nonsecret_token(name: str, token: str) -> bool:
    t = token.strip().strip("'\"")
    if t in _EXAMPLE_VALUES:
        return True
    if _ALLX.match(t) or _PLACEHOLDER.search(t):
        return True
    # GitHub classic PAT: validate trailing base62 CRC32 checksum
    m = re.match(r"^(gh[pousr]|github_pat)_([0-9A-Za-z]{36,})$", t)
    if m:
        try:
            from core.fp_filters import github_token_valid_checksum
            if not github_token_valid_checksum(t):
                return True
        except Exception:
            pass
    # demo JWT (sub=1234567890)
    if t.startswith("eyJ"):
        try:
            import base64, json as _json
            p = t.split(".")
            if len(p) >= 2:
                pad = p[1] + "=" * (-len(p[1]) % 4)
                if str(_json.loads(base64.urlsafe_b64decode(pad)).get("sub")) == "1234567890":
                    return True
        except Exception:
            pass
    return False


def find_secrets(text: str, path: str = "") -> list[dict]:
    out = []
    for name, rx, sev in _SECRETS:
        for m in rx.finditer(text):
            val = m.group(0)
            # Extract the candidate token (quoted value if present, else whole match).
            quoted = re.search(r"['\"]([^'\"]{8,})['\"]", val)
            token = quoted.group(1) if quoted else val
            # v3.5: universal non-secret screen (all types).
            if _is_nonsecret_token(name, token):
                continue
            # Extra entropy screen for the noisy generic/assignment patterns.
            if "Generic" in name or "Assignment" in name:
                if _entropy(token) < 2.5:
                    continue
            line = text.count("\n", 0, m.start()) + 1
            out.append({
                "type": name,
                "severity": sev,
                "match": val[:120],
                "line": line,
                "path": path,
            })
    return out


# Structured data/document assignments are intentionally separate from the
# default source-code rule table. They are used only by the explicit historical
# data/document scan mode, where values are screened and redacted before a
# finding is persisted.
_STRUCTURED_SECRET_KEY = (
    r"api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|"
    r"password|passwd|client[_-]?secret"
)
_STRUCTURED_SECRET_PATTERNS = (
    # JSON/YAML/properties-style key/value pairs, including quoted JSON keys.
    re.compile(
        rf"(?i)(?P<key>[\"']?(?:{_STRUCTURED_SECRET_KEY})[\"']?)"
        rf"\s*[:=]\s*[\"'](?P<value>[^\"'\s]{{8,}})[\"']"
    ),
    # XML-like elements: <api_key>value</api_key>.
    re.compile(
        rf"(?is)<(?P<key>{_STRUCTURED_SECRET_KEY})(?:\s[^>]*)?>\s*"
        rf"(?P<value>[^<\s]{{8,}})\s*</(?P=key)\s*>"
    ),
    # HTML form fields and data-* attributes carrying a credential-like value.
    re.compile(
        rf"(?is)(?:name|id)=[\"'](?P<key>{_STRUCTURED_SECRET_KEY})[\"']"
        rf"[^>]{{0,300}}?value=[\"'](?P<value>[^\"'\s]{{8,}})[\"']"
    ),
    re.compile(
        rf"(?i)data-(?P<key>{_STRUCTURED_SECRET_KEY})\s*=\s*[\"']"
        rf"(?P<value>[^\"'\s]{{8,}})[\"']"
    ),
    # HTML attributes in the reverse order: value before name/id.
    re.compile(
        rf"(?is)value=[\"'](?P<value>[^\"'\s]{{8,}})[\"']"
        rf"[^>]{{0,300}}?(?:name|id)=[\"'](?P<key>{_STRUCTURED_SECRET_KEY})[\"']"
    ),
    # .env/properties/plain-text assignments with an unquoted, token-shaped value.
    re.compile(
        rf"(?im)^[ \t]*(?P<key>{_STRUCTURED_SECRET_KEY})[ \t]*[:=][ \t]*"
        rf"(?P<value>[A-Za-z0-9_./+\-=:@]{{12,}})[ \t]*(?:#.*)?$"
    ),
)


def find_structured_data_secrets(text: str, path: str = "") -> list[dict]:
    """Find credential-like assignments in opt-in data/document files.

    This helper never persists values.  Callers must apply the production
    placeholder/entropy policy and redact ``candidate`` before evidence is
    written.  It is intentionally not called by the default source scanner.
    """
    out: list[dict] = []
    seen: set[tuple[int, str, str]] = set()
    for rx in _STRUCTURED_SECRET_PATTERNS:
        for match in rx.finditer(text):
            candidate = match.group("value").strip()
            key = match.group("key").strip("'\"")
            if _is_nonsecret_token("Structured Secret Assignment", candidate):
                continue
            if _entropy(candidate) < 2.5:
                continue
            line = text.count("\n", 0, match.start()) + 1
            identity = (line, key.lower(), candidate)
            if identity in seen:
                continue
            seen.add(identity)
            out.append({
                "type": f"Structured secret assignment ({key})",
                "severity": "MEDIUM",
                "match": match.group(0)[:240],
                "candidate": candidate,
                "line": line,
                "path": path,
            })
    return out


# ── Endpoints / URLs / hosts ──────────────────────────────────────────────────
_URL_RE   = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+""")
_PATH_RE  = re.compile(r"""['"`](/(?:api|v\d|rest|graphql|auth|oauth|internal|admin|user|users|upload|download|file|files|collect|ingest|track|event|events)[A-Za-z0-9_\-/.{}:]*)['"`]""")
# Binary/decompiled blobs (DEX, Mach-O) store paths UNQUOTED — match them too,
# anchored to a boundary and requiring a real segment after the keyword.
_PATH_BARE_RE = re.compile(r"""(?:^|[\s"'(>=,\\])(/(?:api|v\d+|rest|graphql|auth|oauth|internal|admin|users?|upload|download|files?|collect|ingest|track|events?)(?:/[A-Za-z0-9_\-{}.]+)+)""")
_ENDPOINT_ASSIGN = re.compile(r"""(?i)(?:endpoint|url|uri|path|route|baseurl|base_url|host)\s*[:=]\s*['"`]([^'"`]{1,200})['"`]""")
_HOST_RE  = re.compile(r"https?://([A-Za-z0-9.\-]+)")


def find_endpoints(text: str) -> dict:
    urls = set(_URL_RE.findall(text))
    paths = set(m.group(1) for m in _PATH_RE.finditer(text))
    paths |= set(m.group(1) for m in _PATH_BARE_RE.finditer(text))
    for m in _ENDPOINT_ASSIGN.finditer(text):
        v = m.group(1)
        if v.startswith("http"):
            urls.add(v)
        elif v.startswith("/"):
            paths.add(v)
    hosts = set()
    for u in urls:
        hm = _HOST_RE.match(u)
        if hm:
            hosts.add(hm.group(1).split(":")[0])
    # Trim noise: drop urls that are clearly schemas/namespaces/docs.
    drop = ("w3.org", "schemas.", "xmlns", "example.com", "localhost", "127.0.0.1",
            "googleapis.com/auth", "github.com", "npmjs", "apache.org", "purl.org")
    urls = {u for u in urls if not any(d in u for d in drop)}
    hosts = {h for h in hosts if not any(d in h for d in drop)}
    return {"urls": sorted(urls), "paths": sorted(paths), "hosts": sorted(hosts)}


# ── Dangerous sinks (SAST-lite, review-grade) ─────────────────────────────────
_SINK_DEFS = [
    # (name, regex, severity, languages-hint)
    ("eval() — code execution",          r"\beval\s*\(",                              "MEDIUM"),
    ("Function() constructor",           r"\bnew\s+Function\s*\(",                    "LOW"),
    ("child_process.exec",               r"child_process\.(exec|execSync)\s*\(",      "HIGH"),
    ("os.system / subprocess shell",     r"\bos\.system\s*\(|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True", "HIGH"),
    ("Python exec()",                    r"(?<![A-Za-z_])exec\s*\(",                  "MEDIUM"),
    ("innerHTML assignment (DOM XSS)",   r"\.innerHTML\s*=",                          "MEDIUM"),
    ("dangerouslySetInnerHTML",          r"dangerouslySetInnerHTML",                  "MEDIUM"),
    ("document.write (DOM XSS)",         r"document\.write\s*\(",                     "LOW"),
    ("pickle.loads (deserialization)",   r"pickle\.loads?\s*\(",                      "HIGH"),
    ("yaml.load unsafe",                 r"yaml\.load\s*\((?![^)]*Safe)",             "MEDIUM"),
    ("SQL string concatenation",         r"(?i)(select|insert|update|delete)\s+.*['\"]\s*\+\s*[A-Za-z_]", "MEDIUM"),
    ("Weak hash (MD5/SHA1)",             r"(?i)\b(md5|sha1)\s*\(",                    "LOW"),
    ("Insecure cipher (DES/ECB)",        r"(?i)\b(DES|ECB|RC4)\b",                    "LOW"),
    ("Hardcoded crypto IV/key call",     r"(?i)(createCipher|AES\.new)\s*\(",         "LOW"),
    ("TLS verification disabled",        r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)", "MEDIUM"),
    ("Android cleartext allowed",        r"usesCleartextTraffic\s*=\s*['\"]true['\"]","LOW"),
    # XXE — XML parsing without external-entity hardening
    ("XXE: lxml resolve_entities",       r"etree\.(XMLParser|parse)\s*\((?![^)]*resolve_entities\s*=\s*False)", "MEDIUM"),
    ("XXE: DocumentBuilderFactory",      r"DocumentBuilderFactory\.newInstance\s*\(",  "MEDIUM"),
    ("XXE: SAXParser/XMLReader",         r"(SAXParserFactory|XMLReaderFactory|XMLInputFactory)\.new", "MEDIUM"),
    ("XXE: PHP libxml entity loader",    r"libxml_disable_entity_loader\s*\(\s*false\s*\)", "HIGH"),
    ("XXE: .NET XmlDocument",            r"new\s+XmlDocument\s*\(|XmlTextReader\s*\(", "LOW"),
    # Crypto misuse (beyond MD5/SHA1/DES already above)
    ("Weak PRNG for security",           r"(?i)(java\.util\.Random|Math\.random\s*\(|random\.random\s*\(|mt_rand\s*\()", "LOW"),
    ("PBKDF2 low iterations",            r"(?i)PBKDF2[A-Za-z]*\([^)]*,\s*(\d{1,4})\s*[,)]", "MEDIUM"),
    ("Hardcoded IV",                     r"(?i)(iv|initialization[_-]?vector)\s*[:=]\s*['\"][A-Fa-f0-9]{16,}['\"]", "MEDIUM"),
    ("Static/zero IV",                   r"(?i)IvParameterSpec\s*\(\s*new\s+byte\[", "MEDIUM"),
    ("RSA small key",                    r"(?i)(RSA|generateKeyPair)[^;\n]{0,40}(512|1024)\b", "MEDIUM"),
    ("CBC mode (padding-oracle risk)",   r"(?i)/CBC/|AES/CBC|Cipher\.getInstance\(['\"][^'\"]*CBC", "LOW"),
]
_SINKS = [(name, re.compile(rx), sev) for name, rx, sev in _SINK_DEFS]

# Files we never bother scanning for sinks (binary/vendored/minified handled by caller).
def find_sinks(text: str, path: str = "") -> list[dict]:
    # TypeScript declaration files describe signatures; they do not execute
    # their declared functions. Secret/configuration checks still run elsewhere.
    if str(path).lower().endswith((".d.ts", ".d.mts", ".d.cts")):
        return []
    out = []
    for name, rx, sev in _SINKS:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            out.append({
                "type": name,
                "severity": sev,
                "match": m.group(0)[:120],
                "line": line,
                "path": path,
            })
            if len([o for o in out if o["type"] == name]) >= 25:
                break   # cap per-pattern noise
    return out


# ── File walking helpers ──────────────────────────────────────────────────────
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "out", ".next",
             "__pycache__", ".venv", "venv", "target", "Pods", ".gradle",
             "bower_components", "coverage", ".idea", ".cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz",
            ".tar", ".jar", ".class", ".so", ".dylib", ".dll", ".lock"}
# v3.5: dropped .json/.jsonl/.csv/.md/.txt from the DEFAULT secret-scan scope.
# Those are the manifest/dataset/doc files that produced the git-SHA, plugin-ID,
# dataset-label and doc-example false positives. Endpoint extraction still reads
# them via ENDPOINT_EXT below; they just no longer feed the secret/sink engine.
SCAN_EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt",
            ".swift", ".rb", ".php", ".c", ".cpp", ".h", ".cs", ".yaml",
            ".yml", ".env", ".sh", ".tf", ".properties", ".gradle",
            ".plist", ".smali", ".m", ".mm", ".dart", ".vue", ".config",
            ".ini", ".toml", ""}
# Files scanned for endpoints/URLs only (not secrets/sinks): manifests & docs.
ENDPOINT_EXT = {".json", ".xml", ".html", ".md", ".txt"}
# v2.21 compatibility set. These remain endpoint-only by default and become
# full secret/sink inputs only with the explicit --code-scan-data-files option.
HISTORICAL_DATA_EXT = frozenset(ENDPOINT_EXT)


def is_minified(name: str) -> bool:
    n = name.lower()
    # v2.20: catch .min.js AND versioned variants like jquery.min.3.5.1.js,
    # plus common vendored libraries that produce secret/endpoint false positives.
    if ".min." in n and n.endswith((".js", ".css")):
        return True
    if n.endswith((".min.js", ".min.css", ".bundle.js")) or ".bundle." in n:
        return True
    vendor = ("jquery", "bootstrap", "angular", "vue.js", "react.production",
              "lodash", "moment.min", "popper", "polyfill", "chunk-vendors",
              "runtime.", "vendors~", "package-lock.json", "yarn.lock", "pnpm-lock")
    return any(v in n for v in vendor)
