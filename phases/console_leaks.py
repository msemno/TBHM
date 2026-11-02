"""
Phase: console_leaks

Developers often leave `console.log(apiKey)` / `console.log(token)` in
production builds. This is a goldmine — these lines:
  - Leak runtime secrets (API keys, JWTs, internal IDs)
  - Reveal internal architecture details
  - Show backend endpoint structure

How to use:
  1. Get a list of all JS files seen so far (recon/javascript.txt)
  2. Grep for console.* calls
  3. Classify what's being logged (token? secret? URL? user data?)
  4. Raise a finding per high-confidence hit
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from core import anti_block, noise_filter

try:
    import requests
except ImportError:
    requests = None


# Match console.log / console.error / console.warn / console.info / console.debug
CONSOLE_RE = re.compile(
    r"console\.(log|error|warn|info|debug|trace)\s*\(([^)]{1,500})\)",
    re.I | re.S,
)

# Inside a console call, look for high-signal content
SECRET_CONTEXT = [
    (re.compile(r"\b(token|apikey|api_key|api-key|secret|password|pwd|jwt|"
                r"auth|authorization|bearer|access_key|access_token|"
                r"client_secret|private_key|priv_key|aws_secret|"
                r"session_id|sessionid|csrf|x-api-key)\b", re.I),
     "secret-named variable logged"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                          "Google API key in log"),
    (re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),              "Stripe key in log"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36,}"),                            "GitHub PAT in log"),
    (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z]{24,}"),       "Slack token in log"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "JWT in log"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                "AWS Access Key ID in log"),
    (re.compile(r"https?://[a-z0-9.\-]+/(api|v\d+)/[\w/?=&\-]+", re.I), "Internal API URL in log"),
]


def run(ctx):
    if not requests:
        return
    js_file = ctx.output / "recon" / "javascript.txt"
    if not js_file.exists():
        ctx.log("WARN", "console_leaks", "no javascript.txt — skipping")
        return
    js_urls = ctx.runner.read_lines(js_file)
    if not js_urls:
        return

    from core.targets import get_root_domains
    in_scope = set(get_root_domains(ctx))

    ctx.log("INFO", "console_leaks", f"scanning {min(len(js_urls), 100)} JS files…")
    n = 0
    for js_url in js_urls[:100]:
        if noise_filter.is_noise(js_url, in_scope_hosts=in_scope)[0]:
            continue
        host = urlparse(js_url).hostname or ""
        try:
            h = anti_block.headers_for(host)
            r = requests.get(js_url, headers=h, timeout=15, verify=False)
            anti_block.observe(host, r.status_code, len(r.content))
            if r.status_code != 200 or not r.text:
                continue
        except Exception:
            continue

        # Find all console.* calls
        for m in CONSOLE_RE.finditer(r.text):
            level   = m.group(1)
            content = m.group(2).strip()
            # Skip empty / trivially-short
            if len(content) < 5:
                continue

            for pat, label in SECRET_CONTEXT:
                hit = pat.search(content)
                if not hit:
                    continue
                # We have a real leak
                snippet = content[:200].replace("\n", " ")
                ctx.save_finding({
                    "phase": "console_leaks", "severity": "MEDIUM", "confidence": "HIGH",
                    "title": f"console.{level} leaks sensitive data: {label}",
                    "target": host, "url": js_url,
                    "evidence": f"console.{level}({snippet!r})",
                    "description": "Production JS contains a console statement that logs "
                                   f"sensitive data ({label}). Open browser DevTools console "
                                   "on the affected page; the value is visible to any user.",
                    "impact": "Token/key leakage to any browser session that loads this page. "
                              "Can also reveal internal architecture / endpoint shape.",
                    "remediation": "Remove all console.* statements from production builds. "
                                  "Use a build-time plugin (terser drop_console, babel-plugin-transform-remove-console).",
                    "cwe": "CWE-532", "mrs_score": 70,
                })
                n += 1
                break  # one finding per console call is enough

    ctx.log("OK", "console_leaks", f"console_leaks: {n} findings")
