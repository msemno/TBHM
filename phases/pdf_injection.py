"""
Phase: pdf_injection

Detect endpoints that turn user-controlled input into PDF/CSV/Excel exports
or printed reports. If your name in account-settings ends up in a generated
PDF, you can usually inject:

  - <iframe src="http://attacker.com/x"> in HTML-to-PDF (wkhtmltopdf, Puppeteer)
  - =cmd|' /C calc'!A1 in CSV (Excel formula injection)
  - <img src=...> SSRF
  - Java-style template tags ${...} for SSTI

This phase ONLY discovers and labels candidate endpoints — it doesn't fire
actual XSS/SSRF/SSTI payloads (that would require OOB infrastructure and is
the job of audit + waf_evasion_ssrf). It surfaces:
   "Manually test PDF/CSV injection here: ..."

Why is this valuable even without active exploitation?
  - The "discover an export endpoint that takes user input" workflow is what
    bug bounty hunters waste hours on manually.
  - This phase points the human at the right places.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from core import anti_block, noise_filter
from core.targets import get_root_domains

try:
    import requests
except ImportError:
    requests = None


# URL patterns that suggest a generation/export endpoint
EXPORT_PATH_RE = re.compile(
    r"/(export|print|download|invoice|invoices?|receipt|report|reports?|"
    r"pdf|generate|render|preview|certificate|certificates?|"
    r"statement|statements?|summary|ticket-print|email-preview)\b",
    re.I,
)

# Content-types that indicate generation backend
GENERATED_CT_RE = re.compile(
    r"application/(pdf|vnd\.openxmlformats|vnd\.ms-excel|x-csv|csv)|"
    r"text/csv|text/calendar|application/x-iwork|"
    r"image/(svg|png)\+xml",
    re.I,
)


def run(ctx):
    if not requests:
        return

    crawl_file = ctx.output / "recon" / "crawl_urls.txt"
    alive_file = ctx.output / "recon" / "alive.txt"
    urls = set()
    for f in (crawl_file, alive_file):
        if f.exists():
            urls.update(ctx.runner.read_lines(f))

    in_scope = set(get_root_domains(ctx))

    # 1. URL-pattern matches (cheap, no extra network)
    candidates = []
    for u in urls:
        if noise_filter.is_noise(u, in_scope_hosts=in_scope)[0]:
            continue
        path = urlparse(u).path or "/"
        if EXPORT_PATH_RE.search(path):
            candidates.append((u, "path_match"))

    if not candidates:
        ctx.log("INFO", "pdf_injection",
                "no export-shaped URLs found via path heuristic")

    # 2. HEAD probe on alive URLs to look for application/pdf content-type
    for u in list(urls)[:60]:
        if noise_filter.is_noise(u, in_scope_hosts=in_scope)[0]:
            continue
        if any(u == c[0] for c in candidates):
            continue
        host = urlparse(u).hostname or ""
        try:
            r = requests.head(u, headers=anti_block.headers_for(host),
                              timeout=8, verify=False, allow_redirects=False)
            anti_block.observe(host, r.status_code, 0)
            ct = r.headers.get("Content-Type", "")
            if GENERATED_CT_RE.search(ct):
                candidates.append((u, f"content-type:{ct.split(';')[0]}"))
        except Exception:
            continue

    if not candidates:
        ctx.log("INFO", "pdf_injection", "no PDF/export endpoints — skipping")
        return

    ctx.log("INFO", "pdf_injection",
            f"━━━ Found {len(candidates)} PDF/export candidate(s) for manual testing ━━━")

    for url, reason in candidates[:30]:
        host = urlparse(url).hostname or ""
        ctx.save_finding({
            "phase": "pdf_injection", "severity": "INFO", "confidence": "MEDIUM",
            "title": f"PDF/Export endpoint — manual injection-testing candidate ({reason})",
            "target": host, "url": url, "method": "GET",
            "evidence": f"Discovered via {reason}. Path matches export pattern OR "
                        "response Content-Type indicates document generation.",
            "description": (
                "Endpoint appears to generate PDFs/CSVs/Excel files. These backends "
                "often render user-controlled input (account name, address, comments) "
                "via wkhtmltopdf / Puppeteer / Excel-formula evaluators. Common bugs:\n"
                "  • HTML→PDF SSRF: inject <iframe src='http://oob/x'> in any reflected field\n"
                "  • CSV formula injection: inject =cmd|' /C calc'!A1 in name/title\n"
                "  • SSTI: inject {{7*7}} or ${7*7}\n"
                "  • Stored XSS in PDF metadata\n"
                "\nManual workflow: find which user-controlled field appears in the "
                "generated document, then inject payload into THAT field via its normal "
                "input endpoint, then re-fetch this export URL and inspect the output."
            ),
            "impact": "HIGH-CRITICAL if exploitable: SSRF to internal services, "
                     "RCE via wkhtmltopdf JS context, sensitive metadata leakage. "
                     "INFO until manual confirmation.",
            "remediation": "Sanitize/escape user input when rendering into HTML for PDF. "
                          "Disable JavaScript and network access in wkhtmltopdf "
                          "(--disable-javascript --disable-external-links). "
                          "Prefix CSV cells starting with = + - @ with a single quote.",
            "cwe": "CWE-918",       # SSRF is most common impact
            "mrs_score": 50,
        })

    ctx.log("OK", "pdf_injection",
            f"pdf_injection: surfaced {min(len(candidates), 30)} candidates")
