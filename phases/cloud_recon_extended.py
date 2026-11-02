"""
Phase: cloud_recon_extended

Adds to v2.3's cloud_recon (S3/GCS/Azure/Firebase) with:
  - DigitalOcean Spaces
  - Cloudflare R2 (custom-domain enumeration)
  - Backblaze B2
  - AWS Lambda function URLs
  - Azure Function apps + AppRunner
  - Google App Engine apps
  - Heroku app subdomain enumeration

Plus FP prevention from review feedback:
  - Typo detection (e.g., "atlassain-backup" — not your target)
  - Ownership signal verification (target name in file contents)
  - Billing-dead bucket detection (GCP UserProjectAccountProblem)
  - 403-AccessDenied = bucket properly secured = NOT a finding
"""
from __future__ import annotations
import re
import time
from collections import Counter
from urllib.parse import urlparse

from core import anti_block, noise_filter
from core.targets import get_root_domains

try:
    import requests
except ImportError:
    requests = None


# ──────────────────────────────────────────────────────────────────────────────
# Per-provider URL builders
# ──────────────────────────────────────────────────────────────────────────────
def _do_spaces_urls(name: str) -> list[str]:
    """DigitalOcean Spaces — typical regions."""
    return [f"https://{name}.{region}.digitaloceanspaces.com"
            for region in ("nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1")]


def _r2_urls(name: str) -> list[str]:
    """Cloudflare R2 typically uses custom domains, but check the default pattern."""
    return [f"https://{name}.r2.cloudflarestorage.com",
            f"https://pub-{name}.r2.dev"]


def _b2_urls(name: str) -> list[str]:
    """Backblaze B2 with various endpoints."""
    return [f"https://f000.backblazeb2.com/file/{name}/",
            f"https://{name}.s3.us-west-002.backblazeb2.com"]


def _gae_urls(name: str) -> list[str]:
    """Google App Engine app subdomains."""
    return [f"https://{name}.appspot.com",
            f"https://{name}.uc.r.appspot.com"]


def _azure_func_urls(name: str) -> list[str]:
    """Azure Functions + AppRunner."""
    return [f"https://{name}.azurewebsites.net",
            f"https://{name}.scm.azurewebsites.net"]


def _heroku_urls(name: str) -> list[str]:
    """Heroku app subdomain enumeration."""
    return [f"https://{name}.herokuapp.com"]


# v2.7 additions ──────────────────────────────────────────────────────────────
def _oracle_oci_urls(name: str) -> list[str]:
    """Oracle Cloud Infrastructure Object Storage.
    URL shape: objectstorage.{region}.oraclecloud.com/n/{namespace}/b/{bucket}/o/
    We don't know the namespace, so we try a list of common ones + the target name itself.
    """
    out = []
    namespaces = (name, name + "-objstore", name + "objectstorage")
    regions = ("us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1",
               "ap-tokyo-1", "uk-london-1")
    for ns in namespaces:
        for region in regions:
            out.append(f"https://objectstorage.{region}.oraclecloud.com/n/{ns}/b/{name}/o/")
    return out


def _wasabi_urls(name: str) -> list[str]:
    """Wasabi hot storage (S3-compatible)."""
    return [f"https://s3.wasabisys.com/{name}",
            f"https://{name}.s3.wasabisys.com",
            f"https://s3.us-east-2.wasabisys.com/{name}",
            f"https://s3.eu-central-1.wasabisys.com/{name}"]


def _ibm_cos_urls(name: str) -> list[str]:
    """IBM Cloud Object Storage."""
    regions = ("us-south", "us-east", "eu-de", "eu-gb", "ap-tok", "au-syd")
    return [f"https://s3.{region}.cloud-object-storage.appdomain.cloud/{name}"
            for region in regions]


def _linode_urls(name: str) -> list[str]:
    """Linode Object Storage (S3-compatible)."""
    return [f"https://{name}.{region}.linodeobjects.com"
            for region in ("us-east-1", "us-southeast-1", "eu-central-1",
                           "ap-south-1", "fr-par-1")]


def _vultr_urls(name: str) -> list[str]:
    """Vultr Object Storage (S3-compatible)."""
    return [f"https://{name}.{loc}.vultrobjects.com"
            for loc in ("ewr1", "sjc1", "ams1", "sgp1", "fra1")]


def _alibaba_oss_urls(name: str) -> list[str]:
    """Alibaba Cloud OSS."""
    return [f"https://{name}.oss-{region}.aliyuncs.com"
            for region in ("cn-hangzhou", "cn-shanghai", "cn-beijing",
                           "ap-southeast-1", "us-west-1", "eu-central-1")]


def _scaleway_urls(name: str) -> list[str]:
    """Scaleway Object Storage."""
    return [f"https://{name}.s3.{region}.scw.cloud"
            for region in ("nl-ams", "fr-par", "pl-waw")]


def _firebase_storage_urls(name: str) -> list[str]:
    """Firebase Storage public buckets (covered partially elsewhere)."""
    return [f"https://firebasestorage.googleapis.com/v0/b/{name}.appspot.com/o/",
            f"https://firebasestorage.googleapis.com/v0/b/{name}/o/"]


PROVIDERS_V27 = [
    ("oracle_oci",          _oracle_oci_urls,      "list_bucket"),
    ("wasabi",              _wasabi_urls,          "list_bucket"),
    ("ibm_cos",             _ibm_cos_urls,         "list_bucket"),
    ("linode_objects",      _linode_urls,          "list_bucket"),
    ("vultr_objects",       _vultr_urls,           "list_bucket"),
    ("alibaba_oss",         _alibaba_oss_urls,     "list_bucket"),
    ("scaleway_objects",    _scaleway_urls,        "list_bucket"),
    ("firebase_storage",    _firebase_storage_urls,"head_only"),
]


PROVIDERS = [
    ("digitalocean_spaces", _do_spaces_urls,  "list_bucket"),
    ("cloudflare_r2",       _r2_urls,         "head_only"),
    ("backblaze_b2",        _b2_urls,         "list_bucket"),
    ("google_appengine",    _gae_urls,        "head_only"),
    ("azure_functions",     _azure_func_urls, "head_only"),
    ("heroku",              _heroku_urls,     "head_only"),
] + PROVIDERS_V27


def run(ctx):
    if not requests:
        return

    # Generate bucket name candidates from target list
    candidates = _generate_candidates(ctx)
    if not candidates:
        ctx.log("INFO", "cloud_recon_extended", "no candidates — skipping")
        return

    in_scope = set(get_root_domains(ctx))
    target_org = ctx.targets[0].split(".")[0].lower() if ctx.targets else ""

    ctx.log("INFO", "cloud_recon_extended",
            f"━━━ Extended cloud recon: {len(candidates)} candidate names "
            f"× {len(PROVIDERS)} providers ━━━")

    n_findings = 0
    for provider_id, url_builder, probe_type in PROVIDERS:
        for name in candidates:
            for url in url_builder(name):
                if noise_filter.is_noise(url, in_scope_hosts=in_scope)[0]:
                    continue
                try:
                    finding = _probe_resource(url, provider_id, probe_type,
                                               name, target_org,
                                               target_host_full=ctx.targets[0]
                                                                if ctx.targets else target_org,
                                               ctx=ctx)
                except Exception:
                    continue
                if finding:
                    ctx.save_finding(finding)
                    n_findings += 1
                time.sleep(0.1)

    ctx.log("OK", "cloud_recon_extended",
            f"cloud_recon_extended: {n_findings} findings")


# ──────────────────────────────────────────────────────────────────────────────
# Candidate generation — bucket name permutations from target list
# ──────────────────────────────────────────────────────────────────────────────
def _generate_candidates(ctx) -> list[str]:
    """Build a list of plausible cloud-resource names from the targets."""
    seeds = set()
    for t in ctx.targets:
        host = urlparse(t).hostname or t
        # Strip TLD and split
        labels = host.lower().replace("https://", "").split(".")
        for lbl in labels:
            if lbl and len(lbl) >= 3 and lbl not in ("www", "com", "org", "net",
                                                     "io", "co", "ai"):
                seeds.add(lbl)
    if not seeds:
        return []
    candidates = set()
    for s in seeds:
        candidates.add(s)
        for suffix in ("backup", "backups", "prod", "production", "staging",
                       "dev", "test", "internal", "private", "public", "media",
                       "assets", "uploads", "data", "files", "logs", "cdn",
                       # v2.7 additions — names that frequently host secrets
                       "secrets", "confidential", "archive", "archives", "dumps",
                       "snapshots", "exports", "reports", "audit", "audits",
                       "compliance", "legal", "hr", "finance", "payroll",
                       "credentials", "creds", "vault", "infra", "ops",
                       "ci", "cicd", "artifacts", "releases", "downloads",
                       "static", "tmp", "temp", "cache", "old", "legacy",
                       "v1", "v2", "v3", "qa", "uat", "stage", "stg"):
            candidates.add(f"{s}-{suffix}")
            candidates.add(f"{s}{suffix}")
            candidates.add(f"{s}_{suffix}")
        for prefix in ("backup", "prod", "dev", "staging",
                       "internal", "private", "old", "legacy", "test"):
            candidates.add(f"{prefix}-{s}")
            candidates.add(f"{prefix}{s}")
    return sorted(candidates)[:200]   # cap raised from 80 to 200 to fit new permutations


# ──────────────────────────────────────────────────────────────────────────────
# Probe — with FP prevention from review feedback
# ──────────────────────────────────────────────────────────────────────────────
def _probe_resource(url: str, provider_id: str, probe_type: str,
                    candidate_name: str, target_org: str,
                    target_host_full: str = None,
                    ctx=None) -> dict | None:
    host = urlparse(url).hostname or ""
    headers = anti_block.headers_for(host)
    try:
        if probe_type == "head_only":
            r = requests.head(url, timeout=8, allow_redirects=False,
                               headers=headers, verify=False)
        else:
            r = requests.get(url, timeout=10, allow_redirects=False,
                              headers=headers, verify=False)
        anti_block.observe(host, r.status_code, len(r.content) if hasattr(r, 'content') else 0)
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None

    # FP filter 1: bucket exists but properly secured = NOT A FINDING
    if r.status_code in (401, 403):
        body = (r.text or "")[:2000]
        if any(s in body for s in ("AccessDenied", "<Error>", "permission",
                                    "Forbidden", "unauthorized")):
            return None     # properly secured — don't even create a finding row

    # 404 → doesn't exist
    if r.status_code == 404:
        return None

    # 200 → potentially exposed
    if r.status_code != 200:
        return None

    body = (r.text or "")[:50000]

    # FP filter 2: bucket-listing or app-running? Must look like a real resource.
    is_bucket_listing = ("<ListBucketResult" in body or "<Contents>" in body or
                         "isTruncated" in body)

    if probe_type == "list_bucket" and not is_bucket_listing:
        # 200 but not a bucket listing → likely a landing page or 404 disguised as 200
        if len(body) < 100:
            return None
        # Could still be a real exposed app (e.g. Heroku app). Treat as info.
        return None

    # FP filter 3: extract bucket contents (keys) and verify ownership
    keys = re.findall(r"<Key>([^<]+)</Key>", body) if is_bucket_listing else []

    # Empty bucket = informational only
    if is_bucket_listing and not keys:
        return {
            "phase": "cloud_recon_extended", "severity": "INFO",
            "confidence": "MEDIUM",
            "title": f"[{provider_id}] public bucket '{candidate_name}' is empty",
            "target": host, "url": url, "method": "GET",
            "evidence": f"GET {url} → 200, bucket listed but contains 0 files.",
            "description": "Bucket is publicly listable but contains no files. "
                          "No data exposed today, but the misconfiguration remains.",
            "impact": "Low — informational. If files are later added, they'll be public.",
            "remediation": "Set the bucket ACL to private.",
            "cwe": "CWE-732",
            "mrs_score": 30,
        }

    # FP filter 4: billing-dead detection (GCP UserProjectAccountProblem)
    if keys:
        first_key = keys[0]
        try:
            sample = requests.get(url.rstrip("/") + "/" + first_key,
                                   timeout=10, verify=False,
                                   headers={"Range": "bytes=0-3000"}).text
        except Exception:
            sample = ""
        if "UserProjectAccountProblem" in sample or "billing" in sample.lower():
            return {
                "phase": "cloud_recon_extended", "severity": "INFO",
                "confidence": "HIGH",
                "title": f"[{provider_id}] abandoned bucket '{candidate_name}' (billing-dead)",
                "target": host, "url": url,
                "evidence": "Bucket lists but file fetch returns "
                           "'UserProjectAccountProblem' — billing inactive. "
                           "Files are not actually accessible.",
                "description": "Bucket appears listable but the billing account is "
                              "suspended, making content unfetchable. This is NOT "
                              "an active vulnerability.",
                "impact": "None — bucket is functionally dead.",
                "remediation": "Cosmetic — release the bucket name.",
                "cwe": "", "mrs_score": 20,
            }

    # v2.10 STRICT ownership filter (downloads sample, checks prior research,
    # detects different-owner buckets) — runs BEFORE the legacy substring check.
    if keys and (target_host_full or target_org):
        try:
            from core import ownership_confirm
            host_for_check = target_host_full or target_org
            strict = ownership_confirm.confirm_bucket_ownership(
                bucket_url=url, listing_xml=body, target_host=host_for_check,
            )
        except Exception:
            strict = None

        if strict:
            verdict = strict.get("verdict", "")
            if verdict == "DIFFERENT_OWNER":
                # Bucket clearly owned by someone else (Magic Lingua, not magic.link).
                # Record in dropped_findings so it shows in false_positives_review.md
                if ctx and hasattr(ctx, "storage"):
                    try:
                        ctx.storage._record_drop({
                            "phase": "cloud_recon_extended", "severity": "HIGH",
                            "title": f"[{provider_id}] bucket '{candidate_name}' "
                                     f"appeared owned by different org",
                            "url": url, "target": host,
                            "evidence": strict.get("advisory", ""),
                            "method": "GET",
                        }, reason=f"strict_ownership: DIFFERENT_OWNER — "
                                  f"{strict.get('advisory','')}",
                          source="ownership_confirm")
                    except Exception:
                        pass
                return None
            if verdict == "PRIOR_RESEARCH":
                return {
                    "phase": "cloud_recon_extended", "severity": "LOW",
                    "confidence": "HIGH",
                    "title": f"[{provider_id}] bucket '{candidate_name}' — "
                             f"prior researcher artifacts present (likely already reported)",
                    "target": host, "url": url, "method": "GET",
                    "evidence": f"Indicator file: {strict.get('evidence', [''])[0]}. "
                                f"Total keys: {strict.get('keys_count', 0)}.",
                    "description": "This bucket appears to have been previously probed "
                                  "by another security researcher (security-test files, "
                                  "permission probes, POC files visible). The bug has "
                                  "very likely already been reported. Submit ONLY if "
                                  "you can demonstrate novel impact beyond the prior work.",
                    "impact": strict.get("advisory", ""),
                    "remediation": "Set bucket ACL to private.",
                    "cwe": "CWE-732", "mrs_score": 35,
                }
            if verdict == "UNKNOWN_OWNER":
                return {
                    "phase": "cloud_recon_extended", "severity": "INFO",
                    "confidence": "LOW",
                    "title": f"[{provider_id}] bucket '{candidate_name}' — "
                             f"OWNERSHIP UNVERIFIED (do not report yet)",
                    "target": host, "url": url, "method": "GET",
                    "evidence": (
                        f"Bucket lists {strict.get('keys_count', 0)} files but "
                        f"NO {host_for_check}-distinctive content was found in "
                        f"file names or sample download. "
                        f"Sample preview: {(strict.get('sample_preview') or '')[:200]!r}"
                    ),
                    "description": (
                        "Tool found a public bucket with this name, but could not "
                        "confirm it actually belongs to your target. Bucket names are "
                        "global — any company can register one with a common name "
                        "(e.g. 'magic-test', 'atlassian-backup'). Do NOT submit as a "
                        "finding without manually verifying ownership."
                    ),
                    "impact": strict.get("advisory", ""),
                    "remediation": "Manual verification required — see curl block below "
                                  "for step-by-step ownership checks.",
                    "cwe": "", "mrs_score": 20,
                }
            # OWNED_BY_TARGET or EMPTY_BUCKET → fall through to legacy logic
            # which will produce the CRITICAL finding.

    # FP filter 5: ownership verification — does this bucket actually belong to target?
    if keys and target_org:
        ownership = _verify_ownership(keys, target_org, body)
        if not ownership["confirmed"]:
            return {
                "phase": "cloud_recon_extended", "severity": "INFO",
                "confidence": "LOW",
                "title": f"[{provider_id}] public bucket '{candidate_name}' — "
                         f"ownership unclear",
                "target": host, "url": url,
                "evidence": (f"Public bucket with {len(keys)} files. "
                            f"Ownership signal: {ownership['reason']}. "
                            f"Sample keys: {keys[:3]}"),
                "description": (
                    "Bucket is public but does not show signals tying it to your "
                    "target organization. May be a third-party with a similar name."
                ),
                "impact": "Possibly out-of-scope — manually verify ownership before "
                         "reporting.",
                "remediation": "If yours, set to private. If not yours, ignore.",
                "cwe": "CWE-732", "mrs_score": 40,
            }
        # Real exposure!
        return {
            "phase": "cloud_recon_extended", "severity": "CRITICAL",
            "confidence": "HIGH",
            "title": f"[{provider_id}] publicly listable bucket '{candidate_name}' "
                     f"with confirmed target ownership",
            "target": host, "url": url,
            "evidence": (f"GET {url} → 200, {len(keys)} files. "
                        f"Ownership signals: {', '.join(ownership['signals'])}. "
                        f"Sample keys: {keys[:5]}"),
            "description": (
                f"Bucket lists {len(keys)} files publicly. Ownership signals confirm "
                f"it belongs to the target organization."
            ),
            "impact": (
                "Wholesale data exfiltration — depending on file content, this can "
                "include database backups, credentials, customer PII, source code, "
                "and infrastructure secrets."
            ),
            "remediation": (
                "Immediately set bucket ACL to private. Audit access logs for "
                "unauthorized downloads. Review IAM permissions on the bucket."
            ),
            "cwe": "CWE-732",
            "mrs_score": 95,
        }

    # 200 on head_only providers — likely a real app
    if probe_type == "head_only":
        return {
            "phase": "cloud_recon_extended", "severity": "INFO",
            "confidence": "MEDIUM",
            "title": f"[{provider_id}] live resource '{candidate_name}' responding",
            "target": host, "url": url,
            "evidence": f"HEAD/GET {url} → 200, {len(body)} bytes",
            "description": (
                "A cloud resource with a name matching the target organization "
                "responded. This is informational — manually verify ownership "
                "and access controls."
            ),
            "impact": "Variable — review the resource's actual contents.",
            "remediation": "If owned: ensure proper authentication. If not: ignore.",
            "cwe": "", "mrs_score": 35,
        }

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Ownership verification
# ──────────────────────────────────────────────────────────────────────────────
COMMON_TYPOS = {
    "atlassain":  "atlassian",
    "anthorpic":  "anthropic",
    "anthroipc":  "anthropic",
    "antrhopic":  "anthropic",
    "githhub":    "github",
    "googl":      "google",
    "miscrosoft": "microsoft",
}


def _verify_ownership(keys: list[str], target_org: str, full_body: str) -> dict:
    """
    Determine whether the bucket contents actually belong to the target.
    Returns {confirmed: bool, signals: [...], reason: str}.
    """
    signals = []
    target_org = target_org.lower()

    # Check 1: target name in any file key
    for k in keys[:50]:
        if target_org in k.lower():
            signals.append(f"file key contains '{target_org}'")
            break

    # Check 2: typo detection — bucket might be a third-party with a typo
    all_text = " ".join(keys[:100]).lower() + " " + full_body[:5000].lower()
    for typo, correct in COMMON_TYPOS.items():
        # If target_org == "atlassian" and bucket has "atlassain" all over → third party
        if correct.lower() == target_org and typo in all_text:
            return {
                "confirmed": False,
                "signals":   [f"⚠️  consistent typo '{typo}' (should be '{correct}')"],
                "reason":    "typo suggests third-party bucket",
            }

    # Check 3: target name in body content
    if target_org in full_body.lower() and target_org not in ("aws", "amazon",
                                                                "google"):
        signals.append(f"target name '{target_org}' in response body")

    # Check 4: filename patterns suggesting target's product
    target_keywords = (target_org, target_org + "-", "_" + target_org)
    for k in keys[:200]:
        if any(kw in k.lower() for kw in target_keywords):
            signals.append(f"product-specific filename: {k}")
            break

    if signals:
        return {"confirmed": True, "signals": signals, "reason": "ownership confirmed"}
    return {"confirmed": False, "signals": [],
            "reason": f"no signals tying bucket to '{target_org}'"}
