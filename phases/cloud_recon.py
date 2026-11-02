"""
Phase: cloud_recon

Cloud-specific reconnaissance. Often produces easy wins for bug bounty:
  - Open S3 buckets containing internal data
  - GCP buckets with directory listing enabled
  - Azure storage with public containers
  - SSRF → cloud metadata endpoint exposure (covered in audit phase)
  - Subdomain pointing to non-existent cloud bucket (takeover)

Approach:
  1. Generate candidate bucket names from target domain
  2. Probe S3, GCS, Azure endpoints
  3. Check JS files for cloud URLs (s3.amazonaws.com, storage.googleapis.com, etc.)
  4. Flag interesting buckets (public, listable, writable)
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse

from core.targets import get_root_domains

try:
    import requests
except ImportError:
    requests = None


# Bucket name patterns to try, derived from target name "example"
def _bucket_candidates(name_base: str) -> list[str]:
    base = name_base.lower().split(".")[0]
    suffixes = ["", "-dev", "-prod", "-staging", "-stage", "-test", "-uat", "-qa",
                "-backup", "-backups", "-bak", "-data", "-files", "-assets",
                "-private", "-public", "-internal", "-admin", "-api",
                "-images", "-static", "-media", "-uploads", "-cdn",
                "-logs", "-logging", "-archive", "-old", "-new", "-temp",
                "-config", "-secret", "-secrets", "-keys", "-db",
                "-www", "-web", "-app"]
    prefixes = ["", "dev-", "prod-", "staging-", "test-", "backup-",
                "internal-", "admin-", "private-"]
    candidates = set()
    for p in prefixes:
        for s in suffixes:
            candidates.add(f"{p}{base}{s}")
    # Common patterns
    candidates.update([
        f"{base}-files", f"{base}-storage", f"{base}-bucket",
        f"{base}.com", f"{base}-cloud",
    ])
    return sorted(candidates)


# Patterns to detect cloud URLs already exposed in JS / responses
CLOUD_URL_PATTERNS = {
    "S3":          re.compile(r"([a-z0-9.\-]+)\.s3[.\-][a-z0-9\-]*\.amazonaws\.com", re.I),
    "S3_path":     re.compile(r"s3[.\-][a-z0-9\-]*\.amazonaws\.com/([a-z0-9.\-]+)", re.I),
    "GCS":         re.compile(r"storage\.googleapis\.com/([a-z0-9.\-_]+)", re.I),
    "GCS_alt":     re.compile(r"([a-z0-9.\-_]+)\.storage\.googleapis\.com", re.I),
    "Azure":       re.compile(r"([a-z0-9]+)\.blob\.core\.windows\.net", re.I),
    "Azure_file":  re.compile(r"([a-z0-9]+)\.file\.core\.windows\.net", re.I),
    "DigOcean":    re.compile(r"([a-z0-9.\-]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com", re.I),
    "Firebase":    re.compile(r"([a-z0-9.\-]+)\.firebaseio\.com", re.I),
    "Firebase_v2": re.compile(r"([a-z0-9.\-]+)\.firebaseapp\.com", re.I),
}


def run(ctx):
    if not requests:
        ctx.log("WARN", "cloud_recon", "requests not installed — skipping")
        return

    # 1. Discover cloud URLs from already-collected JS + URLs
    discovered = _discover_from_files(ctx)

    # 2. Generate candidates from target domain names
    candidates = set()
    for d in get_root_domains(ctx):
        for c in _bucket_candidates(d):
            candidates.add(c)
    # Cap to keep network traffic reasonable
    candidates = sorted(candidates)[:200]

    ctx.log("INFO", "cloud_recon",
            f"  {len(discovered)} cloud URLs from existing data, "
            f"{len(candidates)} bucket candidates to probe")

    n = 0

    # Probe S3 buckets
    n += _probe_s3(ctx, candidates, discovered.get("S3", set()))
    # Probe GCS buckets
    n += _probe_gcs(ctx, candidates, discovered.get("GCS", set()))
    # Probe Azure storage
    n += _probe_azure(ctx, candidates, discovered.get("Azure", set()))
    # Probe Firebase RTDB
    n += _probe_firebase(ctx, discovered.get("Firebase", set()))

    # 3. Always flag any cloud URL found in JS
    for cloud, names in discovered.items():
        for name in list(names)[:20]:
            ctx.save_finding({
                "phase": "cloud_recon", "severity": "INFO", "confidence": "HIGH",
                "title": f"Cloud reference found in app: {cloud} → '{name}'",
                "target": get_root_domains(ctx)[0] if get_root_domains(ctx) else "",
                "description": f"References to a {cloud} resource '{name}' were found in "
                               f"the target's JS or responses. Worth manually checking "
                               f"for misconfiguration.",
                "impact": "Information disclosure if resource is public/listable.",
                "remediation": "Ensure cloud resources have correct ACL / IAM policies.",
                "mrs_score": 30,
            })

    ctx.log("OK", "cloud_recon", f"cloud_recon: {n} actionable findings")


# ──────────────────────────────────────────────────────────────────────────────
# Discovery: scan existing JS/URL files for cloud references
# ──────────────────────────────────────────────────────────────────────────────
def _discover_from_files(ctx) -> dict[str, set]:
    found = {k: set() for k in CLOUD_URL_PATTERNS}
    candidate_files = [
        ctx.output / "recon" / "javascript.txt",
        ctx.output / "recon" / "urls.txt",
        ctx.output / "recon" / "js_endpoints.txt",
        ctx.output / "recon" / "crawl_urls.txt",
    ]
    # Also scan any cached JS files
    js_cache = ctx.output / "recon" / "js_cache"
    if js_cache.exists():
        for p in js_cache.rglob("*"):
            if p.is_file():
                candidate_files.append(p)

    for path in candidate_files:
        if not path.exists():
            continue
        try:
            text = path.read_text(errors="ignore")[:5_000_000]  # cap each file
        except Exception:
            continue
        for cloud, pat in CLOUD_URL_PATTERNS.items():
            for m in pat.finditer(text):
                found[cloud].add(m.group(1))
    return found


# ──────────────────────────────────────────────────────────────────────────────
# S3 probing
# ──────────────────────────────────────────────────────────────────────────────
def _probe_s3(ctx, candidates, known: set) -> int:
    n = 0
    all_targets = set(known) | set(candidates)
    for bucket in list(all_targets)[:120]:
        if not re.fullmatch(r"[a-z0-9.\-]{3,63}", bucket):
            continue
        for region_path in (
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ):
            try:
                r = requests.get(region_path, timeout=6, allow_redirects=False)
            except Exception:
                continue

            # Bucket exists?
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                # v2.10: strict ownership check before claiming HIGH severity
                try:
                    from core import ownership_confirm
                    target_host_full = (ctx.targets[0] if ctx.targets else bucket)
                    strict = ownership_confirm.confirm_bucket_ownership(
                        bucket_url=region_path, listing_xml=r.text,
                        target_host=target_host_full,
                    )
                except Exception:
                    strict = None

                if strict and strict.get("verdict") == "DIFFERENT_OWNER":
                    # Different owner — drop as FP
                    try:
                        ctx.storage._record_drop({
                            "phase": "cloud_recon", "severity": "HIGH",
                            "title": f"S3 bucket '{bucket}' appeared owned by different org",
                            "url": region_path, "target": bucket,
                            "evidence": strict.get("advisory", ""),
                            "method": "GET",
                        }, reason=f"strict_ownership: DIFFERENT_OWNER — "
                                  f"{strict.get('advisory','')}",
                          source="ownership_confirm")
                    except Exception:
                        pass
                    n += 1
                    break
                if strict and strict.get("verdict") == "PRIOR_RESEARCH":
                    ctx.save_finding({
                        "phase": "cloud_recon", "severity": "LOW", "confidence": "HIGH",
                        "title": f"S3 bucket '{bucket}' — prior researcher artifacts visible",
                        "target": bucket, "url": region_path,
                        "evidence": f"Indicator: {strict.get('evidence', [''])[0]}",
                        "description": "Bucket has been previously probed by another researcher. "
                                      "The bug is likely already reported. Submit ONLY if you "
                                      "demonstrate novel impact.",
                        "impact": "Possibly out-of-scope due to duplicate.",
                        "remediation": "Set bucket ACL to private.",
                        "cwe": "CWE-732", "mrs_score": 35,
                    })
                    n += 1
                    break
                if strict and strict.get("verdict") == "UNKNOWN_OWNER":
                    ctx.save_finding({
                        "phase": "cloud_recon", "severity": "INFO", "confidence": "LOW",
                        "title": f"S3 bucket '{bucket}' — OWNERSHIP UNVERIFIED (do not report)",
                        "target": bucket, "url": region_path,
                        "evidence": f"Bucket lists {strict.get('keys_count', 0)} files. "
                                    f"No {target_host_full}-distinctive content found.",
                        "description": "Tool found public bucket but cannot confirm ownership. "
                                      "Names are global namespace — could be a third-party with "
                                      "similar name. Verify ownership manually before reporting.",
                        "impact": strict.get("advisory", ""),
                        "remediation": "Manual verification required.",
                        "cwe": "", "mrs_score": 20,
                    })
                    n += 1
                    break

                # OWNED_BY_TARGET or fallback: Public listing!
                ctx.save_finding({
                    "phase": "cloud_recon", "severity": "HIGH", "confidence": "HIGH",
                    "title": f"Public S3 bucket with listing enabled: {bucket}",
                    "target": bucket, "url": region_path,
                    "evidence": f"GET {region_path} returned 200 with ListBucketResult XML"
                                + (f". Ownership evidence: {strict.get('evidence', [])}"
                                   if strict and strict.get("verdict") == "OWNED_BY_TARGET" else ""),
                    "description": f"S3 bucket '{bucket}' allows public listing. "
                                   "Anyone can enumerate every file. Often contains private data.",
                    "impact": "Information disclosure. Possibly credentials / PII / source.",
                    "remediation": "Block public ACLs at account level. Use bucket policies to deny "
                                  "anonymous list/get.",
                    "cwe": "CWE-732", "mrs_score": 90,
                })
                n += 1
                break
            elif r.status_code == 403 and "AccessDenied" in r.text:
                # Bucket exists but no listing (still worth noting)
                ctx.save_finding({
                    "phase": "cloud_recon", "severity": "INFO", "confidence": "HIGH",
                    "title": f"S3 bucket exists (private): {bucket}",
                    "target": bucket, "url": region_path,
                    "evidence": f"GET {region_path} returned 403 AccessDenied (bucket exists)",
                    "description": "Bucket exists. Listing is denied but individual files might be public. "
                                   "Try guessing common file paths: /index.html, /backup.zip, etc.",
                    "mrs_score": 35,
                })
                break  # one finding is enough
            elif r.status_code == 404 and "NoSuchBucket" in r.text:
                # No bucket. Could be takeover candidate if DNS points here.
                pass
    return n


# ──────────────────────────────────────────────────────────────────────────────
# GCS probing
# ──────────────────────────────────────────────────────────────────────────────
def _probe_gcs(ctx, candidates, known: set) -> int:
    n = 0
    all_targets = set(known) | set(candidates)
    for bucket in list(all_targets)[:80]:
        if not re.fullmatch(r"[a-z0-9.\-_]{3,222}", bucket):
            continue
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            r = requests.get(url, timeout=6, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and "<ListBucketResult" in r.text:
            ctx.save_finding({
                "phase": "cloud_recon", "severity": "HIGH", "confidence": "HIGH",
                "title": f"Public GCS bucket with listing enabled: {bucket}",
                "target": bucket, "url": url,
                "evidence": f"GET {url} returned 200 with ListBucketResult XML",
                "description": f"GCS bucket '{bucket}' is public + listable.",
                "impact": "Information disclosure.",
                "remediation": "Set IAM to remove allUsers / allAuthenticatedUsers permissions.",
                "cwe": "CWE-732", "mrs_score": 90,
            })
            n += 1
    return n


# ──────────────────────────────────────────────────────────────────────────────
# Azure Blob probing
# ──────────────────────────────────────────────────────────────────────────────
def _probe_azure(ctx, candidates, known: set) -> int:
    n = 0
    all_targets = set(known) | set(candidates)
    for storage in list(all_targets)[:80]:
        if not re.fullmatch(r"[a-z0-9]{3,24}", storage):
            continue
        url = f"https://{storage}.blob.core.windows.net/?comp=list"
        try:
            r = requests.get(url, timeout=6, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and "<Containers>" in r.text:
            ctx.save_finding({
                "phase": "cloud_recon", "severity": "HIGH", "confidence": "HIGH",
                "title": f"Public Azure storage with listable containers: {storage}",
                "target": storage, "url": url,
                "evidence": "Listing containers via ?comp=list returned 200",
                "description": f"Azure storage account '{storage}' allows anonymous container listing.",
                "impact": "Information disclosure.",
                "remediation": "Disable anonymous container access in storage account settings.",
                "cwe": "CWE-732", "mrs_score": 90,
            })
            n += 1
    return n


# ──────────────────────────────────────────────────────────────────────────────
# Firebase RTDB probing
# ──────────────────────────────────────────────────────────────────────────────
def _probe_firebase(ctx, known: set) -> int:
    n = 0
    for db in list(known)[:30]:
        url = f"https://{db}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=6, allow_redirects=False)
        except Exception:
            continue
        if r.status_code == 200 and r.text and r.text.strip() not in ("null",):
            # Public read on root!
            preview = r.text[:200]
            ctx.save_finding({
                "phase": "cloud_recon", "severity": "CRITICAL", "confidence": "HIGH",
                "title": f"Firebase RTDB readable without auth: {db}",
                "target": db, "url": url,
                "evidence": f"GET /.json returned 200 with content: {preview}",
                "description": f"Firebase Realtime DB '{db}' allows anonymous read of root. "
                               "Often exposes entire user database.",
                "impact": "Massive data leak (users, messages, internal state).",
                "remediation": "Set Firebase rules: read: auth != null (or stricter).",
                "cwe": "CWE-732", "mrs_score": 95,
            })
            n += 1
    return n
