"""
Cloud bucket ownership confirmation.

THE BUG WE'RE FIXING:
Bucket names are global namespace. `magic-test` could be owned by:
  - magic.link (our target)
  - magic-the-gathering fan site
  - Magic Lingua language app
  - someone's random test bucket

Old logic: bucket exists + listable + has files → CRITICAL finding
This was wrong. We need ACTUAL OWNERSHIP CONFIRMATION before reporting.

NEW WORKFLOW:
  1. Bucket discovered → run confirm_bucket_ownership()
  2. Download small sample (smallest text file in bucket, max 10KB)
  3. Check for target-distinctive strings in keys + sample content
  4. Check for competitor signals (different owner)
  5. Check for prior researcher activity (likely already reported)
  6. Decide: OWNED_BY_TARGET / DIFFERENT_OWNER / UNKNOWN_OWNER / PRIOR_RESEARCH

Verdicts → finding handling:
  OWNED_BY_TARGET    → keep severity, attach evidence
  DIFFERENT_OWNER    → DROP (record in dropped_findings for review)
  UNKNOWN_OWNER      → downgrade to INFO + flag "needs manual verification"
  PRIOR_RESEARCH     → downgrade to LOW + flag "likely already reported"
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None


# File-name patterns that indicate someone already poked this bucket
PRIOR_RESEARCH_PATTERNS = [
    (re.compile(r"-security-test-",      re.I), "prior-researcher security test file"),
    (re.compile(r"-write-test",          re.I), "prior-researcher write probe"),
    (re.compile(r"permission-check",     re.I), "prior-researcher permission probe"),
    (re.compile(r"\.capability-probe",   re.I), "prior-researcher capability probe"),
    (re.compile(r"^test-?\d+\.txt$",     re.I), "prior-researcher test file"),
    (re.compile(r"^poc-",                re.I), "prior-researcher POC file"),
    (re.compile(r"bug.?bounty",          re.I), "explicit bug-bounty test file"),
    (re.compile(r"researcher[-_]",       re.I), "researcher-tagged file"),
    (re.compile(r"hackerone",            re.I), "HackerOne-tagged file"),
    (re.compile(r"bugcrowd",             re.I), "Bugcrowd-tagged file"),
]


# Optional target-specific corpus — user can extend via profile YAML
# Maps target host root → list of distinctive strings expected in owned content
BUILT_IN_OWNERSHIP_CORPUS = {
    "anthropic.com": ["anthropic", "claude.ai", "claude-3", "constitutional-ai",
                      "anthropic api", "model-context-protocol"],
    "magic.link":    ["magic.link", "magic sdk", "didtoken", "did:ethr",
                      "magic-sdk", "magic wallet", "passwordless auth"],
    "stripe.com":    ["stripe", "stripe.com", "pk_live_", "sk_test_"],
    "github.com":    ["github", "octocat", "github actions"],
}


def extract_target_keywords(target_host: str,
                            extra_corpus: list | None = None) -> list[str]:
    """
    Auto-derive target-distinctive keywords. Combines:
      - The primary domain word (anthropic.com → "anthropic")
      - The full host
      - Built-in corpus entries for known targets
      - User-supplied extra_corpus from profile YAML
    """
    keywords = set()
    if not target_host:
        return []
    target_host = target_host.lower()
    # primary domain word
    parts = target_host.replace("https://", "").replace("http://", "").split(".")
    parts = [p for p in parts if p and len(p) > 2]
    if parts:
        keywords.add(parts[0])
    keywords.add(target_host)
    # built-in corpus
    for known_host, words in BUILT_IN_OWNERSHIP_CORPUS.items():
        if known_host in target_host or target_host in known_host:
            keywords.update(w.lower() for w in words)
    # user extras
    if extra_corpus:
        keywords.update(s.lower() for s in extra_corpus if s)
    # Filter generic/too-short
    keywords = {k for k in keywords if k and len(k) >= 3 and k not in {"www", "the", "and"}}
    return sorted(keywords)


def detect_prior_research(keys: list[str]) -> dict:
    """Returns dict {'prior_research': bool, 'indicator': str, 'reason': str}."""
    for k in keys[:300]:
        for pat, label in PRIOR_RESEARCH_PATTERNS:
            if pat.search(k):
                return {
                    "prior_research": True,
                    "indicator": k,
                    "reason": label,
                    "advisory": "Bucket appears to have been previously probed by another "
                               "researcher. This is likely a known/already-reported finding. "
                               "Submit ONLY if you have novel impact to demonstrate.",
                }
    return {"prior_research": False, "indicator": "", "reason": ""}


def _extract_keys_from_listing(listing_xml: str, limit: int = 300) -> list[str]:
    """Parse <Key>…</Key> tokens from an S3-style bucket listing XML."""
    if not listing_xml:
        return []
    return re.findall(r"<Key>([^<]+)</Key>", listing_xml)[:limit]


def _extract_sizes_from_listing(listing_xml: str) -> list[int]:
    if not listing_xml:
        return []
    return [int(s) for s in re.findall(r"<Size>(\d+)</Size>", listing_xml)]


def confirm_bucket_ownership(bucket_url: str, listing_xml: str,
                              target_host: str,
                              extra_corpus: list | None = None,
                              competitor_signals: list | None = None,
                              session=None,
                              timeout: int = 12) -> dict:
    """
    Verify a public bucket belongs to the target before reporting.

    Args:
      bucket_url:        e.g. https://storage.googleapis.com/magic-test
      listing_xml:       the bucket listing XML body we already fetched
      target_host:       the bug-bounty scope host (e.g. magic.link)
      extra_corpus:      extra strings unique to target (from profile)
      competitor_signals: strings indicating a DIFFERENT owner

    Returns dict with verdict + evidence. See module docstring for verdicts.
    """
    if not requests:
        return {"verdict": "UNKNOWN_OWNER", "evidence": [],
                "reason": "requests library unavailable"}

    s = session or requests.Session()
    keys = _extract_keys_from_listing(listing_xml)
    sizes = _extract_sizes_from_listing(listing_xml)

    if not keys:
        return {"verdict": "EMPTY_BUCKET", "evidence": [],
                "reason": "bucket exists but contains no objects"}

    target_keywords = extract_target_keywords(target_host, extra_corpus)

    # 1. Prior research check — short-circuits regardless of ownership
    prior = detect_prior_research(keys)
    if prior["prior_research"]:
        return {
            "verdict": "PRIOR_RESEARCH",
            "evidence": [prior["indicator"]],
            "advisory": prior["advisory"],
            "keys_count": len(keys),
        }

    # 2. Pull text from filenames first (cheap, no extra request)
    names_text = " ".join(keys[:100]).lower()

    # 3. Try to download a small text file to look at actual content
    sample_text = ""
    sample_url = ""
    text_extensions = re.compile(r"\.(txt|md|json|html|xml|csv|log|yaml|yml|js|css)$", re.I)
    # Sort keys by size (smallest first) where size info available
    keys_with_idx = list(enumerate(keys))
    if len(sizes) == len(keys):
        keys_with_idx = sorted(keys_with_idx,
                                key=lambda kv: (not text_extensions.search(kv[1]),
                                                sizes[kv[0]] if sizes[kv[0]] > 0 else 999999))
    else:
        keys_with_idx = sorted(keys_with_idx,
                                key=lambda kv: not text_extensions.search(kv[1]))

    for _, candidate_key in keys_with_idx[:5]:
        try:
            sample_url = bucket_url.rstrip("/") + "/" + candidate_key.lstrip("/")
            r = s.get(sample_url, timeout=timeout, verify=False,
                      headers={"Range": "bytes=0-10240"})
            if r.status_code in (200, 206) and r.text and len(r.text) > 10:
                sample_text = r.text[:10000].lower()
                break
        except Exception:
            continue

    full_corpus = (names_text + " " + sample_text).lower()

    # Check for competitor signals FIRST — if a competitor brand appears clearly,
    # that takes priority over generic substring matches like "magic" → "magiclingua".
    competitor_matches = []
    if competitor_signals:
        for c in competitor_signals:
            c_low = c.lower().strip()
            if not c_low or len(c_low) < 3:
                continue
            # Use word-boundary or hyphen/underscore-bounded match
            if re.search(r"(^|[\s/\-_.,;:'\"!?\(\)\[\]\{\}])" + re.escape(c_low) +
                          r"([\s/\-_.,;:'\"!?\(\)\[\]\{\}]|$)", full_corpus):
                competitor_matches.append(c)
            # Also allow plain substring for very specific brand names (>=6 chars)
            elif len(c_low) >= 6 and c_low in full_corpus:
                competitor_matches.append(c)

    # Check for target signals USING WORD BOUNDARIES so "magic" doesn't
    # falsely match "magiclingua" or "magicarp".
    target_matches = []
    for kw in target_keywords:
        if not kw or len(kw) < 3:
            continue
        # For short generic keywords (3-5 chars), require strict boundary
        if len(kw) <= 5:
            if re.search(r"(^|[\s/\-_.,;:'\"!?\(\)\[\]\{\}])" + re.escape(kw) +
                          r"([\s/\-_.,;:'\"!?\(\)\[\]\{\}]|$)", full_corpus):
                target_matches.append(kw)
        else:
            # Longer brand names: substring OK (e.g. "magic.link" can match raw)
            if kw in full_corpus:
                target_matches.append(kw)

    # 6. Decide verdict
    if competitor_matches and not target_matches:
        return {
            "verdict": "DIFFERENT_OWNER",
            "evidence": competitor_matches,
            "advisory": f"Bucket content references '{competitor_matches[0]}'. "
                        f"Does NOT appear to belong to {target_host}.",
            "sample_url": sample_url,
            "sample_preview": sample_text[:300],
            "keys_count": len(keys),
        }

    if target_matches:
        return {
            "verdict": "OWNED_BY_TARGET",
            "evidence": target_matches,
            "advisory": f"Confirmed: bucket contains {target_host}-distinctive content.",
            "sample_url": sample_url,
            "sample_preview": sample_text[:300],
            "keys_count": len(keys),
        }

    return {
        "verdict": "UNKNOWN_OWNER",
        "evidence": [],
        "advisory": f"No {target_host}-distinctive content found in bucket "
                    f"({len(keys)} keys checked). DO NOT report as a finding "
                    f"without manually verifying ownership (whois the cloud account, "
                    f"check for DNS records pointing to the bucket, contact the target).",
        "sample_url": sample_url,
        "sample_preview": sample_text[:300],
        "keys_count": len(keys),
    }


def build_bucket_verification_curl(bucket_url: str) -> str:
    """
    Generate the curl verification script for a cloud bucket finding.
    User can copy-paste this entire block into their terminal.
    """
    # Sanitize bucket URL for filename
    safe_name = re.sub(r"[^\w.\-]", "_", urlparse(bucket_url).path.strip("/") or "bucket")
    safe_name = safe_name[:50] or "bucket"

    return f"""# ───────────────────────────────────────────────────────────────────
# OWNERSHIP VERIFICATION — RUN THIS BEFORE REPORTING
# Bucket: {bucket_url}
# ───────────────────────────────────────────────────────────────────

# 1. List the bucket anonymously
curl -s "{bucket_url}" > {safe_name}.xml
wc -c {safe_name}.xml

# 2. Count objects
grep -oE "<Key>[^<]+</Key>" {safe_name}.xml | wc -l

# 3. First 30 file names — look for target name patterns
grep -oE "<Key>[^<]+</Key>" {safe_name}.xml | head -30

# 4. Last 10 (recent activity)
grep -oE "<Key>[^<]+</Key>" {safe_name}.xml | tail -10

# 5. Date range — is this bucket active or abandoned?
grep -oE "<LastModified>[^<]+</LastModified>" {safe_name}.xml | sort -u | head -3
grep -oE "<LastModified>[^<]+</LastModified>" {safe_name}.xml | sort -u | tail -3

# 6. CRITICAL: prior researcher activity check
grep -iE "(security-test|write-test|permission-check|capability-probe|poc-|test-[0-9])" {safe_name}.xml \\
  || echo "  ✓ no prior researcher artifacts visible"

# 7. Total bucket size
grep -oE "<Size>[0-9]+</Size>" {safe_name}.xml | grep -oE "[0-9]+" \\
  | awk '{{s+=$1}} END {{printf "  Total size: %.2f MB\\n", s/1024/1024}}'

# 8. Download smallest text file to manually verify OWNERSHIP
SMALLEST=$(grep -oE "<Key>[^<]+\\.(txt|json|md|html|yaml|csv)</Key>" {safe_name}.xml \\
  | sed 's/<[^>]*>//g' | head -1)
if [ -n "$SMALLEST" ]; then
  echo
  echo "  Sample file: $SMALLEST"
  echo "  ─────────────────────────────────────────────"
  curl -s "{bucket_url}/$SMALLEST" | head -30
fi

# ───────────────────────────────────────────────────────────────────
# DECISION RULES:
#   • Files / content mention TARGET name/branding  → REAL finding
#   • Files / content mention DIFFERENT company     → FALSE POSITIVE
#   • Generic names only, no clear owner            → DO NOT report
#                                                     (need manual whois/DNS verify)
#   • Prior researcher files present                → likely already reported
# ───────────────────────────────────────────────────────────────────"""
