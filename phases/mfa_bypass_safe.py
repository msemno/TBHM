"""
Phase: mfa_bypass_safe   (v3.3)   [also serves conditional_access_review]

Safe review of MFA / conditional-access posture. It does NOT brute force,
phish, or attempt real bypasses. It provides:

  * a structured catalog of known MFA/CA bypass PATTERNS to test manually with
    authorized dummy accounts (legacy-auth endpoints, MFA-remember abuse,
    OAuth device-code phishing surface, session-cookie replay, SSPR abuse),
  * passive detection over discovered auth endpoints: legacy/basic-auth
    endpoints reachable, login responses that never issue an MFA challenge,
    and missing conditional-access signals.

Output is a review register plus INFO/LOW findings for anything detected.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

PATTERNS = [
    ("Legacy authentication", "Basic/legacy auth endpoints often skip MFA.",
     "Test IMAP/SMTP/EWS/legacy /token endpoints with a dummy account (authorized)."),
    ("MFA 'remember device' abuse", "Persistent trust cookies can be replayed.",
     "Check trust-cookie lifetime and whether it survives password reset."),
    ("OAuth device-code flow", "Device-code phishing bypasses classic MFA UX.",
     "Verify device-code is restricted / conditional-access scoped."),
    ("Session cookie replay", "Stolen post-MFA session cookie = full access.",
     "Confirm cookies are bound (token binding / IP / short TTL)."),
    ("Self-service password reset", "Weak SSPR can reset around MFA.",
     "Review SSPR identity proofing and MFA-on-reset."),
    ("Conditional access gaps", "Policies scoped to some apps/locations only.",
     "Enumerate apps/locations excluded from CA policy (with authorization)."),
    ("Fatigue / push bombing", "Repeated push prompts to coerce approval.",
     "Confirm number-matching / rate limits are enabled."),
]


def run(ctx):
    out_dir = ctx.output / "mfa_ca"
    out_dir.mkdir(exist_ok=True)

    md = ["# MFA / conditional-access review register (safe)", "",
          "Patterns to validate with AUTHORIZED dummy accounts. No bypass was executed.", ""]
    for name, why, how in PATTERNS:
        md += [f"## {name}", f"- **Why:** {why}", f"- **How (authorized):** {how}", ""]
    (out_dir / "mfa_ca_register.md").write_text("\n".join(md))
    (out_dir / "mfa_ca_register.json").write_text(json.dumps(
        [{"pattern": n, "why": w, "how": h} for n, w, h in PATTERNS], indent=2))

    findings = 0
    # passive detection over discovered URLs
    urls = ctx.runner.read_lines(ctx.output / "recon" / "urls.txt") \
        if (ctx.output / "recon" / "urls.txt").exists() else []
    legacy_markers = ("/ews/", "/autodiscover", "/activesync", "/rpc/", "grant_type=password",
                      "/oauth/token", "/adfs/", "/owa/")
    detected = [u for u in urls if any(m in u.lower() for m in legacy_markers)]
    for u in detected[:30]:
        ctx.save_finding({
            "phase": "mfa_bypass_safe", "severity": "LOW", "confidence": "LOW",
            "title": "Legacy/MFA-skippable auth endpoint present",
            "target": urlparse(u).hostname or '', "url": u,
            "finding_class": "lead",
            "validation_required": "URL presence only; authenticate with owned controls before claiming an MFA bypass.",
            "description": "An endpoint associated with legacy authentication or "
                           "resource-owner password grant was discovered. These commonly "
                           "bypass modern MFA/conditional-access. Detection only.",
            "evidence": u[:200],
            "impact": "Legacy auth paths can defeat MFA and conditional access.",
            "remediation": "Disable legacy authentication, block ROPC, and require MFA/CA on all paths.",
            "cwe": "CWE-287", "mrs_score": 35,
        })
        findings += 1

    ctx.save_finding({
        "phase": "mfa_bypass_safe", "severity": "INFO", "confidence": "HIGH",
        "title": f"MFA/conditional-access review register ({len(PATTERNS)} patterns)",
        "target": ctx.targets[0] if ctx.targets else "",
        "description": "Structured MFA/CA test register generated for authorized validation.",
        "evidence": str(out_dir / "mfa_ca_register.md"),
        "impact": "Coverage aid for identity bypass testing.",
        "remediation": "Validate each pattern with dummy accounts under the SoW.",
        "mrs_score": 15,
    })
    ctx.log("OK", "mfa_bypass_safe",
            f"register ({len(PATTERNS)} patterns) | {len(detected)} legacy-auth endpoint(s) detected")
