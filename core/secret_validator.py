"""
core/secret_validator.py   (v3.6)

Optional LIVE validation of secrets that already passed the static FP gate.
Turns "possible credential" into "confirmed live" (or "confirmed dead") by making
a single, minimal, READ-ONLY identity call to the provider.

GATED: only runs when --validate-secrets is passed. It touches third-party APIs
with discovered credentials, which is a deliberate, authorised-only action. It
performs the least-privilege identity check per provider and never mutates.

Zero hard dependency: uses urllib from stdlib. Network calls are wrapped and
time-limited; any failure returns ("error", ...) not a crash.

Public API:
    validate(secret_type, value) -> (state, detail)
        state in {"live", "dead", "unknown", "skipped", "error"}
    annotate_finding(finding, state, detail) -> mutates finding in place
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

_TIMEOUT = 8


def _get(url, headers=None, data=None, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return None, str(e)


def _validate_github(token: str):
    status, body = _get("https://api.github.com/user",
                        headers={"Authorization": f"Bearer {token}",
                                 "User-Agent": "tbhm-secret-validator",
                                 "Accept": "application/vnd.github+json"})
    if status == 200:
        try:
            login = json.loads(body).get("login", "?")
        except Exception:
            login = "?"
        return "live", f"GitHub token is LIVE (authenticated as '{login}')"
    if status in (401, 403):
        return "dead", f"GitHub token rejected (HTTP {status}) — not live"
    return "unknown", f"GitHub check inconclusive (HTTP {status})"


def _validate_slack(token: str):
    status, body = _get("https://slack.com/api/auth.test",
                        headers={"Authorization": f"Bearer {token}",
                                 "User-Agent": "tbhm-secret-validator"})
    if status == 200:
        try:
            j = json.loads(body)
            if j.get("ok"):
                return "live", f"Slack token LIVE (team '{j.get('team','?')}')"
            return "dead", f"Slack token invalid ({j.get('error','?')})"
        except Exception:
            return "unknown", "Slack response unparseable"
    return "unknown", f"Slack check inconclusive (HTTP {status})"


def _validate_google_api(key: str):
    # least-privilege: a key-validation endpoint that fails closed for bad keys.
    status, body = _get(
        f"https://www.googleapis.com/customsearch/v1?key={key}&cx=000&q=x")
    # 400 with keyInvalid => dead; 403 with API not enabled but key valid => live-ish
    if status == 400 and "API key not valid" in body:
        return "dead", "Google API key not valid"
    if status in (200, 403):
        return "live", f"Google API key accepted by Google (HTTP {status})"
    return "unknown", f"Google key check inconclusive (HTTP {status})"


def _validate_aws(access_key_id: str, secret_value: str = ""):
    # A live check requires SigV4 signing (STS GetCallerIdentity). We avoid
    # bundling boto3; if it's importable we use it, else we report 'unknown' and
    # tell the operator how to check by hand.
    try:
        import boto3  # type: ignore
        from botocore.exceptions import ClientError  # type: ignore
    except Exception:
        return "unknown", ("AWS live check needs boto3 + the paired secret; "
                           "run: aws sts get-caller-identity")
    if not secret_value:
        return "unknown", "AWS access key present but paired secret not captured"
    try:
        sts = boto3.client("sts", aws_access_key_id=access_key_id,
                           aws_secret_access_key=secret_value)
        ident = sts.get_caller_identity()
        return "live", f"AWS creds LIVE (arn {ident.get('Arn','?')})"
    except Exception as e:
        return "dead", f"AWS creds rejected ({type(e).__name__})"


def _validate_stripe(key: str):
    status, body = _get("https://api.stripe.com/v1/balance",
                        headers={"Authorization": f"Bearer {key}",
                                 "User-Agent": "tbhm-secret-validator"})
    if status == 200:
        return "live", "Stripe key LIVE (balance endpoint reachable)"
    if status in (401,):
        return "dead", "Stripe key rejected (HTTP 401)"
    return "unknown", f"Stripe check inconclusive (HTTP {status})"


def _validate_sendgrid(key: str):
    status, body = _get("https://api.sendgrid.com/v3/scopes",
                        headers={"Authorization": f"Bearer {key}",
                                 "User-Agent": "tbhm-secret-validator"})
    if status == 200:
        return "live", "SendGrid key LIVE"
    if status in (401, 403):
        return "dead", f"SendGrid key rejected (HTTP {status})"
    return "unknown", f"SendGrid check inconclusive (HTTP {status})"


_DISPATCH = {
    "GitHub Token": _validate_github,
    "GitHub Fine-grained PAT": _validate_github,
    "Slack Token": _validate_slack,
    "Google API Key": _validate_google_api,
    "Stripe Secret Key": _validate_stripe,
    "SendGrid API Key": _validate_sendgrid,
}


def validate(secret_type: str, value: str, paired_secret: str = "") -> tuple[str, str]:
    """Return (state, detail). state in live|dead|unknown|skipped|error."""
    if not value:
        return "skipped", "no value"
    try:
        if secret_type == "AWS Access Key ID":
            return _validate_aws(value, paired_secret)
        fn = _DISPATCH.get(secret_type)
        if not fn:
            return "skipped", f"no live validator for '{secret_type}'"
        return fn(value)
    except Exception as e:
        return "error", f"{type(e).__name__}: {e}"


def annotate_finding(finding: dict, state: str, detail: str) -> dict:
    """Attach validation outcome. LIVE promotes to confirmed + verified_at."""
    from datetime import datetime
    finding.setdefault("validation", {})
    finding["validation"] = {"state": state, "detail": detail,
                             "checked_at": datetime.utcnow().isoformat()}
    finding["evidence"] = (finding.get("evidence", "") +
                           f"  |  live-validation: {state.upper()} — {detail}")
    if state == "live":
        finding["verified"] = True
        finding["verified_at"] = datetime.utcnow().isoformat()
        finding["verification_method"] = "live-credential-validation"
        finding["finding_class"] = "confirmed"
        finding["confidence"] = "HIGH"
        finding["severity"] = "HIGH"
    elif state == "dead":
        # a dead credential is not a live finding — downgrade to informational
        finding["severity"] = "INFO"
        finding["confidence"] = "LOW"
        finding["fp_note"] = "credential validated as DEAD/rotated"
    return finding
