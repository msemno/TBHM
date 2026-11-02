"""Structured native OSINT collector framework.

Only providers with real implementations are registered as native. Automated
tests inject a transport and never call public services.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class ProviderDefinition:
    provider_id: str
    name: str
    implementation_state: str
    base_url: str
    api_key_env: str | None
    timeout_seconds: int
    requests_per_second: float
    max_retries: int
    terms_note: str
    pii_classification: str
    approval_required: bool
    supports_pagination: bool


PROVIDERS = {
    "rdap": ProviderDefinition(
        provider_id="rdap", name="RDAP.org bootstrap service", implementation_state="native",
        base_url="https://rdap.org", api_key_env=None, timeout_seconds=20,
        requests_per_second=1.0, max_retries=2,
        terms_note="Use for authorized domain/IP registration lookups and respect registry terms and rate limits.",
        pii_classification="may contain registration contact data; redact person-level fields unless policy permits",
        approval_required=False, supports_pagination=False,
    )
}


def provider_status(provider_id: str, environ: dict[str, str] | None = None) -> dict:
    import os
    environ = environ if environ is not None else os.environ
    provider = PROVIDERS.get(provider_id)
    if not provider:
        return {"provider_id": provider_id, "implementation_state": "unavailable", "available": False, "reason": "provider is not implemented"}
    missing_key = bool(provider.api_key_env and not environ.get(provider.api_key_env))
    return {
        "provider_id": provider.provider_id,
        "name": provider.name,
        "implementation_state": provider.implementation_state,
        "available": not missing_key,
        "api_key_required": bool(provider.api_key_env),
        "api_key_present": not missing_key if provider.api_key_env else None,
        "terms_note": provider.terms_note,
        "pii_classification": provider.pii_classification,
        "approval_required": provider.approval_required,
    }


def _default_transport(url: str, *, timeout: int, headers: dict[str, str]) -> tuple[int, dict, dict[str, str]]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(4_000_000)
        return int(getattr(response, "status", 200)), json.loads(raw.decode("utf-8", errors="replace")), dict(response.headers.items())


def _rdap_url(query: str, query_type: str) -> str:
    if query_type not in {"domain", "ip"}:
        raise ValueError("RDAP query_type must be domain or ip")
    value = query.strip().lower()
    if not value or any(ch in value for ch in " /\\?#&;|`$<>\n\r\t"):
        raise ValueError("invalid RDAP query")
    return f"https://rdap.org/{query_type}/{urllib.parse.quote(value, safe='.:')}"


def collect(provider_id: str, query: str, *, query_type: str = "domain", timeout: int | None = None,
            retries: int | None = None, transport: Callable | None = None, redact_pii: bool = True,
            sleep: Callable[[float], None] = time.sleep) -> dict:
    provider = PROVIDERS.get(provider_id)
    if not provider or provider.implementation_state != "native":
        raise ValueError(f"provider is not natively implemented: {provider_id}")
    if provider_id != "rdap":
        raise ValueError(f"no collector implementation for provider: {provider_id}")
    url = _rdap_url(query, query_type)
    transport = transport or _default_transport
    attempts = max(1, min(int(retries if retries is not None else provider.max_retries) + 1, 5))
    timeout = max(1, min(int(timeout or provider.timeout_seconds), 120))
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            status, payload, headers = transport(url, timeout=timeout, headers={"User-Agent": "TBHM/4.0.0 authorized-rdap-collector", "Accept": "application/rdap+json, application/json"})
            if status >= 400:
                raise RuntimeError(f"provider returned HTTP {status}")
            normalized = normalize_rdap(payload, redact_pii=redact_pii)
            return {
                "provider": provider_id,
                "query": query,
                "query_type": query_type,
                "status": "ok",
                "http_status": status,
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "provenance": {"request_url": url, "provider_name": provider.name, "terms_note": provider.terms_note},
                "pii": {"classification": provider.pii_classification, "redacted": redact_pii},
                "result": normalized,
                "pagination": {"supported": provider.supports_pagination, "pages": 1},
            }
        except (urllib.error.URLError, TimeoutError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < attempts:
                sleep(min(2 ** (attempt - 1), 4))
    return {"provider": provider_id, "query": query, "query_type": query_type, "status": "error", "error": last_error, "collected_at": datetime.now(timezone.utc).isoformat()}


def normalize_rdap(payload: dict, *, redact_pii: bool = True) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("RDAP response must be an object")
    result = {
        "object_class_name": payload.get("objectClassName"),
        "handle": payload.get("handle"),
        "ldh_name": payload.get("ldhName"),
        "unicode_name": payload.get("unicodeName"),
        "status": list(payload.get("status") or []),
        "events": [{"action": x.get("eventAction"), "date": x.get("eventDate")} for x in payload.get("events", []) if isinstance(x, dict)],
        "nameservers": [x.get("ldhName") for x in payload.get("nameservers", []) if isinstance(x, dict) and x.get("ldhName")],
        "entities": [],
        "notices": [x.get("title") for x in payload.get("notices", []) if isinstance(x, dict) and x.get("title")],
        "port43": payload.get("port43"),
    }
    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        row = {"handle": entity.get("handle"), "roles": list(entity.get("roles") or [])}
        if not redact_pii:
            row["vcard_array"] = entity.get("vcardArray")
        result["entities"].append(row)
    return result
