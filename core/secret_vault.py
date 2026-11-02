"""Run-scoped sealed handoff for discovered secret candidates.

Older TBHM wrote discovered client-side secrets to ``recon/js_secrets.txt`` in
plaintext so ``api_key_pivot`` could validate them. That left live client
credentials sitting unencrypted on the tester's disk. This module keeps the
capability but seals the values: they are encrypted under a per-run key with
restrictive permissions, decrypted only in-process during the same run, and the
key can be shredded at finalize so the sealed blob becomes unrecoverable
afterwards. Findings stay redacted; only this sealed channel carries raw values,
and only to the authorized in-run validator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets as _secrets
from pathlib import Path

try:  # Prefer a vetted AEAD when present on the analysis host.
    from cryptography.fernet import Fernet, InvalidToken  # type: ignore
    _HAVE_FERNET = True
except Exception:  # noqa: BLE001
    _HAVE_FERNET = False

_KEY_NAME = ".tbhm_run_secret.key"
_VAULT_NAME = "js_secrets.sealed"
_MAGIC_FERNET = b"TBHMv1F\n"
_MAGIC_STDLIB = b"TBHMv1S\n"


def _run_dir(ctx) -> Path:
    return Path(getattr(ctx, "output", "."))


def _key_path(ctx) -> Path:
    return _run_dir(ctx) / _KEY_NAME


def _vault_path(ctx) -> Path:
    return _run_dir(ctx) / "recon" / _VAULT_NAME


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_or_create_key(ctx) -> bytes:
    key_path = _key_path(ctx)
    if key_path.is_file():
        raw = key_path.read_bytes().strip()
        if raw:
            return raw
    key = Fernet.generate_key() if _HAVE_FERNET else base64.urlsafe_b64encode(_secrets.token_bytes(32))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    _restrict(key_path)
    return key


def _existing_key(ctx) -> bytes | None:
    key_path = _key_path(ctx)
    if not key_path.is_file():
        return None
    raw = key_path.read_bytes().strip()
    return raw or None


def _stdlib_seal(key_b64: bytes, plaintext: bytes) -> bytes:
    key = base64.urlsafe_b64decode(key_b64)
    nonce = _secrets.token_bytes(16)
    # SHA-256 counter-mode keystream (encrypt) then HMAC-SHA256 (authenticate).
    stream = bytearray()
    counter = 0
    while len(stream) < len(plaintext):
        stream += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return _MAGIC_STDLIB + base64.b64encode(nonce + tag + cipher)


def _stdlib_unseal(key_b64: bytes, blob: bytes) -> bytes | None:
    key = base64.urlsafe_b64decode(key_b64)
    raw = base64.b64decode(blob[len(_MAGIC_STDLIB):])
    nonce, tag, cipher = raw[:16], raw[16:48], raw[48:]
    if not hmac.compare_digest(tag, hmac.new(key, nonce + cipher, hashlib.sha256).digest()):
        return None
    stream = bytearray()
    counter = 0
    while len(stream) < len(cipher):
        stream += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(cipher, stream))


def seal(ctx, records: list[dict]) -> Path | None:
    """Encrypt secret-candidate records to the run-scoped vault. Returns path or None."""
    records = [r for r in (records or []) if isinstance(r, dict) and r.get("match")]
    if not records:
        return None
    key = _load_or_create_key(ctx)
    # Merge with anything a prior phase already sealed this run.
    existing = unseal(ctx) or []
    seen = {(r.get("type"), r.get("match"), r.get("url")) for r in existing}
    merged = list(existing)
    for r in records:
        sig = (r.get("type"), r.get("match"), r.get("url"))
        if sig not in seen:
            seen.add(sig)
            merged.append({"type": r.get("type", "unknown"), "match": r.get("match"), "url": r.get("url", "")})
    plaintext = json.dumps(merged, ensure_ascii=False).encode("utf-8")
    if _HAVE_FERNET:
        blob = _MAGIC_FERNET + Fernet(key).encrypt(plaintext)
    else:
        blob = _stdlib_seal(key, plaintext)
    vault = _vault_path(ctx)
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_bytes(blob)
    _restrict(vault)
    return vault


def unseal(ctx) -> list[dict]:
    """Decrypt and return sealed records for this run, or [] if unavailable."""
    vault = _vault_path(ctx)
    key = _existing_key(ctx)
    if not vault.is_file() or key is None:
        return []
    blob = vault.read_bytes()
    try:
        if blob.startswith(_MAGIC_FERNET) and _HAVE_FERNET:
            plaintext = Fernet(key).decrypt(blob[len(_MAGIC_FERNET):])
        elif blob.startswith(_MAGIC_STDLIB):
            plaintext = _stdlib_unseal(key, blob)
            if plaintext is None:
                return []
        else:
            return []
        data = json.loads(plaintext.decode("utf-8"))
        return data if isinstance(data, list) else []
    except Exception:  # noqa: BLE001 - tampered/foreign vault => no secrets
        return []


def shred(ctx) -> None:
    """Destroy the run key so the sealed vault becomes unrecoverable (run-scoped)."""
    key_path = _key_path(ctx)
    try:
        if key_path.is_file():
            size = key_path.stat().st_size or 64
            with key_path.open("wb") as fh:
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
            key_path.unlink()
    except OSError:
        pass
