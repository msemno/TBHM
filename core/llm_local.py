"""Safe local LLM client used for evidence enrichment and triage.

Only local/loopback Ollama endpoints are accepted. The client does
not expose tool calling, does not execute model-generated commands, and applies
secret redaction before content is sent to the model.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests


_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s,'\";]{4,}"), r"\1=[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(?:ntlm|lm|sha1|sha256|md5)?\s*[:=]?\s*[a-f0-9]{32,128}\b"), "[REDACTED_HASH]"),
]


def redact_text(value: object, limit: int = 6000) -> str:
    text = str(value or "")[:limit]
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def is_loopback_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        if host in {"localhost", "localhost.localdomain"}:
            return True
        return ipaddress.ip_address(host).is_loopback
    except Exception:
        return False


@dataclass
class LocalLLMConfig:
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "qwen3-cybersec:4b"
    timeout: int = 180
    context: int = 4096
    temperature: float = 0.1


class OllamaClient:
    def __init__(self, config: LocalLLMConfig):
        self.config = config
        self.base = config.endpoint.rstrip("/")
        parsed = urlparse(self.base)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("local LLM endpoint must be an unauthenticated HTTP(S) loopback URL")
        if not is_loopback_url(self.base):
            raise ValueError("local LLM endpoint must resolve to a loopback address")
        # Do not inherit HTTP(S)_PROXY. A proxy or redirect could otherwise move
        # redacted-but-sensitive assessment data off the local machine.
        self.session = requests.Session()
        self.session.trust_env = False

    def list_models(self) -> list[str]:
        response = self.session.get(
            f"{self.base}/api/tags", timeout=min(self.config.timeout, 20),
            allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise ValueError("local LLM endpoint attempted an HTTP redirect")
        response.raise_for_status()
        data = response.json()
        return [str(m.get("name", "")) for m in data.get("models", []) if m.get("name")]

    def available(self) -> tuple[bool, str]:
        try:
            models = self.list_models()
            if self.config.model in models:
                return True, f"model available: {self.config.model}"
            # Ollama can expose model names with or without :latest aliases.
            wanted = self.config.model.split(":", 1)[0]
            if any(m.split(":", 1)[0] == wanted for m in models):
                return True, f"compatible model alias available for {wanted}"
            return False, f"model not found; available models: {', '.join(models[:12]) or 'none'}"
        except Exception as exc:
            return False, f"Ollama unavailable: {exc}"

    def chat_json_schema(self, system: str, user: str, schema: dict) -> dict:
        """Request a constrained shape; the caller still validates semantics."""
        if not isinstance(schema, dict) or schema.get('type') != 'object':
            raise ValueError('object JSON schema required')
        return self.chat_json(system, user, schema=schema)

    def chat_json_bounded(self, system: str, user: str, schema: dict, *, max_output_tokens: int = 512) -> dict:
        """A compatible opt-in bound for compact advisory responses."""
        if not isinstance(schema, dict) or schema.get('type') != 'object':
            raise ValueError('object JSON schema required')
        if type(max_output_tokens) is not int or not 128 <= max_output_tokens <= 4096:
            raise ValueError('output-token bound must be an integer in 128..4096')
        return self.chat_json(system, user, schema=schema, max_output_tokens=max_output_tokens)

    def chat_json(self, system: str, user: str, *, schema: dict | None = None,
                  max_output_tokens: int | None = None) -> dict:
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": schema if schema is not None else "json",
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": max(1024, min(int(self.config.context), 8192)),
            },
        }
        if max_output_tokens is not None:
            payload['options']['num_predict'] = max_output_tokens
        response = self.session.post(
            f"{self.base}/api/chat",
            json=payload,
            timeout=self.config.timeout,
            allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise ValueError("local LLM endpoint attempted an HTTP redirect")
        # v4-fix: /api/chat returns 400 for models whose Modelfile lacks a chat
        # template (common for custom-created models like qwen3-cybersec:4b). Rather
        # than fail the whole advisory, surface the reason and fall back to
        # /api/generate, which does not require a chat template.
        if response.status_code == 400:
            try:
                _detail = response.json().get("error", "")
            except Exception:
                _detail = (response.text or "")[:200]
            content = self._generate_fallback(system, user, schema=schema, max_output_tokens=max_output_tokens)
            if not content:
                raise ValueError(f"local LLM /api/chat 400 ({_detail}); /api/generate fallback empty")
            data = None
        else:
            response.raise_for_status()
            data = response.json()
            if data.get('done_reason') == 'length' or data.get('done') is False:
                raise ValueError('local LLM response was incomplete or reached its output-token limit')
            content = ((data.get("message") or {}).get("content") or "").strip()
        if not content:
            raise ValueError("empty local LLM response")
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Models occasionally wrap JSON in a fenced block despite format=json.
            match = re.search(r"\{.*\}", content, re.S)
            if not match:
                raise
            return json.loads(match.group(0))

    def _generate_fallback(self, system: str, user: str, *, schema: dict | None = None,
                           max_output_tokens: int | None = None) -> str:
        """Call /api/generate (no chat template required) and return raw text.
        Used when /api/chat rejects a template-less custom model with HTTP 400."""
        prompt = (system.strip() + "\n\n" + user.strip()
                  + "\n\nRespond with ONLY a valid JSON object and nothing else.")
        gen = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "format": schema if schema is not None else "json",
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": max(1024, min(int(self.config.context), 8192)),
            },
        }
        if max_output_tokens is not None:
            gen['options']['num_predict'] = max_output_tokens
        r = self.session.post(f"{self.base}/api/generate", json=gen,
                              timeout=self.config.timeout, allow_redirects=False)
        if 300 <= r.status_code < 400:
            raise ValueError("local LLM endpoint attempted an HTTP redirect")
        r.raise_for_status()
        data = r.json() or {}
        if data.get('done_reason') == 'length' or data.get('done') is False:
            raise ValueError('local LLM fallback was incomplete or reached its output-token limit')
        return (data.get("response") or "").strip()


@dataclass
class LocalLLMRuntime:
    """Process-local TBHM LLM runtime descriptor.

    The runtime is created by the orchestrator and reused by phases/reporting.
    Model weights remain managed by the operator's local Ollama installation;
    TBHM does not redistribute them.
    """
    client: OllamaClient
    hardware: dict
    endpoint: str
    model: str
    context: int
    timeout: int


def runtime_from_args(args) -> LocalLLMRuntime:
    """Build the shared local-only runtime from parsed TBHM arguments."""
    from core.hardware_profile import detect as detect_hardware

    hardware = detect_hardware()
    endpoint = getattr(args, "local_llm_url", None) or "http://127.0.0.1:11434"
    model = getattr(args, "local_llm_model", None) or "qwen3-cybersec:4b"
    recommended = int(hardware.get("recommended_context", 4096) or 4096)
    requested = int(getattr(args, "local_llm_context", 0) or recommended)
    context = max(1024, min(requested, 8192))
    timeout = max(30, min(int(getattr(args, "local_llm_timeout", 180) or 180), 900))
    client = OllamaClient(LocalLLMConfig(
        endpoint=endpoint,
        model=model,
        timeout=timeout,
        context=context,
        temperature=0.1,
    ))
    return LocalLLMRuntime(
        client=client,
        hardware=hardware,
        endpoint=endpoint,
        model=model,
        context=context,
        timeout=timeout,
    )


def local_llm_status(args) -> dict:
    """Return hardware and Ollama/model readiness without requiring a target."""
    try:
        runtime = runtime_from_args(args)
        ready, detail = runtime.client.available()
        return {
            "ready": ready,
            "detail": detail,
            "endpoint": runtime.endpoint,
            "model": runtime.model,
            "context": runtime.context,
            "hardware": runtime.hardware,
            "ollama_binary": shutil.which("ollama") or "",
        }
    except Exception as exc:
        from core.hardware_profile import detect as detect_hardware
        return {
            "ready": False,
            "detail": str(exc),
            "endpoint": getattr(args, "local_llm_url", ""),
            "model": getattr(args, "local_llm_model", ""),
            "hardware": detect_hardware(),
            "ollama_binary": shutil.which("ollama") or "",
        }


def setup_local_model(args) -> dict:
    """Explicitly ask a local Ollama installation to pull or create a model.

    No shell is used. ``--local-llm-modelfile`` creates an operator-defined
    local alias; without a Modelfile, Ollama's normal ``pull`` path is used.
    """
    if getattr(args, 'offline', False):
        return {'ok': False, 'detail': 'offline mode forbids model setup/pull', 'command': []}
    binary = shutil.which("ollama")
    if not binary:
        return {"ok": False, "detail": "ollama binary not found", "command": []}
    model = getattr(args, "local_llm_model", None) or "qwen3-cybersec:4b"
    modelfile = getattr(args, "local_llm_modelfile", None)
    if modelfile:
        path = Path(modelfile).expanduser().resolve()
        if not path.is_file():
            return {"ok": False, "detail": f"Modelfile not found: {path}", "command": []}
        command = [binary, "create", model, "-f", str(path)]
    else:
        command = [binary, "pull", model]
    timeout = max(60, min(int(getattr(args, "local_llm_setup_timeout", 3600) or 3600), 14400))
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "detail": (proc.stdout or proc.stderr or "").strip()[-4000:],
            "command": [Path(command[0]).name, *command[1:]],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": f"local model setup timed out after {timeout}s", "command": [Path(command[0]).name, *command[1:]]}
    except Exception as exc:
        return {"ok": False, "detail": str(exc), "command": [Path(command[0]).name, *command[1:]]}
