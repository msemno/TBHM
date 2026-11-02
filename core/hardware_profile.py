"""Local hardware detection and conservative LLM sizing recommendations.

The module is intentionally dependency-light and never changes system settings.
It is used only to describe the current machine and choose safe defaults for
optional local model inference.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def _ram_gb() -> float:
    try:
        import psutil  # already a TBHM dependency
        return round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:
        try:
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            return round((pages * page_size) / (1024 ** 3), 1)
        except Exception:
            return 0.0


def _nvidia_gpus() -> list[dict]:
    cmd = [
        "nvidia-smi",
        "--query-gpu=name,memory.total,driver_version",
        "--format=csv,noheader,nounits",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    out = []
    for line in proc.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        try:
            memory_mb = int(float(parts[1]))
        except Exception:
            memory_mb = 0
        out.append({
            "name": parts[0],
            "memory_mb": memory_mb,
            "memory_gb": round(memory_mb / 1024, 1),
            "driver_version": parts[2],
        })
    return out


def detect() -> dict:
    """Return a small JSON-serializable hardware profile."""
    ram = _ram_gb()
    gpus = _nvidia_gpus()
    best_vram = max((g.get("memory_gb", 0.0) for g in gpus), default=0.0)

    if best_vram >= 8 and ram >= 16:
        quant = "Q4_K_M"
        alternate = "Q8_0 (optional; less headroom)"
        ctx = 4096
        mode = "GPU-preferred with CPU fallback"
    elif best_vram >= 6 and ram >= 12:
        quant = "Q4_K_M"
        alternate = "Q5_K_M only if monitoring shows headroom"
        ctx = 3072
        mode = "GPU-preferred"
    elif ram >= 16:
        quant = "Q4_K_M"
        alternate = "Q5_K_M may be slower"
        ctx = 2048
        mode = "CPU fallback"
    else:
        quant = "Q4_K_M"
        alternate = "Use a smaller model if memory pressure occurs"
        ctx = 2048
        mode = "conservative CPU/GPU offload"

    return {
        "ram_gb": ram,
        "nvidia_gpus": gpus,
        "best_vram_gb": best_vram,
        "recommended_model_size": "4B",
        "recommended_quantization": quant,
        "alternate_quantization": alternate,
        "recommended_context": ctx,
        "recommended_parallel_requests": 1,
        "inference_mode": mode,
    }


def write(path: str | Path) -> dict:
    data = detect()
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
