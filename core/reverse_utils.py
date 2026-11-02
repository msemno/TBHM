"""Shared helpers for the v3.9.2 reverse-engineering pipeline.

All native helpers are static. Dynamic artifacts are parsed only after they were
produced in an operator-controlled sandbox. No target binary is executed here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable


MAGIC_TYPES = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Fat"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"PK\x03\x04", "ZIP/APK/IPA/JAR"),
    (b"dex\n", "Android DEX"),
    (b"\x00asm", "WebAssembly"),
]

SUSPICIOUS_IMPORTS = {
    "strcpy": ("CWE-120", "Unbounded string copy"),
    "strcat": ("CWE-120", "Unbounded string concatenation"),
    "gets": ("CWE-242", "Inherently dangerous input function"),
    "sprintf": ("CWE-120", "Potential unbounded formatting"),
    "vsprintf": ("CWE-120", "Potential unbounded formatting"),
    "system": ("CWE-78", "Command execution sink"),
    "popen": ("CWE-78", "Command execution sink"),
    "execve": ("CWE-78", "Process execution sink"),
    "CreateProcessA": ("CWE-78", "Windows process creation capability"),
    "CreateProcessW": ("CWE-78", "Windows process creation capability"),
    "WinExec": ("CWE-78", "Windows command execution capability"),
    "VirtualAlloc": ("CWE-693", "Executable-memory-related capability"),
    "VirtualProtect": ("CWE-693", "Memory protection modification capability"),
    "WriteProcessMemory": ("CWE-94", "Cross-process memory modification capability"),
    "CreateRemoteThread": ("CWE-94", "Cross-process thread creation capability"),
    "InternetOpenUrlA": ("CWE-319", "Network retrieval capability"),
    "InternetOpenUrlW": ("CWE-319", "Network retrieval capability"),
    "URLDownloadToFileA": ("CWE-494", "Remote file download capability"),
    "URLDownloadToFileW": ("CWE-494", "Remote file download capability"),
    "RegSetValueExA": ("CWE-732", "Registry modification capability"),
    "RegSetValueExW": ("CWE-732", "Registry modification capability"),
}

SECRET_RE = re.compile(
    rb"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*[\"']?([^\s\x00\"']{8,})"
)
URL_RE = re.compile(rb"(?i)https?://[^\s\x00\"'<>]{4,}")
IP_RE = re.compile(rb"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def iter_files(path: str | Path | None, max_files: int = 50, max_file_mb: int = 200) -> Iterable[Path]:
    if not path:
        return []
    root = Path(path)
    candidates = [root] if root.is_file() else root.rglob("*") if root.is_dir() else []
    out = []
    max_bytes = max(1, min(int(max_file_mb), 4096)) * 1024 * 1024
    for item in candidates:
        try:
            if item.is_file() and item.stat().st_size <= max_bytes:
                out.append(item)
        except OSError:
            continue
        if len(out) >= max(1, min(int(max_files), 1000)):
            break
    return out


def _file_cache_key(path: Path | str) -> tuple[str, int, int]:
    """Return a cache key that changes whenever the artifact changes.

    File size plus nanosecond mtime avoids re-hashing unchanged binaries across
    reverse-analysis phases while still invalidating the cache after an edit.
    The resolved path is used only as an in-process key and is never reported.
    """
    resolved = Path(path).resolve(strict=True)
    stat = resolved.stat()
    return str(resolved), int(stat.st_size), int(stat.st_mtime_ns)


@lru_cache(maxsize=256)
def _hashes_cached(path_value: str, size: int, mtime_ns: int) -> tuple[str, str, str]:
    del size, mtime_ns  # identity inputs intentionally participate in the cache key
    path = Path(path_value)
    md5 = hashlib.md5()  # nosec - evidence fingerprint only
    sha1 = hashlib.sha1()  # nosec - evidence fingerprint only
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def clear_artifact_cache() -> None:
    """Clear process-local reverse-analysis metadata caches."""
    _hashes_cached.cache_clear()
    _magic_type_cached.cache_clear()
    _sample_entropy_cached.cache_clear()


def artifact_id(path: Path | str) -> str:
    """Canonical identity shared by every reverse-analysis stage."""
    try:
        return "sha256:" + hashes(Path(path))["sha256"]
    except Exception:
        return ""


def hashes(path: Path) -> dict:
    md5, sha1, sha256 = _hashes_cached(*_file_cache_key(path))
    return {"md5": md5, "sha1": sha1, "sha256": sha256}


def entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


@lru_cache(maxsize=128)
def _sample_entropy_cached(path_value: str, size: int, mtime_ns: int, max_bytes: int) -> float:
    del size, mtime_ns
    with Path(path_value).open("rb") as handle:
        return entropy_bytes(handle.read(max_bytes))


def sample_entropy(path: Path, max_bytes: int = 16 * 1024 * 1024) -> float:
    max_bytes = max(1024, min(int(max_bytes), 1024 * 1024 * 1024))
    try:
        return _sample_entropy_cached(*_file_cache_key(path), max_bytes)
    except OSError:
        return 0.0


@lru_cache(maxsize=256)
def _magic_type_cached(path_value: str, size: int, mtime_ns: int) -> str:
    del size, mtime_ns
    with Path(path_value).open("rb") as handle:
        head = handle.read(16)
    for magic, name in MAGIC_TYPES:
        if head.startswith(magic):
            return name
    return "unknown"


def magic_type(path: Path) -> str:
    try:
        return _magic_type_cached(*_file_cache_key(path))
    except OSError:
        return "unknown"


def extract_strings(path: Path, minimum: int = 8, max_strings: int = 5000,
                    max_bytes: int = 64 * 1024 * 1024) -> list[str]:
    minimum = max(4, min(int(minimum), 64))
    max_bytes = max(1024, min(int(max_bytes), 1024 * 1024 * 1024))
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    out = []
    for match in pattern.finditer(data):
        out.append(match.group(0).decode("utf-8", "replace")[:2000])
        if len(out) >= max_strings:
            break
    return out


def indicators(strings: list[str]) -> dict:
    joined = "\n".join(strings).encode("utf-8", "replace")
    urls = sorted({m.group(0).decode("utf-8", "replace")[:500] for m in URL_RE.finditer(joined)})[:500]
    ip_values = set()
    for match in IP_RE.finditer(joined):
        candidate = match.group(0).decode("ascii", "ignore")
        try:
            ip_values.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    ips = sorted(ip_values)[:500]
    secret_markers = []
    for match in SECRET_RE.finditer(joined):
        label = match.group(0).split(b"=", 1)[0].split(b":", 1)[0].decode("utf-8", "replace")[:80]
        secret_markers.append(f"{label}=[REDACTED]")
        if len(secret_markers) >= 100:
            break
    imports = []
    text = joined.decode("utf-8", "replace")
    for name, (cwe, reason) in SUSPICIOUS_IMPORTS.items():
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text):
            imports.append({"name": name, "cwe": cwe, "reason": reason})
    return {"urls": urls, "ips": ips, "secret_markers": secret_markers, "suspicious_imports": imports}


def secret_candidates(strings: list[str]) -> list[dict]:
    """v3.9.3: return secret candidates WITH their actual value, so callers can
    run the real value through the FP gate (example/placeholder detection) and
    only redact when storing evidence. Never persist the raw value.

    Each item: {"label": "api_key", "value": "<real>", "redacted": "api_key=[REDACTED]"}.
    """
    joined = "\n".join(strings).encode("utf-8", "replace")
    out = []
    for match in SECRET_RE.finditer(joined):
        whole = match.group(0)
        value = match.group(1).decode("utf-8", "replace")[:200]
        label = whole.split(b"=", 1)[0].split(b":", 1)[0].decode("utf-8", "replace")[:80].strip()
        out.append({"label": label, "value": value, "redacted": f"{label}=[REDACTED]"})
        if len(out) >= 100:
            break
    return out


def raw_short_imports(path: Path, already: set | None = None,
                      max_bytes: int = 64 * 1024 * 1024) -> list[dict]:
    """v3.9.3: detect dangerous API names shorter than the printable-string floor
    (gets/system/popen/strcpy/WinExec/...) by scanning raw bytes directly. Mirrors
    the reverse_triage fallback so the legacy phase gets the same coverage."""
    already = already or set()
    out = []
    max_bytes = max(1024, min(int(max_bytes), 1024 * 1024 * 1024))
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return out
    for name, (cwe, reason) in SUSPICIOUS_IMPORTS.items():
        if name in already:
            continue
        token = re.escape(name.encode("ascii", "ignore"))
        if re.search(rb"(?<![A-Za-z0-9_])" + token + rb"(?![A-Za-z0-9_])", data):
            out.append({"name": name, "cwe": cwe, "reason": reason})
    return out


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def bounded_text(value: str, limit: int = 2_000_000) -> str:
    return str(value or "")[: max(0, min(int(limit), 10_000_000))]


def safe_stem(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.name)[:120] or "artifact"


# ---------------------------------------------------------------------------
# v3.9.7.4: firmware-container awareness (static, dependency-free)
#
# magic_type() above stays authoritative for the strict executable formats its
# existing callers rely on (ELF/PE/Mach-O/ZIP/DEX/WASM). The helpers below add
# recognition of the *container* formats those callers previously reported as
# "unknown" (vendor images, boot images, embedded filesystems), plus pure-bytes
# ELF-header parsing and a checksec-equivalent that consumes readelf text. None
# of this executes the target; it only reads bytes and parses tool text the
# firmware phase already collects.
# ---------------------------------------------------------------------------

# (offset, magic, label). offset None => search the scanned head window.
# Only distinctive (>=4-byte) magics are searched window-wide to avoid noise;
# short magics are pinned to offset 0.
FIRMWARE_SIGNATURES = [
    (0, b"\x27\x05\x19\x56", "uImage (U-Boot legacy)"),
    (None, b"hsqs", "SquashFS (little-endian)"),
    (None, b"sqsh", "SquashFS (big-endian)"),
    (None, b"shsq", "SquashFS (older little-endian)"),
    (None, b"qshs", "SquashFS (older big-endian)"),
    (None, b"HDR0", "TRX (Broadcom/vendor)"),
    (None, b"\x85\x19\x03\x20", "JFFS2 (little-endian)"),
    (None, b"UBI#", "UBI volume"),
    (None, b"UBI!", "UBIfs"),
    (None, b"\x45\x3d\xcd\x28", "CramFS"),
    (0, b"\xfd7zXZ\x00", "XZ stream"),
    (0, b"ANDROID!", "Android boot image"),
    (0, b"\xd0\x0d\xfe\xed", "Devicetree blob (FDT)"),
]

# Brand markers seen inside the first head window of many vendor images.
FIRMWARE_VENDOR_HINTS = [
    (b"TP-LINK", "TP-Link vendor image"),
    (b"tp-link", "TP-Link vendor image"),
    (b"D-Link", "D-Link vendor image"),
    (b"DLK", "D-Link vendor image"),
    (b"NETGEAR", "Netgear vendor image"),
    (b"Netgear", "Netgear vendor image"),
    (b"U-Boot", "U-Boot-based image"),
]

# e_machine -> (name, {endianness: qemu-user binary}). Only the common embedded
# and desktop targets are mapped; unknown machines fall back to the raw id.
ELF_MACHINES = {
    0x02: ("SPARC", {}),
    0x03: ("x86", {"little": "qemu-i386-static"}),
    0x08: ("MIPS", {"little": "qemu-mipsel-static", "big": "qemu-mips-static"}),
    0x14: ("PowerPC", {"big": "qemu-ppc-static", "little": "qemu-ppc64le-static"}),
    0x15: ("PowerPC64", {"big": "qemu-ppc64-static", "little": "qemu-ppc64le-static"}),
    0x28: ("ARM", {"little": "qemu-arm-static", "big": "qemu-armeb-static"}),
    0x2A: ("SuperH", {"little": "qemu-sh4-static", "big": "qemu-sh4eb-static"}),
    0x3E: ("x86-64", {"little": "qemu-x86_64-static"}),
    0xB7: ("AArch64", {"little": "qemu-aarch64-static", "big": "qemu-aarch64_be-static"}),
    0xF3: ("RISC-V", {"little": "qemu-riscv64-static"}),
}


def container_type(path: Path, scan_bytes: int = 64 * 1024 * 1024) -> str:
    """Best-effort firmware/container label.

    The old implementation only inspected 4 KiB and missed filesystems embedded
    later in vendor images.  This implementation scans a bounded window while
    keeping pinned header checks exact.
    """
    limit = max(4096, min(int(scan_bytes), 256 * 1024 * 1024))
    try:
        with path.open("rb") as handle:
            head = handle.read(limit)
    except OSError:
        return ""
    for off, magic, label in FIRMWARE_SIGNATURES:
        if off is None:
            if magic in head:
                return label
        elif len(head) >= off + len(magic) and head[off:off + len(magic)] == magic:
            return label
    vendor_window = head[: min(len(head), 1024 * 1024)]
    for marker, label in FIRMWARE_VENDOR_HINTS:
        if marker in vendor_window:
            return label
    return ""

def identify(path: Path) -> str:
    """Unified identity: the strict executable magic if present, else a
    container label, else 'unknown'. Never returns '' so callers can log it."""
    strict = magic_type(path)
    if strict != "unknown":
        return strict
    return container_type(path) or "unknown"


def find_offsets(path: Path, needle: bytes, max_bytes: int = 64 * 1024 * 1024,
                 max_hits: int = 16) -> list[int]:
    """Byte offsets where ``needle`` occurs in the first ``max_bytes``. Used to
    locate an embedded filesystem (e.g. SquashFS) for offset-based carving."""
    try:
        with path.open("rb") as handle:
            data = handle.read(max(1024, min(int(max_bytes), 1024 * 1024 * 1024)))
    except OSError:
        return []
    out, start = [], 0
    while len(out) < max_hits:
        idx = data.find(needle, start)
        if idx < 0:
            break
        out.append(idx)
        start = idx + 1
    return out


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def elf_header_info(path: Path) -> dict:
    """Pure-bytes ELF header parse (class, endianness, machine, type) plus the
    matching qemu-user binary. No external tool; resolves the 'mips vs mipsel'
    question directly so the operator does not have to assume."""
    try:
        with path.open("rb") as handle:
            hdr = handle.read(20)
    except OSError:
        return {}
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return {}
    ei_class = {1: "ELF32", 2: "ELF64"}.get(hdr[4], "?")
    endian = {1: "little", 2: "big"}.get(hdr[5])
    if endian is None:
        return {"class": ei_class, "data": "?", "endianness": "?", "machine": "?", "type": "?"}
    e_type = int.from_bytes(hdr[16:18], endian)
    e_machine = int.from_bytes(hdr[18:20], endian)
    name, qemu_map = ELF_MACHINES.get(e_machine, (f"0x{e_machine:x}", {}))
    type_name = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type))
    return {
        "class": ei_class,
        "data": "little-endian" if endian == "little" else "big-endian",
        "endianness": endian,
        "machine": name,
        "machine_id": e_machine,
        "type": type_name,
        "qemu": qemu_map.get(endian, ""),
    }


def parse_hardening(header: str = "", program_headers: str = "",
                    dynamic: str = "", symbols: str = "", sections: str = "",
                    valid: dict | None = None, binary_type: str = "") -> dict:
    """Parse readelf output using tri-state mitigation values.

    ``None``/``unknown`` means the tool output was unavailable or invalid; it is
    never converted into a missing-mitigation finding.  ``valid`` may contain
    booleans for header/program_headers/dynamic/symbols/sections.
    """
    if valid is None:
        valid = {
            "header": bool(header.strip()), "program_headers": bool(program_headers.strip()),
            "dynamic": bool(dynamic.strip()), "symbols": bool(symbols.strip()),
            "sections": bool(sections.strip()),
        }
    result = {
        "nx": None, "pie": None, "relro": "unknown", "canary": None,
        "stripped": None, "rpath": None, "runpath": None, "fortify": None,
        "binary_type": binary_type or "", "analysis_valid": bool(valid.get("header") or valid.get("program_headers")),
        "tool_validity": dict(valid),
    }

    if valid.get("program_headers"):
        ph_lines = program_headers.splitlines()
        for i, line in enumerate(ph_lines):
            if "GNU_STACK" in line:
                flags = line.split("GNU_STACK", 1)[1]
                if not re.search(r"[RWE]", flags) and i + 1 < len(ph_lines):
                    flags = ph_lines[i + 1]
                result["nx"] = "E" not in re.findall(r"[RWE]", flags)
                break

    if valid.get("header"):
        is_pie = False
        known = False
        if "Position-Independent Executable" in header:
            is_pie, known = True, True
        for line in header.splitlines():
            if line.strip().startswith("Type:"):
                known = True
                if "DYN" in line:
                    if binary_type == "DYN" and valid.get("program_headers"):
                        is_pie = "INTERP" in program_headers
                    elif valid.get("program_headers"):
                        is_pie = "INTERP" in program_headers
                else:
                    is_pie = False
                break
        if known:
            result["pie"] = is_pie

    if valid.get("program_headers"):
        result["relro"] = "partial" if "GNU_RELRO" in program_headers else "none"
        if result["relro"] == "partial" and valid.get("dynamic"):
            if "BIND_NOW" in dynamic or re.search(r"FLAGS(_1)?.*\bNOW\b", dynamic):
                result["relro"] = "full"

    if valid.get("symbols") or valid.get("dynamic"):
        sym_blob = (symbols if valid.get("symbols") else "") + "\n" + (dynamic if valid.get("dynamic") else "")
        result["canary"] = "__stack_chk_fail" in sym_blob or "__stack_chk_guard" in sym_blob
        result["fortify"] = bool(re.search(r"__\w+_chk\b", sym_blob))

    if valid.get("dynamic"):
        result["rpath"] = "RPATH" in dynamic
        result["runpath"] = "RUNPATH" in dynamic

    if valid.get("sections"):
        result["stripped"] = not (".symtab" in sections or re.search(r"\bSYMTAB\b", sections))

    return result

def hardening_gaps(h: dict) -> list[str]:
    """Human-readable confirmed missing mitigations; unknown values are omitted."""
    gaps = []
    if h.get("nx") is False:
        gaps.append("no NX (executable stack)")
    # PIE is meaningful for executables, not ordinary shared objects.
    if h.get("pie") is False and h.get("binary_type") not in {"DYN_SHARED", "REL"}:
        gaps.append("no PIE")
    if h.get("relro") in {"none", "partial"}:
        gaps.append(f"RELRO={h.get('relro')}")
    if h.get("canary") is False:
        gaps.append("no stack canary")
    if h.get("rpath") is True:
        gaps.append("RPATH set")
    if h.get("runpath") is True:
        gaps.append("RUNPATH set")
    return gaps

