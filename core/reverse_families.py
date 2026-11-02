"""Managed inventory workflows for UEFI, drivers, mobile, protocol and hardware evidence."""
from __future__ import annotations

import hashlib
import json
import plistlib
import re
import struct
import subprocess
import shutil
import zipfile
from pathlib import Path
from typing import Iterable

from core.reverse_utils import identify, extract_strings, hashes

UEFI_MAGIC = (b"_FVH", b"EFI PART", b"$VSS", b"NVAR")
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
DRIVER_IMPORTS = re.compile(r"(?i)\b(IoCreateDevice|IoCreateSymbolicLink|IoCompleteRequest|IofCompleteRequest|WdfDeviceCreate|WdfIoQueueCreate|MmMapIoSpace|ProbeForRead|ProbeForWrite|copy_from_user|copy_to_user|register_chrdev|unlocked_ioctl|compat_ioctl)\b")
IOCTL_RE = re.compile(r"(?i)(?:IOCTL_[A-Z0-9_]+|CTL_CODE\s*\([^\n]{1,180}\)|0x(?:22|80|9c)[0-9a-f]{4,6})")
BOOT_RE = re.compile(r"(?i)(u-boot|barebox|uefi|edk2|secure boot|verified boot|kernel panic|watchdog|jtag|uart|swd|spi|nand|nor|mmc|bootargs|console=)")
SECRET_RE = re.compile(r"(?i)(password|passwd|secret|token|private key|debug unlock|root shell)")


def detect_family(path: str | Path) -> dict:
    p = Path(path)
    data = p.read_bytes()[:4 * 1024 * 1024] if p.is_file() else b""
    info = identify(p) if p.is_file() else {"type": "directory"}
    suffix = p.suffix.lower()
    family = "generic"
    reasons = []
    capture_magic = data[:4] in PCAP_MAGIC
    if p.is_dir() and suffix == ".kext":
        family = "macos_kernel_extension"; reasons.append("macOS kernel-extension bundle directory")
    elif suffix in {".pcap", ".pcapng"} or (suffix == ".cap" and capture_magic):
        family = "protocol_capture"; reasons.append("packet-capture magic or extension")
    elif suffix in {".fd", ".rom", ".efi"} or (suffix == ".cap" and not capture_magic) or any(m in data for m in UEFI_MAGIC):
        family = "uefi"; reasons.append("UEFI/firmware-volume marker or extension")
    elif suffix == ".sys":
        family = "windows_driver"; reasons.append("Windows driver extension")
    elif suffix == ".ko":
        family = "linux_kernel_module"; reasons.append("Linux kernel module extension")
    elif suffix == ".kext":
        family = "macos_kernel_extension"; reasons.append("macOS kernel extension")
    elif suffix in {".apk", ".aab", ".ipa", ".dex", ".vdex", ".oat"}:
        family = "mobile"; reasons.append("mobile package/bytecode extension")
    elif suffix in {".bin", ".dump", ".flash", ".img"} and BOOT_RE.search(data.decode("latin1", errors="ignore")):
        family = "hardware_or_firmware_dump"; reasons.append("boot/hardware strings in raw image")
    return {"path": str(p), "family": family, "reasons": reasons, "identification": info}


def _bounded_tree_inventory(root: Path, max_files: int = 50000, max_total_bytes: int = 2 * 1024 * 1024 * 1024) -> dict:
    files, total = [], 0
    if not root.is_dir():
        return {"files": [], "count": 0, "bytes": 0}
    for item in root.rglob("*"):
        if len(files) >= max_files:
            break
        try:
            if not item.is_file() or item.is_symlink():
                continue
            resolved = item.resolve()
            resolved.relative_to(root.resolve())
            size = item.stat().st_size
        except Exception:
            continue
        if total + size > max_total_bytes:
            break
        total += size
        files.append({"path": item.relative_to(root).as_posix(), "size": size})
    return {"files": files, "count": len(files), "bytes": total}


def _run_static_tool(runner, command: list[str], *, timeout: int, log_name: str, cwd: Path | None = None) -> dict:
    rc, stdout, stderr = runner.run(command, timeout=timeout, log_name=log_name, cwd=cwd)
    return {"command": command, "returncode": rc, "stdout": stdout[:2_000_000], "stderr": stderr[:100_000]}


def analyze_uefi(path: str | Path, runner=None, output_dir: str | Path | None = None, execute_tools: bool = False) -> dict:
    p = Path(path)
    data = p.read_bytes()
    markers = {marker.decode("latin1", errors="ignore"): [m.start() for m in re.finditer(re.escape(marker), data)][:1000]
               for marker in UEFI_MAGIC if marker in data}
    tools = []
    if runner and runner.has("UEFIExtract"):
        tools.append("UEFIExtract")
    if runner and runner.has("uefi-firmware-parser"):
        tools.append("uefi-firmware-parser")
    text = "\n".join(extract_strings(p, minimum=8, max_bytes=min(p.stat().st_size, 64 * 1024 * 1024)))
    runs, extracted = [], {}
    if execute_tools and runner and output_dir:
        tool_root = Path(output_dir); tool_root.mkdir(parents=True, exist_ok=True)
        if runner.has("uefi-firmware-parser"):
            dest = tool_root / "uefi-firmware-parser"; dest.mkdir(parents=True, exist_ok=True)
            runs.append(_run_static_tool(runner, ["uefi-firmware-parser", "-b", str(p), "-e", "-o", str(dest)],
                                         timeout=1800, log_name=f"uefi_parser_{p.stem}"))
            extracted["uefi-firmware-parser"] = _bounded_tree_inventory(dest)
        elif runner.has("UEFIExtract"):
            dest = tool_root / "UEFIExtract"; dest.mkdir(parents=True, exist_ok=True)
            runs.append(_run_static_tool(runner, ["UEFIExtract", str(p), "all"], timeout=1800,
                                         log_name=f"uefi_extract_{p.stem}", cwd=dest))
            extracted["UEFIExtract"] = _bounded_tree_inventory(dest)
    return {"schema": "tbhm.uefi/1.1", "artifact": hashes(p), "markers": markers,
            "secure_boot_strings": sorted(set(re.findall(r"(?i).{0,40}(?:secure boot|pk|kek|dbx|capsule|signature).{0,80}", text)))[:500],
            "update_strings": sorted(set(re.findall(r"(?i).{0,40}(?:capsule|update|rollback|flash|spi).{0,80}", text)))[:500],
            "available_extractors": tools, "tool_runs": runs, "extracted": extracted,
            "execution_performed": bool(runs), "execution_kind": "static_parser_only" if runs else "none"}


def analyze_driver(path: str | Path, runner=None, output_dir: str | Path | None = None, execute_tools: bool = False) -> dict:
    p = Path(path)
    bundle = {}
    analysis_target = p
    if p.is_dir() and p.suffix.lower() == ".kext":
        info_path = p / "Contents" / "Info.plist"
        if info_path.is_file():
            try:
                value = plistlib.loads(info_path.read_bytes())
                bundle["info_plist"] = {str(k): value[k] for k in value if k in {
                    "CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion", "OSBundleLibraries",
                    "IOKitPersonalities", "NSSystemExtensionUsageDescription"
                }}
                executable = str(value.get("CFBundleExecutable") or "")
                candidate = p / "Contents" / "MacOS" / executable
                if executable and candidate.is_file() and not candidate.is_symlink():
                    analysis_target = candidate
            except Exception as exc:
                bundle["plist_error"] = str(exc)
        bundle["inventory"] = _bounded_tree_inventory(p, max_files=10000, max_total_bytes=1024 * 1024 * 1024)
    if not analysis_target.is_file():
        return {"schema": "tbhm.driver/1.2", "artifact": {"path": str(p)}, "driver_type": "macos",
                "bundle": bundle, "error": "no analyzable driver binary found", "execution_performed": False}
    text = "\n".join(extract_strings(analysis_target, minimum=5, max_bytes=min(analysis_target.stat().st_size, 128 * 1024 * 1024)))
    imports = sorted({m.group(1) for m in DRIVER_IMPORTS.finditer(text)})
    ioctls = sorted({m.group(0) for m in IOCTL_RE.finditer(text)})[:5000]
    modinfo = {}
    if analysis_target.suffix.lower() == ".ko" and runner and runner.has("modinfo"):
        rc, stdout, stderr = runner.run(["modinfo", str(analysis_target)], timeout=60, log_name=f"modinfo_{analysis_target.stem}")
        modinfo = {"returncode": rc, "stdout": stdout[:100000], "stderr": stderr[:5000]}
    tool_runs = []
    if execute_tools and runner:
        if runner.has("rabin2"):
            tool_runs.append(_run_static_tool(runner, ["rabin2", "-Ij", str(analysis_target)], timeout=300, log_name=f"driver_rabin2_{analysis_target.stem}"))
        if runner.has("objdump"):
            tool_runs.append(_run_static_tool(runner, ["objdump", "-p", str(analysis_target)], timeout=300, log_name=f"driver_objdump_{analysis_target.stem}"))
    driver_type = "windows" if analysis_target.suffix.lower() == ".sys" else "linux" if analysis_target.suffix.lower() == ".ko" else "macos"
    return {"schema": "tbhm.driver/1.2", "artifact": hashes(analysis_target), "container_path": str(p),
            "driver_type": driver_type, "bundle": bundle,
            "privileged_api_indicators": imports, "ioctl_indicators": ioctls, "modinfo": modinfo,
            "risk_tags": sorted(set((["ioctl_attack_surface"] if ioctls else []) +
                                     (["user_kernel_copy"] if any(x in imports for x in ("copy_from_user", "copy_to_user")) else []) +
                                     (["physical_memory_mapping"] if "MmMapIoSpace" in imports else []))),
            "tool_runs": tool_runs, "execution_performed": bool(tool_runs), "execution_kind": "static_parser_only" if tool_runs else "none"}


def analyze_mobile_package(path: str | Path, runner=None, output_dir: str | Path | None = None, execute_tools: bool = False) -> dict:
    p = Path(path)
    suffix = p.suffix.lower()
    result = {
        "schema": "tbhm.mobile-package/1.0", "artifact": hashes(p),
        "package_type": suffix.lstrip("."), "entries": [], "dex_files": [],
        "native_libraries": [], "manifests": [], "signing_files": [],
        "framework_hints": [], "plist_metadata": [], "execution_performed": False,
    }
    if suffix in {".dex", ".vdex", ".oat"}:
        result["dex_files"] = [p.name]
        return result
    if not zipfile.is_zipfile(p):
        result["error"] = "package is not a ZIP-compatible mobile archive"
        return result
    frameworks = set()
    with zipfile.ZipFile(p) as archive:
        for info in archive.infolist()[:200000]:
            name = info.filename.replace("\\", "/")
            if Path(name).is_absolute() or ".." in Path(name).parts:
                result.setdefault("unsafe_paths", []).append(name)
                continue
            row = {"path": name, "size": info.file_size, "compressed": info.compress_size}
            result["entries"].append(row)
            low = name.lower()
            if low.endswith(".dex"): result["dex_files"].append(name)
            if low.endswith((".so", ".dylib", ".framework", ".a")): result["native_libraries"].append(name)
            if low.endswith(("androidmanifest.xml", "info.plist", "entitlements.plist", "network_security_config.xml")):
                result["manifests"].append(name)
            if low.startswith("meta-inf/") or "embedded.mobileprovision" in low: result["signing_files"].append(name)
            if low.endswith("info.plist"):
                try:
                    raw_plist = archive.read(info)
                    value = plistlib.loads(raw_plist)
                    result["plist_metadata"].append({"path": name, "bundle_id": value.get("CFBundleIdentifier"),
                                                     "bundle_version": value.get("CFBundleVersion"),
                                                     "url_schemes": value.get("CFBundleURLTypes", []),
                                                     "ats": value.get("NSAppTransportSecurity", {}),
                                                     "background_modes": value.get("UIBackgroundModes", [])})
                except Exception:
                    pass
            if "libflutter.so" in low or "flutter_assets" in low: frameworks.add("flutter")
            if "index.android.bundle" in low or "reactnative" in low: frameworks.add("react-native")
            if "cordova" in low or "www/cordova.js" in low: frameworks.add("cordova")
            if "assemblies/" in low or low.endswith("xamarin.forms.dll"): frameworks.add("xamarin-dotnet")
    result["framework_hints"] = sorted(frameworks)
    result["tool_runs"] = []
    if execute_tools and runner:
        if suffix in {".apk", ".aab"}:
            if runner.has("apkanalyzer"):
                result["tool_runs"].append(_run_static_tool(runner, ["apkanalyzer", "manifest", "print", str(p)], timeout=300, log_name=f"apkanalyzer_{p.stem}"))
            elif runner.has("aapt2"):
                result["tool_runs"].append(_run_static_tool(runner, ["aapt2", "dump", "badging", str(p)], timeout=300, log_name=f"aapt2_{p.stem}"))
            elif runner.has("aapt"):
                result["tool_runs"].append(_run_static_tool(runner, ["aapt", "dump", "badging", str(p)], timeout=300, log_name=f"aapt_{p.stem}"))
            if output_dir and runner.has("jadx"):
                dest = Path(output_dir) / "jadx"; dest.mkdir(parents=True, exist_ok=True)
                result["tool_runs"].append(_run_static_tool(runner, ["jadx", "--no-res", "--no-imports", "-d", str(dest), str(p)], timeout=1800, log_name=f"jadx_{p.stem}"))
                result["jadx_inventory"] = _bounded_tree_inventory(dest)
    result["execution_performed"] = bool(result["tool_runs"])
    result["execution_kind"] = "static_parser_only" if result["tool_runs"] else "none"
    result["counts"] = {
        "entries": len(result["entries"]), "dex": len(result["dex_files"]),
        "native_libraries": len(result["native_libraries"]), "manifests": len(result["manifests"]),
        "signing_files": len(result["signing_files"]), "plist_metadata": len(result["plist_metadata"]),
    }
    return result


def _pcap_header(path: Path) -> dict:
    data = path.read_bytes()[:32]
    if len(data) < 12:
        return {"valid": False}
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        byte_order_magic = data[8:12]
        return {"valid": byte_order_magic in {b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"},
                "format": "pcapng", "magic": magic.hex(), "byte_order_magic": byte_order_magic.hex()}
    if len(data) < 24:
        return {"valid": False, "magic": magic.hex()}
    endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    if magic not in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        return {"valid": False, "magic": magic.hex()}
    major, minor, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiiii", data[4:24])
    return {"valid": True, "magic": magic.hex(), "version": f"{major}.{minor}", "snaplen": snaplen, "linktype": network}


def analyze_protocol_capture(path: str | Path, runner=None, max_packets: int = 10000) -> dict:
    p = Path(path)
    result = {"schema": "tbhm.protocol/1.0", "artifact": hashes(p), "header": _pcap_header(p),
              "protocols": {}, "endpoints": [], "fields": [], "execution_performed": False}
    if runner and runner.has("tshark"):
        rc, stdout, stderr = runner.run([
            "tshark", "-r", str(p), "-c", str(max(1, min(max_packets, 100000))), "-T", "fields",
            "-e", "frame.number", "-e", "_ws.col.Protocol", "-e", "ip.src", "-e", "ip.dst",
            "-e", "ipv6.src", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
            "-e", "udp.srcport", "-e", "udp.dstport", "-E", "separator=|"
        ], timeout=600, log_name=f"protocol_{p.stem}")
        rows = []
        for line in stdout.splitlines():
            cols = line.split("|")
            if len(cols) < 10:
                continue
            proto = cols[1] or "unknown"
            result["protocols"][proto] = result["protocols"].get(proto, 0) + 1
            rows.append({"frame": cols[0], "protocol": proto, "src": cols[2] or cols[4], "dst": cols[3] or cols[5],
                         "src_port": cols[6] or cols[8], "dst_port": cols[7] or cols[9]})
        result["endpoints"] = rows[:10000]
        result["tshark"] = {"returncode": rc, "stderr": stderr[:5000]}
        result["execution_performed"] = True
        result["execution_kind"] = "offline_capture_parser"
    return result


def analyze_hardware_evidence(path: str | Path, max_files: int = 5000) -> dict:
    root = Path(path)
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()] if root.is_dir() else []
    records, markers, secrets = [], [], []
    for p in files[:max_files]:
        if p.stat().st_size > 512 * 1024 * 1024:
            continue
        try:
            text = p.read_text(errors="ignore")[:20_000_000]
        except Exception:
            text = "\n".join(extract_strings(p, minimum=6, max_bytes=min(p.stat().st_size, 32 * 1024 * 1024)))
        boot_hits = [m.group(0) for m in BOOT_RE.finditer(text)][:500]
        secret_hits = [m.group(0) for m in SECRET_RE.finditer(text)][:200]
        records.append({"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size,
                        "boot_hardware_markers": boot_hits, "sensitive_markers": secret_hits})
        markers.extend({"path": str(p), "marker": x} for x in boot_hits)
        secrets.extend({"path": str(p), "marker": x} for x in secret_hits)
    return {"schema": "tbhm.hardware-evidence/1.0", "records": records,
            "boot_hardware_markers": markers, "sensitive_markers": secrets,
            "execution_performed": False}
