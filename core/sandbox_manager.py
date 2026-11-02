"""TBHM-owned disposable sandbox and VM lifecycle management.

Container execution is rootless-compatible, network-off by default, read-only,
capability-free and resource bounded. QEMU mode creates a temporary qcow2 overlay
and captures serial output; it does not expose host disks or networking by
default. Every execution path requires an explicit caller-side authorization gate.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Sequence


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxResult:
    backend: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: float
    ended_at: float
    timed_out: bool = False
    workspace: str = ""
    overlay: str = ""
    network: str = "none"
    policy: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def parse_command_json(value: str | Path | None) -> list[str]:
    if not value:
        return []
    raw = Path(value).read_text(errors="ignore") if Path(str(value)).is_file() else str(value)
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise SandboxError(f"sandbox command must be a JSON array: {exc}") from exc
    if not isinstance(data, list) or not data or not all(isinstance(x, (str, int, float)) for x in data):
        raise SandboxError("sandbox command must be a non-empty JSON array of scalar arguments")
    return [str(x) for x in data]


class SandboxManager:
    def __init__(self, output: str | Path):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _artifact(path: str | Path) -> Path:
        artifact = Path(path).expanduser().resolve(strict=True)
        if not artifact.is_file() or artifact.is_symlink():
            raise SandboxError("artifact must be a regular non-symlink file")
        return artifact

    @staticmethod
    def container_engine(preferred: str = "auto") -> str:
        names = [preferred] if preferred not in {"", "auto"} else ["podman", "docker"]
        for name in names:
            if shutil.which(name):
                return name
        raise SandboxError("neither podman nor docker is available")

    def run_container(self, artifact: str | Path, image: str, guest_command: Sequence[str], *,
                      engine: str = "auto", timeout: int = 300, memory_mb: int = 1024,
                      cpus: float = 1.0, pids: int = 128, network: str = "none",
                      environment: dict[str, str] | None = None,
                      case_file: str | Path | None = None) -> SandboxResult:
        artifact = self._artifact(artifact)
        if not image or any(ch.isspace() for ch in image):
            raise SandboxError("a local container image name is required")
        if network not in {"none", "bridge"}:
            raise SandboxError("network must be none or bridge")
        engine_bin = self.container_engine(engine)
        run_id = f"sandbox-{uuid.uuid4().hex[:12]}"
        workspace = self.output / run_id
        workspace.mkdir(mode=0o733)
        # The guest runs as uid/gid 65534.  Owner-only 0700 would make the
        # bind-mounted /output directory unwritable and silently defeat evidence
        # collection.  0733 permits creation without exposing directory listing
        # to unrelated local users.
        workspace.chmod(0o733)
        cmd = [
            engine_bin, "run", "--rm", "--pull=never", "--name", run_id,
            "--network", network, "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(max(16, min(pids, 4096))),
            "--memory", f"{max(128, min(memory_mb, 32768))}m", "--cpus", str(max(0.1, min(cpus, 32))),
            "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
            "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=64m",
            "-v", f"{artifact}:/input/artifact:ro", "-v", f"{workspace}:/output:rw",
        ]
        if case_file is not None:
            case_path = self._artifact(case_file)
            cmd += ["-v", f"{case_path}:/input/case:ro"]
        for key, value in sorted((environment or {}).items()):
            if not key.replace("_", "").isalnum():
                raise SandboxError(f"invalid environment key: {key}")
            cmd += ["-e", f"{key}={value}"]
        cmd += [image, *[str(x) for x in guest_command]]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, min(timeout, 86400)), check=False)
            result = SandboxResult("container", cmd, proc.returncode, proc.stdout, proc.stderr,
                                   started, time.time(), workspace=str(workspace), network=network,
                                   policy={"read_only": True, "cap_drop": "ALL", "no_new_privileges": True,
                                           "user": "65534:65534", "pull": "never"})
        except subprocess.TimeoutExpired as exc:
            subprocess.run([engine_bin, "rm", "-f", run_id], capture_output=True, text=True, check=False)
            result = SandboxResult("container", cmd, 124, exc.stdout or "", exc.stderr or "timeout",
                                   started, time.time(), timed_out=True, workspace=str(workspace), network=network,
                                   policy={"read_only": True, "cap_drop": "ALL", "no_new_privileges": True})
        (workspace / "sandbox-result.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return result

    def run_qemu_vm(self, base_image: str | Path, *, qemu_binary: str = "qemu-system-x86_64",
                    memory_mb: int = 1024, cpus: int = 1, timeout: int = 300,
                    kernel: str | Path | None = None, initrd: str | Path | None = None,
                    append: str = "console=ttyS0", extra_args: Sequence[str] = ()) -> SandboxResult:
        base = Path(base_image).expanduser().resolve(strict=True)
        if not base.is_file() or base.is_symlink():
            raise SandboxError("base VM image must be a regular non-symlink file")
        if not shutil.which(qemu_binary):
            raise SandboxError(f"missing QEMU binary: {qemu_binary}")
        if not shutil.which("qemu-img"):
            raise SandboxError("missing qemu-img")
        run_id = f"vm-{uuid.uuid4().hex[:12]}"
        workspace = self.output / run_id
        workspace.mkdir(mode=0o700)
        overlay = workspace / "overlay.qcow2"
        info = subprocess.run(["qemu-img", "info", "--output=json", str(base)],
                              capture_output=True, text=True, check=False)
        if info.returncode != 0:
            raise SandboxError(f"cannot inspect base VM image: {info.stderr[-1000:]}")
        try:
            base_format = str(json.loads(info.stdout).get("format") or "").strip()
        except Exception as exc:
            raise SandboxError(f"invalid qemu-img info output: {exc}") from exc
        if base_format not in {"raw", "qcow2", "vmdk", "vdi", "vhdx"}:
            raise SandboxError(f"unsupported base VM image format: {base_format or 'unknown'}")
        create = subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", base_format, "-b", str(base), str(overlay)],
                                capture_output=True, text=True, check=False)
        if create.returncode != 0:
            raise SandboxError(f"cannot create disposable VM overlay: {create.stderr[-1000:]}")
        cmd = [
            qemu_binary, "-nodefaults", "-no-reboot", "-nographic", "-serial", "stdio",
            "-monitor", "none", "-m", str(max(128, min(memory_mb, 65536))),
            "-smp", str(max(1, min(cpus, 32))), "-net", "none",
            "-drive", f"file={overlay},if=virtio,format=qcow2,cache=unsafe",
        ]
        if kernel:
            cmd += ["-kernel", str(Path(kernel).expanduser().resolve(strict=True)), "-append", append]
        if initrd:
            cmd += ["-initrd", str(Path(initrd).expanduser().resolve(strict=True))]
        safe_extra = [str(x) for x in extra_args]
        forbidden = {"-drive", "-blockdev", "-netdev", "-nic", "-device", "-chardev", "-fsdev"}
        if any(arg.split("=", 1)[0] in forbidden for arg in safe_extra):
            raise SandboxError("extra QEMU args may not add host drives, devices, networking or filesystems")
        cmd += safe_extra
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, min(timeout, 86400)), check=False)
            result = SandboxResult("qemu", cmd, proc.returncode, proc.stdout, proc.stderr,
                                   started, time.time(), workspace=str(workspace), overlay=str(overlay), network="none",
                                   policy={"disposable_overlay": True, "base_format": base_format, "network": "none", "serial_only": True})
        except subprocess.TimeoutExpired as exc:
            result = SandboxResult("qemu", cmd, 124, exc.stdout or "", exc.stderr or "timeout",
                                   started, time.time(), timed_out=True, workspace=str(workspace), overlay=str(overlay),
                                   network="none", policy={"disposable_overlay": True, "base_format": base_format, "network": "none"})
        (workspace / "vm-result.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return result
