"""Explicit disposable container/QEMU execution owned by TBHM."""
from __future__ import annotations
import json
from pathlib import Path
from core import redteam_utils as RT
from core.sandbox_manager import SandboxManager, SandboxError, parse_command_json
from core.reverse_phase_utils import write_json


def run(ctx):
    if not getattr(ctx.args, "reverse_sandbox", False):
        return
    if not getattr(ctx.args, "confirm_isolated_execution", False):
        raise RuntimeError("--reverse-sandbox requires --confirm-isolated-execution")
    out = RT.evidence_dir(ctx, "25f_reverse_sandbox")
    manager = SandboxManager(out)
    backend = str(getattr(ctx.args, "reverse_sandbox_backend", "container") or "container")
    timeout = int(getattr(ctx.args, "reverse_sandbox_timeout", 300))
    try:
        if backend == "container":
            artifact = getattr(ctx.args, "binary_path", None)
            image = getattr(ctx.args, "reverse_sandbox_image", None)
            command = parse_command_json(getattr(ctx.args, "reverse_sandbox_command", None))
            if not artifact or not image or not command:
                raise SandboxError("container mode requires --binary-path, --reverse-sandbox-image and --reverse-sandbox-command JSON")
            result = manager.run_container(artifact, image, command, engine=getattr(ctx.args, "reverse_sandbox_engine", "auto"),
                                           timeout=timeout, memory_mb=int(getattr(ctx.args, "reverse_sandbox_memory_mb", 1024)),
                                           cpus=float(getattr(ctx.args, "reverse_sandbox_cpus", 1.0)),
                                           pids=int(getattr(ctx.args, "reverse_sandbox_pids", 128)),
                                           network=str(getattr(ctx.args, "reverse_sandbox_network", "none")))
        elif backend == "qemu":
            image = getattr(ctx.args, "reverse_vm_image", None)
            if not image: raise SandboxError("qemu mode requires --reverse-vm-image")
            result = manager.run_qemu_vm(image, qemu_binary=str(getattr(ctx.args, "reverse_qemu_binary", "qemu-system-x86_64")),
                                         memory_mb=int(getattr(ctx.args, "reverse_sandbox_memory_mb", 1024)),
                                         cpus=int(float(getattr(ctx.args, "reverse_sandbox_cpus", 1))), timeout=timeout,
                                         kernel=getattr(ctx.args, "reverse_vm_kernel", None), initrd=getattr(ctx.args, "reverse_vm_initrd", None),
                                         append=str(getattr(ctx.args, "reverse_vm_append", "console=ttyS0")))
        else:
            raise SandboxError("sandbox backend must be container or qemu")
        write_json(out / "REVERSE_SANDBOX_INDEX.json", {"schema": "tbhm.sandbox/1.0", "runs": [result.to_dict()]})
        ctx.log("OK", "reverse_sandbox_analysis", f"{backend} run completed rc={result.returncode}")
    except SandboxError as exc:
        write_json(out / "REVERSE_SANDBOX_INDEX.json", {"schema": "tbhm.sandbox/1.0", "runs": [], "error": str(exc)})
        ctx.log("WARN", "reverse_sandbox_analysis", str(exc))
