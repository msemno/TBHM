"""Verify TBHM packages or source trees without executing their code."""
from __future__ import annotations
from pathlib import Path
from core import redteam_utils as RT
from core.package_verifier import verify_zip, verify_tree
from core.reverse_phase_utils import write_json


def run(ctx):
    source = getattr(ctx.args, "verify_package", None)
    if not source:
        return
    out = RT.evidence_dir(ctx, "00_package_verification")
    path = Path(source).expanduser().resolve(strict=True)
    result = verify_zip(path) if path.is_file() and path.suffix.lower() == ".zip" else verify_tree(path, getattr(ctx.args, "verify_manifest", None), True)
    write_json(out / "PACKAGE_VERIFICATION.json", result)
    RT.write_md(out / "PACKAGE_VERIFICATION_SUMMARY.md", "Package Verification", [
        ("Target", str(path)), ("Passed", str(result.get("passed"))), ("Issues", str(len(result.get("issues", [])))),
        ("Method", "CRC/path/symlink/duplicate checks for ZIPs; manifest hashes and Python compilation for source trees."),
    ])
    if not result.get("passed"):
        raise RuntimeError("package verification failed: " + "; ".join(result.get("issues", [])[:10]))
    ctx.log("OK", "package_verification", "package verification passed")
