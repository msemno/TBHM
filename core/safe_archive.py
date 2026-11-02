"""Hardened archive extraction shared across phases.

Analysis inputs (APK/IPA/firmware containers/evidence bundles) are attacker
controlled. ``ZipFile.extractall`` trusts member names and sizes, so a malicious
archive can write outside the destination (path traversal / absolute paths),
plant symlinks that redirect later writes, or exhaust disk/inodes with a
decompression bomb. This module extracts with all of those defeated and returns
a structured report instead of raising on hostile input.
"""

from __future__ import annotations

import stat
import json
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

_EXTRACTION_TIMEOUT_SECONDS = 30.0
_EXTRACT_WORKER_CODE = ('import sys; sys.path.insert(0, sys.argv[1]); '
                        'from core.safe_archive import _extract_worker; _extract_worker()')


@dataclass
class ExtractReport:
    destination: str
    extracted: int = 0
    skipped: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    total_bytes: int = 0
    truncated: bool = False

    @property
    def safe(self) -> bool:
        return not self.rejected


def safe_extract_zip(
    archive: str | Path,
    destination: str | Path,
    *,
    max_files: int = 40_000,
    max_total_bytes: int = 4 * 1024 * 1024 * 1024,
    max_file_bytes: int = 1024 * 1024 * 1024,
    max_ratio: float = 200.0,
) -> ExtractReport:
    """Run all archive parsing, CRC and decompression under one outer deadline.

    The isolated worker has no children and is killed on expiry, including when
    a filesystem/decompressor call never returns. Existing signatures and report
    fields are preserved. A timed-out extraction is never advertised as usable.
    """
    archive = Path(archive).resolve()
    destination = Path(destination).resolve()
    job = {'archive': str(archive), 'destination': str(destination), 'options': {
        'max_files': max_files, 'max_total_bytes': max_total_bytes,
        'max_file_bytes': max_file_bytes, 'max_ratio': max_ratio,
    }}
    worker = subprocess.Popen([sys.executable, '-c', _EXTRACT_WORKER_CODE,
                               str(Path(__file__).resolve().parents[1])],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, shell=False)
    try:
        stdout, _ = worker.communicate(json.dumps(job).encode(), timeout=_EXTRACTION_TIMEOUT_SECONDS)
        if worker.returncode == 0:
            return ExtractReport(**json.loads(stdout))
        return ExtractReport(str(destination), rejected=['extraction-worker-failed'])
    except subprocess.TimeoutExpired:
        worker.kill()
        worker.communicate()
        return ExtractReport(str(destination), truncated=True, rejected=['extraction-timeout'])
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait()


def _extract_worker():
    job = json.load(sys.stdin)
    try:
        report = _extract_zip(job['archive'], job['destination'], **job['options'])
    except Exception as exc:
        report = ExtractReport(job['destination'], rejected=[f'archive-error:{type(exc).__name__}'])
    print(json.dumps(asdict(report)))


def _extract_zip(archive, destination, *, max_files, max_total_bytes, max_file_bytes, max_ratio):
    """Extract ``archive`` into ``destination`` with hostile-input defenses.

    Nothing is written outside ``destination``. Symlink members, absolute paths
    and ``..`` traversal are rejected. Per-file, total-size, count and
    compression-ratio caps bound decompression bombs. The archive is never
    trusted to size itself: writing stops at ``max_file_bytes`` per member.
    """
    archive = Path(archive)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    report = ExtractReport(destination=str(root))

    with zipfile.ZipFile(archive) as zf:
        # ZipExtFile checks CRC while approved members are streamed below.
        # testzip() would decompress every member before any safety budget.
        for info in zf.infolist():
            name = info.filename
            member = PurePosixPath(name)

            if member.is_absolute() or member.drive or ".." in member.parts:
                report.rejected.append(f"unsafe-path:{name}")
                continue

            unix_mode = (info.external_attr >> 16) & 0o177777
            if stat.S_ISLNK(unix_mode):
                report.rejected.append(f"symlink:{name}")
                continue

            target = (root / Path(*member.parts)).resolve()
            if target != root and root not in target.parents:
                report.rejected.append(f"escapes-root:{name}")
                continue

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if report.extracted >= max_files:
                report.truncated = True
                report.skipped.append(f"file-count-cap:{name}")
                continue

            declared = int(getattr(info, "file_size", 0) or 0)
            compressed = int(getattr(info, "compress_size", 0) or 0)
            if declared > max_file_bytes:
                report.skipped.append(f"oversize-member:{name}")
                continue
            if compressed > 0 and declared / compressed > max_ratio and declared > 1024 * 1024:
                report.skipped.append(f"suspicious-ratio:{name}")
                continue
            if report.total_bytes + declared > max_total_bytes:
                report.truncated = True
                report.skipped.append(f"total-size-cap:{name}")
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info, "r") as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_file_bytes:
                            report.skipped.append(f"stream-exceeded-cap:{name}")
                            break
                        if report.total_bytes + written > max_total_bytes:
                            report.truncated = True
                            report.skipped.append(f"total-size-cap:{name}")
                            break
                        sink.write(chunk)
            except Exception as exc:  # noqa: BLE001 - hostile input must not crash the phase
                report.rejected.append(f"read-error:{name}:{str(exc)[:120]}")
                try:
                    target.unlink()
                except OSError:
                    pass
                continue

            # Never inherit setuid/setgid/executable bits from an untrusted member.
            try:
                target.chmod(0o600)
            except OSError:
                pass
            report.total_bytes += written
            report.extracted += 1

    return report
