#!/usr/bin/env python3
"""Create a private, bounded, redacted review copy of one TBHM run.

This collector does not run TBHM, contact a network service, modify source runs,
copy databases, or certify that arbitrary customer data is safe to publish.
Python 3.10+ on Linux/POSIX is required. Inspect the copy before sharing it.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import uuid
from urllib.parse import quote, quote_plus

VERSION = "2026-10-25.review-bundle-1"
SCHEMA = "tbhm.run-review-bundle/1"
MAX_DEPTH = 10
MAX_VISITED = 10000
ROOT_FILES = {
    "execution_ledger.json", "report.json", "report.sarif", "operator_queue.json",
    "evidence_graph.json", "run.log", "console.log", "PARTIAL_RUN.json",
    "ci_summary.json", "ci_incomplete_summary.json", "learning_overview.json",
    "METHODOLOGY_AUDIT.md", "REPORT_final.md", "REPORT_confirmed.md",
    "REPORT_leads.md", "ROE_STAMP.txt", "coverage_map.json", "test_coverage.json",
}
DIRECTORIES = {
    "evidence", "llm_analysis", "source_code_full", "code", "correlation",
    "redteam", "mobile", "spec", "diagnostics", "js_analysis", "recon",
}
BLOCK_DIRS = {
    ".git", ".venv", "node_modules", "delivery", "database", "databases",
    "backups", "models", "_apk", "_ipa", "_recovered", "__pycache__",
}
EXTENSIONS = {".json", ".jsonl", ".sarif", ".md", ".txt", ".csv", ".log"}
BLOCK_NAME = re.compile(
    r"(?i)(?:^\.env(?:\.|$)|(?:\.sqlite3?|\.db|\.pem|\.key|\.p12|\.pfx|"
    r"\.apk|\.ipa|\.pcap|\.pcapng|\.zip|\.gz|\.7z|\.bin|\.exe)$|"
    r"(?:gitleaks|trufflehog|private[-_]?key|id_ed25519|id_rsa))"
)
SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_\-\s])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|"
    r"authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|sessionid|"
    r"session[_-]?id|auth)(?:$|[_\-\s])"
)
BODY_KEYS = {
    "body", "request_body", "response_body", "raw_request", "raw_response",
    "postdata", "post_data", "source_code", "source_snippet", "source_excerpt",
    "prompt", "system_prompt", "user_prompt", "completion", "model_response",
    "raw_output", "raw", "html", "payload", "content", "evidence",
}
SECRET_FLAGS = {"--password", "--passwd", "--token", "--api-key", "--secret",
                "--client-secret", "--auth", "--cookie", "--user"}
TEXT_SECRET_FLAGS = SECRET_FLAGS
TOOL_FILES = (
    "tbhm.py", "core/version.py", "core/runner.py", "core/request_guard.py",
    "core/evidence_redaction.py", "core/llm_local.py", "core/llm_review.py",
    "core/ai_plane/observer.py", "core/ai_plane/embeddings.py",
    "core/ai_plane/advisor.py", "core/ai_plane/public_knowledge.py",
    "core/ai_plane/run_learning.py", "core/ai_plane/cli.py",
    "phases/recon.py", "phases/discovery.py", "phases/diagnostics.py",
    "phases/local_llm_triage.py", "phases/strict_finding_validation.py",
)


class CollectionError(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def checked_path(value: str) -> Path:
    if not value or not value.strip():
        raise CollectionError("An explicit nonempty path is required")
    return Path(os.path.abspath(os.path.expanduser(value)))


@contextmanager
def directory_fd(path: Path):
    """Open every directory component without following symbolic links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def signature(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def read_regular(root: Path, relative: str, maximum: int) -> bytes:
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not rel.parts or any(x in {"", ".", ".."} for x in rel.parts):
        raise CollectionError("Unsafe relative input")
    with directory_fd(root) as root_fd:
        parent = os.dup(root_fd)
        fd = None
        try:
            for part in rel.parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = nxt
            fd = os.open(rel.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CollectionError("Single-link regular input required")
            if before.st_size > maximum:
                raise CollectionError("Input exceeds the file byte limit")
            chunks = []
            size = 0
            while True:
                piece = os.read(fd, min(262144, maximum + 1 - size))
                if not piece:
                    break
                chunks.append(piece)
                size += len(piece)
                if size > maximum:
                    raise CollectionError("Input grew beyond the file byte limit")
            after = os.fstat(fd)
            current = os.stat(rel.name, dir_fd=parent, follow_symlinks=False)
            if signature(before) != signature(after) or signature(after) != signature(current):
                raise CollectionError("Input changed during collection; retry after the run settles")
            return b"".join(chunks)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)


def external_bytes(path: Path, maximum: int) -> bytes:
    return read_regular(path.parent, path.name, maximum)


class Redactor:
    def __init__(self, known_values=(), aliases=None, include_evidence=False):
        self.counts = Counter()
        self.include_evidence = include_evidence
        self.aliases = dict(aliases or {})
        self.aliases.setdefault(str(Path.home()), "[USER_HOME]")
        self.known_values = set()
        for value in known_values:
            if len(value) < 4 or not value.strip() or "\n" in value or "\r" in value:
                raise CollectionError("Each known redaction value must be a single line of at least 4 characters")
            self.known_values.update({value, quote(value, safe=""), quote_plus(value),
                                      json.dumps(value)[1:-1]})

    def sub(self, name, pattern, replacement, text, flags=0):
        value, count = re.subn(pattern, replacement, text, flags=flags)
        self.counts[name] += count
        return value

    def text(self, value: str) -> str:
        text = value
        for original in sorted(self.known_values, key=len, reverse=True):
            count = text.count(original)
            if count:
                text = text.replace(original, "[REDACTED_KNOWN_VALUE]")
                self.counts["known_value"] += count
        text = self.sub("private_key", r"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----|\Z)", "[REDACTED_PRIVATE_KEY]", text)
        text = self.sub("authorization", r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", text)
        text = self.sub("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\b", "[REDACTED_JWT]", text)
        text = self.sub("provider_token", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b", "[REDACTED_PROVIDER_TOKEN]", text)
        text = self.sub("url_userinfo", r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
        names = r"password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|client[_-]?secret|sessionid"
        text = self.sub("assignment", r"(?i)(\b(?:" + names + r")\b[\"']?\s*[=:]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&;,\}\]\r\n]+)", r"\1[REDACTED]", text)
        text = self.sub("header", r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie)[\"']?\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
        flags = "|".join(re.escape(x) for x in sorted(TEXT_SECRET_FLAGS, key=len, reverse=True))
        text = self.sub("secret_flag", r"(?i)((?:" + flags + r")(?:=|\s+))(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s]+)", r"\1[REDACTED]", text)
        text = self.sub("user_home", r"/home/[^/\s\"']+|[A-Za-z]:\\Users\\[^\\\s\"']+", "[USER_HOME]", text)
        for original in sorted(self.aliases, key=len, reverse=True):
            count = text.count(original)
            if count:
                text = text.replace(original, self.aliases[original])
                self.counts["alias"] += count
        return text

    def value(self, value, depth=0):
        if depth > 80:
            raise CollectionError("Structured input exceeds the nesting limit")
        if isinstance(value, dict):
            header_pair = SENSITIVE_KEY.search(str(value.get("name", ""))) is not None
            output = {}
            for key, item in value.items():
                normalized = re.sub(r"[-\s]", "_", key.lower())
                if SENSITIVE_KEY.search(key) or (header_pair and key.lower() == "value"):
                    output[self.text(key)] = "[REDACTED_FIELD]"
                    self.counts["sensitive_field"] += 1
                elif not self.include_evidence and normalized in BODY_KEYS:
                    output[self.text(key)] = "[OMITTED_FROM_MINIMAL_REVIEW_COPY]"
                    self.counts["body_omitted"] += 1
                elif key.lower() in {"argv", "command", "cmd"} and isinstance(item, list):
                    output[self.text(key)] = self.argv(item, depth + 1)
                else:
                    output[self.text(key)] = self.value(item, depth + 1)
            return output
        if isinstance(value, list):
            return [self.value(x, depth + 1) for x in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def argv(self, values, depth):
        result = []
        hide_next = False
        curl = bool(values and isinstance(values[0], str) and Path(values[0]).name.lower() in {"curl", "curl.exe"})
        for value in values:
            if hide_next:
                result.append("[REDACTED_ARG]")
                self.counts["secret_argument"] += 1
                hide_next = False
                continue
            result.append(self.value(value, depth))
            hide_next = isinstance(value, str) and (value.lower() in SECRET_FLAGS or (curl and value in {"-u", "-b"}))
        return result

    def encoded(self, data: bytes, suffix: str) -> bytes:
        text = data.decode("utf-8-sig", errors="strict")
        if "\x00" in text:
            raise CollectionError("Binary/NUL content is not accepted")
        if suffix in {".json", ".sarif"}:
            value = json.loads(text)
            text = json.dumps(self.value(value), ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        elif suffix == ".jsonl":
            lines = []
            for line in text.splitlines():
                if line.strip():
                    lines.append(json.dumps(self.value(json.loads(line)), ensure_ascii=False, allow_nan=False))
            text = "\n".join(lines) + "\n"
        else:
            text = self.text(text)
        for value in self.known_values:
            if value in text:
                raise CollectionError("A supplied redaction value remains in the review copy")
        return text.encode("utf-8")


def candidates(root, include_tool_logs, include_evidence):
    """Bounded descriptor-relative traversal; no symlink directories followed."""
    result, rejected = [], []
    visited = 0
    allowed = set(DIRECTORIES)
    if include_tool_logs:
        allowed.add("logs")
    if include_evidence:
        allowed.add("PER-FINDING")

    def walk(fd, prefix, depth):
        nonlocal visited
        with os.scandir(fd) as entries:
            rows = []
            for entry in entries:
                visited += 1
                if visited > MAX_VISITED:
                    raise CollectionError("Run inventory exceeds the traversal limit")
                rows.append(entry)
            rows.sort(key=lambda e: e.name)
        for entry in rows:
            rel = prefix + entry.name
            if entry.name in BLOCK_DIRS or BLOCK_NAME.search(entry.name):
                continue
            if entry.is_dir(follow_symlinks=False):
                if depth == 0 and entry.name not in allowed:
                    continue
                if depth >= MAX_DEPTH:
                    rejected.append({"source_relative": rel, "reason": "directory depth limit"})
                    continue
                try:
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except OSError:
                    rejected.append({"source_relative": rel, "reason": "directory unavailable or replaced"})
                    continue
                try:
                    walk(child, rel + "/", depth + 1)
                finally:
                    os.close(child)
            elif (depth == 0 and entry.name in ROOT_FILES) or (
                    depth > 0 and Path(entry.name).suffix.lower() in EXTENSIONS):
                if not entry.is_file(follow_symlinks=False):
                    rejected.append({"source_relative": rel, "reason": "nonregular or symlink input"})
                else:
                    result.append(rel)
            elif depth == 0 and entry.name in allowed and entry.is_symlink():
                rejected.append({"source_relative": rel, "reason": "symlink directory rejected"})
    with directory_fd(root) as fd:
        walk(fd, "", 0)
    priority = {"execution_ledger.json": 0, "report.json": 1, "run.log": 2, "console.log": 3}
    result.sort(key=lambda s: (priority.get(s, 10), s))
    return result, rejected


def private_write(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


def make_private_parent(path: Path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
    finally:
        os.close(fd)


def build_snapshot(root: Path):
    result = {"files": {}, "declared_version": {}, "runtime_python": sys.version.split()[0],
              "platform": sys.platform, "optional_tool_versions_executed": False}
    for rel in TOOL_FILES:
        try:
            raw = read_regular(root, rel, 2 * 1024 * 1024)
            result["files"][rel] = {"sha256": sha(raw), "bytes": len(raw)}
            if rel == "core/version.py":
                for node in ast.parse(raw.decode()).body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        for target in node.targets:
                            if isinstance(target, ast.Name) and target.id in {"VERSION", "SEMANTIC_VERSION", "DISPLAY_VERSION"}:
                                result["declared_version"][target.id] = node.value.value
        except (OSError, ValueError, SyntaxError, CollectionError, UnicodeError):
            result["files"][rel] = {"status": "unavailable"}
    result["interpretation"] = "Source fingerprints identify supplied files; they do not attest to the code loaded by a past process or validate its behavior."
    return result


def collect(args):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise CollectionError("Run this collector on Kali/Linux/POSIX with O_NOFOLLOW support")
    run = checked_path(args.run)
    output_home = checked_path(args.output_home)
    if run == output_home or run in output_home.parents:
        raise CollectionError("The output directory must be outside the source run")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,59}", args.run_alias):
        raise CollectionError("Use a non-sensitive run alias of 1-60 letters, digits, dots, underscores or hyphens")
    known = []
    if args.redact_file:
        raw = external_bytes(checked_path(args.redact_file), 65536)
        known = [x for x in raw.decode("utf-8").splitlines() if x]
    aliases = {}
    if args.alias_map:
        aliases = json.loads(external_bytes(checked_path(args.alias_map), 65536))
        if not isinstance(aliases, dict) or not all(isinstance(k, str) and len(k) >= 4 and isinstance(v, str) and v and "\n" not in v for k, v in aliases.items()):
            raise CollectionError("Alias map must be an object of nonempty string replacements with source keys at least 4 characters long")
    redact = Redactor(known, aliases, args.include_evidence)
    files, rejected = candidates(run, args.include_tool_logs, args.include_evidence)
    if not files:
        raise CollectionError("No recognized run artifacts found; use the actual output directory containing the ledger/report/log")
    make_private_parent(output_home)
    bundle = output_home / (args.run_alias + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    bundle.mkdir(mode=0o700)
    (bundle / "artifacts").mkdir(mode=0o700)
    entries = []
    skipped = list(rejected)
    total = 0
    max_file = args.max_file_mb * 1024 * 1024
    max_total = args.max_total_mb * 1024 * 1024
    sources = [(run, rel, rel) for rel in files]
    for index, extra in enumerate(args.extra, 1):
        path = checked_path(extra)
        if path.suffix.lower() not in EXTENSIONS or BLOCK_NAME.search(path.name):
            skipped.append({"source_relative": "external-" + str(index), "reason": "external input format/name is not accepted"})
        else:
            sources.append((path.parent, path.name, "external-" + str(index) + path.suffix.lower()))
    for root, rel, label in sources:
        if len(entries) >= args.max_files:
            skipped.append({"source_relative": label, "reason": "selected file count limit"})
            continue
        try:
            raw = read_regular(root, rel, max_file)
            clean = redact.encoded(raw, Path(rel).suffix.lower())
            if len(clean) > max_file or total + len(clean) > max_total:
                raise CollectionError("Review output exceeds the configured byte budget")
            destination = "artifacts/" + f"{len(entries)+1:04d}" + Path(rel).suffix.lower()
            private_write(bundle / destination, clean)
            entries.append({"source_relative": redact.text(label), "destination": destination,
                            "original_sha256": sha(raw), "review_sha256": sha(clean),
                            "original_bytes": len(raw), "review_bytes": len(clean),
                            "changed_by_sanitizer": raw != clean})
            total += len(clean)
        except (OSError, ValueError, RecursionError, UnicodeError, CollectionError) as exc:
            skipped.append({"source_relative": redact.text(label), "reason": redact.text(type(exc).__name__ + ": " + str(exc))})
    if args.tool_home:
        snapshot = redact.value(build_snapshot(checked_path(args.tool_home)))
        raw = json_bytes(snapshot)
        private_write(bundle / "build_snapshot.json", raw)
    notes = (
        "# Private review copy\n\n"
        "Inspect every included file before sharing. Automatic redaction is not a privacy certificate.\n\n"
        "This is a derived troubleshooting copy, not an original proof bundle. Source runs were read only. "
        "Minimal mode omits selected JSON body/evidence/prompt fields; text/Markdown/logs can still contain such content. "
        "Preserve original evidence, controls, hashes and delivery seals locally.\n\n"
        "No databases, model weights, archives, APK/IPA/PCAP, private-key files, raw Gitleaks/TruffleHog reports, "
        "or extracted mobile trees are intentionally collected. Missing/skipped files remain visible in manifest.json. "
        "No scan, model request, training, upload or external tool-version command was executed. "
        "A verified review-copy hash does not prove a vulnerability or authorize reuse/training.\n"
    )
    private_write(bundle / "REVIEW_BEFORE_SHARING.md", notes.encode())
    auxiliary = {}
    for name in ("build_snapshot.json", "REVIEW_BEFORE_SHARING.md"):
        if (bundle / name).exists():
            auxiliary[name] = sha((bundle / name).read_bytes())
    copied_labels = {item["source_relative"] for item in entries}
    missing_primary = [x for x in ("execution_ledger.json", "report.json", "run.log") if x not in copied_labels]
    incomplete = bool(skipped or missing_primary)
    manifest = {
        "schema": SCHEMA, "collector_version": VERSION, "created_at": utc(),
        "run_alias": args.run_alias, "collection_complete": not incomplete,
        "source_run_modified": False, "ai_memory_modified": False,
        "network_or_subprocess_used": False, "training_executed": False,
        "privacy_certified": False, "manual_review_required": True,
        "original_evidence_authority": False, "include_evidence": args.include_evidence,
        "include_tool_logs": args.include_tool_logs, "files": entries,
        "skipped": redact.value(skipped), "redaction_counts": dict(redact.counts),
        "limits": {"max_files": args.max_files, "max_file_mb": args.max_file_mb, "max_total_mb": args.max_total_mb},
        "review_bytes": total, "auxiliary_sha256": auxiliary,
        "missing_primary": missing_primary,
        "limitations": "No general secret detector can guarantee removal of arbitrary customer data. Original-file hashes are fingerprints, not signatures or proof validation. A running scan can change between separately read artifacts.",
    }
    private_write(bundle / "manifest.json", json_bytes(manifest))
    verification = verify_directory(bundle)
    if not verification["integrity_matches"]:
        raise CollectionError("New review copy failed integrity verification")
    archive = None
    if args.archive:
        archive = Path(str(bundle) + ".tar.gz")
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as target, tarfile.open(fileobj=target, mode="w:gz") as tf:
            for rel in verification["verified_files"]:
                raw = read_regular(bundle, rel, max(max_file, 4 * 1024 * 1024))
                if sha(raw) != verification["verified_sha256"][rel]:
                    raise CollectionError("Review artifact changed before archiving")
                info = tarfile.TarInfo(bundle.name + "/" + rel)
                info.size = len(raw)
                info.mode = 0o600
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                import io
                tf.addfile(info, io.BytesIO(raw))
    return {"status": "partial" if incomplete else "complete", "bundle": str(bundle),
            "archive": str(archive) if archive else None, "files_collected": len(entries),
            "files_skipped": len(skipped), "missing_primary": missing_primary, "privacy_certified": False,
            "next": "Inspect manifest.json and every review artifact before sharing.",
            "exit_code": 3 if incomplete else 0}


def verify_directory(bundle: Path):
    manifest_raw = read_regular(bundle, "manifest.json", 4 * 1024 * 1024)
    manifest = json.loads(manifest_raw)
    if manifest.get("schema") != SCHEMA:
        raise CollectionError("Unsupported review bundle schema")
    expected = {"manifest.json": None}
    recorded_sizes = {}
    records = manifest.get("files", [])
    if not isinstance(records, list) or len(records) > 512:
        raise CollectionError("Manifest file count limit")
    for item in records:
        rel = item["destination"]
        if not re.fullmatch(r"artifacts/\d{4}\.(?:json|jsonl|sarif|md|txt|csv|log)", rel) or rel in expected:
            raise CollectionError("Invalid or duplicate manifest destination")
        expected[rel] = item["review_sha256"]
        size = item.get("review_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 512 * 1024 * 1024:
            raise CollectionError("Invalid review byte count")
        recorded_sizes[rel] = size
    if sum(recorded_sizes.values()) > 512 * 1024 * 1024:
        raise CollectionError("Manifest total byte limit")
    for rel, digest in manifest.get("auxiliary_sha256", {}).items():
        if rel not in {"build_snapshot.json", "REVIEW_BEFORE_SHARING.md"}:
            raise CollectionError("Unrecognized auxiliary file")
        expected[rel] = digest
    mismatches = []
    verified_hashes = {}
    for rel, digest in expected.items():
        try:
            data = read_regular(bundle, rel, recorded_sizes.get(rel, 4 * 1024 * 1024) + 1)
            if digest is not None and sha(data) != digest:
                mismatches.append(rel)
            if rel in recorded_sizes and len(data) != recorded_sizes[rel]:
                mismatches.append(rel)
            verified_hashes[rel] = sha(data)
        except (OSError, CollectionError):
            mismatches.append(rel)
    actual = set()
    for root, dirs, files in os.walk(bundle, followlinks=False):
        for name in dirs:
            if (Path(root) / name).is_symlink():
                mismatches.append(str((Path(root) / name).relative_to(bundle)))
        for name in files:
            actual.add(str((Path(root) / name).relative_to(bundle)))
    unexpected = sorted(actual - set(expected))
    return {"schema": SCHEMA, "integrity_matches": not mismatches and not unexpected,
            "mismatches": mismatches, "unexpected_files": unexpected,
            "verified_files": sorted(expected), "privacy_certified": False,
            "verified_sha256": verified_hashes,
            "original_proof_validated": False}


def positive(value):
    number = int(value)
    if not 1 <= number <= 512:
        raise argparse.ArgumentTypeError("Use an integer from 1 through 512")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("collect", help="Create a private review copy outside the source run")
    p.add_argument("--run", required=True)
    p.add_argument("--output-home", default=str(Path.home() / "tbhm-work/review-bundles"))
    p.add_argument("--run-alias", default="engagement-run")
    p.add_argument("--tool-home")
    p.add_argument("--extra", action="append", default=[])
    p.add_argument("--redact-file", help="Local one-secret-per-line input; never copied")
    p.add_argument("--alias-map", help="Local original-to-alias JSON object; never copied")
    p.add_argument("--include-tool-logs", action="store_true")
    p.add_argument("--include-evidence", action="store_true", help="Retain body/source/prompt fields for private review; inspect before sharing")
    p.add_argument("--max-file-mb", type=positive, default=10)
    p.add_argument("--max-total-mb", type=positive, default=100)
    p.add_argument("--max-files", type=positive, default=256)
    p.add_argument("--archive", action="store_true", help="Also create a private tar.gz; inspect before sharing")
    p = sub.add_parser("verify", help="Verify a review directory's recorded file hashes")
    p.add_argument("--bundle", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.action == "collect":
            result = collect(args)
            code = result.pop("exit_code")
        else:
            result = verify_directory(checked_path(args.bundle))
            code = 0 if result["integrity_matches"] else 2
        print(json.dumps(result, indent=2))
        return code
    except (OSError, ValueError, CollectionError, RecursionError) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
