"""Firmware and embedded static-analysis phase for TBHM v3.9.7.5.

The phase preserves the v3.9.7.3 hashing/binwalk/strings workflow and adds
validated recursive extraction, a confined root-filesystem audit, ELF and
hardening inventory, accounts, key classification, startup-service parsing,
permissions, web/CGI leads, artifact provenance, and structured evidence.

No firmware code is executed.  Extraction is opt-in and should still be run in
a disposable VM because external extractors parse attacker-controlled data.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import time
from pathlib import Path

from core import firmware_safety as FS
from core import redteam_utils as RT
from core import reverse_utils as RU

PATTERNS = [
    "password", "passwd", "secret", "token", "apikey", "api_key", "private key",
    "BEGIN RSA", "root:", "telnet", "dropbear", "busybox", "http://", "https://",
    "mqtt", "rtsp",
]

INSECURE_SERVICES = {
    "telnetd": ("HIGH", "Cleartext remote administration (Telnet)"),
    "tftpd": ("MEDIUM", "Unauthenticated or weakly authenticated file transfer (TFTP)"),
    "ftpd": ("MEDIUM", "Often cleartext file transfer (FTP)"),
    "dropbear": ("LOW", "SSH daemon — verify keys and authentication configuration"),
    "sshd": ("LOW", "SSH daemon — verify keys and authentication configuration"),
    "httpd": ("LOW", "Web management interface — audit CGI and authentication"),
    "uhttpd": ("LOW", "Web management interface — audit CGI and authentication"),
    "boa": ("LOW", "Legacy web server — audit CGI and authentication"),
    "lighttpd": ("LOW", "Web server — audit CGI and authentication"),
    "miniupnpd": ("MEDIUM", "UPnP daemon — verify WAN exposure"),
    "snmpd": ("MEDIUM", "SNMP daemon — verify community strings and access control"),
}

CMDEXEC_RE = re.compile(
    r"\b(system|popen|execve|execl|execlp|execvp|eval)\s*\(|os\.execute|io\.popen|/bin/(?:sh|ash|bash)\b"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----")
SSH_PUBLIC_RE = re.compile(r"^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[^ ]+)\s+")

MAX_AUDIT_ELF = 60
MAX_FW_READ = 256 * 1024 * 1024
MAX_ROOTFS_FILES = 100_000
MAX_GRAPH_FILES = 2_000


def _rootfs_candidates(base: Path):
    if not base.is_dir() or base.is_symlink():
        return
    for dirpath, dirnames, _filenames in os.walk(base, followlinks=False):
        dpath = Path(dirpath)
        dirnames[:] = [n for n in dirnames if not (dpath / n).is_symlink()]
        yield dpath


def _locate_rootfs(base: Path) -> Path | None:
    """Select the shallowest validated filesystem-looking directory."""
    candidates: list[Path] = []
    for candidate in _rootfs_candidates(base) or []:
        if any((candidate / marker).is_dir() for marker in ("etc", "bin", "sbin", "usr", "lib")):
            ok, _detail = FS.validate_rootfs(candidate)
            if ok:
                candidates.append(candidate)
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: (len(p.relative_to(base).parts), str(p)))[0]


def _reset_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _attempt_record(tool: str, cmd: list[str], rc: int, started: float,
                    root: Path | None, validation: dict, stderr: str = "") -> dict:
    return {
        "tool": tool,
        "command": [str(x) for x in cmd],
        "returncode": int(rc),
        "duration_seconds": round(time.time() - started, 3),
        "rootfs": str(root) if root else "",
        "validation": validation,
        "stderr_tail": str(stderr or "")[-4000:],
    }


def _validate_candidate(path: Path | None) -> tuple[Path | None, dict]:
    if path is None:
        return None, {"reason": "no candidate", "file_count": 0, "markers": []}
    ok, detail = FS.validate_rootfs(path)
    return (path if ok else None), detail


def _carve_and_unsquash(ctx, fw: Path, work: Path, attempts: list[dict]) -> Path | None:
    work.mkdir(parents=True, exist_ok=True)
    offsets = RU.find_offsets(fw, b"hsqs", max_bytes=MAX_FW_READ)
    offsets += [x for x in RU.find_offsets(fw, b"sqsh", max_bytes=MAX_FW_READ) if x not in offsets]
    if not offsets:
        return None
    for offset in offsets[:4]:
        carved = work / f"rootfs_0x{offset:x}.squashfs"
        try:
            with fw.open("rb") as handle, carved.open("wb") as output:
                handle.seek(offset)
                remaining = MAX_FW_READ
                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    output.write(chunk)
                    remaining -= len(chunk)
        except OSError as exc:
            attempts.append({"tool": "internal_carver", "offset": offset, "returncode": 1,
                             "error": str(exc)})
            continue
        ctx.log("INFO", "firmware_reverse", f"carved SquashFS at offset 0x{offset:x} -> {carved.name}")
        for tool in ("unsquashfs", "sasquatch"):
            if not ctx.runner.has(tool):
                continue
            dest = work / f"{tool}_0x{offset:x}_rootfs"
            _reset_directory(dest)
            cmd = [tool, "-f", "-d", str(dest), str(carved)]
            started = time.time()
            rc, _stdout, stderr = ctx.runner.run(cmd, timeout=900, log_name=f"rt_firmware_{tool}_{offset:x}")
            candidate = _locate_rootfs(dest) if rc == 0 else None
            root, validation = _validate_candidate(candidate)
            attempts.append(_attempt_record(tool, cmd, rc, started, root, validation, stderr))
            if rc == 0 and root is not None:
                return root
    return None


def _extract(ctx, fw: Path, out: Path) -> tuple[Path | None, list[dict]]:
    """Validated extractor chain: unblob -> binwalk -> offset SquashFS carve."""
    fw = fw.expanduser().resolve(strict=True)
    work = out / "extracted"
    work.mkdir(parents=True, exist_ok=True)
    attempts: list[dict] = []

    if ctx.runner.has("unblob"):
        dest = work / "unblob"
        _reset_directory(dest)
        report = work / "unblob-report.json"
        cmd = ["unblob", "-f", "-e", str(dest), "--report", str(report), str(fw)]
        started = time.time()
        rc, _stdout, stderr = ctx.runner.run(cmd, timeout=1800, log_name="rt_firmware_unblob")
        candidate = _locate_rootfs(dest) if rc == 0 else None
        root, validation = _validate_candidate(candidate)
        attempts.append(_attempt_record("unblob", cmd, rc, started, root, validation, stderr))
        if rc == 0 and root is not None:
            RU.write_json(out / "FIRMWARE_EXTRACTION_PROVENANCE.json", {"firmware": str(fw), "attempts": attempts})
            return root, attempts

    if ctx.runner.has("binwalk"):
        dest = work / "binwalk"
        _reset_directory(dest)
        cmd = ["binwalk", "-Me"]
        # Preserve v3.9.7.3 root compatibility without forcing sudo or an
        # interactive password prompt.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            rc_h, out_h, err_h = ctx.runner.run(["binwalk", "--help"], timeout=30,
                                                log_name="rt_firmware_binwalk_help")
            if rc_h == 0 and "--run-as" in (out_h + err_h):
                cmd.append("--run-as=root")
        cmd.append(str(fw))
        started = time.time()
        rc, _stdout, stderr = ctx.runner.run(cmd, timeout=1800, cwd=dest,
                                             log_name="rt_firmware_binwalk_extract")
        candidate = _locate_rootfs(dest) if rc == 0 else None
        root, validation = _validate_candidate(candidate)
        attempts.append(_attempt_record("binwalk", cmd, rc, started, root, validation, stderr))
        if rc == 0 and root is not None:
            RU.write_json(out / "FIRMWARE_EXTRACTION_PROVENANCE.json", {"firmware": str(fw), "attempts": attempts})
            return root, attempts

    root = _carve_and_unsquash(ctx, fw, work, attempts)
    RU.write_json(out / "FIRMWARE_EXTRACTION_PROVENANCE.json", {"firmware": str(fw), "attempts": attempts})
    return root, attempts


def _elf_inventory(ctx, rootfs: Path, out: Path) -> list[dict]:
    elves = []
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        if RU.is_elf(item):
            info = RU.elf_header_info(item)
            info["path"] = rel.as_posix()
            try:
                info["size"] = item.stat().st_size
            except OSError:
                info["size"] = 0
            elves.append(info)
        if len(elves) >= 5000:
            break
    lines = [f"{e.get('class','?')} {e.get('data','?')} {e.get('machine','?')} "
             f"{e.get('type','?')} qemu={e.get('qemu') or 'n/a'}\t{e['path']}" for e in elves]
    (out / "elf-inventory.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return elves


def _dominant_arch(elves: list[dict]) -> dict:
    from collections import Counter
    machines = Counter((e.get("machine", "?"), e.get("endianness", "?"), e.get("qemu", ""))
                       for e in elves if e.get("machine"))
    if not machines:
        return {}
    (machine, endian, qemu), _count = machines.most_common(1)[0]
    return {"machine": machine, "endianness": endian, "qemu": qemu}


def _audit_hardening(ctx, rootfs: Path, elves: list[dict], out: Path) -> list[dict]:
    if not ctx.runner.has("readelf"):
        (out / "hardening-limitations.txt").write_text("readelf is unavailable; hardening not tested.\n")
        return []
    rows, failures = [], []

    def rank(e):
        name = Path(e["path"]).name.lower()
        return 0 if any(k in name for k in ("http", "cgi", "telnet", "dropbear", "upnp", "boa", "ssh", "rtsp")) else 1

    for e in sorted(elves, key=rank)[:MAX_AUDIT_ELF]:
        target = FS.safe_resolve(rootfs, e["path"])
        if target is None or not target.is_file():
            continue
        stem = RU.safe_stem(target)
        results = {}
        for key, flags in {
            "header": ["-h"], "program_headers": ["-lW"], "dynamic": ["-dW"],
            "symbols": ["-sW"], "sections": ["-SW"],
        }.items():
            rc, stdout, stderr = ctx.runner.run(["readelf", *flags, str(target)], timeout=60,
                                                log_name=f"fw_readelf_{stem}_{key}")
            results[key] = {"rc": rc, "stdout": stdout, "stderr": stderr}
        valid = {key: row["rc"] == 0 and bool(row["stdout"].strip()) for key, row in results.items()}
        hard = RU.parse_hardening(
            header=results["header"]["stdout"], program_headers=results["program_headers"]["stdout"],
            dynamic=results["dynamic"]["stdout"], symbols=results["symbols"]["stdout"],
            sections=results["sections"]["stdout"], valid=valid, binary_type=e.get("type", ""),
        )
        hard["path"] = e["path"]
        rows.append(hard)
        if not hard.get("analysis_valid"):
            failures.append(f"{e['path']}: readelf output unavailable/invalid")
            continue
        gaps = RU.hardening_gaps(hard)
        if gaps:
            netfacing = rank(e) == 0
            ctx.save_finding({
                "phase": "firmware_reverse_safe", "severity": "MEDIUM" if netfacing else "LOW",
                "confidence": "HIGH", "title": f"Weak binary hardening: {Path(e['path']).name}",
                "target": e["path"], "url": "",
                "description": f"{e.get('machine','?')} {e.get('type','?')} binary has confirmed missing "
                               f"exploit mitigations: {', '.join(gaps)}.",
                "evidence": f"{e['path']}: " + "; ".join(gaps),
                "impact": "Missing mitigations lower the bar for exploiting a separate memory-corruption bug.",
                "remediation": "Rebuild with stack protection, full RELRO, NX and PIE where applicable; remove unsafe RPATH/RUNPATH.",
                "cwe": "CWE-1277", "mrs_score": 40 if netfacing else 25,
            })
    if rows:
        header = "path\tnx\tpie\trelro\tcanary\tstripped\trpath\trunpath\tanalysis_valid"
        def val(v): return "unknown" if v is None else str(v).lower()
        body = "\n".join(
            f"{r['path']}\t{val(r['nx'])}\t{val(r['pie'])}\t{r['relro']}\t{val(r['canary'])}\t"
            f"{val(r['stripped'])}\t{val(r['rpath'])}\t{val(r['runpath'])}\t{r['analysis_valid']}"
            for r in rows
        )
        (out / "checksec.txt").write_text(header + "\n" + body + "\n", encoding="utf-8")
    if failures:
        (out / "hardening-limitations.txt").write_text("\n".join(failures) + "\n", encoding="utf-8")
    return rows


def _audit_accounts(ctx, rootfs: Path, out: Path) -> dict:
    result = {"passwd_users": [], "root_shells": [], "empty_password_fields": [],
              "duplicate_uid0": [], "shadow_present": False, "unsafe_paths_skipped": []}
    passwd_text = FS.safe_read_text(rootfs, "etc/passwd")
    shadow_text = FS.safe_read_text(rootfs, "etc/shadow")
    if passwd_text is not None:
        uid0 = []
        for line in passwd_text.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, pw, uid, _gid, _comment, _home, shell = parts[:7]
            result["passwd_users"].append(user)
            if uid == "0":
                uid0.append(user)
                if shell and shell not in ("/bin/false", "/sbin/nologin", "/bin/nologin"):
                    result["root_shells"].append(f"{user}:{shell}")
            if pw == "":
                result["empty_password_fields"].append(user)
        if len(uid0) > 1:
            result["duplicate_uid0"] = uid0
    elif (rootfs / "etc" / "passwd").exists():
        result["unsafe_paths_skipped"].append("etc/passwd")

    if shadow_text is not None:
        result["shadow_present"] = True
        for line in shadow_text.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, pwhash = parts[0], parts[1]
            if pwhash == "":
                result["empty_password_fields"].append(f"shadow:{user}")
            elif pwhash not in ("*", "!", "!!", "x") and user == "root":
                ctx.save_finding({
                    "phase": "firmware_reverse_safe", "severity": "HIGH", "confidence": "HIGH",
                    "title": "Firmware ships a root password hash in /etc/shadow",
                    "target": "etc/shadow", "url": "",
                    "description": "The image contains a hashed root password. This is offline-crackable evidence, not a recovered password.",
                    "evidence": "root hash present in /etc/shadow [value redacted]",
                    "impact": "If a uniform hash is cracked, administrative access may be possible across affected devices.",
                    "remediation": "Provision unique per-device credentials and force secure enrollment at first boot.",
                    "cwe": "CWE-798", "mrs_score": 75,
                })
    elif (rootfs / "etc" / "shadow").exists():
        result["unsafe_paths_skipped"].append("etc/shadow")

    if result["duplicate_uid0"]:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "HIGH", "confidence": "HIGH",
            "title": "Multiple account names map to UID 0",
            "target": "etc/passwd", "url": "",
            "description": "More than one account is configured with superuser UID 0.",
            "evidence": ", ".join(result["duplicate_uid0"][:20]),
            "impact": "Expands root-level authentication and accountability risk.",
            "remediation": "Retain one controlled UID-0 account and assign distinct non-zero UIDs to other identities.",
            "cwe": "CWE-250", "mrs_score": 65,
        })
    if result["root_shells"]:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "MEDIUM", "confidence": "HIGH",
            "title": "UID 0 account with an interactive shell in firmware",
            "target": "etc/passwd", "url": "",
            "description": "One or more UID-0 accounts have an interactive login shell.",
            "evidence": ", ".join(result["root_shells"][:20]),
            "impact": "Broadens the interactive root attack surface if an authentication path is weak.",
            "remediation": "Restrict UID-0 accounts and use nologin shells for service identities.",
            "cwe": "CWE-250", "mrs_score": 45,
        })
    if result["empty_password_fields"]:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "HIGH", "confidence": "HIGH",
            "title": "Account with an empty password field in firmware",
            "target": "etc/passwd", "url": "",
            "description": "An account has an empty password field, which can permit passwordless login depending on PAM/login configuration.",
            "evidence": ", ".join(result["empty_password_fields"][:20]),
            "impact": "Potential passwordless authentication to the device.",
            "remediation": "Remove or lock the account and require securely provisioned credentials.",
            "cwe": "CWE-258", "mrs_score": 65,
        })
    RT.save_json(out / "accounts.json", result)
    return result


def _audit_keys(ctx, rootfs: Path, out: Path) -> dict:
    private_keys, certificates, public_keys, unknown_pem = [], [], [], []
    name_hints = ("id_rsa", "id_dsa", "id_ecdsa", "host_key", "server.key")
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        try:
            if item.stat().st_size > 2_000_000:
                continue
            head = item.read_bytes()[:64_000].decode("latin-1", "ignore")
        except OSError:
            continue
        rel_s = rel.as_posix()
        name = item.name.lower()
        if PRIVATE_KEY_RE.search(head) or any(k in name for k in name_hints):
            private_keys.append(rel_s)
        elif CERT_RE.search(head):
            certificates.append(rel_s)
        elif SSH_PUBLIC_RE.search(head):
            public_keys.append(rel_s)
        elif name.endswith(".pem"):
            unknown_pem.append(rel_s)
        if sum(map(len, (private_keys, certificates, public_keys, unknown_pem))) >= 1000:
            break
    if private_keys:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "HIGH", "confidence": "HIGH",
            "title": "Private key material embedded in firmware",
            "target": private_keys[0], "url": "",
            "description": "A private-key marker or strongly indicative private-key filename was found in the firmware filesystem.",
            "evidence": "\n".join(private_keys[:40]),
            "impact": "Shared private keys can enable device impersonation or fleet-wide trust compromise.",
            "remediation": "Generate private keys per device at enrollment or first boot; do not ship shared private keys.",
            "cwe": "CWE-321", "mrs_score": 70,
        })
    mapping = {
        "private-key-files.txt": private_keys,
        "public-certificates.txt": certificates,
        "public-key-files.txt": public_keys,
        "unknown-pem-files.txt": unknown_pem,
        "key-files.txt": sorted(set(private_keys + certificates + public_keys + unknown_pem)),
    }
    for filename, rows in mapping.items():
        (out / filename).write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return {"private_keys": private_keys, "certificates": certificates,
            "public_keys": public_keys, "unknown_pem": unknown_pem}


def _audit_services(ctx, rootfs: Path, out: Path) -> dict:
    init_files, executable_text = [], []
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        rel_s = rel.as_posix()
        if "init.d/" in rel_s or "rc.d/" in rel_s or item.name in ("rcS", "inittab", "rc.local"):
            init_files.append(rel_s)
            text = FS.safe_read_text(rootfs, rel_s, max_bytes=2_000_000)
            if text is not None:
                executable_text.append(FS.strip_shell_comments(text))
        if len(init_files) >= 500:
            break
    combined = "\n".join(executable_text)
    referenced, started = [], []
    for svc, (sev, why) in INSECURE_SERVICES.items():
        if re.search(rf"\b{re.escape(svc)}\b", combined):
            referenced.append(svc)
            # Require an executable-looking command, not a comment or a variable
            # name. This still remains a static startup lead.
            command_re = re.compile(rf"(?m)^\s*(?:exec\s+|start-stop-daemon\b[^\n]*--exec\s+\S*/)?(?:\S*/)?{re.escape(svc)}\b")
            if command_re.search(combined):
                started.append(svc)
                if sev in ("HIGH", "MEDIUM"):
                    ctx.save_finding({
                        "phase": "firmware_reverse_safe", "severity": sev, "confidence": "MEDIUM",
                        "title": f"Insecure service startup command found in firmware init: {svc}",
                        "target": "etc/init", "url": "",
                        "description": f"{why}. An executable startup statement was found in firmware init files; runtime exposure is not yet confirmed.",
                        "evidence": f"startup command for {svc} found in init/service scripts",
                        "impact": "Potential insecure or weakly authenticated remote service exposed at boot.",
                        "remediation": "Disable by default, require authenticated opt-in, and prefer encrypted protocols.",
                        "cwe": "CWE-1188", "mrs_score": 60 if sev == "HIGH" else 45,
                    })
    (out / "startup-services.txt").write_text("\n".join(sorted(started)) + ("\n" if started else ""), encoding="utf-8")
    (out / "service-references.txt").write_text("\n".join(sorted(referenced)) + ("\n" if referenced else ""), encoding="utf-8")
    (out / "init-files.txt").write_text("\n".join(init_files) + ("\n" if init_files else ""), encoding="utf-8")
    return {"started": started, "referenced": referenced, "init_files": init_files}


def _audit_permissions(ctx, rootfs: Path, out: Path) -> dict:
    suid, sgid, world_writable = [], [], []
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        try:
            mode = item.stat().st_mode
        except OSError:
            continue
        rel_s = rel.as_posix()
        if mode & stat.S_ISUID:
            suid.append(rel_s)
        if mode & stat.S_ISGID:
            sgid.append(rel_s)
        if mode & stat.S_IWOTH:
            world_writable.append(rel_s)
    for filename, rows in (("suid-files.txt", suid), ("sgid-files.txt", sgid),
                           ("world-writable-files.txt", world_writable)):
        (out / filename).write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    if suid:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "LOW", "confidence": "HIGH",
            "title": "SUID binaries present in firmware", "target": suid[0], "url": "",
            "description": "SUID binaries execute with owner privilege and require justification and input review.",
            "evidence": "\n".join(suid[:40]),
            "impact": "A separate vulnerability in a SUID-root binary can enable local privilege escalation.",
            "remediation": "Remove unnecessary SUID bits and audit the retained binaries.",
            "cwe": "CWE-269", "mrs_score": 30,
        })
    dangerous_ww = [p for p in world_writable if any(x in p.lower() for x in
                    ("etc/", "init", "rc.", "cron", "profile", "passwd", "shadow", "www/", "cgi"))]
    if dangerous_ww:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "MEDIUM", "confidence": "HIGH",
            "title": "Security-sensitive firmware files are world-writable",
            "target": dangerous_ww[0], "url": "",
            "description": "World-writable startup, configuration, credential, or web files were found.",
            "evidence": "\n".join(dangerous_ww[:40]),
            "impact": "A low-privileged local process may be able to alter privileged startup or service behavior.",
            "remediation": "Remove world-write permissions and enforce least-privilege ownership.",
            "cwe": "CWE-732", "mrs_score": 50,
        })
    return {"suid": suid, "sgid": sgid, "world_writable": world_writable,
            "dangerous_world_writable": dangerous_ww}


def _audit_web(ctx, rootfs: Path, out: Path) -> dict:
    web_roots, cgi_files, command_leads = set(), [], []
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        rel_s = rel.as_posix()
        parts = rel.parts
        for idx, part in enumerate(parts[:-1]):
            if part.lower() in ("www", "htdocs", "html", "web", "web_cgi"):
                web_roots.add(Path(*parts[:idx + 1]).as_posix())
        low = item.name.lower()
        is_cgi = "cgi-bin/" in rel_s or low.endswith((".cgi", ".lua", ".asp", ".php"))
        if is_cgi:
            cgi_files.append(rel_s)
        in_web = any(part.lower() in ("www", "htdocs", "html", "web", "web_cgi") for part in parts[:-1])
        if is_cgi or in_web:
            try:
                if item.stat().st_size <= 2_000_000 and not RU.is_elf(item):
                    text = item.read_text(errors="ignore")
                    # Interpreter shebangs such as #!/bin/sh establish file type;
                    # they are not evidence that request data reaches a shell.
                    lines = text.splitlines()
                    analysis_text = "\n".join(lines[1:]) if lines and lines[0].startswith("#!") else text
                    if CMDEXEC_RE.search(analysis_text):
                        command_leads.append(rel_s)
            except OSError:
                continue
    if command_leads:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "MEDIUM", "confidence": "LOW",
            "title": "Command-execution primitive in firmware web/CGI source",
            "target": command_leads[0], "url": "",
            "description": "Web/CGI source references a process or shell execution primitive. Reachability and attacker control are not proven.",
            "evidence": "\n".join(command_leads[:40]),
            "impact": "Potential command-injection path if untrusted request data reaches the sink without strict validation.",
            "remediation": "Avoid shell command construction, use fixed argument arrays and allowlists, then validate the complete source-to-sink path.",
            "cwe": "CWE-78", "mrs_score": 55,
        })
    web_rows = sorted(web_roots)
    for filename, rows in (("web-roots.txt", web_rows), ("web-cgi-files.txt", cgi_files),
                           ("command-execution-leads.txt", command_leads)):
        (out / filename).write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return {"web_roots": web_rows, "cgi_files": cgi_files,
            "command_execution_leads": command_leads}




def _parse_control_blocks(text: str) -> list[dict]:
    rows = []
    for block in re.split(r"\n\s*\n", text or ""):
        fields = {}
        current = ""
        for line in block.splitlines():
            if not line.strip():
                continue
            if line[:1].isspace() and current:
                fields[current] = (fields.get(current, "") + " " + line.strip()).strip()
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            current = key.strip()
            fields[current] = value.strip()
        name = fields.get("Package") or fields.get("Name")
        if name:
            rows.append({
                "name": name, "version": fields.get("Version", ""),
                "architecture": fields.get("Architecture", ""),
                "source": fields.get("Source", ""), "description": fields.get("Description", "")[:500],
            })
    return rows


def _parse_apk_installed(text: str) -> list[dict]:
    rows = []
    current = {}
    for line in (text or "").splitlines() + [""]:
        if not line.strip():
            if current.get("name"):
                rows.append(current)
            current = {}
            continue
        if len(line) > 2 and line[1] == ":":
            key, value = line[0], line[2:]
            if key == "P": current["name"] = value
            elif key == "V": current["version"] = value
            elif key == "A": current["architecture"] = value
            elif key == "T": current["description"] = value[:500]
    return rows


def _component_inventory(rootfs: Path, out: Path) -> dict:
    """Create a package/component inventory without claiming CVE applicability."""
    packages, sources = [], []
    candidates = [
        ("var/lib/dpkg/status", "dpkg"), ("usr/lib/opkg/status", "opkg"),
        ("var/lib/opkg/status", "opkg"), ("lib/apk/db/installed", "apk"),
    ]
    for rel, kind in candidates:
        text = FS.safe_read_text(rootfs, rel, max_bytes=20_000_000)
        if text is None:
            continue
        parsed = _parse_apk_installed(text) if kind == "apk" else _parse_control_blocks(text)
        for row in parsed:
            row["package_manager"] = kind
            row["evidence_path"] = rel
        packages.extend(parsed)
        sources.append({"path": rel, "package_manager": kind, "packages": len(parsed)})
    # Deduplicate exact package records across mirrored databases.
    dedup = {}
    for row in packages:
        key = (row.get("name", ""), row.get("version", ""), row.get("architecture", ""))
        dedup.setdefault(key, row)
    packages = sorted(dedup.values(), key=lambda r: (r.get("name", ""), r.get("version", "")))
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "firmware", "name": rootfs.name},
                     "properties": [{"name": "tbhm:confirmation", "value": "inventory-only"}]},
        "components": [
            {"type": "library", "name": row.get("name", "unknown"),
             **({"version": row["version"]} if row.get("version") else {}),
             "properties": [
                 {"name": "tbhm:package_manager", "value": row.get("package_manager", "")},
                 {"name": "tbhm:evidence_path", "value": row.get("evidence_path", "")},
                 {"name": "tbhm:architecture", "value": row.get("architecture", "")},
             ]}
            for row in packages
        ],
    }
    RU.write_json(out / "FIRMWARE_COMPONENT_INVENTORY.json", {"sources": sources, "packages": packages})
    RU.write_json(out / "FIRMWARE_SBOM.cdx.json", sbom)
    RT.write_csv(out / "firmware-packages.csv", packages)
    return {"sources": sources, "packages": packages, "sbom_components": len(packages)}


def _audit_update_chain(ctx, rootfs: Path, out: Path) -> dict:
    """Find update/flash handlers and distinguish verification from write actions."""
    candidates, verified, unverified = [], [], []
    name_re = re.compile(r"(?i)(?:^|[-_.])(update|upgrade|firmware|flash|mtd|recovery)(?:[-_.]|$)")
    flash_re = re.compile(r"(?i)\b(?:mtd(?:_write)?|flashcp|nandwrite|ubiformat|fw_setenv)\b|\bdd\b[^\n]{0,160}\bof=/dev/(?:mtd|ubi|mmcblk)")
    verify_re = re.compile(r"(?i)(?:openssl\b[^\n]{0,160}\b(?:verify|dgst)|gpgv?\b|minisign\b|sha(?:256|512)sum\s+-c\b|verify[_ -]?(?:signature|image)|rsa[_ -]?verify|ed25519|x509|certificate[_ -]?verify)")
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_ROOTFS_FILES):
        rel_s = rel.as_posix()
        if not name_re.search(item.name) and not any(x in rel_s.lower() for x in ("/upgrade", "/update", "/recovery")):
            continue
        try:
            size = item.stat().st_size
            if size > 3_000_000 or RU.is_elf(item):
                candidates.append({"path": rel_s, "kind": "binary-or-large", "flash_action": None, "verification": None})
                continue
            text = item.read_text(errors="ignore")
        except OSError:
            continue
        has_flash = bool(flash_re.search(text))
        has_verify = bool(verify_re.search(text))
        row = {"path": rel_s, "kind": "text", "flash_action": has_flash, "verification": has_verify}
        candidates.append(row)
        if has_flash and has_verify:
            verified.append(rel_s)
        elif has_flash:
            unverified.append(rel_s)
    if unverified:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "MEDIUM", "confidence": "LOW",
            "title": "[LEAD] Firmware write path without visible authenticity verification",
            "target": unverified[0], "url": "", "finding_class": "lead", "verified": False,
            "description": "A static update/flash script performs a firmware write but no signature or checksum-verification primitive was found in the same file. Verification may occur elsewhere.",
            "evidence": "\n".join(unverified[:40]),
            "impact": "If the complete update chain accepts unauthenticated images, an attacker with update access could install modified firmware.",
            "remediation": "Trace the complete update call graph and enforce signed-image verification, anti-rollback controls and fail-closed error handling before every flash operation.",
            "cwe": "CWE-494", "mrs_score": 55,
        })
    RU.write_json(out / "FIRMWARE_UPDATE_CHAIN.json", {
        "candidates": candidates, "write_paths_with_local_verification": verified,
        "write_paths_without_local_verification": unverified,
        "confirmation": "static-lead-only",
    })
    (out / "firmware-update-handlers.txt").write_text(
        "\n".join(row["path"] for row in candidates) + ("\n" if candidates else ""), encoding="utf-8")
    return {"candidates": candidates, "verified": verified, "unverified": unverified}


def _binary_priorities(rootfs: Path, elves: list[dict], services: dict, out: Path) -> list[dict]:
    """Rank high-value binaries before expensive decompilation or symbolic work."""
    service_names = set(services.get("started", [])) | set(services.get("referenced", []))
    rows = []
    network_words = ("http", "web", "cgi", "telnet", "ssh", "dropbear", "upnp", "snmp", "rtsp", "mqtt", "dns", "dhcp", "ftp")
    parser_words = ("parse", "xml", "json", "zip", "tar", "image", "media", "protocol", "update", "upgrade")
    for e in elves:
        path = e.get("path", "")
        target = FS.safe_resolve(rootfs, path)
        if target is None or not target.is_file():
            continue
        score, reasons = 10, ["ELF executable/library"]
        name = Path(path).name.lower()
        try:
            mode = target.stat().st_mode
            if mode & stat.S_ISUID:
                score += 30; reasons.append("SUID")
            if mode & stat.S_ISGID:
                score += 15; reasons.append("SGID")
        except OSError:
            pass
        if any(word in name for word in network_words):
            score += 25; reasons.append("network/service name")
        if any(word in name for word in parser_words):
            score += 15; reasons.append("parser/update name")
        if any(svc in name or name in svc for svc in service_names):
            score += 20; reasons.append("referenced by startup inventory")
        try:
            imports = RU.raw_short_imports(target)
        except Exception:
            imports = []
        if imports:
            score += min(25, 5 + len(imports) * 2); reasons.append("security-sensitive API strings")
        try:
            strings = RU.extract_strings(target, minimum=8, max_strings=800)
            indicators = RU.indicators(strings)
            if indicators.get("urls") or indicators.get("ips"):
                score += 10; reasons.append("embedded network indicators")
        except Exception:
            pass
        rows.append({
            "path": path, "score": min(score, 100), "reasons": reasons,
            "machine": e.get("machine", ""), "type": e.get("type", ""),
            "recommended_next_phases": ["reverse_triage", "reverse_static_analysis", "reverse_symbolic_analysis"],
        })
    rows.sort(key=lambda r: (-r["score"], r["path"]))
    RU.write_json(out / "FIRMWARE_BINARY_PRIORITIES.json", {"binaries": rows[:1000]})
    RT.write_csv(out / "firmware-binary-priorities.csv", [
        {**r, "reasons": "; ".join(r["reasons"]),
         "recommended_next_phases": ",".join(r["recommended_next_phases"])} for r in rows[:1000]
    ])
    return rows


def _attack_surface_map(rootfs: Path, services: dict, web: dict, update: dict, out: Path) -> dict:
    interfaces = []
    for service in services.get("started", []):
        interfaces.append({"type": "startup_service", "name": service, "runtime_exposure": "unknown"})
    for path in web.get("cgi_files", [])[:5000]:
        interfaces.append({"type": "web_cgi", "name": path, "runtime_exposure": "unknown"})
    for path in update.get("candidates", [])[:1000]:
        interfaces.append({"type": "firmware_update_handler", "name": path.get("path", ""),
                           "runtime_exposure": "unknown"})
    payload = {
        "schema": "tbhm-attack-surface-1", "rootfs": str(rootfs), "interfaces": interfaces,
        "limitations": "Static inventory only; authentication, network exposure, handlers and input reachability require controlled runtime/decompiler validation.",
    }
    RU.write_json(out / "FIRMWARE_ATTACK_SURFACE.json", payload)
    return payload

def _artifact_graph(rootfs: Path, firmware: Path | None, out: Path, elves: list[dict]) -> dict:
    nodes, edges = [], []
    firmware_id = ""
    if firmware and firmware.is_file():
        firmware_id = RU.artifact_id(firmware)
        nodes.append({"id": firmware_id, "kind": "firmware_image", "path": str(firmware),
                      "format": RU.identify(firmware), "size": firmware.stat().st_size})
    root_node = {"id": "", "kind": "extracted_rootfs", "path": str(rootfs)}
    nodes.append(root_node)
    elf_set = {e["path"] for e in elves}
    manifest_rows = []
    pending_edges = []
    for item, rel in FS.iter_regular_files(rootfs, max_files=MAX_GRAPH_FILES):
        try:
            digest = RU.artifact_id(item)
            node = {"id": digest, "kind": "elf" if rel.as_posix() in elf_set else "file",
                    "path": rel.as_posix(), "size": item.stat().st_size,
                    "format": RU.identify(item)}
        except OSError:
            continue
        nodes.append(node)
        manifest_rows.append(f"{rel.as_posix()}\0{digest}")
        pending_edges.append(digest)
    manifest_hash = hashlib.sha256("\n".join(sorted(manifest_rows)).encode()).hexdigest()
    root_id = "rootfs-sha256:" + manifest_hash
    root_node["id"] = root_id
    root_node["bounded_manifest_sha256"] = manifest_hash
    root_node["manifest_entries"] = len(manifest_rows)
    if firmware_id:
        edges.append({"from": firmware_id, "to": root_id, "relation": "extracts_to"})
    edges.extend({"from": root_id, "to": digest, "relation": "contains"} for digest in pending_edges)
    graph = {"schema": "tbhm-artifact-graph-1", "nodes": nodes, "edges": edges,
             "truncated": len(nodes) >= MAX_GRAPH_FILES + (2 if firmware_id else 1),
             "bounded_manifest_sha256": manifest_hash}
    RU.write_json(out / "FIRMWARE_ARTIFACT_GRAPH.json", graph)
    return graph


def _rootfs_audit(ctx, rootfs: Path, out: Path, firmware: Path | None = None) -> dict:
    rootfs = FS.canonical_root(rootfs)
    ctx.log("OK", "firmware_reverse", f"auditing confined extracted rootfs: {rootfs}")
    elves = _elf_inventory(ctx, rootfs, out)
    arch = _dominant_arch(elves)
    hardening = _audit_hardening(ctx, rootfs, elves, out)
    accounts = _audit_accounts(ctx, rootfs, out)
    services = _audit_services(ctx, rootfs, out)
    keys = _audit_keys(ctx, rootfs, out)
    permissions = _audit_permissions(ctx, rootfs, out)
    web = _audit_web(ctx, rootfs, out)
    components = _component_inventory(rootfs, out)
    update = _audit_update_chain(ctx, rootfs, out)
    priorities = _binary_priorities(rootfs, elves, services, out)
    attack_surface = _attack_surface_map(rootfs, services, web, update, out)
    graph = _artifact_graph(rootfs, firmware, out, elves)
    summary = {
        "rootfs": str(rootfs), "elf_count": len(elves), "dominant_arch": arch,
        "hardening_rows": len(hardening), "accounts": accounts,
        "services": services, "services_started": services["started"],
        "key_material": keys, "key_files": keys["private_keys"],
        "permissions": permissions, "web": web, "components": components,
        "update_chain": update, "binary_priorities": priorities[:100],
        "attack_surface_interfaces": len(attack_surface["interfaces"]),
        "artifact_graph_nodes": len(graph["nodes"]), "execution_performed": False,
    }
    RU.write_json(out / "FIRMWARE_ROOTFS_INDEX.json", summary)
    qemu = arch.get("qemu") or "n/a"
    RT.write_md(out / "FIRMWARE_ROOTFS_SUMMARY.md", "Firmware Root Filesystem Audit", [
        ("Root filesystem", str(rootfs)),
        ("ELF binaries", f"{len(elves)} (dominant: {arch.get('machine','?')} {arch.get('endianness','?')}-endian; suggested user-mode emulator: {qemu})"),
        ("Accounts", f"{len(accounts.get('passwd_users', []))} users; root shells: {len(accounts.get('root_shells', []))}; duplicate UID0: {len(accounts.get('duplicate_uid0', []))}"),
        ("Startup services", ", ".join(services["started"]) or "none confirmed from executable init statements"),
        ("Key material", f"private={len(keys['private_keys'])}; certificates={len(keys['certificates'])}; public={len(keys['public_keys'])}; unknown PEM={len(keys['unknown_pem'])}"),
        ("Permissions", f"SUID={len(permissions['suid'])}; SGID={len(permissions['sgid'])}; world-writable={len(permissions['world_writable'])}"),
        ("Web/CGI", f"{len(web['cgi_files'])} CGI file(s); {len(web['command_execution_leads'])} command-execution lead(s)"),
        ("Components/SBOM", f"{components['sbom_components']} package component(s) from {len(components['sources'])} package database(s)"),
        ("Update chain", f"{len(update['candidates'])} handler candidate(s); {len(update['unverified'])} local write path(s) without visible verification"),
        ("Prioritization", f"{len(priorities)} ELF file(s) ranked; top={priorities[0]['path'] if priorities else 'none'}"),
        ("Attack surface", f"{len(attack_surface['interfaces'])} static interface candidate(s)"),
        ("Artifact graph", f"{len(graph['nodes'])} node(s), {len(graph['edges'])} relationship(s)"),
        ("Next step", "Prioritize network-facing ELF files for reverse_static_analysis and import controlled runtime evidence before confirming a vulnerability."),
        ("Safety", "Static read-only audit. Firmware symlinks were confined to the extracted root; the filesystem was not chrooted into, executed or emulated."),
    ])
    return summary


def run(ctx):
    out = RT.evidence_dir(ctx, "12_firmware_reverse")
    firmware = getattr(ctx.args, "firmware", None)
    rootfs_arg = getattr(ctx.args, "firmware_rootfs", None)

    if rootfs_arg:
        try:
            supplied = Path(rootfs_arg).expanduser().resolve(strict=True)
            root = _locate_rootfs(supplied) or supplied
            ok, detail = FS.validate_rootfs(root)
            if not ok:
                raise ValueError(detail.get("reason", "rootfs validation failed"))
            _rootfs_audit(ctx, root, out, Path(firmware).expanduser().resolve(strict=True) if firmware else None)
        except Exception as exc:
            ctx.log("WARN", "firmware_reverse", f"--firmware-rootfs rejected: {exc}")
        if not firmware:
            return

    if not firmware:
        RT.write_md(out / "FIRMWARE_NOT_RUN.md", "Firmware / Reverse Static Review Not Run", [
            ("Reason", "No --firmware image was supplied. This branch is Not Tested, not Safe."),
            ("How to run", "./tbhm.py -d authorized.local --profile authorized_redteam -y --redteam --firmware /absolute/path/device.bin --firmware-extract"),
        ])
        return

    try:
        fw = Path(firmware).expanduser().resolve(strict=True)
    except Exception as exc:
        ctx.log("WARN", "firmware_reverse", f"firmware file not found: {firmware}: {exc}")
        return
    if not fw.is_file():
        ctx.log("WARN", "firmware_reverse", f"firmware path is not a file: {fw}")
        return

    hashes = RU.hashes(fw)
    size = fw.stat().st_size
    sha = hashes["sha256"]
    (out / "firmware_hashes.txt").write_text(
        f"file: {fw}\nsize: {size}\nmd5: {hashes['md5']}\nsha1: {hashes['sha1']}\nsha256: {sha}\n",
        encoding="utf-8",
    )

    identified = RU.identify(fw)
    container = RU.container_type(fw)
    ctx.log("OK", "firmware_reverse", f"identified {fw.name} as: {identified}")
    if container:
        ctx.save_finding({
            "phase": "firmware_reverse_safe", "severity": "INFO", "confidence": "HIGH",
            "title": f"Firmware container identified: {container}", "target": str(fw), "url": "",
            "description": f"{fw.name} is a firmware/container image ({container}); SHA-256 {sha}.",
            "evidence": f"{fw.name}: {identified}; size {size}",
            "impact": "Baseline identification for the firmware assessment.",
            "remediation": "N/A — informational.", "cwe": "", "mrs_score": 10, "verified": True,
        })

    if ctx.runner.has("binwalk"):
        ctx.runner.run(["binwalk", str(fw)], timeout=300, log_name="rt_firmware_binwalk", capture_mode="tail")

    hits = []
    if ctx.runner.has("strings"):
        # Stream strings output straight to disk so multi-gigabyte firmware
        # images are never buffered whole in memory (lifecycle bounded-output).
        strings_path = out / "firmware_strings.txt"
        rc, _tail, _stderr = ctx.runner.run(["strings", "-a", "-n", "6", str(fw)], timeout=600,
                                            log_name="rt_firmware_strings", capture_mode="none",
                                            stdout_path=strings_path)
        if rc == 0 and strings_path.exists():
            counts = {pattern: 0 for pattern in PATTERNS}
            with strings_path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    low = line.lower()
                    for pattern in PATTERNS:
                        counts[pattern] += low.count(pattern.lower())
            hits = [{"pattern": pattern, "count": count} for pattern, count in counts.items() if count]
            RT.write_csv(out / "firmware_pattern_hits.csv", hits)
            if hits:
                RT.add_control_finding(
                    ctx, "firmware_reverse_safe", "Firmware contains security-relevant strings", "LOW",
                    "Static strings review found security-relevant words. This is triage evidence, not proof of exploitability.",
                    ", ".join(f"{h['pattern']}={h['count']}" for h in hits[:20]), target=str(fw),
                    remediation="Review the extracted filesystem and complete source-to-sink/runtime validation.",
                )

    rootfs_summary = None
    extraction_attempts = []
    if getattr(ctx.args, "firmware_extract", False):
        rootfs, extraction_attempts = _extract(ctx, fw, out)
        if rootfs:
            rootfs_summary = _rootfs_audit(ctx, rootfs, out, fw)
        else:
            ctx.log("WARN", "firmware_reverse", "validated extraction produced no root filesystem; review FIRMWARE_EXTRACTION_PROVENANCE.json or pass --firmware-rootfs")

    RT.write_md(out / "FIRMWARE_REVERSE_SUMMARY.md", "Firmware / Reverse Engineering Static Summary", [
        ("File", str(fw)), ("SHA256", sha), ("Identified as", identified),
        ("What was tested", "Identification, streaming hashes, binwalk signature scan, strings and security-pattern inventory" +
         (", validated extraction and a confined static rootfs audit." if rootfs_summary else ".")),
        ("Extraction attempts", str(len(extraction_attempts))),
        ("Root filesystem", str(rootfs_summary.get("rootfs")) if rootfs_summary else "Not extracted or validation failed."),
        ("What was not done", "No exploitation, flashing, credential use, device takeover, chroot, runtime emulation, or destructive modification."),
    ])
    ctx.log("OK", "firmware_reverse", f"firmware static review written to {out}")
