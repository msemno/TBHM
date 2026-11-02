"""Bounded subprocess execution for TBHM.

The Python implementation streams output to disk, retains only bounded tails in
memory, supports cancellation/timeouts, and can run independent jobs through a
bounded pool.  An optional Go helper provides the same argv-only contract; the
Python control plane remains authoritative and transparently falls back when the
helper is unavailable.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable
from core.evidence_redaction import safe_argv, redact_text, StreamRedactor


class _TailBuffer:
    def __init__(self, maximum: int | None):
        self.maximum = None if maximum is None else max(1024, int(maximum))
        self.data = bytearray()
        self.discarded_bytes = 0
        self.lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        with self.lock:
            self.data.extend(chunk)
            if self.maximum is not None and len(self.data) > self.maximum:
                self.discarded_bytes += len(self.data) - self.maximum
                del self.data[:-self.maximum]

    def text(self) -> str:
        with self.lock:
            return bytes(self.data).decode("utf-8", errors="replace")


from core.execution_ledger import tracked_tool


class Runner:
    @staticmethod
    def _feed_input(pipe, payload) -> None:
        try:
            pipe.write(payload)
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            try: pipe.close()
            except (OSError, ValueError): pass

    def __init__(self, profile: dict, limits, monitor, output_dir: Path):
        from core.evidence_redaction import register_secrets, _SENSITIVE_KEY
        register_secrets(v for k, v in os.environ.items() if k not in {'PWD', 'OLDPWD'} and (_SENSITIVE_KEY.search(k) or k in {'CHAOS_KEY', 'PDCP_API_KEY'}))
        self.profile = profile
        self.limits = limits
        self.monitor = monitor
        self.output_dir = Path(output_dir)
        self.logs_dir = self.output_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        self.last_call_time: dict[str, float] = {}
        runtime = profile.get("runtime", {}) or {}
        self.threads = max(1, int(runtime.get("threads", 10) or 10))
        self.max_parallel_tools = max(1, int(runtime.get("max_parallel_tools", min(self.threads, 4)) or 4))
        self.capture_tail_bytes = max(64 * 1024, min(int(runtime.get("capture_tail_bytes", 4 * 1024 * 1024)), 16 * 1024 * 1024))
        self.executor_backend = str(runtime.get("executor_backend", "python") or "python").lower()
        root = Path(__file__).resolve().parents[1]
        configured = str(runtime.get("go_executor_path") or os.environ.get("TBHM_GO_EXECUTOR") or "")
        self.go_executor = Path(configured) if configured else root / "bin" / "tbhm-go-executor"
        self._cancel_event = threading.Event()
        self._go_evidence_protocol = None

    def has(self, tool: str) -> bool:
        available = shutil.which(tool) is not None
        ledger = getattr(self, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='capability', tool=tool, status='available' if available else 'unavailable')
        return available

    def require(self, tool: str, ctx_log_fn=None) -> bool:
        if self.has(tool):
            return True
        ledger = getattr(self, 'execution_ledger', None)
        if ledger:
            ledger.record(kind='dependency', tool=tool, status='missing-required-tool')
        msg = f"required tool not installed: {tool}  (run install.sh)"
        if ctx_log_fn:
            ctx_log_fn("WARN", "runner", msg)
        return False

    def cancel(self) -> None:
        self._cancel_event.set()

    def reset_cancel(self) -> None:
        self._cancel_event.clear()

    def _safe_command(self, cmd: list[str], redactions: list[str] | None) -> list[str]:
        """Use the central evidence policy without altering child arguments."""
        return safe_argv(cmd, redactions or ())

    def _write_header(self, log_path: Path, safe_cmd: list[str]) -> None:
        with log_path.open("ab") as handle:
            handle.write((f"\n{'='*60}\n$ {' '.join(safe_cmd)}\n{'='*60}\n").encode())

    def _run_go(self, cmd: list[str], *, timeout: int, log_path: Path,
                input_data: str | None, cwd: str | Path | None, env: dict | None,
                capture_mode: str, stdout_path=None, stderr_path=None) -> tuple[int, str, str] | None:
        if self.executor_backend not in {"go", "auto"}:
            return None
        # The helper intentionally returns bounded tails. Full-capture callers
        # remain on Python so historical parsers never lose records.
        if capture_mode != "tail":
            return None
        if not self.go_executor.is_file() or not os.access(self.go_executor, os.X_OK):
            return None
        if os.name != 'posix':
            return None
        if self._go_evidence_protocol is None:
            try:
                probe = subprocess.run([str(self.go_executor), '--evidence-protocol'],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1)
                self._go_evidence_protocol = probe.returncode == 0 and probe.stdout.strip() == '2'
            except (OSError, subprocess.SubprocessError):
                self._go_evidence_protocol = False
        # An older helper falls back before any scanner job is dispatched.
        if not self._go_evidence_protocol:
            return None
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        stdout_tail = _TailBuffer(self.capture_tail_bytes)
        stderr_tail = _TailBuffer(self.capture_tail_bytes)
        stream_threads = []
        stop_streams = threading.Event()
        logf = log_path.open('ab')
        lock = threading.Lock()
        job = {
            "argv": [str(x) for x in cmd], "cwd": str(cwd or ""),
            "env": {str(k): str(v) for k, v in (env or {}).items()},
            "timeout_ms": max(1, int(timeout)) * 1000,
            # Raw helper output never opens an ordinary evidence file. Dedicated
            # inherited pipes feed exactly the same sanitizer as Python jobs.
            "log_path": os.devnull, "input": input_data or "",
            "stdout_fd": out_write, "stderr_fd": err_write,
            "tail_bytes": self.capture_tail_bytes,
        }
        proc: subprocess.Popen | None = None
        try:
            deadline = time.monotonic() + max(1, timeout)
            proc = subprocess.Popen(
                [str(self.go_executor)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(out_write, err_write),
                start_new_session=(os.name == "posix"), shell=False,
            )
            for fd in (out_write, err_write): os.close(fd)
            out_write = err_write = None
            for fd, tail, label, artifact in (
                    (out_read, stdout_tail, b'\n--- STDOUT ---\n', stdout_path),
                    (err_read, stderr_tail, b'\n--- STDERR ---\n', stderr_path)):
                thread = threading.Thread(target=self._stream_pipe,
                    args=(os.fdopen(fd, 'rb'), logf, tail, label, lock,
                          Path(artifact) if artifact else None, stop_streams), daemon=True)
                stream_threads.append(thread); thread.start()
            assert proc.stdin is not None

            # Drain helper pipes concurrently. A JSON result containing a large
            # output tail can exceed the OS pipe buffer and otherwise deadlock if
            # the parent waits for process exit before reading it.
            stdout_parts: list[str] = []
            stderr_parts: list[str] = []
            def _drain(pipe, parts: list[str]) -> None:
                try:
                    if pipe is not None:
                        parts.append(pipe.read())
                finally:
                    try:
                        if pipe is not None:
                            pipe.close()
                    except Exception:
                        pass
            out_thread = threading.Thread(target=_drain, args=(proc.stdout, stdout_parts), daemon=True)
            err_thread = threading.Thread(target=_drain, args=(proc.stderr, stderr_parts), daemon=True)
            out_thread.start(); err_thread.start()
            feed_thread = threading.Thread(target=self._feed_input,
                args=(proc.stdin, json.dumps(job)), daemon=True)
            feed_thread.start()
            interrupted: tuple[int, str] | None = None
            while proc.poll() is None:
                if self._cancel_event.is_set():
                    self._terminate_process_group(proc)
                    interrupted = (130, "cancelled")
                    break
                if time.monotonic() >= deadline:
                    self._terminate_process_group(proc)
                    interrupted = (124, f"go executor timeout after {timeout}s")
                    break
                time.sleep(0.05)
            feed_thread.join(timeout=0.5)
            out_thread.join(timeout=0.5); err_thread.join(timeout=0.5)
            if interrupted is not None:
                stop_streams.set()
            for thread in stream_threads: thread.join(timeout=0.1 if interrupted else 2)
            stdout = "".join(stdout_parts)
            stderr = "".join(stderr_parts)
            if interrupted is not None:
                return interrupted[0], stdout_tail.text(), interrupted[1] + '\n' + stderr_tail.text()
            if proc.returncode != 0:
                return int(proc.returncode or 1), stdout_tail.text(), redact_text(stderr)
            if not stdout.strip():
                return 65, stdout_tail.text(), 'go executor returned no result: '+redact_text(stderr)[:500]
            result = json.loads(stdout)
            return (int(result.get("exit_code", 1)),
                    stdout_tail.text(),
                    stderr_tail.text() or redact_text(result.get('error') or ''))
        except Exception as exc:
            if proc is not None and proc.poll() is None:
                self._terminate_process_group(proc)
            # Never retry a potentially dispatched scanner on a helper error.
            return 1, stdout_tail.text(), redact_text(f"go executor failed: {exc}")
        finally:
            for fd in (out_write, err_write):
                if fd is not None: os.close(fd)
            stop_streams.set()
            for thread in stream_threads: thread.join(timeout=0.1)
            if not stream_threads:
                os.close(out_read); os.close(err_read)
            logf.close()

    @staticmethod
    def _terminate_process_group(proc: subprocess.Popen) -> None:
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
                # The leader can exit before an owned child that ignores TERM.
                # Its new-session group remains owned while a child holds it.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            try: proc.kill()
            except Exception: pass

    def _stream_pipe(self, pipe, logf, tail: _TailBuffer, label: bytes, lock: threading.Lock,
                     artifact_path: Path | None = None, stop_event=None) -> None:
        artifact = None
        sanitizer = StreamRedactor()
        try:
            if artifact_path is not None:
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact = artifact_path.open("ab")
            with lock:
                if stop_event is not None and stop_event.is_set():
                    return
                logf.write(label)
                logf.flush()
            while True:
                chunk = pipe.read(64 * 1024)
                if not chunk:
                    break
                if stop_event is not None and stop_event.is_set():
                    return
                chunk = sanitizer.feed(chunk)
                if stop_event is not None and stop_event.is_set():
                    return
                tail.append(chunk)
                if artifact is not None:
                    artifact.write(chunk); artifact.flush()
                with lock:
                    if stop_event is not None and stop_event.is_set():
                        return
                    logf.write(chunk)
                    logf.flush()
            if stop_event is not None and stop_event.is_set():
                return
            chunk = sanitizer.finish()
            if stop_event is not None and stop_event.is_set():
                return
            tail.append(chunk)
            if artifact is not None:
                artifact.write(chunk); artifact.flush()
            with lock:
                if stop_event is not None and stop_event.is_set():
                    return
                logf.write(chunk); logf.flush()
        finally:
            if artifact is not None:
                try: artifact.close()
                except Exception: pass
            try: pipe.close()
            except Exception: pass

    @tracked_tool
    def run(self, cmd: list[str], timeout: int = 300, log_name: str = None,
            input_data: str = None, allow_fail: bool = True,
            cwd: str | Path | None = None, env: dict | None = None,
            log_redactions: list[str] | None = None, capture_mode: str = "full",
            stdout_path: str | Path | None = None, stderr_path: str | Path | None = None) -> tuple[int, str, str]:
        """Execute argv without a shell.

        ``capture_mode="full"`` preserves historical parser behavior. Callers that
        do not parse stdout should request ``tail`` or ``none`` for bounded RAM. Full streams are always written to the run log;
        optional artifact paths provide parser-friendly files without RAM growth.
        """
        capture_mode = str(capture_mode or "tail").lower()
        if capture_mode not in {"tail", "full", "none"}:
            if allow_fail:
                return 2, "", f"invalid capture_mode: {capture_mode}"
            raise ValueError("capture_mode must be tail, full, or none")
        if not isinstance(cmd, list) or not cmd or not str(cmd[0]).strip():
            if allow_fail:
                return 2, "", "invalid empty command"
            raise ValueError("cmd must be a non-empty argv list")
        from core.lifecycle import check
        check(self)
        if self.profile.get('runtime', {}).get('require_external_containment', False):
            # This release has no generic subprocess destination/byte broker.
            # A mandatory external-containment profile cannot fall back to raw CLI.
            return 77, '', 'mandatory external containment is unavailable for this adapter'
        phase_deadline = getattr(self, '_phase_deadline', None)
        if phase_deadline is not None:
            timeout = min(timeout, max(0.01, phase_deadline-time.monotonic()))
        if (self.profile.get('runtime', {}).get('offline') and
                Path(str(cmd[0])).name not in {'semgrep', 'gitleaks', 'ruff', 'bandit', 'file', 'strings', 'readelf', 'objdump', 'aapt', 'aapt2'}):
            ledger = getattr(self, 'execution_ledger', None)
            if ledger:
                ledger.record(kind='tool', argv=self._safe_command(cmd, log_redactions), status='blocked', reason='adapter not approved for offline execution')
            return 77, '', 'offline mode: external adapter blocked before launch'
        env = dict(env or {})
        env.update({'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
                    'SEMGREP_APP_TOKEN': '', 'GIT_TERMINAL_PROMPT': '0'})
        if self._cancel_event.is_set():
            return 130, "", "cancelled before start"
        self.monitor.wait_if_pressured(max_wait_sec=15)
        check(self)
        log_name = log_name or str(cmd[0]).replace("/", "_")
        log_path = self.logs_dir / f"{log_name}.log"
        safe_cmd = self._safe_command(cmd, log_redactions)
        self._write_header(log_path, safe_cmd)

        if self.profile.get('runtime', {}).get('offline'):
            from core.offline_isolation import child_argv
            cmd = child_argv(cmd)

        go_result = self._run_go(cmd, timeout=timeout, log_path=log_path,
                                 input_data=input_data, cwd=cwd, env=env,
                                 capture_mode=capture_mode, stdout_path=stdout_path,
                                 stderr_path=stderr_path)
        if go_result is not None:
            return go_result

        child_env = os.environ.copy()
        if env:
            child_env.update({str(k): str(v) for k, v in env.items()})
        capture_limit = min(int(self.profile.get("runtime", {}).get("max_full_capture_bytes", 64 * 1024 * 1024)), 128 * 1024 * 1024) if capture_mode == "full" else (0 if capture_mode == "none" else self.capture_tail_bytes)
        # ``none`` still retains a tiny diagnostic tail while full data remains in logs/artifacts.
        if capture_limit == 0:
            capture_limit = 4096
        stdout_tail = _TailBuffer(capture_limit)
        stderr_tail = _TailBuffer(capture_limit)
        try:
            with log_path.open("ab") as logf:
                deadline = time.monotonic() + max(1, timeout)
                proc = subprocess.Popen(
                    [str(x) for x in cmd], stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(cwd) if cwd else None,
                    env=child_env, start_new_session=(os.name == "posix"), shell=False,
                )
                lock = threading.Lock()
                stop_streams = threading.Event()
                t_out = threading.Thread(target=self._stream_pipe,
                                         args=(proc.stdout, logf, stdout_tail, b"\n--- STDOUT ---\n", lock,
                                               Path(stdout_path) if stdout_path else None, stop_streams), daemon=True)
                t_err = threading.Thread(target=self._stream_pipe,
                                         args=(proc.stderr, logf, stderr_tail, b"\n--- STDERR ---\n", lock,
                                               Path(stderr_path) if stderr_path else None, stop_streams), daemon=True)
                t_out.start(); t_err.start()
                feeder = None
                if input_data is not None and proc.stdin is not None:
                    feeder = threading.Thread(target=self._feed_input,
                        args=(proc.stdin, input_data.encode()), daemon=True)
                    feeder.start()
                rc = None
                while rc is None:
                    if self._cancel_event.is_set():
                        self._terminate_process_group(proc)
                        rc = 130
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate_process_group(proc)
                        rc = 124
                        break
                    try:
                        rc = proc.wait(timeout=min(0.25, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                if feeder is not None:
                    feeder.join(timeout=0.5)
                # A successfully exited leader can leave a pipe-holding child.
                # Such a job is incomplete; terminate only its owned session.
                if rc in (124, 130):
                    stop_streams.set()
                t_out.join(timeout=0.1 if rc in (124, 130) else 2)
                t_err.join(timeout=0.1 if rc in (124, 130) else 2)
                incomplete_output = t_out.is_alive() or t_err.is_alive()
                if incomplete_output:
                    self._terminate_process_group(proc)
                    t_out.join(timeout=0.25); t_err.join(timeout=0.25)
                    incomplete_output = t_out.is_alive() or t_err.is_alive()
                with lock:
                    stop_streams.set()
                if rc == 124:
                    return 124, stdout_tail.text(), f"timeout after {timeout}s\n{stderr_tail.text()}".strip()
                if rc == 130:
                    return 130, stdout_tail.text(), f"cancelled\n{stderr_tail.text()}".strip()
                if incomplete_output:
                    return int(rc or 65), stdout_tail.text(), stderr_tail.text() + '\noutput sanitization incomplete'
                if capture_mode == 'full' and (stdout_tail.discarded_bytes or stderr_tail.discarded_bytes):
                    return int(rc or 65), stdout_tail.text(), stderr_tail.text() + '\nfull capture byte budget exceeded; results incomplete'
                return int(rc or 0), stdout_tail.text(), stderr_tail.text()
        except FileNotFoundError:
            if not allow_fail:
                raise
            return 127, "", f"command not found: {cmd[0]}"
        except Exception as exc:
            if not allow_fail:
                raise
            return 1, stdout_tail.text(), redact_text(exc)

    def run_many(self, jobs: Iterable[dict], *, max_workers: int | None = None) -> list[dict]:
        """Run independent, already-authorized tool jobs with bounded parallelism.

        Each job is a dict accepted by ``run`` plus an optional ``job_id``.  The
        caller remains responsible for dependencies, scope and rate limits.
        """
        rows = list(jobs)
        if not rows:
            return []
        workers = max(1, min(int(max_workers or self.max_parallel_tools), self.threads, len(rows)))
        out: list[dict] = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tbhm-tool") as pool:
            future_map = {}
            for index, job in enumerate(rows):
                item = dict(job)
                job_id = item.pop("job_id", index)
                future_map[pool.submit(self.run, **item)] = job_id
            for future in as_completed(future_map):
                job_id = future_map[future]
                try:
                    rc, stdout, stderr = future.result()
                    out.append({"job_id": job_id, "returncode": rc, "stdout": stdout, "stderr": stderr})
                except Exception as exc:
                    out.append({"job_id": job_id, "returncode": 1, "stdout": "", "stderr": str(exc)})
        return out

    def run_lines(self, cmd: list[str], timeout: int = 300, log_name: str = None, **kwargs) -> list[str]:
        rc, out, err = self.run(cmd, timeout=timeout, log_name=log_name, capture_mode="full", **kwargs)
        return [line.strip() for line in out.splitlines() if line.strip()]

    def write_lines(self, path: Path, lines):
        unique = sorted(set(line for line in lines if line))
        Path(path).write_text("\n".join(unique) + ("\n" if unique else ""))
        return len(unique)

    def read_lines(self, path: Path) -> list[str]:
        if not Path(path).exists():
            return []
        return [line.strip() for line in Path(path).read_text().splitlines() if line.strip()]

    def throttle(self, key: str = "global"):
        rl = self.profile.get("rate_limit", {})
        rps = rl.get("global_rps", 10)
        if rps <= 0:
            return
        min_interval = 1.0 / rps
        last = self.last_call_time.get(key, 0.0)
        delta = time.time() - last
        if delta < min_interval:
            time.sleep(min_interval - delta)
        self.last_call_time[key] = time.time()
