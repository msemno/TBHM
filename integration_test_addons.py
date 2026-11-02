"""End-to-end integration test for the TBHM add-ons.

Stands up a local mock HTTP endpoint that is deliberately 'injectable' (it
emits a MySQL error string when it sees a lone quote, and differs on
TRUE/FALSE), runs the SQLi phase against it through the adapter, then runs the
net/AD and service phases (which correctly report unsupported/empty on this
Linux box), and finally asserts the logging channels were populated.

No external network. Localhost only.
"""

import json
import sys
import time
import threading
import tempfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent))
from tbhm_addons import run_phase, describe  # noqa: E402


class MockVulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        idv = (q.get("id", ["1"])[0])
        body = "<html><body>Product listing\n"
        # error-based: lone quote -> MySQL error signature
        if idv.count("'") % 2 == 1 and "AND" not in idv.upper() and "OR" not in idv.upper():
            body = ("You have an error in your SQL syntax; check the manual "
                    "near ''" )
        # boolean-based: TRUE returns long body, FALSE returns short
        elif "1'='1" in idv or "1=1" in idv:
            body += "row " * 200  # long
        elif "1'='2" in idv or "1=2" in idv:
            body += "x"  # short
        else:
            body += "default listing " * 20
        body += "\n</body></html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_server():
    srv = HTTPServer(("127.0.0.1", 0), MockVulnHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def main():
    print(describe())
    print()
    srv, port = start_server()
    run_root = tempfile.mkdtemp(prefix="tbhm_integ_")
    target = f"http://127.0.0.1:{port}/product.php?id=1"

    base_cfg = {
        "engagement": "INTEGRATION-TEST",
        "run_root": run_root,
        "roe_ref": "selftest-0001",
        "session_handle": "acct-lowpriv",
        "req_delay": 0.05,      # fast for test
        "time_delay_s": 1,
    }

    # 1) SQLi phase against the mock vulnerable endpoint
    cfg = dict(base_cfg, target=target, phase_id="ADD-SQLI")
    sqli = run_phase("ADD-SQLI", cfg)
    print("SQLi findings:", len(sqli["findings"]))
    for f in sqli["findings"]:
        print(f"  - {f['technique']:<8} on {f['parameter']}: {f['evidence'][:60]}")

    # 2) net/AD phase — no DC supplied, network-only, should run clean
    cfg2 = dict(base_cfg, target="127.0.0.1", phase_id="ADD-NETAD")
    netad = run_phase("ADD-NETAD", cfg2)
    print("Net/AD errors (expected 'network only'):", netad.get("errors"))

    # 3) service primitive — Linux, should report unsupported_platform
    cfg3 = dict(base_cfg, target="127.0.0.1", phase_id="ADD-SVCPRIM")
    svc = run_phase("ADD-SVCPRIM", cfg3)
    print("Service platform_supported:", svc["platform_supported"],
          "| errors:", svc.get("errors"))

    srv.shutdown()

    # 4) verify logging channels
    logs = Path(run_root) / "logs"
    print("\n--- log channel line counts ---")
    ok = True
    for name, min_lines in [("full.jsonl", 5), ("audit.jsonl", 5),
                            ("full.log", 5), ("background.json", 1)]:
        p = logs / name
        n = sum(1 for _ in p.open()) if p.exists() else 0
        flag = "OK" if n >= min_lines else "LOW"
        if n < min_lines:
            ok = False
        print(f"  {name:<18} {n:>4} lines  [{flag}]")

    # show a sample tool log line proving reproducibility (argv captured)
    print("\n--- sample reproducibility record (argv captured) ---")
    with (logs / "full.jsonl").open() as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("verb") == "tool" and rec.get("extra", {}).get("argv"):
                print("  ", json.dumps(rec["extra"]["argv"]))
                break

    print("\nRUN ROOT:", run_root)
    print("RESULT:", "PASS" if (ok and len(sqli["findings"]) >= 1) else "FAIL")


if __name__ == "__main__":
    main()
