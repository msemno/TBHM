"""v3.9.3 regression tests — guards every fix in this release so it can't
silently regress. Run: python3 integration_test_v393.py
"""
import sys, tempfile, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import fp_filters as FP
from core import taint_engine as TE
from core import reverse_utils as RU

_fail = []


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        _fail.append(name)


def test_p03_runtime_proof_status():
    """Runtime proof must require a success status, not any 3-digit code."""
    def proof(code):
        return FP._has_runtime_proof(
            {"phase": "code_intel", "title": "route probe",
             "evidence": f"GET https://x/admin -> {code} (len=10)"})
    check("200 is runtime proof", proof("200") is True)
    check("302 is runtime proof", proof("302") is True)
    check("401 is NOT runtime proof", proof("401") is False)
    check("403 is NOT runtime proof", proof("403") is False)
    check("404 is NOT runtime proof", proof("404") is False)
    check("500 is NOT runtime proof", proof("500") is False)


def test_p02_taint_no_self_confirm():
    """A static taint flow must NOT self-confirm without reachability."""
    flows = TE.analyze_python(
        "import os\nfrom flask import request\n"
        "def h():\n c=request.args.get('x')\n os.system('ping '+c)\n", "h.py")
    check("taint flow detected", len(flows) == 1)
    fl = flows[0]
    check("static-only flow is NOT confirmed", fl.confirmed is False)
    fl.mark_reachable("live 200")
    check("confirmed after reachability corroboration", fl.confirmed is True)


def test_a_secret_value_before_redaction():
    """Real secret survives the gate; example/placeholder dropped; stored redacted."""
    cands = RU.secret_candidates([
        "api_key=sk_live_9fJ2kLmN8xQ4vW7pR3tY6uZ1aB5cD0eF",
        "password=EXAMPLE_PLACEHOLDER_VALUE"])
    check("secret_candidates keeps the real value in memory",
          any(c["value"].startswith("sk_live_") for c in cands))
    # simulate the phase decision: value-based dummy screen
    real = next(c for c in cands if c["value"].startswith("sk_live_"))
    example = next(c for c in cands if "EXAMPLE" in c["value"])
    dummy_real, _ = FP.is_dummy_secret({"evidence": f'x = "{real["value"]}"',
                                        "title": "Hardcoded secret: Generic"})
    dummy_ex, _ = FP.is_dummy_secret({"evidence": f'x = "{example["value"]}"',
                                      "title": "Hardcoded secret: Generic"})
    check("real key NOT treated as dummy", dummy_real is False)
    check("placeholder IS treated as dummy", dummy_ex is True)
    check("redacted form never contains the real value",
          "sk_live_" not in real["redacted"])


def test_b_raw_short_imports():
    """Dangerous APIs shorter than the string floor are caught via raw bytes."""
    binf = Path(tempfile.mkdtemp()) / "agent"
    binf.write_bytes(b"\x00".join(
        [b"gets", b"system", b"popen", b"WinExec", b"strcpy", b"padding_padding"]) + b"\x00")
    imps = RU.raw_short_imports(binf)
    names = {i["name"] for i in imps}
    check("short API 'gets' caught", "gets" in names)
    check("short API 'system' caught", "system" in names)
    check("short API 'WinExec' caught", "WinExec" in names)


def test_full_binary_phase():
    """End-to-end: legacy phase yields findings incl. exactly one real secret."""
    sample = Path(tempfile.mkdtemp()) / "sample.bin"   # worst-case name
    sample.write_bytes(b"\x00".join([
        b"\x7fELF" + b"\x00" * 20,
        b"api_key=sk_live_9fJ2kLmN8xQ4vW7pR3tY6uZ1aB5cD0eF",
        b"aws_key=AKIAIOSFODNN7EXAMPLE",
        b"gets", b"system",
        b"filler_readable_string"]) + b"\x00")
    findings = []

    class Runner:
        def has(self, x): return False
        def run(self, *a, **k): return (1, "", "")

    class Ctx:
        def __init__(self):
            self.output = Path(tempfile.mkdtemp())
            self.args = types.SimpleNamespace(
                binary_path=str(sample), reverse_results=None, reverse_tooling=True,
                reverse_max_files=50, reverse_max_file_mb=200)
            self.runner = Runner()
            self.storage = type("S", (), {})()

        def save_finding(self, f): findings.append(f)
        def log(self, *a, **k): pass

    from phases import reverse_engineering_tooling as R
    R.run(Ctx())
    secrets = [f for f in findings if f.get("cwe") == "CWE-798"]
    imports = [f for f in findings if "API import" in f["title"]]
    check("binary phase produced findings (not a no-op)", len(findings) > 0)
    check("exactly one real secret (example dropped even w/ sample.bin name)",
          len(secrets) == 1)
    check("stored secret evidence is redacted",
          all("[REDACTED]" in s["evidence"] and "sk_live" not in s["evidence"]
              for s in secrets))
    check("short dangerous imports surfaced", len(imports) >= 2)


def main():
    print("TBHM v3.9.3 regression tests")
    for t in (test_p03_runtime_proof_status, test_p02_taint_no_self_confirm,
              test_a_secret_value_before_redaction, test_b_raw_short_imports,
              test_full_binary_phase):
        print(f"\n[{t.__name__}]")
        t()
    print(f"\n{'ALL PASSED' if not _fail else str(len(_fail)) + ' FAILED: ' + ', '.join(_fail)}")
    sys.exit(1 if _fail else 0)


if __name__ == "__main__":
    main()
