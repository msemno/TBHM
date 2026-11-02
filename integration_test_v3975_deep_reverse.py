#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent

from core import reverse_ir as RIR
from core.interprocedural_taint import IRTaintAnalyzer
from core.cross_language_flow import collect_mobile_bridges, collect_js_calls, collect_native_functions, correlate
from core.dynamic_mapper import map_events
from core.fuzz_harness import generate_all
from core.crash_triage import collect_crashes, delta_minimize, reproduce_and_minimize
from core.binary_diff import compare
from core.artifact_store import ArtifactStore
from core.reverse_families import analyze_mobile_package, analyze_protocol_capture, detect_family
from core.package_verifier import verify_zip, verify_tree
from core.js_intelligence import discover_candidates, analyze_text
from core.sandbox_manager import parse_command_json, SandboxError, SandboxResult
from phases import firmware_tooling_extended as FTE


def sample_ir():
    return {
        "schema": RIR.SCHEMA, "backend": "ghidra", "artifact": {"path": "/tmp/sample"},
        "functions": [
            {"name": "handler", "start": "0x1000", "end": "0x1100", "size": 256,
             "parameters": [], "strings": [{"value": "PING /api/admin"}],
             "pcode": [
                 {"mnemonic": "CALL", "address": "0x1010", "callee": "0x5000",
                  "output": {"address": "unique:1"}, "inputs": [{"address": "0x5000"}]},
                 {"mnemonic": "COPY", "address": "0x1020", "output": {"address": "unique:2"},
                  "inputs": [{"address": "unique:1"}]},
                 {"mnemonic": "CALL", "address": "0x1030", "callee": "0x6000", "output": None,
                  "inputs": [{"address": "0x6000"}, {"address": "unique:2"}]},
             ]},
            {"name": "recv", "start": "0x5000", "end": "0x5001", "external": True, "pcode": []},
            {"name": "system", "start": "0x6000", "end": "0x6001", "external": True, "pcode": []},
            {"name": "parse_packet", "start": "0x7000", "end": "0x7100", "size": 256,
             "parameters": [{"name": "data", "type": "const uint8_t *"}, {"name": "len", "type": "size_t"}],
             "strings": [{"value": "MAGIC"}], "pcode": []},
        ], "imports": [], "exports": [], "strings": [], "types": [],
    }


class DummyRunner:
    def read_lines(self, path):
        return Path(path).read_text(errors="ignore").splitlines() if Path(path).is_file() else []
    def write_lines(self, path, values):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("\n".join(sorted(set(values))) + "\n", encoding="utf-8")


class Scope:
    def allows(self, value):
        return "example.com" in str(value)


class DummyCtx:
    def __init__(self, output):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.runner = DummyRunner()
        self.scope = Scope()
        self.scope_excludes = []
        self.targets = ["example.com"]
        self.profile = {"name": "authorized_safe", "active_probes": True,
                        "rate_limit": {"global_rps": 10, "per_target_rps": 10}}
        self.args = SimpleNamespace(js_candidate_results=[], js_candidate_scan_files=1000,
                                    js_max_files=0, js_max_bytes=1000000, js_timeout=5,
                                    js_max_source_maps=250, js_max_recovered_sources=10000)
        self.findings = []
    def save_finding(self, row): self.findings.append(row)
    def log(self, *_args): pass


class Response:
    def __init__(self, body, status=200, ctype="application/javascript"):
        self.content = body.encode()
        self.text = body
        self.status_code = status
        self.headers = {"Content-Type": ctype}
        self.encoding = "utf-8"


class DeepReverseTests(unittest.TestCase):
    def test_universal_ir_and_interprocedural_taint(self):
        native = {"tool": "ghidra", "program": "sample", "functions": sample_ir()["functions"]}
        ir = RIR.add_fingerprints(RIR.normalize(native))
        self.assertEqual(ir["schema"], RIR.SCHEMA)
        self.assertTrue(all(fn.get("fingerprint") for fn in ir["functions"]))
        result = IRTaintAnalyzer(ir).analyze()
        self.assertTrue(any("command_execution:system" in flow["sink"] for flow in result["flows"]), result)

    def test_cross_language_jni_correlation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Bridge.java").write_text('''
class Bridge {
  void setup(WebView w, Bridge instance) { w.addJavascriptInterface(instance, "Bridge"); }
  @JavascriptInterface public String run(String x) { return nativeRun(x); }
  public native int nativeRun(String x);
  static { System.loadLibrary("native"); }
}
''')
            js = root / "app.js"; js.write_text("Bridge.run(location.hash);")
            inventory = collect_mobile_bridges(root)
            calls = collect_js_calls([js])
            ir = {"artifact": {"path": "libnative.so"}, "functions": [
                {"name": "Java_com_example_Bridge_nativeRun", "start": "0x1000", "pcode": [], "calls": []}
            ]}
            native = collect_native_functions([ir])
            result = correlate(inventory, calls, native, [])
            self.assertTrue(any(row.get("native_reached") for row in result["paths"]), result)

    def test_dynamic_mapping_fuzz_crash_diff_and_campaign(self):
        ir = RIR.add_fingerprints(sample_ir())
        mapped = map_events([ir], [{"event": {"pc": "0x1030", "message": "crash addr=0x1031"}}])
        self.assertGreaterEqual(mapped["counts"]["mapped"], 1)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            generated = generate_all(ir, td / "harnesses", 10)
            self.assertGreaterEqual(generated["count"], 1)
            self.assertTrue(Path(generated["generated"][0]["harness"]).is_file())
            crashes = td / "crashes"; crashes.mkdir()
            (crashes / "a.log").write_text("AddressSanitizer: heap-buffer-overflow\n#0 0x1234 in parse_packet\n#1 in main\n")
            (crashes / "b.log").write_text("SIGSEGV\n#0 0x9999 in parse_packet\n#1 in main\n")
            triage = collect_crashes(crashes)
            self.assertEqual(triage["counts"]["unique"], 1)
            minimized, tests = delta_minimize(b"AAAA_CRASH_BBBB", lambda data: b"CRASH" in data)
            self.assertIn(b"CRASH", minimized); self.assertGreater(tests, 0)
            newer = json.loads(json.dumps(ir)); newer["functions"][0]["pcode"].append({"mnemonic": "CALL", "callee": "validate"})
            diff = compare(ir, newer)
            self.assertGreaterEqual(diff["counts"]["changed"], 1)
            artifact = td / "artifact.bin"; artifact.write_bytes(b"same")
            store = ArtifactStore(td / "store")
            try:
                a = store.add(artifact, campaign="c", project="p1")
                b = store.add(artifact, campaign="c", project="p2")
                self.assertFalse(a["deduplicated"]); self.assertTrue(b["deduplicated"])
                self.assertEqual(store.stats()["unique_artifacts"], 1)
            finally: store.close()

    def test_managed_mobile_family_and_package_verification(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); apk = td / "sample.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", "manifest")
                z.writestr("classes.dex", b"dex\n035\x00")
                z.writestr("lib/arm64-v8a/libflutter.so", b"ELF")
                z.writestr("assets/flutter_assets/app.js", "fetch('/api')")
            self.assertEqual(detect_family(apk)["family"], "mobile")
            mobile = analyze_mobile_package(apk)
            self.assertEqual(mobile["counts"]["dex"], 1)
            self.assertIn("flutter", mobile["framework_hints"])
            verified = verify_zip(apk)
            self.assertTrue(verified["passed"], verified)
            tree = td / "tree"; tree.mkdir(); (tree / "ok.py").write_text("x=1\n")
            self.assertTrue(verify_tree(tree)["passed"])

    def test_js_sources_from_katana_paramspider_zap_and_source_map(self):
        from phases import js_analysis
        with tempfile.TemporaryDirectory() as td:
            ctx = DummyCtx(td); recon = Path(td) / "recon"; recon.mkdir()
            (recon / "katana_urls.txt").write_text("https://example.com/a.js\n")
            (recon / "paramspider_urls.txt").write_text("https://example.com/b.js?x=1\n")
            (recon / "zap_urls.txt").write_text("https://example.com/c.js\n")
            candidates = discover_candidates(td)
            self.assertEqual(len(candidates), 3)
            bodies = {
                "https://example.com/a.js": "const u='/api/admin'; const x=location.hash; document.write(x); //# sourceMappingURL=a.js.map",
                "https://example.com/b.js?x=1": "const p=new URLSearchParams(location.search); fetch('/api/user?id='+p.get('id'));",
                "https://example.com/c.js": "window.cfg={featureFlag:true}; new WebSocket('wss://example.com/ws');",
                "https://example.com/a.js.map": json.dumps({"version":3,"sources":["src/original.ts"],"sourcesContent":["fetch('/api/recovered'); const q=location.search; eval(q);"]}),
            }
            def fake_get(_ctx, url, _limiter, _timeout):
                return Response(bodies[url], ctype="application/json" if url.endswith('.map') else "application/javascript"), url, [url]
            with patch.object(js_analysis, "_fetch", side_effect=fake_get):
                js_analysis.run(ctx)
            index = json.loads((Path(td) / "js_analysis" / "JS_USEFULNESS_INDEX.json").read_text())
            analyzed = [r for r in index["records"] if r.get("status") == "analyzed"]
            self.assertEqual(len(analyzed), 3)
            self.assertEqual(index["recovered_sources"], 1)
            endpoints = (recon / "js_endpoints.txt").read_text()
            self.assertIn("/api/recovered", endpoints)
            self.assertIn("/api/user", endpoints)

    def test_js_analysis_content_classification(self):
        result = analyze_text("const x=location.hash; document.write(x); fetch('/api/x');", "https://example.com/app.js")
        self.assertIn(result["classification"], {"useful", "review"})
        self.assertTrue(result["taint_flows"])

    def test_sandbox_command_parser_and_angr_cli_surface(self):
        self.assertEqual(parse_command_json('["/bin/tool", "/input/artifact"]')[0], "/bin/tool")
        with self.assertRaises(SandboxError): parse_command_json("not-json")
        text = (ROOT / "scripts/reverse/angr_triage.py").read_text()
        for flag in ("--mode", "--find", "--avoid", "--seed-file", "--trace-file"):
            self.assertIn(flag, text)
        ghidra = (ROOT / "scripts/ghidra/ExportTbhmAnalysis.java").read_text()
        for token in ("DecompInterface", "HighFunction", "getPcodeOps", "decompiled_c", "basic_blocks"):
            self.assertIn(token, ghidra)


    def test_taint_memory_model_and_aslr_rebasing(self):
        ir = sample_ir()
        ir["artifact"]["image_base"] = "0x1000"
        ir["artifact"]["name"] = "sample.bin"
        ir["functions"][0]["pcode"] = [
            {"mnemonic": "CALL", "callee": "recv", "inputs": [{"address": "0x5000"},
             {"address": "const:fd"}, {"address": "ram:2000"}, {"address": "const:length"}]},
            {"mnemonic": "LOAD", "output": {"address": "unique:loaded"},
             "inputs": [{"address": "const:0"}, {"address": "ram:2000"}]},
            {"mnemonic": "CALL", "callee": "system",
             "inputs": [{"address": "0x6000"}, {"address": "unique:loaded"}]},
        ]
        result = IRTaintAnalyzer(ir).analyze()
        self.assertTrue(any("network:recv" == row["source"] and "system" in row["sink"] for row in result["flows"]), result)
        mapped = map_events([ir], [{"module": "sample.bin", "module_base": "0x7f000000", "pc": "0x7f000030"}])
        self.assertEqual(mapped["counts"]["rebased"], 1, mapped)
        self.assertEqual(mapped["mapped_events"][0]["function"], "handler")

    def test_inline_source_map_and_explicit_limits(self):
        from phases import js_analysis
        with tempfile.TemporaryDirectory() as td:
            ctx = DummyCtx(td); ctx.args.js_max_source_maps = 1; ctx.args.js_max_recovered_sources = 1
            recon = Path(td) / "recon"; recon.mkdir()
            (recon / "javascript.txt").write_text("https://example.com/inline.js\n")
            map_doc = {"version": 3, "sources": ["one.ts", "two.ts"],
                       "sourcesContent": ["fetch('/api/one')", "fetch('/api/two')"]}
            encoded = base64.b64encode(json.dumps(map_doc).encode()).decode()
            body = f"fetch('/api/bundle'); //# sourceMappingURL=data:application/json;base64,{encoded}"
            def fake_get(_ctx, url, _limiter, _timeout):
                return Response(body), url, [url]
            with patch.object(js_analysis, "_fetch", side_effect=fake_get):
                js_analysis.run(ctx)
            index = json.loads((Path(td) / "js_analysis/JS_USEFULNESS_INDEX.json").read_text())
            self.assertEqual(index["recovered_sources"], 1)
            maps = index["records"][0]["source_map_recovery"]
            self.assertEqual(maps[0]["status"], "analyzed")
            self.assertTrue(any(x.get("classification") == "skipped_recovered_source_limit" for x in maps[0]["sources"]))
            endpoints = (recon / "js_endpoints.txt").read_text()
            self.assertIn("/api/one", endpoints)
            self.assertNotIn("/api/two", endpoints)

    def test_package_manifest_validation_and_protocol_cap_detection(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); tree = td / "release"; tree.mkdir()
            payload = tree / "tool.py"; payload.write_text("print('ok')\n"); payload.chmod(0o755)
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            manifest = {"release": "test", "files": [{"path": "tool.py", "sha256": digest,
                                                         "size": payload.stat().st_size, "executable": True}]}
            (tree / "RELEASE_MANIFEST-vtest.json").write_text(json.dumps(manifest))
            self.assertTrue(verify_tree(tree)["passed"])
            archive = td / "release.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                for child in tree.iterdir():
                    if not child.is_file():
                        continue
                    info = zipfile.ZipInfo(f"release/{child.name}")
                    info.external_attr = ((0o100755 if child.name == "tool.py" else 0o100644) << 16)
                    zf.writestr(info, child.read_bytes())
            verified = verify_zip(archive)
            self.assertTrue(verified["passed"], verified)
            cap = td / "capture.cap"
            cap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x02\x00\x04\x00" + b"\x00" * 16)
            self.assertEqual(detect_family(cap)["family"], "protocol_capture")
            self.assertTrue(analyze_protocol_capture(cap)["header"]["valid"])

    def test_sandboxed_crash_minimization_contract(self):
        class FakeManager:
            def __init__(self, output): self.output = Path(output)
            def run_container(self, artifact, image, command, **kwargs):
                data = Path(kwargs["case_file"]).read_bytes()
                crashed = b"CRASH" in data
                text = "AddressSanitizer: heap-buffer-overflow\n#0 0x1234 in parse_packet\n#1 in main\n" if crashed else "ok"
                return SandboxResult("container", list(command), 1 if crashed else 0, "", text, 1.0, 2.0,
                                     workspace=str(self.output), policy={"network": "none", "read_only": True})
        with tempfile.TemporaryDirectory() as td:
            td = Path(td); artifact = td / "parser"; artifact.write_bytes(b"binary")
            case = td / "case"; case.write_bytes(b"AAAA_CRASH_BBBB")
            result = reproduce_and_minimize(FakeManager(td / "out"), artifact, case, "local/image",
                                            ["/input/artifact", "/input/case"], max_tests=100)
            self.assertTrue(result["reproduced"], result)
            self.assertLess(result["minimized"]["bytes"], result["original"]["bytes"])
            self.assertIn(b"CRASH", Path(result["minimized"]["path"]).read_bytes())

    def test_emba_mode_safety_contract(self):
        class RunRecorder:
            def __init__(self): self.calls = []
            def run(self, command, **kwargs):
                self.calls.append((list(command), dict(kwargs)))
                return 0, "", ""
        class EmbaCtx:
            def __init__(self, args):
                self.args = args
                self.runner = RunRecorder()
                self.messages = []
            def log(self, level, phase, message): self.messages.append((level, phase, message))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            firmware = root / "firmware.bin"; firmware.write_bytes(b"firmware")
            emba_root = root / "emba"; (emba_root / "scan-profiles").mkdir(parents=True)
            executable = emba_root / "emba"; executable.write_text("#!/bin/sh\nexit 0\n"); executable.chmod(0o755)
            (emba_root / "scan-profiles/default-scan.emba").write_text("profile\n")
            common = dict(emba=True, firmware=str(firmware), emba_path=str(executable), emba_profile=None,
                          emba_results=None, emba_timeout=600, emba_sandbox_engine="auto",
                          confirm_isolated_execution=True, emba_emulation=False)
            emulation = EmbaCtx(SimpleNamespace(**common, emba_mode="emulation", emba_sandbox_image=""))
            refused = FTE._run_emba(emulation, root / "emulation-out")
            self.assertIsNone(refused)
            self.assertFalse(emulation.runner.calls)
            self.assertTrue(any("sandbox-image" in msg for _lvl, _phase, msg in emulation.messages))
            static = EmbaCtx(SimpleNamespace(**common, emba_mode="static", emba_sandbox_image=""))
            output = FTE._run_emba(static, root / "static-out")
            self.assertIsNotNone(output)
            self.assertEqual(len(static.runner.calls), 1)
            self.assertIn("default-scan.emba", " ".join(static.runner.calls[0][0]))

    def test_phase_and_cli_registration(self):
        import tbhm
        required = {"reverse_ir_analysis", "reverse_taint_analysis", "reverse_cross_language", "reverse_sandbox_analysis",
                    "reverse_dynamic_mapping", "reverse_fuzzing", "reverse_crash_triage", "reverse_diff_analysis",
                    "reverse_campaign_index", "reverse_family_analysis", "package_verification"}
        self.assertTrue(required.issubset(set(tbhm.PHASE_ORDER)))
        help_text = (ROOT / "tbhm.py").read_text(errors="ignore")
        for option in ("--emba-mode", "--js-max-files", "--js-max-source-maps", "--js-max-recovered-sources",
                       "--reverse-ir", "--reverse-taint", "--reverse-sandbox",
                       "--reverse-fuzz-harness", "--reverse-diff-old", "--reverse-campaign-store", "--verify-package"):
            self.assertIn(option, help_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
