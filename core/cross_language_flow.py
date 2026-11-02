"""Cross-language JavaScript -> Java/Kotlin -> JNI -> native correlation.

The correlator builds evidence links from WebView bridge registration and
@JavascriptInterface methods through Java native declarations/System.loadLibrary
into JNI exports and normalized native functions. It is conservative: a matched
name is a supported lead, not proof that attacker-controlled JavaScript reaches a
native sink at runtime.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

JS_CALL_RE = re.compile(r"(?P<object>[A-Za-z_$][\w$]*)\.(?P<method>[A-Za-z_$][\w$]*)\s*\(")
BRIDGE_RE = re.compile(
    r"addJavascriptInterface\s*\(\s*(?P<instance>(?:this\.)?[A-Za-z_$][\w$]*)\s*,\s*[\"'](?P<object>[^\"']+)[\"']\s*\)",
    re.M,
)
INSTANCE_CLASS_RE = re.compile(
    r"(?:(?P<java_class>[A-Za-z_$][\w$<>.]*)\s+(?P<java_name>[A-Za-z_$][\w$]*)\s*=\s*new\s+(?P<java_ctor>[A-Za-z_$][\w$<>.]*)\s*\(|"
    r"(?:val|var)\s+(?P<kt_name>[A-Za-z_$][\w$]*)\s*(?::\s*(?P<kt_type>[A-Za-z_$][\w$<>.]*))?\s*=\s*(?P<kt_ctor>[A-Za-z_$][\w$<>.]*)\s*\()",
    re.M,
)
METHOD_CALL_RE = re.compile(r"(?<![.@\w])(?:this\.)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
CLASS_RE = re.compile(r"\b(?:class|object)\s+(?P<name>[A-Za-z_$][\w$]*)")
METHOD_RE = re.compile(
    r"(?P<annotation>@JavascriptInterface\s*)?(?:public|protected|private|internal|static|final|synchronized|open|override|\s)+"
    r"(?P<ret>[\w.$<>\[\]?]+)\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)",
    re.M,
)
KOTLIN_METHOD_RE = re.compile(
    r"(?P<annotation>@JavascriptInterface\s*)?(?:public|private|protected|internal|open|override|suspend|\s)*"
    r"fun\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)(?:\s*:\s*(?P<ret>[\w.$<>?]+))?",
    re.M,
)
NATIVE_RE = re.compile(
    r"\b(?:public|private|protected|static|final|synchronized|\s)*native\s+(?P<ret>[\w.$<>\[\]]+)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)", re.M,
)
KOTLIN_NATIVE_RE = re.compile(r"\bexternal\s+fun\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)")
LOAD_LIB_RE = re.compile(r"System\.loadLibrary\s*\(\s*[\"'](?P<name>[^\"']+)[\"']\s*\)")
REGISTER_NATIVE_RE = re.compile(r"RegisterNatives|JNINativeMethod")
JNI_EXPORT_RE = re.compile(r"^Java_(?P<class>.+)_(?P<method>[^_]+)$")
JS_SOURCE_RE = re.compile(r"(?i)(location\.(?:href|search|hash)|document\.(?:URL|referrer|cookie)|window\.name|event\.data|localStorage|sessionStorage|postMessage)")


def _iter_source_files(root: Path, suffixes: set[str], max_files: int = 20000) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            break
        if path.is_file() and path.suffix.lower() in suffixes and path.stat().st_size <= 10_000_000:
            count += 1
            yield path


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def _method_calls(text: str, start: int, max_chars: int = 50000) -> list[str]:
    """Recover direct calls from a bounded Java/Kotlin method body."""
    open_brace = text.find("{", start, min(len(text), start + 2000))
    if open_brace < 0:
        return []
    depth, end = 0, min(len(text), open_brace + max_chars)
    for index in range(open_brace, end):
        char = text[index]
        if char == "{": depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    body = text[open_brace:end]
    ignored = {"if", "for", "while", "switch", "catch", "return", "throw", "new", "super", "this"}
    return sorted({m.group("name") for m in METHOD_CALL_RE.finditer(body) if m.group("name") not in ignored})


def collect_mobile_bridges(root: str | Path) -> dict:
    root = Path(root)
    java_methods, native_decls, bridges, libraries = [], [], [], set()
    source_files = list(_iter_source_files(root, {".java", ".kt", ".smali", ".js", ".ts", ".jsx", ".tsx"}))
    class_by_file = {}
    for path in source_files:
        text = _read(path)
        class_match = CLASS_RE.search(text)
        class_name = class_match.group("name") if class_match else path.stem
        class_by_file[str(path)] = class_name
        instances = {}
        for instance in INSTANCE_CLASS_RE.finditer(text):
            groups = instance.groupdict()
            name = groups.get("java_name") or groups.get("kt_name") or ""
            cls = groups.get("java_ctor") or groups.get("java_class") or groups.get("kt_type") or groups.get("kt_ctor") or ""
            if name and cls:
                instances[name] = cls.split(".")[-1].split("<", 1)[0]
        for match in BRIDGE_RE.finditer(text):
            instance_name = match.group("instance").split(".")[-1]
            bridges.append({"file": str(path), "instance": match.group("instance"), "object": match.group("object"),
                            "class": instances.get(instance_name, class_name),
                            "class_resolution": "constructor_or_type" if instance_name in instances else "enclosing_class_fallback"})
        for rx in (METHOD_RE, KOTLIN_METHOD_RE):
            for match in rx.finditer(text):
                if match.groupdict().get("annotation"):
                    java_methods.append({
                        "file": str(path), "class": class_name, "method": match.group("name"),
                        "params": match.groupdict().get("params") or "", "return_type": match.groupdict().get("ret") or "",
                        "javascript_interface": True, "calls": _method_calls(text, match.end()),
                    })
        for rx in (NATIVE_RE, KOTLIN_NATIVE_RE):
            for match in rx.finditer(text):
                native_decls.append({
                    "file": str(path), "class": class_name, "method": match.group("name"),
                    "params": match.groupdict().get("params") or "", "return_type": match.groupdict().get("ret") or "",
                })
        libraries.update(m.group("name") for m in LOAD_LIB_RE.finditer(text))
    return {
        "root": str(root), "bridges": bridges, "javascript_methods": java_methods,
        "native_declarations": native_decls, "loaded_libraries": sorted(libraries),
        "source_files": len(source_files),
    }




def _call_arguments(text: str, opening_paren: int, max_chars: int = 20000) -> str:
    """Return one bounded JavaScript call argument expression.

    This is a lexical helper, not a full JavaScript parser. It handles balanced
    parentheses and quoted/template strings well enough to preserve argument
    evidence without claiming semantic proof.
    """
    depth = 0
    quote = ""
    escaped = False
    end = min(len(text), opening_paren + max_chars)
    for index in range(opening_paren, end):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[opening_paren + 1:index]
    return text[opening_paren + 1:end]

def collect_js_calls(paths: Iterable[str | Path]) -> list[dict]:
    calls = []
    for raw in paths:
        path = Path(raw)
        if not path.is_file() or path.stat().st_size > 10_000_000:
            continue
        text = _read(path)
        for match in JS_CALL_RE.finditer(text):
            opening = text.find("(", match.start(), match.end() + 1)
            arguments = _call_arguments(text, opening) if opening >= 0 else ""
            source_markers = sorted({m.group(1) for m in JS_SOURCE_RE.finditer(arguments)})
            calls.append({
                "file": str(path), "object": match.group("object"), "method": match.group("method"),
                "line": text.count("\n", 0, match.start()) + 1,
                "arguments": arguments[:10000], "source_markers": source_markers,
                "attacker_controlled_argument": bool(source_markers),
            })
    return calls


def collect_native_functions(ir_documents: Iterable[dict]) -> list[dict]:
    rows = []
    for ir in ir_documents:
        artifact = str((ir.get("artifact") or {}).get("path") or "")
        for fn in ir.get("functions", []):
            if not isinstance(fn, dict):
                continue
            name = str(fn.get("name") or "")
            export = JNI_EXPORT_RE.match(name)
            rows.append({
                "artifact": artifact, "name": name, "start": fn.get("start", ""),
                "jni_export": bool(export), "jni_class": export.group("class") if export else "",
                "jni_method": export.group("method") if export else "",
                "calls": fn.get("calls", []), "pcode": fn.get("pcode", []),
                "register_natives_hint": bool(REGISTER_NATIVE_RE.search(fn.get("decompiled_c", ""))),
            })
    return rows


def correlate(bridge_inventory: dict, js_calls: list[dict], native_functions: list[dict], taint_flows: list[dict] | None = None) -> dict:
    paths = []
    bridge_objects = {str(row.get("object")): row for row in bridge_inventory.get("bridges", [])}
    js_methods = {(str(row.get("class")), str(row.get("method"))): row for row in bridge_inventory.get("javascript_methods", [])}
    native_decls = {(str(row.get("class")), str(row.get("method"))): row for row in bridge_inventory.get("native_declarations", [])}
    native_by_method = {}
    for row in native_functions:
        native_by_method.setdefault(str(row.get("jni_method") or row.get("name") or ""), []).append(row)
    sink_by_function = {}
    for flow in taint_flows or []:
        for fn_name in flow.get("call_path", []):
            sink_by_function.setdefault(str(fn_name), []).append(flow)
    for call in js_calls:
        bridge = bridge_objects.get(str(call.get("object")))
        if not bridge:
            continue
        bridge_class = str(bridge.get("class") or "")
        candidates = [row for (cls, method), row in js_methods.items()
                      if method == call.get("method") and (not bridge_class or cls == bridge_class)]
        if not candidates:
            candidates = [row for (_cls, method), row in js_methods.items() if method == call.get("method")]
        for java_method in candidates:
            base = {
                "javascript": call, "bridge": bridge, "java_method": java_method,
                "confidence": "medium", "uncertainty": ["Java instance-to-class resolution is name-based"],
            }
            direct_calls = set(java_method.get("calls") or [])
            native_candidates = [row for (cls, method), row in native_decls.items()
                                 if cls == java_method.get("class") and
                                 (method == java_method.get("method") or method in direct_calls)]
            if not native_candidates:
                paths.append({**base, "path": [
                    f"JS {call.get('object')}.{call.get('method')}",
                    f"@JavascriptInterface {java_method.get('class')}.{java_method.get('method')}"
                ], "native_reached": False, "confirmation_state": "bridge_supported"})
                continue
            for declaration in native_candidates:
                declaration_class = str(declaration.get("class") or "")
                method_matches = native_by_method.get(str(declaration.get("method")), [])
                native_matches = [row for row in method_matches if not row.get("jni_class") or
                                  str(row.get("jni_class")).endswith(declaration_class)]
                class_resolution = "jni_export_class_and_method" if native_matches else ""
                if not native_matches:
                    native_matches = [row for row in native_functions if row.get("register_natives_hint") and
                                      str(declaration.get("method")) in str(row.get("name"))]
                    if native_matches:
                        class_resolution = "register_natives_name_hint"
                if not native_matches:
                    paths.append({**base, "native_declaration": declaration, "path": [
                        f"JS {call.get('object')}.{call.get('method')}",
                        f"Java {java_method.get('class')}.{java_method.get('method')}",
                        f"native {declaration.get('method')}"
                    ], "native_reached": False, "confirmation_state": "jni_declaration_supported",
                    "uncertainty": base["uncertainty"] + ["No JNI export/RegisterNatives match found"]})
                    continue
                for native in native_matches:
                    sinks = sink_by_function.get(str(native.get("name")), [])
                    paths.append({**base, "native_declaration": declaration, "native_function": native,
                                  "native_resolution": class_resolution,
                                  "javascript_source_markers": call.get("source_markers", []),
                                  "attacker_controlled_argument": bool(call.get("attacker_controlled_argument")),
                                  "native_sinks": sinks, "native_reached": True,
                                  "path": [
                                      f"JS {call.get('object')}.{call.get('method')}",
                                      f"Java {java_method.get('class')}.{java_method.get('method')}",
                                      f"JNI {native.get('name')}"
                                  ] + ([str(s.get("sink")) for s in sinks] if sinks else []),
                                  "confirmation_state": "cross_language_taint_path_supported" if
                                      call.get("attacker_controlled_argument") and sinks else "cross_language_static_path_supported"})
    return {
        "schema": "tbhm.cross-language-flow/1.0", "paths": paths,
        "counts": {
            "js_calls": len(js_calls), "bridge_objects": len(bridge_objects),
            "javascript_methods": len(js_methods), "native_declarations": len(native_decls),
            "native_functions": len(native_functions), "correlated_paths": len(paths),
        },
        "limitations": [
            "Reflection, obfuscation, dynamic RegisterNatives tables, and runtime-created bridge names may require manual resolution.",
            "A static bridge chain does not prove that untrusted web content can invoke it.",
        ],
    }


def save(result: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
