# TBHM v3.9.2 IDAPython static export. Run through IDA batch mode.
import json, os, sys
import ida_auto, ida_funcs, ida_nalt, idaapi, idautils, idc

ida_auto.auto_wait()
out_path = None
for arg in idc.ARGV[1:]:
    if arg.startswith("--out="):
        out_path = arg.split("=", 1)[1]
if not out_path:
    out_path = os.environ.get("TBHM_IDA_OUT", "tbhm_ida_export.json")
functions = []
for ea in idautils.Functions():
    calls = []
    for item in idautils.FuncItems(ea):
        for ref in idautils.CodeRefsFrom(item, False):
            fn = ida_funcs.get_func(ref)
            if fn:
                calls.append(idc.get_func_name(fn.start_ea))
    functions.append({"name": idc.get_func_name(ea), "address": hex(ea), "calls": sorted(set(calls))})
imports = []
for index in range(ida_nalt.get_import_module_qty()):
    module = ida_nalt.get_import_module_name(index) or ""
    def cb(ea, name, ordinal):
        imports.append({"module": module, "name": name or str(ordinal), "address": hex(ea)})
        return True
    ida_nalt.enum_import_names(index, cb)
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump({"tool": "ida", "input": idaapi.get_input_file_path(), "functions": functions, "imports": imports}, handle, indent=2)
idc.qexit(0)
