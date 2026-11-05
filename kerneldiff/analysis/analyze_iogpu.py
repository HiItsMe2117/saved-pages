#!/usr/bin/env python3
"""
IOGPUFamily binary analysis — builds queryable JSON knowledge base.
Run on Mac: .venv/bin/python3 analyze_iogpu.py
Output: analysis/iogpufamily_functions.json + analysis/iogpufamily_strings.json
"""
import r2pipe, json, re, sys, os

BINARY = os.path.join(os.path.dirname(__file__), "kexts/com.apple.iokit.IOGPUFamily")
OUT_DIR = os.path.dirname(__file__)

print(f"[*] Opening {BINARY}")
r2 = r2pipe.open(BINARY, flags=["-2"])  # -2 silences stderr

print("[*] Analyzing (aa) ...")
r2.cmd("aa")

# ── 1. All functions ──────────────────────────────────────────────────────────
print("[*] Listing functions ...")
funcs_raw = r2.cmdj("aflj") or []
print(f"    {len(funcs_raw)} functions found")

functions = []
for f in funcs_raw:
    functions.append({
        "name":   f.get("name", ""),
        "offset": hex(f.get("offset", 0)),
        "size":   f.get("size", 0),
        "calls":  f.get("callrefs", []),
    })

# ── 2. Strings ────────────────────────────────────────────────────────────────
print("[*] Extracting strings ...")
strings_raw = r2.cmdj("izj") or []
strings = [{"offset": hex(s.get("vaddr", 0)), "value": s.get("string", "")}
           for s in strings_raw if len(s.get("string", "")) >= 4]
print(f"    {len(strings)} strings found")

# ── 3. Selector dispatch table — find externalMethod ─────────────────────────
print("[*] Locating AGXDeviceUserClient::externalMethod ...")
ext_matches = [f for f in functions if "externalMethod" in f["name"] or
               "ExternalMethod" in f["name"]]
for m in ext_matches:
    print(f"    {m['name']} @ {m['offset']}")

# ── 4. Per-function disassembly for key targets ───────────────────────────────
# Key targets: externalMethod handlers + anything referencing 0x1000 (page size)
key_names = [
    "externalMethod", "newResource", "newBuffer", "allocat",
    "setPageCount", "mapPage", "populatePage", "bitmap",
]

detailed = {}
print("[*] Disassembling key functions ...")
for f in funcs_raw:
    name = f.get("name", "")
    if any(k.lower() in name.lower() for k in key_names):
        offset = f.get("offset", 0)
        disasm = r2.cmd(f"pdf @ {hex(offset)}")
        detailed[name] = {
            "offset": hex(offset),
            "size":   f.get("size", 0),
            "disasm": disasm,
        }
        print(f"    captured: {name} @ {hex(offset)} ({f.get('size',0)} bytes)")

# ── 5. Cross-refs to 0x1000 (page size constant) ─────────────────────────────
print("[*] Searching for page-size (0x1000) references ...")
page_hits = r2.cmd("/x 0010000000000000") or ""  # little-endian 0x1000 as u64
page_xrefs = []
for line in page_hits.strip().splitlines():
    line = line.strip()
    if line.startswith("0x"):
        page_xrefs.append(line)

# ── 6. Search for size-check patterns (cmp + branch near mul/lsl) ─────────────
print("[*] Searching for 'mul' / 'lsl #12' instructions (page-count multiply) ...")
lsl12 = r2.cmd("/ad lsl") or ""
mul_hits = []
for line in lsl12.strip().splitlines():
    if "lsl" in line and ("#0xc" in line or "#12" in line or "lsl #0xc" in line):
        mul_hits.append(line.strip())

# ── 7. Look for the IOGPUFamily selector table directly ──────────────────────
print("[*] Searching for selector table (IOExternalMethodDispatch2022 array) ...")
# The table is an array of {function_ptr (8 bytes), scalar_in, scalar_out,
# struct_in_sz, struct_out_sz} structs. We look for the pattern near externalMethod.
sel_table = {}
for f in funcs_raw:
    name = f.get("name", "")
    if "externalMethod" in name.lower() and "AGX" in name:
        offset = f.get("offset", 0)
        # Disassemble and look for adr/adrp loading a table address
        disasm_lines = r2.cmd(f"pdf @ {hex(offset)}").splitlines()
        sel_table[name] = disasm_lines[:80]  # first 80 lines

# ── Save outputs ──────────────────────────────────────────────────────────────
out_funcs   = os.path.join(OUT_DIR, "iogpufamily_functions.json")
out_strings = os.path.join(OUT_DIR, "iogpufamily_strings.json")
out_detail  = os.path.join(OUT_DIR, "iogpufamily_detail.json")
out_meta    = os.path.join(OUT_DIR, "iogpufamily_meta.json")

with open(out_funcs,   "w") as f: json.dump(functions,  f, indent=2)
with open(out_strings, "w") as f: json.dump(strings,    f, indent=2)
with open(out_detail,  "w") as f: json.dump(detailed,   f, indent=2)
with open(out_meta,    "w") as f: json.dump({
    "binary":      BINARY,
    "func_count":  len(functions),
    "string_count": len(strings),
    "ext_method_matches": ext_matches,
    "page_size_xrefs": page_xrefs[:50],
    "lsl12_hits":  mul_hits[:50],
    "sel_table_disasm": sel_table,
}, f, indent=2)

print(f"\n[+] Done.")
print(f"    {out_funcs}")
print(f"    {out_strings}")
print(f"    {out_detail}")
print(f"    {out_meta}")
r2.quit()
