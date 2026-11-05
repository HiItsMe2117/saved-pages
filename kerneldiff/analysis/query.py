#!/usr/bin/env python3
"""
Query the IOGPUFamily analysis knowledge base.
Usage:
  .venv/bin/python3 query.py <search_term>
  .venv/bin/python3 query.py --sel <N>          # disassembly for selector N
  .venv/bin/python3 query.py --func <name>       # exact function detail
  .venv/bin/python3 query.py --strings <pattern> # grep strings
  .venv/bin/python3 query.py --meta              # summary / sel table
"""
import json, sys, re, os, fnmatch

BASE = os.path.dirname(__file__)

def load(name):
    p = os.path.join(BASE, name)
    if not os.path.exists(p):
        print(f"[!] {p} not found — run analyze_iogpu.py first"); sys.exit(1)
    with open(p) as f: return json.load(f)

def grep_funcs(pattern, funcs):
    pat = pattern.lower()
    return [f for f in funcs if pat in f["name"].lower()]

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)

    funcs   = load("iogpufamily_functions.json")
    strings = load("iogpufamily_strings.json")
    detail  = load("iogpufamily_detail.json")
    meta    = load("iogpufamily_meta.json")

    if args[0] == "--meta":
        print(f"Functions : {meta['func_count']}")
        print(f"Strings   : {meta['string_count']}")
        print(f"\nexternalMethod matches:")
        for m in meta["ext_method_matches"]:
            print(f"  {m['name']:60s} @ {m['offset']}")
        print(f"\nlsl #12 hits (page-count multiply candidates):")
        for h in meta["lsl12_hits"][:20]:
            print(f"  {h}")
        print(f"\nSelector table disasm (first 30 lines each):")
        for name, lines in meta["sel_table_disasm"].items():
            print(f"\n  [{name}]")
            for l in lines[:30]: print(f"    {l}")
        return

    if args[0] == "--strings":
        pat = args[1].lower() if len(args) > 1 else ""
        for s in strings:
            if pat in s["value"].lower():
                print(f"  {s['offset']}  {s['value']}")
        return

    if args[0] == "--func":
        name = args[1]
        # exact or substring match in detail
        hits = {k: v for k, v in detail.items() if name.lower() in k.lower()}
        if not hits:
            # fall back to function list
            hits2 = grep_funcs(name, funcs)
            for f in hits2[:10]: print(json.dumps(f, indent=2))
        else:
            for k, v in hits.items():
                print(f"\n{'='*70}")
                print(f"  {k}  @ {v['offset']}  ({v['size']} bytes)")
                print(v["disasm"])
        return

    if args[0] == "--sel":
        # Find the Nth selector handler from the table
        sel_n = int(args[1])
        print(f"[*] Looking for selector {sel_n} handler...")
        # The selector table entries are 32-byte structs (IOExternalMethodDispatch2022):
        # offset 0: fn ptr (8), offset 8: scalar_in (4), offset 12: scalar_out (4),
        # offset 16: struct_in_sz (8), offset 24: struct_out_sz (8)
        # Look for externalMethod disasm and find the table base, then calculate entry
        for name, lines in meta["sel_table_disasm"].items():
            print(f"\n  [{name}]")
            for l in lines: print(f"    {l}")
        return

    # Default: keyword search across function names
    term = args[0]
    hits = grep_funcs(term, funcs)
    print(f"[*] Functions matching '{term}': {len(hits)}")
    for f in hits[:30]:
        in_detail = "  [disasm available]" if f["name"] in detail else ""
        print(f"  {f['offset']}  {f['size']:6d}B  {f['name']}{in_detail}")

if __name__ == "__main__":
    main()
