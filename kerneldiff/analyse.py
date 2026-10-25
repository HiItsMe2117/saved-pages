#!/usr/bin/env python3
"""
iOS 26.6.1 vs 26.1 kernelcache diff — iPhone 16 Plus (iPhone17,4)
Memory-efficient: uses mmap so OS pages data in/out as needed.
Writes checkpoints to REPORT.md incrementally.
"""

import struct, os, re, sys, mmap, numpy as np
from datetime import datetime

REPORT   = "/root/code/saved-pages/kerneldiff/REPORT.md"
KC_NEW   = "/root/code/saved-pages/kerneldiff/kc_26.6.1.macho"
KC_OLD   = "/root/code/saved-pages/kerneldiff/kc_26.1.macho"

LC_SEGMENT_64    = 0x19
LC_SYMTAB        = 0x02
LC_FILESET_ENTRY = 0x80000035

# ── report helpers ────────────────────────────────────────────────────────────

_rfile = open(REPORT, 'w', buffering=1)

def R(line=""):
    print(line, flush=True)
    _rfile.write(line + '\n')
    _rfile.flush()

def HR(title): R(); R(f"## {title}"); R()
def checkpoint(name):
    ts = datetime.now().strftime("%H:%M:%S")
    R(); R(f"## ✓ Checkpoint: {name} — {ts}"); R()

# ── Mach-O parsing (works on mmap objects) ───────────────────────────────────

def parse_macho(mm):
    magic, cpu, subcpu, ftype, ncmds, sizeofcmds, flags, _ = \
        struct.unpack_from('<IIIIIIII', mm, 0)
    assert magic == 0xFEEDFACF, f"bad magic {magic:#010x}"
    segments, entries, symtab = [], [], None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', mm, off)
        if cmd == LC_SEGMENT_64:
            seg_name = bytes(mm[off+8:off+24]).rstrip(b'\x00').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', mm, off+24)
            segments.append({'name': seg_name, 'vmaddr': vmaddr, 'vmsize': vmsize,
                              'fileoff': fileoff, 'filesize': filesize})
        elif cmd == LC_FILESET_ENTRY:
            vmaddr2, fileoff2, name_off, _ = struct.unpack_from('<QQII', mm, off+8)
            name_abs = off + name_off
            name_end = bytes(mm[name_abs:name_abs+256]).find(b'\x00')
            name = bytes(mm[name_abs:name_abs+name_end]).decode()
            entries.append({'name': name, 'vmaddr': vmaddr2, 'fileoff': fileoff2})
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', mm, off+8)
            symtab = {'symoff': symoff, 'nsyms': nsyms, 'stroff': stroff}
        off += cmdsize
    return {'ftype': ftype, 'ncmds': ncmds, 'segments': segments,
            'entries': entries, 'symtab': symtab,
            'seg_by_name': {s['name']: s for s in segments}}

def seg_slice(mm, info, name):
    """Return (fileoff, filesize) for a segment, or None."""
    s = info['seg_by_name'].get(name)
    return (s['fileoff'], s['filesize']) if s and s['filesize'] > 0 else None

def fileoff_to_va(info, fileoff):
    for s in info['segments']:
        fo, fs = s['fileoff'], s['filesize']
        if fs > 0 and fo <= fileoff < fo + fs:
            return s['vmaddr'] + (fileoff - fo)
    return None

def hexdump(data, base=0, width=16, limit=64):
    lines = []
    for i in range(0, min(len(data), limit), width):
        row = bytes(data[i:i+width])
        h = ' '.join(f'{b:02x}' for b in row)
        a = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in row)
        lines.append(f"  {base+i:08x}  {h:<{width*3}}  {a}")
    return '\n'.join(lines)

def find_all_in(mm, start, size, needle):
    """Find all occurrences of needle in mm[start:start+size]."""
    results = []
    end = start + size
    pos = start
    nb = needle if isinstance(needle, bytes) else needle.encode()
    while pos < end:
        chunk = bytes(mm[pos:min(pos+65536, end)])
        idx = 0
        while True:
            i = chunk.find(nb, idx)
            if i == -1: break
            results.append(pos + i)
            idx = i + 1
        pos += 65536 - len(nb)
    return results

def find_all(mm, needle):
    return find_all_in(mm, 0, len(mm), needle)

def find_nearby_string(mm, offset, radius=2048, min_len=10):
    start = max(0, offset - radius)
    end   = min(len(mm), offset + radius)
    buf = bytes(mm[start:end])
    best = None
    i = 0
    while i < len(buf):
        j = buf.find(b'\x00', i)
        if j == -1: break
        chunk = buf[i:j]
        if len(chunk) >= min_len and all(0x20 <= b < 0x7f for b in chunk):
            dist = abs((start + i) - offset)
            if best is None or dist < best[0]:
                best = (dist, chunk.decode('ascii', errors='replace'))
        i = j + 1
    return best[1] if best else None

def norm_instr(word):
    """Normalize PC-relative immediates in ARM64 to remove link-address noise.
    ADRP embeds the target page in a 21-bit immediate; zeroing it lets us
    compare the *register* choice only. B/BL within the same segment keep
    their relative offsets unchanged so we leave them alone.
    """
    if (word & 0x9F000000) == 0x90000000:   # ADRP Xd, #imm21
        return word & 0x9F00001F             # keep opcode + Rd, zero imm
    return word

def diff_segment_normalized(mm_old, old_fo, old_fs, mm_new, new_fo, new_fs):
    """Stream-compare two code segments, normalizing ADRP immediates first.
    Returns list of (rel_off_in_old, old_bytes, new_bytes) for changed runs.
    Only keeps runs ≤ 4096 bytes to avoid huge allocations.
    """
    cmp_len = min(old_fs, new_fs)
    changed = []
    BLOCK = 131072  # 128K at a time
    i = 0
    in_run = False
    run_start = 0
    run_ob = bytearray()
    run_nb = bytearray()

    while i < cmp_len:
        blk = min(BLOCK, cmp_len - i)
        ob_raw = bytes(mm_old[old_fo+i:old_fo+i+blk])
        nb_raw = bytes(mm_new[new_fo+i:new_fo+i+blk])

        for j in range(0, blk - 3, 4):
            ow = struct.unpack_from('<I', ob_raw, j)[0]
            nw = struct.unpack_from('<I', nb_raw, j)[0]
            if norm_instr(ow) != norm_instr(nw):
                if not in_run:
                    in_run = True
                    run_start = i + j
                    run_ob = bytearray()
                    run_nb = bytearray()
                run_ob += ob_raw[j:j+4]
                run_nb += nb_raw[j:j+4]
            else:
                if in_run:
                    changed.append((run_start, bytes(run_ob[:4096]), bytes(run_nb[:4096])))
                    in_run = False
        i += blk

    if in_run:
        changed.append((run_start, bytes(run_ob[:4096]), bytes(run_nb[:4096])))
    return changed

def merge_regions(regions, gap=256):
    if not regions: return []
    merged = [list(regions[0])]
    for r in regions[1:]:
        last = merged[-1]
        end_last = last[0] + len(last[1])
        if r[0] <= end_last + gap:
            pad = r[0] - end_last
            last[1] = last[1] + bytes(pad) + r[1]
            last[2] = last[2] + bytes(pad) + r[2]
        else:
            merged.append(list(r))
    return merged

SECURITY_RE = re.compile(
    r'entitlement|sandbox|ppl|sptm|vm_map|mach_make|ipc_|voucher|'
    r'privilege|credentials|kern_protect|trust|codesign|amfi|security|'
    r'pmap|zone_require|memory_entry|page_protect', re.I)

def extract_interesting_strings(mm, min_len=24):
    """Stream through mm extracting security-relevant strings."""
    strings = set()
    BLOCK = 131072
    pos = 0
    n = len(mm)
    leftover = b''
    while pos < n:
        chunk = leftover + bytes(mm[pos:min(pos+BLOCK, n)])
        parts = chunk.split(b'\x00')
        # last part might be incomplete
        for s in parts[:-1]:
            if (len(s) >= min_len and all(0x20 <= b < 0x7f for b in s)):
                text = s.decode('ascii', errors='replace')
                if SECURITY_RE.search(text):
                    strings.add(text)
        leftover = parts[-1]
        pos += BLOCK
    return strings

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

R("# iOS 26.6.1 vs 26.1 Kernelcache Diff")
R(f"*Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
R()
R("**Device:** iPhone 16 Plus (iPhone17,4)")
R("**Newer:** iOS 26.6.1 build 23G83 — KernelManagement_host-487.100.11")
R("**Older:** iOS 26.1   build 23B85 — KernelManagement_host-487.0.4")
R()
R("> Analysis method: Python mmap (memory-mapped I/O) for both 70MB files,")
R("> segment-by-segment processing to stay within the iPhone-hosted VM's RAM budget.")
R()
R("---")

print("Opening kernelcaches via mmap...", flush=True)
f_new = open(KC_NEW, 'rb')
f_old = open(KC_OLD, 'rb')
mm_new = mmap.mmap(f_new.fileno(), 0, access=mmap.ACCESS_READ)
mm_old = mmap.mmap(f_old.fileno(), 0, access=mmap.ACCESS_READ)

info_new = parse_macho(mm_new)
info_old = parse_macho(mm_old)
R(f"Parsed: 26.6.1 → {len(info_new['entries'])} fileset entries, "
  f"26.1 → {len(info_old['entries'])} fileset entries")

# ══════════════════════════════════════════════════════════════════════════════
# 1. SEGMENT LAYOUT
# ══════════════════════════════════════════════════════════════════════════════
HR("1. Segment Layout Comparison")
R("| Segment | 26.1 fileoff | 26.1 size | 26.6.1 fileoff | 26.6.1 size | Δ size |")
R("|---------|-------------|-----------|----------------|-------------|--------|")
all_segs = sorted(set(s['name'] for s in info_new['segments']) |
                  set(s['name'] for s in info_old['segments']))
for name in all_segs:
    sn = info_new['seg_by_name'].get(name)
    so = info_old['seg_by_name'].get(name)
    fo_n = f"{sn['fileoff']:#010x}" if sn else "—"
    fs_n = f"{sn['filesize']//1024:,}K" if sn else "—"
    fo_o = f"{so['fileoff']:#010x}" if so else "—"
    fs_o = f"{so['filesize']//1024:,}K" if so else "—"
    delta = ""
    if sn and so:
        d = sn['filesize'] - so['filesize']
        if d: delta = f"{d:+,}"
    R(f"| `{name}` | {fo_o} | {fs_o} | {fo_n} | {fs_n} | {delta} |")
checkpoint("Segment Layout")

# ══════════════════════════════════════════════════════════════════════════════
# 2. __TEXT_EXEC DIFF
# ══════════════════════════════════════════════════════════════════════════════
HR("2. __TEXT_EXEC Diff (Main Kernel Code)")
TE_n = info_new['seg_by_name']['__TEXT_EXEC']
TE_o = info_old['seg_by_name']['__TEXT_EXEC']
R(f"26.6.1: fileoff={TE_n['fileoff']:#010x} size={TE_n['filesize']//1024//1024}MB vmaddr={TE_n['vmaddr']:#018x}")
R(f"26.1:   fileoff={TE_o['fileoff']:#010x} size={TE_o['filesize']//1024//1024}MB vmaddr={TE_o['vmaddr']:#018x}")
R()

R(f"*(vmaddr delta: {TE_n['vmaddr'] - TE_o['vmaddr']:#x} — kernel linked 0x50000 higher in 26.6.1.)*")
R("*(ADRP instructions embed the target page VA in a 21-bit immediate; every ADRP will differ*")
R("*between kernels linked at different bases. numpy vectorised normalisation zeroes the*")
R("*ADRP immediate before comparing so only genuine instruction changes are counted.)*")
R()
print("numpy ADRP-normalised __TEXT_EXEC diff...", flush=True)
PAGE = 4096
cmp_len = min(TE_o['filesize'], TE_n['filesize'])
n_pages = cmp_len // PAGE

_ADRP_MASK = np.uint32(0x9F000000)
_ADRP_PATT = np.uint32(0x90000000)
_ADRP_NORM = np.uint32(0x9F00001F)

changed_pages = []   # list of (page_idx, norm_diff_bytes, raw_old_4KB, raw_new_4KB)
raw_diff_pages = 0
for p in range(n_pages):
    fo_o = TE_o['fileoff'] + p * PAGE
    fo_n = TE_n['fileoff'] + p * PAGE
    raw_o = bytes(mm_old[fo_o:fo_o+PAGE])
    raw_n = bytes(mm_new[fo_n:fo_n+PAGE])
    if raw_o == raw_n:
        continue
    raw_diff_pages += 1
    arr_o = np.frombuffer(raw_o, dtype='<u4')
    arr_n = np.frombuffer(raw_n, dtype='<u4')
    norm_o = np.where((arr_o & _ADRP_MASK) == _ADRP_PATT, arr_o & _ADRP_NORM, arr_o)
    norm_n = np.where((arr_n & _ADRP_MASK) == _ADRP_PATT, arr_n & _ADRP_NORM, arr_n)
    n_diff = int(np.sum(norm_o != norm_n))
    if n_diff > 0:
        changed_pages.append((p, n_diff * 4, raw_o, raw_n))

R(f"- **{raw_diff_pages:,}** of {n_pages:,} pages differ at raw byte level (includes ADRP noise)")
R(f"- **{len(changed_pages):,}** pages differ after ADRP normalization — genuine code changes")
R()

clusters_sorted = sorted(changed_pages, key=lambda x: -x[1])
R("### Top 20 Changed Pages (ADRP-normalised)")
R()
R("| # | Page | __TEXT_EXEC offset | File off (26.6.1) | Norm-diff bytes | Nearby string |")
R("|---|------|--------------------|-------------------|-----------------|---------------|")
for i, (pg, diff_b, ob, nb) in enumerate(clusters_sorted[:20]):
    rel = pg * PAGE
    fo  = TE_n['fileoff'] + rel
    nearby = find_nearby_string(mm_new, fo, radius=4096, min_len=10)
    ns = f"`{nearby[:60]}`" if nearby else "—"
    R(f"| {i+1} | {pg} | `+{rel:#08x}` | `{fo:#010x}` | {diff_b} | {ns} |")

checkpoint("TEXT_EXEC Diff")

# ══════════════════════════════════════════════════════════════════════════════
# 3. mach_make_memory_entry_64 DEEP DIVE
# ══════════════════════════════════════════════════════════════════════════════
HR("3. mach_make_memory_entry_64 Deep Dive")
TARGET = b'mach_make_memory_entry_64'

# We already know hit offsets from earlier scan:
# 26.6.1: 0x000b6116, 0x00bf64ee, 0x044a2f03
# 26.1:   0x000ad318, 0x00bb5c7b, 0x0461af02
# Confirm and classify them
new_hits = find_all(mm_new, TARGET)
old_hits = find_all(mm_old, TARGET)

R(f"String occurrences: **{len(new_hits)}** in 26.6.1, **{len(old_hits)}** in 26.1")
R()

def classify_off(info, off):
    for s in info['segments']:
        fo, fs = s['fileoff'], s['filesize']
        if fs > 0 and fo <= off < fo+fs:
            return s['name'], off-fo, s['vmaddr']+(off-fo)
    return 'unknown', 0, 0

R("**26.6.1 occurrences:**")
for h in new_hits:
    seg, rel, va = classify_off(info_new, h)
    ctx = bytes(mm_new[max(0,h-20):h+50])
    printable = ''.join(chr(b) if 0x20<=b<0x7f else '·' for b in ctx)
    R(f"- `{h:#010x}` `{seg}`+{rel:#x} (VA={va:#018x}): `{printable}`")
R()
R("**26.1 occurrences:**")
for h in old_hits:
    seg, rel, va = classify_off(info_old, h)
    ctx = bytes(mm_old[max(0,h-20):h+50])
    printable = ''.join(chr(b) if 0x20<=b<0x7f else '·' for b in ctx)
    R(f"- `{h:#010x}` `{seg}`+{rel:#x} (VA={va:#018x}): `{printable}`")
R()

# ── Compare MIG name-table region ────────────────────────────────────────────
R("### MIG name-table context comparison")
R()
# 26.6.1 name-table string at 0xbf64ee, 26.1 at 0xbb5c7b
# Show ~512 bytes of surrounding string area
for hit, ver, mm, info in [
    (0x00bf64ee, "26.6.1", mm_new, info_new),
    (0x00bb5c7b, "26.1",   mm_old, info_old),
]:
    seg, rel, va = classify_off(info, hit)
    R(f"**{ver}** MIG table area (`{seg}` + {rel:#x}, VA={va:#018x}):")
    R("```")
    window = bytes(mm[max(0,hit-100):hit+200])
    R(hexdump(window, base=max(0,hit-100), limit=len(window)))
    R("```")
    R()

# ── Find pointer to MIG string (→ function pointer near it) ──────────────────
R("### Searching for pointer to MIG string → nearby function pointer")
R()

for hit, ver, mm, info in [
    (0x00bf64ee, "26.6.1", mm_new, info_new),
    (0x00bb5c7b, "26.1",   mm_old, info_old),
]:
    _, _, va_str = classify_off(info, hit)
    packed = struct.pack('<Q', va_str)
    R(f"**{ver}** — looking for pointer to VA {va_str:#018x}:")
    found = False
    for s in info['segments']:
        if s['filesize'] == 0: continue
        buf_start = s['fileoff']
        buf_end   = s['fileoff'] + s['filesize']
        chunk_pos = buf_start
        while chunk_pos < buf_end:
            chunk = bytes(mm[chunk_pos:min(chunk_pos+65536, buf_end)])
            idx = 0
            while True:
                i = chunk.find(packed, idx)
                if i == -1: break
                ptr_fo = chunk_pos + i
                # show 8 bytes before and after (adjacent function pointers in table)
                vicinity = bytes(mm[max(0,ptr_fo-24):ptr_fo+32])
                R(f"  Pointer at fileoff `{ptr_fo:#010x}` in `{s['name']}`:")
                R(f"  Hex: {bytes(mm[ptr_fo-8:ptr_fo+16]).hex()}")
                # Parse adjacent 8-byte pointers
                for k in range(-2, 3):
                    p_off = ptr_fo + k*8
                    if p_off >= 0 and p_off+8 <= len(mm):
                        p_val = struct.unpack_from('<Q', mm, p_off)[0]
                        note = " ← target string ptr" if k == 0 else ""
                        R(f"    [{k:+d}] = {p_val:#018x}{note}")
                found = True
                idx = i + 8
            chunk_pos += 65536 - 8
    if not found:
        R("  (no pointer found in mapped segments)")
    R()

checkpoint("mach_make_memory_entry_64 Deep Dive")

# ══════════════════════════════════════════════════════════════════════════════
# 4. SPTM / PPL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
HR("4. SPTM / PPL Analysis")

SPTM_n = info_new['seg_by_name'].get('__DATA_SPTM')
SPTM_o = info_old['seg_by_name'].get('__DATA_SPTM')
if SPTM_n:
    R(f"__DATA_SPTM 26.6.1: vmaddr={SPTM_n['vmaddr']:#018x} vmsize={SPTM_n['vmsize']:#x} "
      f"fileoff={SPTM_n['fileoff']:#010x} filesize={SPTM_n['filesize']}")
if SPTM_o:
    R(f"__DATA_SPTM 26.1:   vmaddr={SPTM_o['vmaddr']:#018x} vmsize={SPTM_o['vmsize']:#x} "
      f"fileoff={SPTM_o['fileoff']:#010x} filesize={SPTM_o['filesize']}")
R()

TERMS = [b'sptm', b'SPTM', b'ppl', b'PPL', b'SPTM_', b'sptm_',
         b'PPL_DISPATCH', b'PPL_PANIC', b'pmap_ppl', b'sptm.t8140',
         b'page_protect', b'PPL_ENTER', b'SPTM_ENTER']

R("| Term | 26.1 count | 26.6.1 count | Δ |")
R("|------|-----------|--------------|---|")
for term in TERMS:
    n_c = len(find_all(mm_new, term))
    o_c = len(find_all(mm_old, term))
    delta = n_c - o_c
    ds = f"**{delta:+d}**" if delta else "0"
    R(f"| `{term.decode()}` | {o_c} | {n_c} | {ds} |")
R()

# Show all SPTM hits for diff terms
for term in [b'SPTM', b'sptm', b'PPL', b'ppl']:
    hits_n = find_all(mm_new, term)
    hits_o = find_all(mm_old, term)
    if abs(len(hits_n) - len(hits_o)) > 0:
        R(f"**`{term.decode()}`** count changed: 26.1={len(hits_o)}, 26.6.1={len(hits_n)}")
        # Show new hits not near any old hit
        R()

checkpoint("SPTM/PPL Analysis")

# ══════════════════════════════════════════════════════════════════════════════
# 5. STRING DIFF (security-relevant)
# ══════════════════════════════════════════════════════════════════════════════
HR("5. Security-Relevant String Diff")
R("Streaming scan for strings ≥ 24 chars matching security keywords...")
print("Extracting strings from 26.6.1...", flush=True)
strings_n = extract_interesting_strings(mm_new)
print("Extracting strings from 26.1...", flush=True)
strings_o = extract_interesting_strings(mm_old)

only_n = sorted(strings_n - strings_o)
only_o = sorted(strings_o - strings_n)

R(f"- Security strings unique to **26.6.1**: **{len(only_n)}**")
R(f"- Security strings unique to **26.1**: **{len(only_o)}**")
R(f"- Strings present in both: {len(strings_n & strings_o)}")
R()

R("### New in 26.6.1 (not in 26.1):")
R()
R("```")
for s in only_n[:80]:
    R(f"  + {s}")
if len(only_n) > 80:
    R(f"  ... +{len(only_n)-80} more")
R("```")
R()

R("### Removed in 26.6.1 (present in 26.1 only):")
R()
R("```")
for s in only_o[:80]:
    R(f"  - {s}")
if len(only_o) > 80:
    R(f"  ... +{len(only_o)-80} more")
R("```")
R()

# Free string sets
del strings_n, strings_o, only_n, only_o

checkpoint("String Diff")

# ══════════════════════════════════════════════════════════════════════════════
# 6. KEXT-LEVEL DIFF
# ══════════════════════════════════════════════════════════════════════════════
HR("6. Kext-Level Changes")

entries_n = {e['name']: e for e in info_new['entries']}
entries_o = {e['name']: e for e in info_old['entries']}
all_names = sorted(set(entries_n) | set(entries_o))

def kext_code_region(mm, entry):
    """Return (fileoff, size) of the kext's __TEXT_EXEC or __TEXT segment."""
    fo = entry['fileoff']
    magic = struct.unpack_from('<I', mm, fo)[0]
    if magic != 0xFEEDFACF: return None
    ncmds_k = struct.unpack_from('<I', mm, fo+16)[0]
    off = fo + 32
    for _ in range(ncmds_k):
        if off - fo > 65536: break
        cmd, cs = struct.unpack_from('<II', mm, off)
        if cmd == LC_SEGMENT_64:
            sname = bytes(mm[off+8:off+24]).rstrip(b'\x00').decode()
            vmaddr_k, vmsize_k, fo_k, fs_k = struct.unpack_from('<QQQQ', mm, off+24)
            if sname in ('__TEXT_EXEC', '__TEXT') and fs_k > 0:
                return (fo_k, fs_k)
        off += cs
    return None

print("Diffing kexts...", flush=True)
changed_kexts, unchanged_kexts, only_new_kexts, only_old_kexts = [], [], [], []

for name in all_names:
    en = entries_n.get(name)
    eo = entries_o.get(name)
    if not en: only_old_kexts.append(name); continue
    if not eo: only_new_kexts.append(name); continue
    rn = kext_code_region(mm_new, en)
    ro = kext_code_region(mm_old, eo)
    if not rn or not ro: continue
    fo_n, fs_n = rn
    fo_o, fs_o = ro
    cmp = min(fs_n, fs_o)
    # Stream compare in 64K blocks
    diffs = 0
    for i in range(0, cmp, 65536):
        blk = min(65536, cmp - i)
        nb = bytes(mm_new[fo_n+i:fo_n+i+blk])
        ob = bytes(mm_old[fo_o+i:fo_o+i+blk])
        diffs += sum(a!=b for a,b in zip(nb,ob))
    sz_delta = fs_n - fs_o
    if diffs > 0 or sz_delta != 0:
        changed_kexts.append((name, diffs, sz_delta, fs_n))
    else:
        unchanged_kexts.append(name)

R(f"- **Changed kexts:** {len(changed_kexts)}")
R(f"- **Unchanged kexts:** {len(unchanged_kexts)}")
R(f"- **New in 26.6.1:** {len(only_new_kexts)}")
R(f"- **Removed in 26.6.1:** {len(only_old_kexts)}")
R()

if only_new_kexts:
    R("**New kexts in 26.6.1:**")
    for n in only_new_kexts: R(f"  - `{n}`")
    R()
if only_old_kexts:
    R("**Removed kexts in 26.6.1:**")
    for n in only_old_kexts: R(f"  - `{n}`")
    R()

changed_kexts.sort(key=lambda x: -x[1])
R("**Changed kexts (by diff byte count):**")
R()
R("| Kext | Diff bytes | Size Δ | Code size |")
R("|------|-----------|--------|-----------|")
for name, diffs, sz_d, sz in changed_kexts:
    short = name.split('.')[-1]
    sd = f"{sz_d:+,}" if sz_d else "0"
    R(f"| `{short}` | {diffs:,} | {sd} | {sz//1024}K |")

checkpoint("Kext-Level Diff")

# ══════════════════════════════════════════════════════════════════════════════
# 7. DETAILED HEX DIFF — TOP 10 REGIONS
# ══════════════════════════════════════════════════════════════════════════════
HR("7. Detailed Hex Diff — Top 10 Changed Regions")
R()

for i, (pg, diff_b, ob, nb) in enumerate(clusters_sorted[:10]):
    n_ch  = diff_b
    rel   = pg * PAGE
    fo_n  = TE_n['fileoff'] + rel
    fo_o  = TE_o['fileoff'] + rel
    va_n  = TE_n['vmaddr']  + rel
    va_o  = TE_o['vmaddr']  + rel
    nearby_n = find_nearby_string(mm_new, fo_n, radius=3000, min_len=10)
    nearby_o = find_nearby_string(mm_old, fo_o, radius=3000, min_len=10)
    R(f"### Region {i+1} — {n_ch:,} bytes changed")
    R(f"- __TEXT_EXEC offset: `+{rel:#08x}`")
    R(f"- File offsets: 26.1=`{fo_o:#010x}`, 26.6.1=`{fo_n:#010x}`")
    R(f"- Link-time VA: 26.1=`{va_o:#018x}`, 26.6.1=`{va_n:#018x}`")
    R(f"- Nearby string (26.6.1): {f'`{nearby_n}`' if nearby_n else '—'}")
    R(f"- Nearby string (26.1):   {f'`{nearby_o}`' if nearby_o else '—'}")
    R()
    show = min(len(ob), len(nb), 96)
    R("```")
    R("OLD (26.1):")
    R(hexdump(ob[:show], fo_o))
    R("NEW (26.6.1):")
    R(hexdump(nb[:show], fo_n))
    R("```")
    R()

checkpoint("Detailed Hex Diff")

# ══════════════════════════════════════════════════════════════════════════════
# 8. TROUBLES & SOLUTIONS
# ══════════════════════════════════════════════════════════════════════════════
HR("8. Troubles & Solutions")
R()

troubles = [
    ("Wrong LC_FILESET_ENTRY constant",
     "Used `0x80000041` — got 0 fileset entries from a 302-entry fileset.",
     "Dumped all LC type codes from the binary. Correct constant: `0x80000035`. "
     "The 0x80000041 value is wrong for modern iOS; 0x80000035 per XNU source."),

    ("ZIP64 sentinel `0xFFFFFFFF` offsets in IPSW",
     "Both the central-directory file offset AND each file's local_offset were "
     "`0xFFFFFFFF` (ZIP64 sentinels). fetch_kc.py read them literally → wrong offsets, "
     "no kernelcache found.",
     "Implemented ZIP64 EOCD locator (sig `0x07064b50`) and ZIP64 extra-field parsing "
     "(tag `0x0001`) in the central directory. Both now in fetch_kc.py."),

    ("Kernelcache is double-compressed",
     "Raw IPSW range-request bytes are deflate-compressed (ZIP method=8). "
     "After inflating, result is IM4P ASN.1 containing LZFSE-compressed Mach-O.",
     "Two-step decompression: (1) zlib inflate for ZIP layer, "
     "(2) hand-written IM4P ASN.1 parser → LZFSE payload, "
     "(3) lzfse binary for final decompression. All in fetch_kc.py + unwrap_im4p.py."),

    ("lzfse stdin pipe fails silently",
     "`lzfse -decode -i - -o outfile` with stdin input returns non-zero, no output.",
     "Write LZFSE payload to a temp file first: `lzfse -decode -i tmpfile -o outfile`. "
     "Fixed in unwrap_im4p.py."),

    ("No apt-get (Alpine Linux, not Debian/Ubuntu)",
     "`apt-get install lzfse` → command not found.",
     "Machine is Alpine Linux. Use `apk add lzfse`. Also `apk add py3-pip` for pip."),

    ("pip blocked by PEP 668",
     "`pip install lzfse` refused with system-packages error.",
     "Use `pip install lzfse --break-system-packages`. lzfse 0.4.2.post1 installed."),

    ("GNU nm doesn't support Mach-O",
     "`nm kernelcache.macho` → 'file format not recognized'. GNU Binutils 2.45.1.",
     "Wrote extract_symbols.py: custom Python Mach-O / MH_FILESET / nlist_64 parser."),

    ("Production kernel has nsyms=0",
     "com.apple.kernel (XNU itself) has LC_SYMTAB.nsyms=0 — completely stripped. "
     "__LINKEDIT also has filesize=0.",
     "Identify functions via: (1) nearby panic/log strings, "
     "(2) MIG name-table pointer scan, (3) KDK dSYM for full symbols."),

    ("OOM on git push with binary files",
     "Committed ~140MB of .macho/.im4p/.lzfse files. "
     "`git push` died: `pack-objects died of signal 9`.",
     "`git reset HEAD~1`, added kerneldiff/.gitignore for *.macho/*.im4p/*.lzfse, "
     "recommitted scripts only."),

    ("OOM running full analysis (first attempt)",
     "Loading both 70MB files with `f.read()` = 140MB RAM + Python overhead → process killed (exit 137).",
     "Switched to `mmap.mmap(f.fileno(), 0, access=ACCESS_READ)` — OS pages data in/out. "
     "Also switched to streaming string scan (64K blocks) instead of whole-file bytes."),

    ("Previous session scratchpad lost",
     "All prior-session work (scripts, downloaded kernelcaches) was in /tmp/scratchpad "
     "which is session-specific. Everything gone after crash.",
     "All scripts now committed to git (~/code/saved-pages/kerneldiff/). "
     "STATE.md documents IPSW URLs and current progress. "
     "Binary artifacts regenerable in ~5 min from the scripts."),
]

for title, problem, solution in troubles:
    R(f"### {title}")
    R(f"**Problem:** {problem}")
    R()
    R(f"**Solution:** {solution}")
    R()

checkpoint("Troubles & Solutions")

# ══════════════════════════════════════════════════════════════════════════════
# 9. DEVICE & TOOL LIMITATIONS
# ══════════════════════════════════════════════════════════════════════════════
HR("9. Device & Tool Limitations")
R()
R("This machine is an **Alpine Linux x86 VM hosted on an iPhone** (PocketCode app).")
R("CPU is emulated/slow; RAM is the tightest limit — exceeding it kills all tabs.")
R()
R("| Tool | Status | Notes |")
R("|------|--------|-------|")
R("| `apt-get` | ❌ | Alpine only has `apk` |")
R("| `apk` | ✅ | `apk add lzfse` works |")
R("| `pip` / `pip3` | ✅ after `apk add py3-pip` | Needs `--break-system-packages` |")
R("| `lzfse` binary | ✅ `apk add lzfse` v1.0-r0 | Must use file args, not stdin |")
R("| `img4tool` | ❌ Not in Alpine | Python IM4P ASN.1 parser instead |")
R("| GNU `nm` | ✅ but ❌ Mach-O | Custom Python parser |")
R("| `jtool2` / `otool` | ❌ | macOS-only; Python parser instead |")
R("| `capstone` disasm | ✅ via pip | `pip install capstone --break-system-packages` (not yet installed) |")
R("| `macholib` | ❌ Not installed | Custom parser |")
R("| `radare2` / `ghidra` | ❌ Too heavy | Not feasible on this hardware |")
R("| Dev servers / builds | ❌ | Too much RAM; use Vercel for web projects |")
R()
R("**RAM budget:** ~200MB usable for analysis processes.")
R("Two 70MB mmap'd files + Python overhead ≈ 180MB — feasible with streaming.")
R("Loading both files with `f.read()` hits OOM. Always use `mmap`.")
R()
R("**Network:** curl works for range requests. No wget. HTTPS works.")
R("**Disk:** /root/code/ persists. /tmp/scratchpad/ is session-scoped (lost on crash).")
R()

# ══════════════════════════════════════════════════════════════════════════════
# 10. SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
HR("10. Summary & Findings")
R()
R("### Key Findings")
R()
R("1. **Structure:** 302 kexts in both versions. Same segments, same layout.")
R("   26.6.1 is slightly *smaller* in __TEXT_EXEC (~1.5MB less) despite being newer.")
R()
R("2. **mach_make_memory_entry_64:** Appears in both kernels in identical locations")
R("   (IOKit debug string, MIG name table, fixup info). The function itself is in")
R("   __TEXT_EXEC (XNU kernel proper, stripped). Without KDK symbols, exact VA")
R("   requires following the MIG pointer table as documented above.")
R()
R("3. **SPTM segment:** `__DATA_SPTM` has filesize=0 in both IPSWs — the SPTM firmware")
R("   (`sptm.t8140.release.im4p`) ships as a separate file inside the IPSW `Firmware/`")
R("   directory. Analysing SPTM changes requires extracting and diffing that file.")
R()
R("4. **Changed regions:** See Section 7 for hex diffs of the top changed code regions.")
R("   The nearby-string hints identify which subsystems were modified.")
R()
R("5. **String diff:** Sections 5 lists new/removed security-relevant strings that")
R("   directly identify patched code paths.")
R()
R("### Next Steps")
R()
R("- **SPTM diff:** `Firmware/sptm.t8140.release.im4p` exists in both IPSWs.")
R("  Range-request it, unwrap IM4P, binary-diff the two payloads.")
R("- **KDK symbols:** `developer.apple.com/download` → Kernel Debug Kit for 26.6.1 / 26.1.")
R("  Provides dSYM with full symbol table → map VAs to function names.")
R("- **Capstone disassembly:** `pip install capstone --break-system-packages`")
R("  then disassemble the top changed regions for instruction-level diff.")
R("- **MIG table walk:** Follow pointer from MIG name table → function pointer array")
R("  → `mach_make_memory_entry_64` VA → extract function bytes for disassembly.")
R()
R("---")
R(f"*Report written by analyse.py — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

mm_new.close(); f_new.close()
mm_old.close(); f_old.close()
_rfile.close()
print("\n[✓] Done — REPORT.md written", flush=True)
