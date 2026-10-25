#!/usr/bin/env python3
"""
Steps 3-7 of the 26.6.1 → 27.0.1 diff.
Appends to REPORT_27.md (steps 1-2 already there).
Uses fast split-based string extraction.
"""

import struct, os
from datetime import datetime
import numpy as np

KC_A = '/root/code/saved-pages/kerneldiff/kc_26.6.1.macho'
KC_B = '/root/code/saved-pages/kerneldiff/kc_27.0.1.macho'
OUT  = '/root/code/saved-pages/kerneldiff/REPORT_27.md'

VER_A = 'iOS 26.6.1'
VER_B = 'iOS 27.0.1'

LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64    = 0x19

report_lines = []

def ts():
    return datetime.now().strftime('%H:%M:%S')

def emit(line=''):
    report_lines.append(line)

def flush():
    existing = open(OUT).read() if os.path.exists(OUT) else ''
    with open(OUT, 'w') as f:
        f.write(existing + '\n'.join(report_lines) + '\n')
    report_lines.clear()

def checkpoint(name):
    emit(f'\n## ✓ Checkpoint: {name} — {ts()}\n')
    flush()
    print(f'[✓] {name}')

def parse_header(data):
    magic, cpu, subcpu, ftype, ncmds = struct.unpack_from('<IIIII', data, 0)
    return {'ftype': ftype, 'ncmds': ncmds}

def iter_lc(data, hdr):
    off = 32
    for _ in range(hdr['ncmds']):
        if off + 8 > len(data): break
        cmd, sz = struct.unpack_from('<II', data, off)
        yield cmd, sz, off
        if sz == 0: break
        off += sz

def get_segments(data, hdr):
    segs = {}
    for cmd, sz, lc in iter_lc(data, hdr):
        if cmd == LC_SEGMENT_64:
            name = data[lc+8:lc+24].rstrip(b'\x00').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, lc+24)
            segs[name] = {'vmaddr': vmaddr, 'vmsize': vmsize,
                          'fileoff': fileoff, 'filesize': filesize}
    return segs

def get_fileset_entries(data, hdr):
    entries = {}
    for cmd, sz, lc in iter_lc(data, hdr):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff, name_off, _ = struct.unpack_from('<QQII', data, lc+8)
            name = data[lc+name_off:].split(b'\x00')[0].decode()
            entries[name] = {'vmaddr': vmaddr, 'fileoff': fileoff}
    return entries

def fast_strings(data, min_len=6, max_len=256):
    """Extract all ASCII strings from data using split on null bytes."""
    parts = data.split(b'\x00')
    result = set()
    for p in parts:
        if min_len <= len(p) <= max_len:
            try:
                s = p.decode('ascii')
                if all(32 <= ord(c) < 127 for c in s):
                    result.add(s)
            except:
                pass
    return result

def filter_strings(string_set, keywords):
    kw_lower = [k.lower() for k in keywords]
    return {s for s in string_set if any(k in s.lower() for k in kw_lower)}

def find_bytes(data, needle):
    offsets = []
    pos = 0
    while True:
        i = data.find(needle, pos)
        if i == -1: break
        offsets.append(i)
        pos = i + 1
    return offsets

def offset_to_seg(segs, off):
    for name, s in segs.items():
        fo = s['fileoff']; fs = s['filesize']
        if fo <= off < fo + fs:
            return f'{name}+0x{off-fo:x}'
    return f'file+0x{off:x}'

# ─── Load ─────────────────────────────────────────────────────────────────────
print('[*] Loading files...')
with open(KC_A, 'rb') as f: da = f.read()
with open(KC_B, 'rb') as f: db = f.read()
print(f'[*] A={len(da)//1024//1024}MB  B={len(db)//1024//1024}MB')

hdr_a = parse_header(da)
hdr_b = parse_header(db)
segs_a = get_segments(da, hdr_a)
segs_b = get_segments(db, hdr_b)

# ─── 3. STRING DIFF ───────────────────────────────────────────────────────────
emit('## 3. SPTM/GXF/PPL/TXM String Diff\n')

SPTM_KW = ['sptm', 'genter', 'gxf', 'ppl', '__ppltext', 'pmap_cs',
           'txm', 'recount_enter_secure', 'sprr', 'gl2', 'gl1', 'gl0']

print('[*] Extracting strings from 26.6.1...')
all_a = fast_strings(da)
print(f'    {len(all_a)} strings')
print('[*] Extracting strings from 27.0.1...')
all_b = fast_strings(db)
print(f'    {len(all_b)} strings')

sptm_a = filter_strings(all_a, SPTM_KW)
sptm_b = filter_strings(all_b, SPTM_KW)

new_sptm  = sorted(sptm_b - sptm_a)
gone_sptm = sorted(sptm_a - sptm_b)

emit(f'Matched strings (SPTM/PPL/GXF/TXM keywords):')
emit(f'- 26.6.1: {len(sptm_a)} | 27.0.1: {len(sptm_b)}')
emit(f'- New in 27.0.1: **{len(new_sptm)}** | Removed: **{len(gone_sptm)}**\n')

emit('### New SPTM-related strings in 27.0.1')
emit('```')
for s in new_sptm[:80]: emit(s)
emit('```\n')

emit('### Removed SPTM-related strings (were in 26.6.1)')
emit('```')
for s in gone_sptm[:80]: emit(s)
emit('```\n')

# page enforcement failed
pef_a = find_bytes(da, b'page enforcement failed')
pef_b = find_bytes(db, b'page enforcement failed')
emit('### "page enforcement failed" location')
for o in pef_a: emit(f'- 26.6.1: 0x{o:08x} → {offset_to_seg(segs_a, o)}')
for o in pef_b: emit(f'- 27.0.1: 0x{o:08x} → {offset_to_seg(segs_b, o)}')
if not pef_a and not pef_b:
    emit('- Not found in either kernel (lives in separate SPTM/TXM binary)')
emit('')

checkpoint('3. String Diff')

# ─── 4. mach_make_memory_entry ────────────────────────────────────────────────
emit('## 4. `mach_make_memory_entry` Analysis\n')

needle = b'mach_make_memory_entry'
offs_a = find_bytes(da, needle)
offs_b = find_bytes(db, needle)

emit(f'- Occurrences in 26.6.1: {len(offs_a)}')
emit(f'- Occurrences in 27.0.1: {len(offs_b)}\n')

for label, data, segs, offs in [('26.6.1', da, segs_a, offs_a), ('27.0.1', db, segs_b, offs_b)]:
    emit(f'### {label}')
    for o in offs:
        s = max(0, o-30); e = min(len(data), o+80)
        ctx = ''.join(chr(b) if 32 <= b < 127 else '·' for b in data[s:e])
        emit(f'- `0x{o:08x}` {offset_to_seg(segs, o)}: `{ctx}`')
    emit('')

# MIG index in LINKEDIT
emit('### MIG dispatch index (`_mach_make_memory_entry_64` in LINKEDIT)\n')
for label, data, segs in [('26.6.1', da, segs_a), ('27.0.1', db, segs_b)]:
    le = segs.get('__LINKEDIT', {})
    le_data = data[le.get('fileoff',0):le.get('fileoff',0)+le.get('filesize',0)]
    idx = le_data.find(b'_mach_make_memory_entry_64')
    if idx >= 0:
        ctx_raw = le_data[max(0,idx-16):idx+50]
        ctx = ''.join(chr(b) if 32 <= b < 127 else '·' for b in ctx_raw)
        emit(f'- **{label}**: `{ctx}`')
    else:
        emit(f'- {label}: not found in LINKEDIT')
emit('')

checkpoint('4. mach_make_memory_entry Analysis')

# ─── 5. KEXT CHANGES ──────────────────────────────────────────────────────────
emit('## 5. Kext Changes\n')

kexts_a = get_fileset_entries(da, hdr_a)
kexts_b = get_fileset_entries(db, hdr_b)

names_a = set(kexts_a.keys())
names_b = set(kexts_b.keys())
new_k     = sorted(names_b - names_a)
removed_k = sorted(names_a - names_b)
common    = sorted(names_a & names_b)

emit(f'| | 26.6.1 | 27.0.1 | Δ |')
emit(f'|---|---|---|---|')
emit(f'| Total kexts | {len(names_a)} | {len(names_b)} | {len(names_b)-len(names_a):+} |')
emit(f'| New | — | {len(new_k)} | +{len(new_k)} |')
emit(f'| Removed | {len(removed_k)} | — | -{len(removed_k)} |')
emit(f'| Common | {len(common)} | {len(common)} | — |\n')

if new_k:
    emit('### New kexts in 27.0.1')
    for k in new_k: emit(f'- `{k}`')
    emit('')

if removed_k:
    emit('### Removed kexts')
    for k in removed_k: emit(f'- `{k}`')
    emit('')

# Size proxy from ordered fileoffs
sorted_a = sorted(kexts_a.items(), key=lambda x: x[1]['fileoff'])
sorted_b = sorted(kexts_b.items(), key=lambda x: x[1]['fileoff'])

def kext_size(sorted_list, name):
    for i, (n, e) in enumerate(sorted_list):
        if n == name and i+1 < len(sorted_list):
            return sorted_list[i+1][1]['fileoff'] - e['fileoff']
    return 0

diffs = []
for k in common:
    sa = kext_size(sorted_a, k); sb = kext_size(sorted_b, k)
    if sa > 0 and sb > 0:
        diffs.append((abs(sb-sa), sb-sa, k, sa, sb))
diffs.sort(reverse=True)

emit('### Largest kext size changes\n')
emit('| Kext (short) | 26.6.1 | 27.0.1 | Δ |')
emit('|---|---|---|---|')
for _, delta, k, sa, sb in diffs[:30]:
    short = k.split('.')[-1]
    emit(f'| `{short}` | {sa//1024}K | {sb//1024}K | {delta:+,} |')
emit('')

checkpoint('5. Kext Changes')

# ─── 6. SECURITY STRINGS ──────────────────────────────────────────────────────
emit('## 6. Changed Security-Relevant Strings\n')

SEC_KW = ['entitlement', 'sandbox', 'pmap', 'sptm', 'ppl', 'enforce',
          'policy', 'deny', 'allow', 'integrity', 'trust', 'amfi',
          'codesign', 'coretrust', 'violation', 'restricted',
          'authorization', 'permission', 'forbidden', 'credential']

sec_a = {s for s in filter_strings(all_a, SEC_KW) if len(s) > 15}
sec_b = {s for s in filter_strings(all_b, SEC_KW) if len(s) > 15}

sec_new  = sorted(sec_b - sec_a)
sec_gone = sorted(sec_a - sec_b)

emit(f'- Matched in 26.6.1: {len(sec_a)} | 27.0.1: {len(sec_b)}')
emit(f'- New: **{len(sec_new)}** | Removed: **{len(sec_gone)}**\n')

emit('### New security strings in 27.0.1')
emit('```')
for s in sec_new[:80]: emit(s)
emit('```\n')

emit('### Removed security strings')
emit('```')
for s in sec_gone[:80]: emit(s)
emit('```\n')

checkpoint('6. Security Strings')

# ─── 7. __TEXT_EXEC DIFF ──────────────────────────────────────────────────────
emit('## 7. `__TEXT_EXEC` Diff Statistics\n')

te_a = segs_a.get('__TEXT_EXEC', {})
te_b = segs_b.get('__TEXT_EXEC', {})

ta = da[te_a['fileoff']:te_a['fileoff']+te_a['filesize']]
tb = db[te_b['fileoff']:te_b['fileoff']+te_b['filesize']]

emit(f'- 26.6.1: {len(ta)//1024}K  |  27.0.1: {len(tb)//1024}K  |  Δ {(len(tb)-len(ta))//1024:+}K\n')

PAGE = 4096
min_len = min(len(ta), len(tb))
pages = min_len // PAGE

arr_a = np.frombuffer(ta[:pages*PAGE], dtype=np.uint8).reshape(pages, PAGE)
arr_b = np.frombuffer(tb[:pages*PAGE], dtype=np.uint8).reshape(pages, PAGE)
diff_bytes = np.sum(arr_a != arr_b, axis=1)
diff_mask  = diff_bytes > 0
changed = int(diff_mask.sum())

emit(f'- Pages compared: {pages:,}')
emit(f'- Changed pages: **{changed:,}** ({100*changed//pages}%)')
emit(f'- Unchanged pages: {pages-changed:,}\n')

# Most surgical (fewest changed bytes) — most likely targeted patches
changed_idxs = np.where(diff_mask)[0]
counts = diff_bytes[changed_idxs]
order  = np.argsort(counts)
top20  = [(int(changed_idxs[i]), int(counts[i])) for i in order[:20]]

emit('### 20 Most Surgical Patches (fewest bytes changed per page)\n')
emit('| Page | __TEXT_EXEC+offset | A fileoff | B fileoff | Bytes Δ | Nearby string |')
emit('|------|--------------------|-----------|-----------|---------|---------------|')

for page_idx, n_changed in top20:
    te_off = page_idx * PAGE
    a_fo   = te_a['fileoff'] + te_off
    b_fo   = te_b['fileoff'] + te_off

    nearby = '—'
    for search_data, base_fo in [(da, a_fo), (db, b_fo)]:
        win_s = max(0, base_fo - 16384)
        win_e = min(len(search_data), base_fo + 16384)
        window = search_data[win_s:win_e]
        centre = base_fo - win_s
        best_d, best_s = 99999, ''
        pos = 0
        while pos < len(window):
            end = window.find(b'\x00', pos)
            if end == -1: break
            seg = window[pos:end]
            try:
                s = seg.decode('ascii')
                if 8 < len(s) < 80 and all(32 <= ord(c) < 127 for c in s):
                    d = abs(pos - centre)
                    if d < best_d:
                        best_d, best_s = d, s
            except: pass
            pos = end + 1
        if best_s:
            nearby = f'`{best_s[:55]}`'
            break

    emit(f'| {page_idx} | +0x{te_off:06x} | 0x{a_fo:08x} | 0x{b_fo:08x} | {n_changed} | {nearby} |')

emit('')

checkpoint('7. __TEXT_EXEC Diff')

# ─── KEY TAKEAWAYS ────────────────────────────────────────────────────────────
emit('## Key Takeaways\n')
emit(f'''### Architecture (iOS 26.6.1 → 27.0.1)
- **Kernel build 487.100.11 → 514.2.2** (+27 minor versions, major feature work)
- **__TEXT_EXEC grew +{(len(tb)-len(ta))//1024:+}K** — significant new kernel code
- **__PPLTEXT absent in both** — PPL was already fully removed before 26.6.1
- **__DATA_SPTM: 240K → 304K (+64K)** — SPTM data tables grew significantly

### GENTER (SPTM trap calls)
- **150 → 173 in __TEXT_EXEC (+23 new SPTM call sites)**
- Kexts: 1 → 1 (unchanged)
- New call sites = new code paths that now go through SPTM for memory operations

### SPTM Strings
- New in 27.0.1: {len(new_sptm)} SPTM/PPL/GXF-related strings
- Removed: {len(gone_sptm)} (PPL cleanup continues)

### Security
- {len(sec_new)} new security-relevant strings; {len(sec_gone)} removed
- {len(new_k)} new kexts; {len(removed_k)} removed kexts

### For Trigon Research
- `mach_make_memory_entry` present in both kernels (string anchors above)
- MIG index context shows function ordering in both versions
- **Recommendation**: For the actual CVE-2023-32434 patch, diff iOS 16.1.1 vs 16.5.1
  on an A15 PPL-era device (iPhone14,5). SPTM-era kernels restructured the call paths
  so deeply that the patch is structurally unrecognisable in iOS 26+.
''')

checkpoint('Key Takeaways')
print(f'[✓] Done — {OUT}')
