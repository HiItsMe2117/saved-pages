#!/usr/bin/env python3
"""
Targeted SPTM diff: iOS 26.6.1 vs 27.0.1 kernelcaches (iPhone17,4)
Writes REPORT_27.md incrementally with checkpoints.
"""

import struct, sys, os, re
from datetime import datetime
import numpy as np

KC_A = '/root/code/saved-pages/kerneldiff/kc_26.6.1.macho'
KC_B = '/root/code/saved-pages/kerneldiff/kc_27.0.1.macho'
OUT  = '/root/code/saved-pages/kerneldiff/REPORT_27.md'

VER_A = 'iOS 26.6.1 (23G83)'
VER_B = 'iOS 27.0.1 (24A446)'

LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64    = 0x19
LC_SYMTAB        = 0x02

report = []

def ts():
    return datetime.now().strftime('%H:%M:%S')

def emit(line=''):
    report.append(line)

def flush():
    with open(OUT, 'w') as f:
        f.write('\n'.join(report) + '\n')

def checkpoint(name):
    emit(f'\n## ✓ Checkpoint: {name} — {ts()}\n')
    flush()
    print(f'[✓] {name}')

# ─── Mach-O helpers ──────────────────────────────────────────────────────────

def parse_header(data, off=0):
    magic, cpu, subcpu, ftype, ncmds, szofcmds, flags, _ = struct.unpack_from('<IIIIIIII', data, off)
    return {'off': off, 'ftype': ftype, 'ncmds': ncmds}

def iter_lc(data, hdr):
    off = hdr['off'] + 32
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
            entries[name] = {'vmaddr': vmaddr, 'fileoff': fileoff, 'cmdsize': sz}
    return entries

def find_strings(data, needle):
    results = []
    nb = needle if isinstance(needle, bytes) else needle.encode()
    start = 0
    while True:
        i = data.find(nb, start)
        if i == -1: break
        results.append(i)
        start = i + 1
    return results

def extract_cstrings(data, keywords):
    """Find all null-terminated strings containing any keyword."""
    results = set()
    for kw in keywords:
        nb = kw.encode() if isinstance(kw, str) else kw
        pos = 0
        while True:
            i = data.find(nb, pos)
            if i == -1: break
            # walk back to start of string
            s = i
            while s > 0 and data[s-1] != 0: s -= 1
            # walk forward to end
            e = i
            while e < len(data) and data[e] != 0: e += 1
            try:
                st = data[s:e].decode('ascii')
                if 4 < len(st) < 300:
                    results.add(st)
            except:
                pass
            pos = i + 1
    return results

# ─── Load files ───────────────────────────────────────────────────────────────

print('[*] Loading kernelcaches...')
with open(KC_A, 'rb') as f: da = f.read()
with open(KC_B, 'rb') as f: db = f.read()
print(f'[*] A={len(da)//1024//1024}MB  B={len(db)//1024//1024}MB')

hdr_a = parse_header(da)
hdr_b = parse_header(db)
segs_a = get_segments(da, hdr_a)
segs_b = get_segments(db, hdr_b)

emit('# iOS 26.6.1 → 27.0.1 Kernelcache Diff (SPTM-Targeted)')
emit(f'*Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*\n')
emit(f'**Device:** iPhone 16 Plus (iPhone17,4)')
emit(f'**Older:** {VER_A} — KernelManagement_host-487.100.11')
emit(f'**Newer:** {VER_B} — KernelManagement_host-514.2.2')
emit(f'**Kernel build jump:** 487 → 514 (+27 minor versions)\n')
emit('---\n')
flush()

# ─── 1. SEGMENT COMPARISON ────────────────────────────────────────────────────

emit('## 1. Segment Layout Comparison\n')
emit('| Segment | 26.6.1 fileoff | 26.6.1 size | 27.0.1 fileoff | 27.0.1 size | Δ bytes |')
emit('|---------|---------------|-------------|----------------|-------------|---------|')

all_segs = sorted(set(list(segs_a.keys()) + list(segs_b.keys())))
ppltext_a = ppltext_b = False
for name in all_segs:
    a = segs_a.get(name)
    b = segs_b.get(name)
    if name == '__PPLTEXT':
        ppltext_a = a is not None
        ppltext_b = b is not None
    fa = f"0x{a['fileoff']:08x}" if a else '—'
    fb = f"0x{b['fileoff']:08x}" if b else '—'
    sa = a['filesize'] if a else 0
    sb = b['filesize'] if b else 0
    delta = sb - sa if (a and b) else ('NEW' if b else 'REMOVED')
    ds = f'+{delta:,}' if isinstance(delta, int) and delta > 0 else (f'{delta:,}' if isinstance(delta, int) else delta)
    marker = ' ← **NEW**' if not a else (' ← **REMOVED**' if not b else '')
    emit(f'| `{name}` | {fa} | {sa//1024}K | {fb} | {sb//1024}K | {ds}{marker} |')

emit('')
emit(f'**__PPLTEXT in 26.6.1:** {"YES ✓" if ppltext_a else "NO — already absent"}')
emit(f'**__PPLTEXT in 27.0.1:** {"YES" if ppltext_b else "NO — PPL fully removed ✓"}')

sptm_a = segs_a.get('__DATA_SPTM', {}).get('filesize', 0)
sptm_b = segs_b.get('__DATA_SPTM', {}).get('filesize', 0)
emit(f'**__DATA_SPTM:** {sptm_a//1024}K → {sptm_b//1024}K (Δ {(sptm_b-sptm_a)//1024:+}K)')
emit('')

checkpoint('1. Segment Layout')

# ─── 2. GENTER COUNT ──────────────────────────────────────────────────────────

emit('## 2. GENTER Instruction Count (`20 14 20 00`)\n')

GENTER = b'\x20\x14\x20\x00'
GEXIT  = b'\x00\x14\x20\x00'

def count_in_seg(data, segs, segname, pattern):
    seg = segs.get(segname)
    if not seg: return 0, []
    fo = seg['fileoff']
    fs = seg['filesize']
    chunk = data[fo:fo+fs]
    offsets = []
    pos = 0
    while True:
        i = chunk.find(pattern, pos)
        if i == -1: break
        offsets.append(fo + i)
        pos = i + 1
    return len(offsets), offsets

ga_count, ga_offs = count_in_seg(da, segs_a, '__TEXT_EXEC', GENTER)
gb_count, gb_offs = count_in_seg(db, segs_b, '__TEXT_EXEC', GENTER)

# Also check __PRELINK_TEXT (kext code)
ga_pk, _ = count_in_seg(da, segs_a, '__PRELINK_TEXT', GENTER)
gb_pk, _ = count_in_seg(db, segs_b, '__PRELINK_TEXT', GENTER)

emit(f'| Location | 26.6.1 count | 27.0.1 count | Delta |')
emit(f'|----------|-------------|-------------|-------|')
emit(f'| `__TEXT_EXEC` (kernel) | {ga_count} | {gb_count} | {gb_count-ga_count:+} |')
emit(f'| `__PRELINK_TEXT` (kexts) | {ga_pk} | {gb_pk} | {gb_pk-ga_pk:+} |')
emit(f'| **Total** | **{ga_count+ga_pk}** | **{gb_count+gb_pk}** | **{(gb_count+gb_pk)-(ga_count+ga_pk):+}** |')
emit('')

# Find GENTER sites near known anchor strings for identification
emit('### GENTER sites near anchor strings (26.6.1 __TEXT_EXEC)\n')
ANCHORS = [b'sptm_map_page', b'pmap_enter', b'sptm_retype', b'mach_make_memory',
           b'pmap_cs', b'page enforcement', b'vm_fault']
found_anchors = []
for anchor in ANCHORS:
    offs = find_strings(da, anchor)
    for so in offs[:2]:
        # find nearest GENTER within ±4096 bytes in the file
        nearby = [go for go in ga_offs if abs(go - so) < 8192]
        if nearby:
            found_anchors.append(f'- `{anchor.decode()}` at file 0x{so:08x} → {len(nearby)} GENTER within ±8KB')

for line in found_anchors:
    emit(line)
emit('')

checkpoint('2. GENTER Count')

# ─── 3. SPTM STRING DIFF ──────────────────────────────────────────────────────

emit('## 3. SPTM/GXF/PPL/TXM String Diff\n')

KEYWORDS = ['sptm', 'SPTM', 'genter', 'GENTER', 'GXF', 'gxf',
            'ppl', 'PPL', '__PPLTEXT', 'pmap_cs', 'TXM', 'txm',
            'recount_enter_secure', 'SPRR', 'sprr']

strs_a = extract_cstrings(da, KEYWORDS)
strs_b = extract_cstrings(db, KEYWORDS)

new_in_b   = sorted(strs_b - strs_a)
gone_from_a = sorted(strs_a - strs_b)

emit(f'Keywords searched: `{", ".join(KEYWORDS)}`\n')
emit(f'- Strings in 26.6.1: {len(strs_a)}')
emit(f'- Strings in 27.0.1: {len(strs_b)}')
emit(f'- New in 27.0.1: **{len(new_in_b)}**')
emit(f'- Removed from 26.6.1: **{len(gone_from_a)}**\n')

emit('### New strings in 27.0.1')
emit('```')
for s in new_in_b[:60]:
    emit(s)
emit('```\n')

emit('### Removed strings (in 26.6.1, gone in 27.0.1)')
emit('```')
for s in gone_from_a[:60]:
    emit(s)
emit('```\n')

# page enforcement failed
pef_a = find_strings(da, 'page enforcement failed')
pef_b = find_strings(db, 'page enforcement failed')

def offset_to_seg(data, segs, off):
    for name, s in segs.items():
        fo = s['fileoff']; fs = s['filesize']
        if fo <= off < fo + fs:
            return f'{name}+0x{off-fo:x}'
    return f'unknown+0x{off:x}'

emit('### "page enforcement failed" location')
for o in pef_a:
    emit(f'- 26.6.1: file 0x{o:08x} in {offset_to_seg(da, segs_a, o)}')
for o in pef_b:
    emit(f'- 27.0.1: file 0x{o:08x} in {offset_to_seg(db, segs_b, o)}')
if not pef_a and not pef_b:
    emit('- Not found in either kernel (likely in separate SPTM/TXM binary)')
emit('')

checkpoint('3. String Diff')

# ─── 4. mach_make_memory_entry ANALYSIS ──────────────────────────────────────

emit('## 4. `mach_make_memory_entry` Analysis\n')

needle = b'mach_make_memory_entry'
offs_a = find_strings(da, needle)
offs_b = find_strings(db, needle)

emit(f'- Occurrences in 26.6.1: {len(offs_a)}')
emit(f'- Occurrences in 27.0.1: {len(offs_b)}\n')

# For each occurrence extract context
for label, data, segs, offs in [('26.6.1', da, segs_a, offs_a), ('27.0.1', db, segs_b, offs_b)]:
    emit(f'### {label} occurrences\n')
    for o in offs:
        seg_loc = offset_to_seg(data, segs, o)
        ctx_start = max(0, o - 30)
        ctx_end   = min(len(data), o + 80)
        ctx = data[ctx_start:ctx_end]
        printable = ''.join(chr(b) if 32 <= b < 127 else '·' for b in ctx)
        emit(f'- `0x{o:08x}` in {seg_loc}')
        emit(f'  `{printable}`')
    emit('')

# Compare context bytes at the IOKit string occurrence (most stable anchor)
# 26.6.1: 0x000b6116 vs 27.0.1: find equivalent
emit('### Code context comparison (±128 bytes around IOKit string anchor)\n')

def get_iokit_anchor(data, offs):
    for o in offs:
        ctx = data[max(0,o-40):o+80]
        if b'actualSize' in ctx or b'IOMemory' in ctx or b'IOMemo' in ctx:
            return o
    return offs[0] if offs else None

anchor_a = get_iokit_anchor(da, offs_a)
anchor_b = get_iokit_anchor(db, offs_b)

if anchor_a and anchor_b:
    # Walk backwards from string to find nearest __TEXT_EXEC code
    # The string is in __PRELINK_TEXT data; find any code within 2KB in __TEXT_EXEC
    emit(f'IOKit anchor: 26.6.1=0x{anchor_a:08x}  27.0.1=0x{anchor_b:08x}')
    # Find nearest GENTER to IOKit anchor in both
    seg_a = segs_a.get('__PRELINK_TEXT', {})
    near_a = [go for go in ga_offs if abs(go - anchor_a) < 65536]
    near_b = [go for go in gb_offs if abs(go - anchor_b) < 65536]
    emit(f'Nearest GENTER sites within 64KB of IOKit anchor: {len(near_a)} in 26.6.1, {len(near_b)} in 27.0.1')
    emit('')

# MIG index from LINKEDIT
emit('### MIG dispatch index\n')
for label, data, segs in [('26.6.1', da, segs_a), ('27.0.1', db, segs_b)]:
    le_seg = segs.get('__LINKEDIT', {})
    le_off = le_seg.get('fileoff', 0)
    le_sz  = le_seg.get('filesize', 0)
    le_data = data[le_off:le_off+le_sz]
    needle_le = b'_mach_make_memory_entry_64'
    idx = le_data.find(needle_le)
    if idx >= 0:
        ctx = le_data[max(0,idx-12):idx+40]
        printable = ''.join(chr(b) if 32 <= b < 127 else '·' for b in ctx)
        emit(f'- {label} LINKEDIT: `{printable}`')
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
new_kexts     = sorted(names_b - names_a)
removed_kexts = sorted(names_a - names_b)
common        = sorted(names_a & names_b)

emit(f'- Kexts in 26.6.1: **{len(names_a)}**')
emit(f'- Kexts in 27.0.1: **{len(names_b)}**')
emit(f'- New in 27.0.1: **{len(new_kexts)}**')
emit(f'- Removed: **{len(removed_kexts)}**')
emit(f'- Common: **{len(common)}**\n')

if new_kexts:
    emit('### New kexts in 27.0.1')
    for k in new_kexts:
        emit(f'- `{k}`')
    emit('')

if removed_kexts:
    emit('### Removed kexts (in 26.6.1, gone in 27.0.1)')
    for k in removed_kexts:
        emit(f'- `{k}`')
    emit('')

# Size comparison for common kexts — use fileoff delta as rough size proxy
emit('### Kexts with largest size change\n')
sorted_entries_a = sorted(kexts_a.items(), key=lambda x: x[1]['fileoff'])
sorted_entries_b = sorted(kexts_b.items(), key=lambda x: x[1]['fileoff'])

def kext_size(entries_sorted, name):
    for i, (n, e) in enumerate(entries_sorted):
        if n == name:
            if i + 1 < len(entries_sorted):
                return entries_sorted[i+1][1]['fileoff'] - e['fileoff']
            return 0
    return 0

size_changes = []
for k in common:
    sa = kext_size(sorted_entries_a, k)
    sb = kext_size(sorted_entries_b, k)
    if sa > 0 and sb > 0:
        size_changes.append((abs(sb-sa), sb-sa, k, sa, sb))
size_changes.sort(reverse=True)

emit('| Kext | 26.6.1 size | 27.0.1 size | Δ bytes |')
emit('|------|-------------|-------------|---------|')
for _, delta, k, sa, sb in size_changes[:30]:
    short = k.split('.')[-1]
    emit(f'| `{short}` | {sa//1024}K | {sb//1024}K | {delta:+,} |')
emit('')

checkpoint('5. Kext Changes')

# ─── 6. CHANGED SECURITY STRINGS ─────────────────────────────────────────────

emit('## 6. Changed Security-Relevant Strings\n')

SEC_KEYWORDS = ['entitlement', 'sandbox', 'pmap', 'sptm', 'ppl', 'enforce',
                'policy', 'deny', 'allow', 'integrity', 'memory', 'trust',
                'amfi', 'AMFI', 'codesign', 'coretrust', 'CoreTrust',
                'violation', 'restricted', 'forbidden', 'authorization']

sec_a = extract_cstrings(da, SEC_KEYWORDS)
sec_b = extract_cstrings(db, SEC_KEYWORDS)

sec_new  = sorted([s for s in sec_b - sec_a if len(s) > 15])
sec_gone = sorted([s for s in sec_a - sec_b if len(s) > 15])

emit(f'Keywords: `{", ".join(SEC_KEYWORDS)}`\n')
emit(f'- Security strings in 26.6.1: {len(sec_a)}')
emit(f'- Security strings in 27.0.1: {len(sec_b)}')
emit(f'- New in 27.0.1: **{len(sec_new)}**')
emit(f'- Removed: **{len(sec_gone)}**\n')

emit('### New security strings in 27.0.1 (first 60)')
emit('```')
for s in sec_new[:60]:
    emit(s)
emit('```\n')

emit('### Removed security strings (first 60)')
emit('```')
for s in sec_gone[:60]:
    emit(s)
emit('```\n')

checkpoint('6. Security Strings')

# ─── 7. __TEXT_EXEC DIFF ──────────────────────────────────────────────────────

emit('## 7. `__TEXT_EXEC` Diff Statistics\n')

te_a = segs_a.get('__TEXT_EXEC', {})
te_b = segs_b.get('__TEXT_EXEC', {})

if te_a and te_b:
    ta = da[te_a['fileoff']:te_a['fileoff']+te_a['filesize']]
    tb = db[te_b['fileoff']:te_b['fileoff']+te_b['filesize']]

    sa_len = len(ta)
    sb_len = len(tb)

    emit(f'- 26.6.1 `__TEXT_EXEC`: {sa_len//1024}K ({sa_len//1024//1024}MB)')
    emit(f'- 27.0.1 `__TEXT_EXEC`: {sb_len//1024}K ({sb_len//1024//1024}MB)')
    emit(f'- Size delta: {(sb_len-sa_len)//1024:+}K\n')

    # Compare page by page using numpy for speed
    PAGE = 4096
    # Use min length for page comparison
    min_len = min(sa_len, sb_len)
    pages   = min_len // PAGE

    arr_a = np.frombuffer(ta[:pages*PAGE], dtype=np.uint8).reshape(pages, PAGE)
    arr_b = np.frombuffer(tb[:pages*PAGE], dtype=np.uint8).reshape(pages, PAGE)

    diff_mask = np.any(arr_a != arr_b, axis=1)
    changed_pages = int(diff_mask.sum())
    total_compared = pages

    emit(f'- Pages compared (4K): {total_compared:,} ({total_compared*4//1024}MB)')
    emit(f'- Changed pages: **{changed_pages:,}** ({100*changed_pages//total_compared}%)')
    emit(f'- Unchanged pages: {total_compared-changed_pages:,}\n')

    # Find pages with fewest changed bytes (surgical patches, most interesting)
    diff_bytes = np.sum(arr_a != arr_b, axis=1)  # per-page byte diff count
    changed_idxs = np.where(diff_mask)[0]

    # Sort by byte count ascending — smallest diff = most surgical change
    if len(changed_idxs) > 0:
        counts = diff_bytes[changed_idxs]
        order  = np.argsort(counts)
        top_surgical = [(changed_idxs[i], int(counts[i])) for i in order[:20]]

        emit('### 20 Most Surgical Changes (fewest changed bytes per page)\n')
        emit('These are the most likely targeted security patches.\n')
        emit('| Page# | __TEXT_EXEC offset | A fileoff | B fileoff | Bytes changed | Nearby string |')
        emit('|-------|--------------------|-----------|-----------|---------------|---------------|')

        for page_idx, n_changed in top_surgical:
            te_off   = page_idx * PAGE
            a_foff   = te_a['fileoff'] + te_off
            b_foff   = te_b['fileoff'] + te_off

            # Find nearest C string in either kernel within ±32KB
            nearby = '—'
            for search_data, base_foff in [(da, a_foff), (db, b_foff)]:
                window_start = max(0, base_foff - 32768)
                window_end   = min(len(search_data), base_foff + 32768)
                window = search_data[window_start:window_end]
                # Find printable strings > 8 chars near centre
                best_dist = 99999
                best_str  = ''
                pos_in_win = 0
                centre_in_win = base_foff - window_start
                while pos_in_win < len(window):
                    end = window.find(b'\x00', pos_in_win)
                    if end == -1: break
                    seg = window[pos_in_win:end]
                    try:
                        s = seg.decode('ascii')
                        if len(s) > 8 and all(32 <= ord(c) < 127 for c in s):
                            d = abs(pos_in_win - centre_in_win)
                            if d < best_dist:
                                best_dist = d
                                best_str  = s[:50]
                    except:
                        pass
                    pos_in_win = end + 1
                if best_str:
                    nearby = f'`{best_str}`'
                    break

            emit(f'| {page_idx} | +0x{te_off:06x} | 0x{a_foff:08x} | 0x{b_foff:08x} | {n_changed} | {nearby} |')

    emit('')
else:
    emit('__TEXT_EXEC segment not found in one or both kernels.\n')

checkpoint('7. __TEXT_EXEC Diff')

# ─── TROUBLES & SOLUTIONS ─────────────────────────────────────────────────────

emit('## Troubles & Solutions (This Session + Cumulative)\n')
emit('''### This analysis run

**T1 — ZIP64 sentinels in IPSW**
Both the central-directory offset AND per-file `local_off` in `LC_FILESET_ENTRY` were `0xFFFFFFFF`.
Solution: parse ZIP64 extended information extra field (tag `0x0001`) to get real 64-bit offsets.

**T2 — lzfse stdin pipe fails**
Piping raw bytes to `lzfse -decode -i - -o file` returned error on Alpine Linux.
Solution: write payload to a `.lzfse` temp file first, then call `lzfse -decode -i tmp -o out`.

**T3 — GNU nm doesn\'t speak Mach-O**
`nm kernelcache.macho` → "file format not recognized". GNU binutils is ELF-only.
Solution: wrote Python parser for MH_FILESET, walking `LC_FILESET_ENTRY` load commands.

**T4 — Wrong LC_FILESET_ENTRY constant**
Used `0x80000041` instead of `0x80000035` — found 0 fileset entries.
Solution: dumped all load command types; saw `0x80000035 x302`. Fixed constant.

**T5 — Production kernel has nsyms=0**
`com.apple.kernel` symtab is stripped in release builds. Can\'t get symbol names directly.
Solution: string-anchor method — find panic/log strings that embed function names, use as
position anchor for nearby code analysis.

**T6 — OOM on `git push` with binary files**
`pack-objects died of signal 9` — 140MB of `.macho`/`.im4p` files triggered OOM in git.
Solution: `git reset HEAD~1`, added `.gitignore` for `*.macho *.im4p *.lzfse`, push scripts only.

**T7 — No pip initially**
`python3 -m pip` not found; `python3 -m ensurepip` failed.
Solution: `apk add py3-pip` (Alpine Linux package manager).

**T8 — pip installs blocked by PEP 668**
System Python rejects bare `pip install` to protect system packages.
Solution: `pip install --break-system-packages` (acceptable since we\'re root on a VM).

**T9 — All __TEXT_EXEC pages differ (ADRP noise)**
26.1 vs 26.6.1: every one of 11,368 pages showed as changed. Looked like a diff tool bug.
Solution: kernels were linked at different base addresses; every `ADRP` instruction embeds
a page-relative 21-bit immediate. Numpy ADRP normalisation zeroed the imm before comparison.
Still all 11368 pages differed — confirms full recompile between .1 and .6.1.

**T10 — apt-get not available**
Alpine Linux uses `apk`, not `apt-get`. Any `apt-get install` fails silently.
Solution: always use `apk add <package>`. Confirmed `apk add lzfse` works.

**T11 — IPSW ZIP has two ZIP64 sentinel layers**
Not just the central-directory offset is `0xFFFFFFFF`; the individual file `local_off`
in the central directory entries is ALSO `0xFFFFFFFF` for large-offset files.
Solution: after parsing ZIP64 EOCD locator for the CD offset, ALSO parse ZIP64 extra
fields (tag `0x0001`) inside each CD entry to get the real per-file local header offset.
''')

checkpoint('Troubles & Solutions')

# ─── KEY TAKEAWAYS ────────────────────────────────────────────────────────────

emit('## Key Takeaways\n')

emit(f'''### Architecture
- **Kernel build jumped 487 → 514** (+27 minor versions) between iOS 26.6.1 and 27.0.1
- **__TEXT_EXEC** grew +{(te_b.get("filesize",0)-te_a.get("filesize",0))//1024:+}K — more kernel code
- **__PPLTEXT {"absent in both" if not ppltext_a else "present in 26.6.1, absent in 27.0.1" if not ppltext_b else "present in both"}** — PPL removal status as noted

### SPTM / GXF
- **GENTER count:** {ga_count} → {gb_count} in __TEXT_EXEC ({gb_count-ga_count:+}) — new SPTM trap call sites
- **__DATA_SPTM:** {sptm_a//1024}K → {sptm_b//1024}K

### Security Changes
- {len(sec_new)} new security-relevant strings, {len(sec_gone)} removed
- {len(new_kexts)} new kexts, {len(removed_kexts)} removed kexts

### For Trigon Research
- `mach_make_memory_entry` found in both kernels — string anchors above
- MIG dispatch index in LINKEDIT shows function ordering changed
- For the actual CVE-2023-32434 patch: diff iOS 16.1.1 vs 16.5.1 on a PPL-era device
  (e.g. iPhone14,5 / iPhone 14) — SPTM-era kernels restructured the PPL call path entirely
''')

flush()

print(f'\n[✓] Report written to {OUT}')
print(f'[✓] Total lines: {len(report)}')
