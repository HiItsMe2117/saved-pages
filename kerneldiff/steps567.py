#!/usr/bin/env python3
"""
Steps 5-7 of 26.6.1→27.0.1 diff. Memory-efficient: mmap + chunked numpy.
Appends to REPORT_27.md.
"""
import struct, os, re, gc
from datetime import datetime
import numpy as np

KC_A = '/root/code/saved-pages/kerneldiff/kc_26.6.1.macho'
KC_B = '/root/code/saved-pages/kerneldiff/kc_27.0.1.macho'
OUT  = '/root/code/saved-pages/kerneldiff/REPORT_27.md'

LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64    = 0x19

buf = []

def ts(): return datetime.now().strftime('%H:%M:%S')
def emit(l=''): buf.append(l)
def flush():
    existing = open(OUT).read() if os.path.exists(OUT) else ''
    with open(OUT,'w') as f: f.write(existing + '\n'.join(buf) + '\n')
    buf.clear()

def checkpoint(name):
    emit(f'\n## ✓ Checkpoint: {name} — {ts()}\n')
    flush()
    print(f'[✓] {name}')

# ── Minimal header reader (reads only first 4MB) ──────────────────────────────

def read_header(path, max_bytes=4*1024*1024):
    with open(path,'rb') as f: return f.read(max_bytes)

def parse_hdr(data):
    _, _, _, ftype, ncmds = struct.unpack_from('<IIIII', data)
    return {'ftype': ftype, 'ncmds': ncmds}

def iter_lc(data, hdr):
    off = 32
    for _ in range(hdr['ncmds']):
        if off+8 > len(data): break
        cmd, sz = struct.unpack_from('<II', data, off)
        yield cmd, sz, off
        if sz == 0: break
        off += sz

def get_segs(data, hdr):
    s = {}
    for cmd, sz, lc in iter_lc(data, hdr):
        if cmd == LC_SEGMENT_64:
            name = data[lc+8:lc+24].rstrip(b'\x00').decode()
            vmaddr, vmsize, fo, fs = struct.unpack_from('<QQQQ', data, lc+24)
            s[name] = {'fileoff': fo, 'filesize': fs}
    return s

def get_fse(data, hdr):
    entries = {}
    for cmd, sz, lc in iter_lc(data, hdr):
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff, name_off, _ = struct.unpack_from('<QQII', data, lc+8)
            name = data[lc+name_off:].split(b'\x00')[0].decode()
            entries[name] = fileoff
    return entries

# ── ① Load just headers ───────────────────────────────────────────────────────
print('[*] Reading headers...')
hd_a = read_header(KC_A)
hdr_a = parse_hdr(hd_a)
segs_a = get_segs(hd_a, hdr_a)
fse_a  = get_fse(hd_a, hdr_a)
del hd_a

hd_b = read_header(KC_B)
hdr_b = parse_hdr(hd_b)
segs_b = get_segs(hd_b, hdr_b)
fse_b  = get_fse(hd_b, hdr_b)
del hd_b
gc.collect()
print(f'[*] Segments: A={len(segs_a)} B={len(segs_b)}  FSE: A={len(fse_a)} B={len(fse_b)}')

# ─── STEP 5: Kext Changes ─────────────────────────────────────────────────────
emit('## 5. Kext Changes\n')

names_a = set(fse_a.keys())
names_b = set(fse_b.keys())
new_k  = sorted(names_b - names_a)
rem_k  = sorted(names_a - names_b)
common = sorted(names_a & names_b)

emit('| | 26.6.1 | 27.0.1 | Δ |')
emit('|---|---|---|---|')
emit(f'| Total | {len(names_a)} | {len(names_b)} | {len(names_b)-len(names_a):+} |')
emit(f'| New | — | {len(new_k)} | +{len(new_k)} |')
emit(f'| Removed | {len(rem_k)} | — | -{len(rem_k)} |')
emit(f'| Common | {len(common)} | {len(common)} | — |\n')

if new_k:
    emit('### New kexts in 27.0.1')
    for k in new_k: emit(f'- `{k}`')
    emit('')

if rem_k:
    emit('### Removed kexts')
    for k in rem_k: emit(f'- `{k}`')
    emit('')

# Size from offset differences
sorted_a = sorted(fse_a.items(), key=lambda x: x[1])
sorted_b = sorted(fse_b.items(), key=lambda x: x[1])
map_a = {n: i for i,(n,_) in enumerate(sorted_a)}
map_b = {n: i for i,(n,_) in enumerate(sorted_b)}

def ksize(lst, idx):
    if idx+1 < len(lst): return lst[idx+1][1] - lst[idx][1]
    return 0

diffs = []
for k in common:
    ia, ib = map_a.get(k,-1), map_b.get(k,-1)
    if ia >= 0 and ib >= 0:
        sa, sb = ksize(sorted_a, ia), ksize(sorted_b, ib)
        if sa > 0 and sb > 0:
            diffs.append((abs(sb-sa), sb-sa, k, sa, sb))
diffs.sort(reverse=True)

emit('### Largest size changes\n')
emit('| Kext (short) | 26.6.1 | 27.0.1 | Δ |')
emit('|---|---|---|---|')
for _, delta, k, sa, sb in diffs[:30]:
    short = k.split('.')[-1]
    emit(f'| `{short}` | {sa//1024}K | {sb//1024}K | {delta:+,} |')
emit('')

checkpoint('5. Kext Changes')

# ─── STEP 6: Security Strings (streaming, one file at a time) ─────────────────
emit('## 6. Changed Security-Relevant Strings\n')

SEC_KW = [b'sptm',b'ppl',b'txm',b'gxf',b'pmap',b'entitlement',
          b'sandbox',b'amfi',b'codesign',b'coretrust',b'enforce',
          b'policy',b'integrity',b'trust',b'violation',b'restricted']

PAT = re.compile(rb'[\x20-\x7e]{8,200}')

def stream_kw_strings(path, keywords):
    """Stream file, yield matching strings without loading whole file."""
    matched = set()
    CHUNK = 2*1024*1024  # 2MB chunks with overlap
    OVERLAP = 256
    with open(path,'rb') as f:
        leftover = b''
        while True:
            chunk = f.read(CHUNK)
            if not chunk: break
            data = leftover + chunk
            for m in PAT.finditer(data):
                s = m.group()
                sl = s.lower()
                if any(kw in sl for kw in keywords):
                    try:
                        matched.add(s.decode('ascii'))
                    except: pass
            leftover = data[-OVERLAP:] if len(data) > OVERLAP else b''
    return matched

print('[*] Scanning security strings in 26.6.1...')
sec_a = stream_kw_strings(KC_A, SEC_KW)
print(f'    {len(sec_a)} matches')
print('[*] Scanning security strings in 27.0.1...')
sec_b = stream_kw_strings(KC_B, SEC_KW)
print(f'    {len(sec_b)} matches')
gc.collect()

sec_new  = sorted({s for s in sec_b - sec_a if len(s) > 12})
sec_gone = sorted({s for s in sec_a - sec_b if len(s) > 12})

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

# ─── STEP 7: __TEXT_EXEC diff (chunked, no full array) ───────────────────────
emit('## 7. `__TEXT_EXEC` Diff Statistics\n')

te_a = segs_a.get('__TEXT_EXEC',{})
te_b = segs_b.get('__TEXT_EXEC',{})
fa, fs_a = te_a['fileoff'], te_a['filesize']
fb, fs_b = te_b['fileoff'], te_b['filesize']

emit(f'- 26.6.1: {fs_a//1024}K | 27.0.1: {fs_b//1024}K | Δ {(fs_b-fs_a)//1024:+}K\n')

PAGE = 4096
min_sz = min(fs_a, fs_b)
total_pages = min_sz // PAGE

CHUNK_PAGES = 512  # 512 pages = 2MB per read — keeps peak numpy RAM ~6MB
changed_count = 0
total_diff = []   # (n_bytes_diff, page_idx) for top-20

print(f'[*] Diffing {total_pages} pages in {total_pages//CHUNK_PAGES+1} chunks...')

with open(KC_A,'rb') as fa_f, open(KC_B,'rb') as fb_f:
    for chunk_start in range(0, total_pages, CHUNK_PAGES):
        chunk_end = min(chunk_start + CHUNK_PAGES, total_pages)
        n = chunk_end - chunk_start
        byte_off_a = fa + chunk_start * PAGE
        byte_off_b = fb + chunk_start * PAGE
        fa_f.seek(byte_off_a); ra = fa_f.read(n * PAGE)
        fb_f.seek(byte_off_b); rb = fb_f.read(n * PAGE)
        if len(ra) < n*PAGE or len(rb) < n*PAGE: break
        aa = np.frombuffer(ra, dtype=np.uint8).reshape(n, PAGE)
        ab = np.frombuffer(rb, dtype=np.uint8).reshape(n, PAGE)
        diff = np.sum(aa != ab, axis=1)  # per-page byte diff count
        mask = diff > 0
        changed_count += int(mask.sum())
        for local_i in np.where(mask)[0]:
            total_diff.append((int(diff[local_i]), chunk_start + int(local_i)))
        del aa, ab, ra, rb, diff, mask
        gc.collect()

# Sort to find most surgical patches
total_diff.sort()  # ascending by n_bytes_diff
top20 = total_diff[:20]

emit(f'- Pages compared: {total_pages:,}')
emit(f'- Changed pages: **{changed_count:,}** ({100*changed_count//total_pages}%)')
emit(f'- Unchanged pages: {total_pages-changed_count:,}\n')

emit('### 20 Most Surgical Patches (fewest bytes changed per page)\n')
emit('| Page | __TEXT_EXEC+offset | A fileoff | B fileoff | Bytes Δ | Nearby string |')
emit('|------|--------------------|-----------|-----------|---------|---------------|')

def find_nearby_str(path, fileoff):
    WIN = 16384
    start = max(0, fileoff - WIN)
    with open(path,'rb') as f:
        f.seek(start); window = f.read(2*WIN)
    centre = fileoff - start
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
                if d < best_d: best_d, best_s = d, s
        except: pass
        pos = end + 1
    return best_s[:55] if best_s else '—'

for n_diff, page_idx in top20:
    te_off = page_idx * PAGE
    a_fo   = fa + te_off
    b_fo   = fb + te_off
    nearby = find_nearby_str(KC_A, a_fo)
    if nearby == '—':
        nearby = find_nearby_str(KC_B, b_fo)
    emit(f'| {page_idx} | +0x{te_off:06x} | 0x{a_fo:08x} | 0x{b_fo:08x} | {n_diff} | `{nearby}` |')
emit('')

checkpoint('7. __TEXT_EXEC Diff')

# ─── KEY TAKEAWAYS ────────────────────────────────────────────────────────────
emit('## Key Takeaways\n')
emit(f'''### Architecture (iOS 26.6.1 → 27.0.1)
- **Kernel build 487.100.11 → 514.2.2** (+27 minor versions)
- **__TEXT_EXEC grew +{(fs_b-fs_a)//1024:+}K** — significant new kernel code
- **__PPLTEXT absent in both** — PPL already fully removed before 26.6.1
- **__DATA_SPTM: 240K → 304K (+64K)** — SPTM data tables grew significantly

### GENTER (SPTM trap calls) — from earlier analysis
- **150 → 173 in __TEXT_EXEC (+23 new SPTM call sites)**
- Kexts: 1 → 1 (unchanged)

### Kexts
- {len(names_a)} → {len(names_b)} kexts
- {len(new_k)} new, {len(rem_k)} removed

### Security
- {len(sec_new)} new security-relevant strings; {len(sec_gone)} removed

### __TEXT_EXEC Code Pages
- {changed_count:,} of {total_pages:,} pages changed ({100*changed_count//total_pages}%)
- Top-20 most surgical patches listed above

### For Trigon (CVE-2023-32434) Research
- `mach_make_memory_entry` present in both — see Section 4 for offsets
- MIG dispatch table shifted in both 26.6.1 and 27.0.1
- To study the actual patch, download iOS 16.1.1 vs 16.5.1 for iPhone14,5
  (A15 arm64e, PPL-era) — SPTM-era kernels restructured the call path entirely
''')

# ─── TROUBLES & SOLUTIONS ─────────────────────────────────────────────────────
emit('## Troubles & Solutions\n')
emit('''**T1 — ZIP64 IPSW sentinels** (both cd_offset and local_off = 0xFFFFFFFF)
Solution: parse ZIP64 EOCD locator + ZIP64 extra field (tag 0x0001).

**T2 — lzfse stdin pipe fails on Alpine Linux**
Solution: write payload to temp file first.

**T3 — GNU nm doesn't speak Mach-O**
Solution: Python Mach-O parser walking LC_FILESET_ENTRY (0x80000035).

**T4 — Wrong LC_FILESET_ENTRY constant** (had 0x80000041)
Solution: dump all cmd types; found 302 entries of 0x80000035.

**T5 — Production kernel nsyms=0**
Solution: string-anchor method via panic/log strings.

**T6 — git push OOM with binary files** (pack-objects signal 9)
Solution: .gitignore for *.macho *.im4p *.lzfse.

**T7 — pip not available**
Solution: `apk add py3-pip`

**T8 — pip install blocked by PEP 668**
Solution: `pip install --break-system-packages`

**T9 — All pages differ (ADRP noise from different link base)**
Solution: numpy ADRP normalisation, or accepted as recompile evidence.

**T10 — apt-get not available**
Solution: `apk add` (Alpine Linux).

**T11 — String extraction OOM** (split-on-null creates millions of Python objects)
Solution: streaming chunked reader with re.finditer — never holds > 2MB of data.

**T12 — __TEXT_EXEC numpy diff OOM** (45MB + 49MB arrays + comparison)
Solution: chunked 512-page reads, delete arrays after each chunk with gc.collect().
''')

checkpoint('Troubles & Solutions')
print(f'[✓] Done → {OUT}')
