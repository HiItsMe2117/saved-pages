# AppleAVE2 — iOS 26.6.1 (23G83, build iPhone17,4)

**Binary**: com.apple.driver.AppleAVE2  
**Source version**: 905.40.1.0.0  
**Size**: 2.6 MB · 2783 functions · 0 symbols  
**Kext path (Mac)**: `/Users/codysomerville/kerneldiff_ave2/23G83__iPhone17,4/kexts/com.apple.driver.AppleAVE2`  
**Symbol cache**: `...AppleAVE2.a2s` (148 GOT symbols only)

---

## Segment Map

| Section                      | File off   | VA                       | Size       |
|------------------------------|------------|--------------------------|------------|
| `__TEXT.__const`             | 0x770      | 0xfffffff00724a7d0       | 42,610 B   |
| `__TEXT.__cstring`           | 0x42d80    | 0xfffffff0072xxxx        | 266,482 B  |
| `__TEXT_EXEC.__text`         | 0xd8000    | 0xfffffff0084c24b0       | 1,707,212 B |
| `__DATA_CONST.__mod_init_func`| 0x280510  | 0xfffffff007db94b8       | 56 B       |
| `__DATA_CONST.__const`       | 0x280510   | 0xfffffff007db9528       | 35,680 B   |
| `__DATA_CONST.__kalloc_type` | 0x289070   | 0xfffffff007dc2088       | 18,688 B   |
| `__DATA_CONST.__kalloc_var`  | 0x28d970   | 0xfffffff007dc6988       | 8,240 B    |

**KC_BASE**: `0xfffffff007000000`  
**Pointer encoding**: actual VA = KC_BASE + lower_32_bits_of_stored_value

---

## CalcBufSizeOf Functions — All 17

**Window**: `0xfffffff0084ec894` to `0xfffffff0084f0de8` (16 KB)

| Function                          | String VA                | First xref VA            | Status                    |
|-----------------------------------|--------------------------|--------------------------|---------------------------|
| CalcBufSizeOfMBInputCtrl          | 0xfffffff0072953ac       | 0xfffffff0084ec894       | ANALYZED — no overflow    |
| CalcBufSizeOfMBStats              | 0xfffffff007295653       | 0xfffffff0084ed634       | pending                   |
| CalcBufSizeOfCodedData            | 0xfffffff007295546       | 0xfffffff0084ecf98       | pending                   |
| CalcBufSizeOfStaticAreaCBP0Cntr   | 0xfffffff00729576b       | 0xfffffff0084edb6c       | pending                   |
| CalcBufSizeOfStaticAreaQPModInfo  | 0xfffffff0072957cc       | 0xfffffff0084edd48       | pending                   |
| CalcBufSizeOfRecon                | 0xfffffff007295834       | 0xfffffff0084ee670       | DART-blocked (closed)     |
| CalcBufSizeOfColocated            | 0xfffffff00729588d       | 0xfffffff0084ee860       | ANALYZED — smull, safe    |
| CalcBufSizeOfLFSRef               | 0xfffffff007295a78       | 0xfffffff0084ef1b4       | ANALYZED — 32-bit mul, weak tbnz |
| CalcBufSizeOfHSCOutput            | 0xfffffff007295ad9       | 0xfffffff0084ef470       | pending                   |
| CalcBufSizeOfLFSResult            | 0xfffffff007295af4       | 0xfffffff0084ef6a4       | ANALYZED — 32-bit mul (function start: 0x84ef5b0) |
| CalcBufSizeOfLRSResult            | 0xfffffff007295b51       | 0xfffffff0084efa5c       | pending                   |
| CalcBufSizeOfSrcNeighborInfo      | 0xfffffff007295bdd       | 0xfffffff0084efd08       | pending                   |
| CalcBufSizeOfSrcNeighborPixel     | 0xfffffff007295ccd       | 0xfffffff0084f0108       | pending                   |
| CalcBufSizeOfSrcNeighborData      | 0xfffffff007295d7e       | 0xfffffff0084f03a0       | ANALYZED — 1D, 64-bit, safe |
| CalcBufSizeOfSrcNeighborFwData    | 0xfffffff007295dc8       | 0xfffffff0084f0644       | pending                   |
| CalcBufSizeOfEntropyCoding        | 0xfffffff007295deb       | 0xfffffff0084f0994       | ANALYZED — 2×32-bit mul chain |
| CalcBufSizeOfMCTFOutput           | 0xfffffff007295e55       | 0xfffffff0084f0db0       | ANALYZED — multiple 32-bit mul |

---

## Analyzed Functions — Detail

### CalcBufSizeOfMBInputCtrl (0x84ec7d8)
- Args: x0=level(w19), x1=codec(w20), x2=height(w22), x3=width(w24?)
- AVC main (level≥30): `smull x22, w25, w26` — SAFE, 2GB guard
- AVC legacy (level<30): `mul w24, w8, w24` — 32-bit, only checks bits 27+ (`lsr w8, w24, #0x1b`)
- HEVC main (level≥30): `smull x26, x24, w25` — SAFE
- **No NTL multiplier** — per-frame buffer

### CalcBufSizeOfColocated (0x84ee7a0)
- AVC main: `smull x25, w26, w24` — SAFE, two guards: 2GB + 32MB
- HEVC main: `smull x24, w26, w25` — SAFE
- HEVC legacy (level<30): `smull x24, w26, w25; sbfiz x25, x24, #6, #0x20` — 20-bit truncation but legacy path
- **No NTL multiplier** — per-frame

### CalcBufSizeOfLFSRef (function starts at ~0x84eee68)
- 7-arg function: x0=level, x1=codec(w22), x2=width, x3=height, x4=?, x5=?, x6=?, [sp]=w9_shift, [sp+8]=output_struct
- Main: `mul w26, w12, w13` — **32-bit, NO smull**
  - w12 = `ceil(align128(height) >> w9) / 32) × (1024 or 2048)`
  - w13 = `ceil(align128(width) >> w9 / 32)`
  - Overflow check: `tbnz w26, #0x1f` — **WEAK: only catches wrapped result ≥ 2^31**
- w9 from stack: callers 1 (0x84ccfac) pass w9=0 or 1 (from `and w21, w9_outer, #0x1`); caller 2 (0x852eba0) passes w9=2
- Other callers: 0x8588ee0, 0x8638448, 0x863f528 — NOT YET ANALYZED

### CalcBufSizeOfLFSResult (0x84ef5b0)
- Args: x0=codec, x1=level(w19), x2=?(w22), x3=height(w21), x4=width(w20), x5=LRME flag
- Initial: `smull x25, w4, w3` (area check, 64-bit) — SAFE if area < 2GB
- Then: `mul w9, w9, w10` — **32-bit** at 0x84ef65c (HEVC level≥30 path)
  - w9 = `ceil((width × scale)/128)`; w10 = `64 × ceil((height × scale)/128)`
  - scale=4 if LRME active (w5≠0), scale=1 otherwise
  - Overflow threshold: ~1M pixels per dimension — unreachable
- Then: `madd w8, w9, w10, w8` at 0x84ef664 — adds w9 × 40 + height_aligned

### CalcBufSizeOfSrcNeighborData (0x84f0304)
- 1D function (width only)
- AVC main: `lsl x23, x8, #6` — 64-bit left shift (×64), overflow threshold 537M pixels — unreachable
- HEVC: hard cap at 0x4000=16384 (`csel`)
- **Safe**

### CalcBufSizeOfEntropyCoding (function starts before 0x84f0994)
- Args: 8 params (x0-x7), arg w4 selects base multiplier (table lookup for w4∈{1,2,3}, else 0x600=1536)
- Main path: **TWO 32-bit multiplies at 0x84f0a78 and 0x84f0a7c**
  - `mul w8, w8, w10` (base × ceil(width/32))
  - `mul w8, w8, w9` (× height factor)
  - Then `lsl w0, w8, w6` (additional shift)
- Overflow threshold: ~53K pixels per dimension — unreachable at HW limits

### CalcBufSizeOfMCTFOutput (function starts before 0x84f0b80)
- Complex multi-output: w25, w26, w27, w28 (4 component sizes)
- Args: x0=level, x1=codec?, x2?, x3=height(w21), x4=width(w20), x5=MCTF level, x6=?, x7=?
- 32-bit `mul w25, w8, w10` at 0x84f0c14 (main size component)
  - w8 = 1024 × ceil(height/32) (or 1280 for 10-bit)
  - w10 = ceil(width/32)
  - Overflow threshold: ~8192 blocks (262K pixels per dim) — unreachable

---

## Memory Architecture

**Two memory paths:**
1. **DMA/firmware path**: DPB (Recon), pixel planes → DART-limited → ALL CLOSED
2. **CPU-side kalloc path**: MBInputCtrl, Colocated, LFSRef, LFSResult, EntropyCoding, etc. → NOT DART-limited → TARGET

**Allocator evidence**: `__DATA_CONST.__kalloc_type` has 608 entries; `__kalloc_var` has 1030 entries — CPU-side buffers use the standard kernel heap.

---

## LFSRef Callers (5 total)

| Address        | Stack arg [sp] = w9 (shift) | Codec passed |
|----------------|------------------------------|--------------|
| 0x84ccfac      | 0 or 1 (from `and #0x1`)     | w1=5 (AV1)   |
| 0x852eba0      | 2 (hardcoded `mov w8, #0x2`) | w1=4         |
| 0x8588ee0      | NOT ANALYZED                 | ?            |
| 0x8638448      | NOT ANALYZED                 | ?            |
| 0x863f528      | NOT ANALYZED                 | ?            |

---

## Already-Patched CVE Context (closed on target)

**CVE-2026-64747** — fixed in iOS 26.6 (before our 26.6.1 target):
- Component: AVEVideoEncoder (same as our targets)
- Researcher: Franco Belman, Blackwing Intelligence (same researcher as CVE-2026-112689)
- Fix: "better size validation" — buffer overflow, kernel privilege escalation (CVSS 7.8)
- Status on 26.6.1: **ALREADY PATCHED** — 26.6.1 is a point release on top of 26.6

**Implication**: The 26.6.1 kext already has the 64747 "size validation" fix applied. What we see in our 26.6.1 baseline IS the patched version for 64747. The 26.7.2 diff adds CVE-2026-112689 on top of that.

Download iOS 26.5 OTA to see the pre-64747 kext: confirms the pattern and helps identify the still-open 112689 path.

---

## CVE-2026-112689 — Open Surface Confirmed (2026-11-04)

### What 26.6.1 is MISSING (added in 26.7.2):

`AVE_AVC_CheckInfo` in 26.6.1 is at **0xfffffff00851c454** (1100 bytes).  
In 26.7.2 it's at 0xfffffff0085244f4 (larger, with new frame dimension check).

The 26.6.1 version validates:
- `[x1, #0x2df8]` — sub 1, compare ≤ 2 → iNumViews bound  
- `[x21, #0x2df4]` — sub 1, compare ≤ 2 → iLayerNum bound  
- Then proceeds directly to CalcBufSizeOf allocation with frame fields [x21, #0xa58] / [x21, #0xa5c]

**MISSING**: After passing iNumViews/iLayerNum bounds, 26.6.1 does NOT call `sub_fffffff00853aa34` (which validates frame dimensions against codec-level macroblock table).

### Exploit path (CVE-2026-112689):

1. Create VideoToolbox session with valid iNumViews=1, iLayerNum=1
2. Set frame dimensions (struct offsets 0xa58/0xa5c) to values that cause CalcBufSizeOf to overflow/undercompute
3. AVE_AVC_CheckInfo passes → kernext proceeds to allocate undersized buffer  
4. Write loop uses actual dimensions → OOB kernel heap write

**Key frame dimension fields**:
- `[x21, #0xa58]` → passed as arg3 to dimension checker (width-related)
- `[x21, #0xa5c]` → passed as arg4 to dimension checker (height-related)

---

## Notes / Open Questions

- Do any CalcBufSizeOf functions have an **NTL multiplier** in the caller (not in the CalcBufSizeOf itself)?
- Are there CPU-side WRITE functions that use a different bounds formula than the allocation?
- Three unanalyzed LFSRef callers — could pass larger shift values
- The 26.5→26.6.1 diff will show what CVE-2026-64747's "size validation" fix added (reference template)
- Next: identify which specific CalcBufSizeOf function uses [x21, #0xa58] / [x21, #0xa5c] directly
