# AppleAVE2 Kext — Architecture Notes
**Binary:** com.apple.driver.AppleAVE2 · 23G83 (iPhone17,4 / iOS 26.6.1)  
**Source version:** 905.40.1.0.0 · arm64e Mach-O · 2.6 MB · 0 symbols · 2783 functions

---

## Pointer Encoding (critical for analysis)

arm64e chained fixup, NOT full VAs:  
- Actual VA = `KC_BASE (0xfffffff007000000) + lower_32_bits_of_stored_value`  
- Auth ptrs: `0x8011XXXX_YYYYYYYY` (PAC key IA, diversity XXXX)  
- Unauthenticated rebases: `0x001000000YYYYYYYY`  
- Never search for full VAs in `__DATA_CONST` — always decode via KC_BASE offset

---

## Segment Map

| Segment.__section           | File off   | VA                       | Size       | Notes                  |
|-----------------------------|------------|--------------------------|------------|------------------------|
| `__TEXT.__const`            | 0x770      | 0xfffffff00724a7d0       | 42,610 B   |                        |
| `__TEXT.__cstring`          | 0x42d80    | 0xfffffff00728cde0       | 266,482 B  | log/function name strings |
| `__TEXT.__os_log`           | 0x84272    | 0xfffffff0072ce2d2       | 341,016 B  |                        |
| `__TEXT_EXEC.__text`        | 0xd8000    | 0xfffffff0084c24b0       | 1,707,212 B| **all function code**  |
| `__DATA_CONST.__auth_got`   | 0x280000   | 0xfffffff007db9018       | 976 B      | 122 PAC-signed GOT entries |
| `__DATA_CONST.__got`        | 0x2803d0   | 0xfffffff007db93e8       | 200 B      |                        |
| `__DATA_CONST.__mod_init_func` | 0x2804a0 | 0xfffffff007db94b8      | 56 B       | 7 constructors         |
| `__DATA_CONST.__const`      | 0x280510   | 0xfffffff007db9528       | 35,680 B   | **vtables** (KC_BASE encoded) |
| `__DATA_CONST.__kalloc_type`| 0x289070   | 0xfffffff007dc2088       | 18,688 B   | 608 kalloc_type entries|
| `__DATA_CONST.__kalloc_var` | 0x28d970   | 0xfffffff007dc6988       | 8,240 B    | 1030 kalloc_var entries|

---

## Module Map (high level)

```
VTCompressionSession (userspace)
  └─ IOKit / IOUserClient
       └─ AppleAVE2UserClient  (kext, IOKit entry)
            └─ AVE_Client_DispatchCmd
                 ├─ AVE_CHM_*     (firmware command queue — DMA → DART-mapped)
                 ├─ AVE_IOP       (IOP interface — coprocessor side)
                 ├─ AVE_BufPool   (kernel heap pool — CPU-side, kalloc-backed)
                 └─ AVE_BlkPool   (block pool — CPU-side, kalloc-backed)
```

**Two memory paths — this distinction is the key:**  
1. **Firmware/DMA path**: IOSurface buffers (DPB, pixel planes). Writes go via firmware DMA → DART IOMMU → physically contiguous (`kmem_alloc_contig`). **ALL blocked by DART on 26.6.1.**  
2. **CPU-side path**: Kernel heap buffers (MBInputCtrl, SrcNeighbor*, Colocated, MBStats, etc.). Writes go via host application CPU in kernel virtual address space. `kalloc`-backed. **NOT DART-limited — target path.**

---

## 7 Constructor VAs (mod_init_func)

```
0xfffffff008514510   0x00856e418   0x00857e50c   0x0085b1510
0x0085d68c8         0x00864880c   0x008653468
```
(Apply KC_BASE offset formula to get real VAs for constructors 2-7)

---

## CalcBufSizeOf Functions — All 17 Located

**ALL references in a 16 KB window:** `0xfffffff0084ec894` to `0xfffffff0084f0de8`

| Function name                      | String VA                  | First xref VA            |
|------------------------------------|----------------------------|--------------------------|
| CalcBufSizeOfMBInputCtrl           | 0xfffffff0072953ac         | 0xfffffff0084ec894       |
| CalcBufSizeOfMBStats               | 0xfffffff007295653         | 0xfffffff0084ed634       |
| CalcBufSizeOfCodedData             | 0xfffffff007295546         | 0xfffffff0084ecf98       |
| CalcBufSizeOfStaticAreaCBP0Cntr    | 0xfffffff00729576b         | 0xfffffff0084edb6c       |
| CalcBufSizeOfStaticAreaQPModInfo   | 0xfffffff0072957cc         | 0xfffffff0084edd48       |
| CalcBufSizeOfRecon                 | 0xfffffff007295834         | 0xfffffff0084ee670       |
| CalcBufSizeOfColocated             | 0xfffffff00729588d         | 0xfffffff0084ee860       |
| CalcBufSizeOfLFSRef                | 0xfffffff007295a78         | 0xfffffff0084ef1b4       |
| CalcBufSizeOfHSCOutput             | 0xfffffff007295ad9         | 0xfffffff0084ef470       |
| CalcBufSizeOfLFSResult             | 0xfffffff007295af4         | 0xfffffff0084ef6a4       |
| CalcBufSizeOfLRSResult             | 0xfffffff007295b51         | 0xfffffff0084efa5c       |
| CalcBufSizeOfSrcNeighborInfo       | 0xfffffff007295bdd         | 0xfffffff0084efd08       |
| CalcBufSizeOfSrcNeighborPixel      | 0xfffffff007295ccd         | 0xfffffff0084f0108       |
| CalcBufSizeOfSrcNeighborData       | 0xfffffff007295d7e         | 0xfffffff0084f03a0       |
| CalcBufSizeOfSrcNeighborFwData     | 0xfffffff007295dc8         | 0xfffffff0084f0644       |
| CalcBufSizeOfEntropyCoding         | 0xfffffff007295deb         | 0xfffffff0084f0994       |
| CalcBufSizeOfMCTFOutput            | 0xfffffff007295e55         | 0xfffffff0084f0db0       |

---

## CalcBufSizeOfMBInputCtrl — Partial Reversal

**Function:** `sub_fffffff0084ec7d8` (function start: 0xfffffff0084ec7d8)  
**Args:** x0=session?, w1=codec(1=AVC/2=HEVC), x2=height(?), x3=width(?)  
**Saved:** x19=x0, x20=x2, x21=x3  

**AVC path (w1==1):**
```
w24 = ceil(height/16)        // macroblock rows
// if level (w19) >= 30 (H.264 Level 3.0):
x25 = align(w24<<4, 64)      // height in pixels, 64-aligned
w26 = align(ceil(width/16), 4) * 4  // width blocks, 4-aligned
x22 = smull(w25, w26)        // 64-bit product
// OVERFLOW CHECK: if x22 >= 0x80000000 → log "AVC size overflow" → ...
// if x22 < 0x80000000 → SUCCESS
```

**HEVC path (w1==2):**
```
w8 = (height + 63) >> 5      // ceil(height/32) blocks
w25 = w8 & ~1                // round down to even
x24 = sbfiz(w25, #5)         // height in pixels (32px CTUs)
w25 = ((width+63)>>5) & ~1   // width blocks (32px CTUs)
x26 = smull(x24, w25)        // 64-bit product
// OVERFLOW CHECK: if w8 sign-bit set, OR x26 >= 0x80000000 → ...
// if x26 < 0x80000000 → SUCCESS (mov x22, x26)
```

**Key observation**: No NTL multiplier in MBInputCtrl — it's a per-frame buffer (not per reference frame).

**Overflow detection**: PRESENT in both paths. Uses `tbnz` to catch negative intermediates + `cmp x26, #0x80000000` guard.  
**But**: legacy AVC path (`cmp w19, #0x1e` / `b.lt`) uses 32-bit `mul w24, w8, w24` with only `lsr w8, w24, #0x1b` overflow check (checks bits 27+). A product that sets bits 27-30 will be **missed** by this check.

---

## Surfaces with NTL multiplier (reference-frame buffers = higher priority)

Based on naming conventions:
- **Colocated** (motion vectors, one per reference frame) — NTL multiplier expected ✓
- **LFSRef** (loop filter reference) — NTL multiplier expected ✓  
- **LFSResult / LRSResult** — NTL multiplier possible ✓
- **Recon** (DPB) — NTL multiplier CONFIRMED (closed via DART)

These are the highest-priority targets for CPU-side overflow.

---

## iOS 26.7.2 CVE Mapping

| CVE               | Researcher            | Fix type                   | Likely target              |
|-------------------|-----------------------|----------------------------|----------------------------|
| CVE-2026-112689   | Blackwing Intelligence| "improved input validation"| parameter pre-validation   |
| CVE-2026-112470   | Hcamael + 章鱼哥       | "improved bounds checking" | write OOB (buffer created correctly, writes beyond) |
| CVE-2026-112468   | Hcamael + 章鱼哥       | "improved bounds checking" | write OOB                  |
| CVE-2026-112469   | Hcamael + 章鱼哥       | "improved bounds checking" | write OOB                  |

Blackwing's pattern: size calculation overflow → small allocation → firmware/CPU writes OOB  
Hcamael's pattern: correct size, but write index can exceed buffer (loop bounds, stride calculation)

---

## Tools on Mac

- `ipsw`: `/opt/homebrew/bin/ipsw` — disassembly, kext extraction, symbol cache
- `r2`/radare2: `/opt/homebrew/bin/r2`
- Ghidra.app, Hopper Disassembler.app
- Kext path: `/Users/codysomerville/kerneldiff_ave2/23G83__iPhone17,4/kexts/com.apple.driver.AppleAVE2`
- Symbol cache: `...AppleAVE2.a2s` (148 GOT symbols only, no function names)

**Disasm command pattern:**
```
ipsw macho disass <kext> --cache <kext>.a2s --vaddr 0xfffffff00XXXXXXX --count 100 --no-color
```
