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

## IOKit User Client Dispatch Table (2026-11-04)

**Service**: `AppleAVE2UserClient`  
**Dispatch table VA**: `0xfffffff007dc1840` (in `__DATA_CONST.__const`)  
**Table format**: `IOExternalMethodDispatch` — 24 bytes/entry: `[action:8][scalar_in:4][struct_in:4][scalar_out:4][struct_out:4]`

| Sel | Action VA              | struct_in   | struct_out  | Notes                        |
|-----|------------------------|-------------|-------------|------------------------------|
|  0  | 0xfffffff0086401ec     | 0x38        | 0x20        |                              |
|  1  | 0xfffffff008640aa8     | 0x1a0a0     | 0x20        | Large config struct (Configure?) |
|  2  | 0xfffffff00864157c     | 0x1a0b0     | 0x150       | "pIn->iUCInfoIdx >= 0" assertion |
|  3  | 0xfffffff008642094     | 0x30        | 0x20        |                              |
|  4  | 0xfffffff0086428ac     | 0x30        | 0x20        |                              |
|  5  | 0xfffffff0086430c4     | 0x30        | 0x20        |                              |
|  6  | 0xfffffff0086438dc     | 0x30        | 0x20        |                              |
|  7  | 0xfffffff0086440f4     | 0x30        | 0x20        |                              |
|  8  | 0xfffffff00864490c     | 0           | 0           | "Config" / "AppleAVE2UserClient" |
|  9  | 0xfffffff008644dd4     | 0           | 0           | **Prepare** — `S_AVE_UCInParam_Prepare` assertion |
| 10  | 0xfffffff00864526c     | 0           | 0           |                              |
| 11  | 0xfffffff008645708     | 0           | 0           |                              |
| 12  | 0xfffffff008645ba4     | 0           | 0           |                              |

### Key notes

- **Selectors 8–12** have `si=ss=so=sso=0` — the IoKit framework does NOT validate struct sizes for these. The handlers validate internally.
- **Selector 9 = Prepare**: Trampoline at 0x8644dd4 uses `autda x16, #0xcda1; ldr x8, [x16, #0x88]; blraa x8, x16` — authenticated vtable dispatch at offset 0x88. That vtable slot is `0x8644aa8` (the Prepare outer handler).
- **Call chain (Prepare)**: sel-9 trampoline → vtable[0x88] = 0x8644aa8 → 0x86450b4 → 0x86454fc → `AVE_Client_Prepare` (0x8523fb0) → `AVE_AVC_CheckInfo` (0x851c454, via fptr) + allocation
- **ARM64e vtable dispatch**: The function 0x8644aa8 appears to have "zero direct BL callers" because it's dispatched exclusively via `blraa` (authenticated indirect call) — the signed vtable pointer is NOT searchable in DATA_CONST without the signing key.
- **Input struct for Prepare**: `S_AVE_UCInParam_Prepare`. From the code at 0x86454ec–0x86454fc:
  - `x20+0x18` → arg1 to AVE_Client_Prepare
  - `x20+0x228` → arg2
  - `x20+0x338` → arg3
  - `x20+0x28` → arg4

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

## CVE-2026-112689 — Root Cause CONFIRMED (2026-11-04, Mac+Phone joint analysis)

### Corrected understanding: fix is in `AVE_Client_CheckGGMInfo`, NOT in dimension tables

**Earlier hypothesis (wrong)**: fix = new dimension validator `sub_fffffff00853aa34` added to `AVE_AVC_CheckInfo`.  
**Confirmed root cause**: fix = two new out-of-range guards added to `AVE_Client_CheckGGMInfo` before the TOCTOU bypass.

The dimension table data at `__DATA_CONST.__const` is **IDENTICAL** between 26.6.1 and 26.7.2 — all 110 non-null TableHeader pointers resolve to the same values in both versions. The validator function `sub_fffffff00852f9d4` itself is also unchanged.

---

### The Bypass: `AVE_Client_CheckGGMInfo` at 0xfffffff00851dd2c (HEVC path)

This function validates an HEVC encode session's GGM (Global Generic Model) parameters. It is called during the START encode path (after PREPARE allocates buffers).

**Function args:**
- x0 = arg0 (encoder_state, x21 in body)
- x1 = arg1 (some obj, x20 in body)
- x2 = arg2 (codec control flag, x23 in body) — **bit0 = bypass trigger**
- x3 = arg3 (Config struct pointer, x22 in body) — same 0x1a0a0 struct as Sel 1

**Bypass mechanism at VA 0xfffffff00851df84:**

```asm
tbnz  w23, #0, loc_dfb4         ; ← BYPASS: if bit0(arg2) set → skip mismatch check entirely
ldr   w8, [x22, #0x2ec0]        ; read Config[0x2ec0] = mode_flag
cmp   w8, #0x1
b.ne  loc_dfb4                  ; ← BYPASS: if mode_flag ≠ 1 → skip mismatch check entirely
; --- actual PREPARE/START mismatch check (only reached if both bypasses inactive) ---
ldr   w8, [x21, #0x1838]        ; encoder_state[0x1838] = prepared width (set during Sel 9)
ldr   w9, [x22, #0xa58]         ; Config[0xa58] = start width (from new Config struct)
cmp   w8, w9
b.ne  → error                   ; mismatch → error
ldr   w8, [x21, #0x183c]        ; encoder_state[0x183c] = prepared height
ldr   w9, [x22, #0xa5c]         ; Config[0xa5c] = start height
cmp   w8, w9
b.ne  → error
```

**Bypass trigger**: set `Config[0x2ec0]` to any value ≠ 1 (user-controllable via Sel 1 input struct).

---

### The Fix (26.7.2): two new guards at VA 0xfffffff008527b18

```asm
ldr  w8, [x21, #0x1c8]          ; ← NEW: Config[0x1c8] = iLAFrameCnt (LookAhead frame count)
cmp  w8, #0x15                   ;        compare with 21
b.hs → "LookAhead frame count is out of range"  ; always fail before reaching bypass
ldr  w8, [x21, #0x248]          ; ← NEW: Config[0x248] = iNumOfFrame_B (B-frame count)
cmp  w8, #0x4                    ;        compare with 4
b.hs → "B Frame number is out of range"         ; always fail before reaching bypass
; ---- then existing tbnz/mode bypass (still present in 26.7.2) ----
```

Note: in 26.7.2, x21 = arg3 = Config struct (arg assignments changed between versions).

**26.6.1 missing**: NO iLAFrameCnt check before the bypass in `AVE_Client_CheckGGMInfo`. An earlier check at 0xfffffff00851d614 (`ldr w8, [x21, #0x1c8]; cmp w8, #0x15`) is on the PREPARE path, NOT on the START path that calls `AVE_Client_CheckGGMInfo`.

---

### Exploit chain (CVE-2026-112689):

```
1. Sel 0 (init): HEVC codec (eEncType=4)
2. Sel 1 (config): width=64, height=64, iLAFrameCnt=21, mode_flag=0 (at Config[0x2ec0])
3. Sel 9 (prepare): allocates small buffer; sets encoder_state[0x1838/0x183c] = 64/64
4. Sel 1 (reconfig): width=4096, height=4096, same iLAFrameCnt=21, mode_flag=0
5. START selector (10 or 11): calls AVE_Client_CheckGGMInfo via PATH B
   → HEVC dimension validator passes (4096×4096 is valid HEVC)
   → cbz w0 → reaches bypass site
   → mode_flag=0 ≠ 1 → BYPASS ACTIVATED → mismatch check SKIPPED
   → Codec processes 4096×4096 frame into 64×64 buffer → OOB write
```

**Key input struct fields for the bypass:**
- `Config[0xa58]` = ui32Width (start dimensions)
- `Config[0xa5c]` = ui32Height
- `Config[0x2ec0]` = mode_flag — set to 0 to activate bypass
- `Config[0x1c8]`  = iLAFrameCnt — set to 21 to reach bypass via secondary PATH B

---

## Notes / Open Questions

- Which exact selector (10, 11, or 12) calls `AVE_Client_CheckGGMInfo` via PATH B?
- What is PATH B exactly? (the code path that bypasses the 0x851d614 iLAFrameCnt check on the PREPARE path)
- Does calling Sel 1 twice (after Prepare) trigger PATH B?
- Confirm the PoC selector sequence before running on device
