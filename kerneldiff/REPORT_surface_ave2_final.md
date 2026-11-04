# Surface AVE2 / Surface E — DPB Buffer-Size Overflow: Final Analysis

**Date:** 2026-11-04  
**Target:** iPhone 16 Plus (iPhone17,4) · iOS 26.6.1 (23G83)  
**Status:** DEFINITIVELY CLOSED — DART IOMMU blocks OOB write  

---

## 1. Vulnerability Mechanics (confirmed)

`DPB_unit × NTL` computed in **32-bit arithmetic** in AVE2 firmware. With 4K HEVC
(`CTU_W=60, CTU_H=34`, 1024 bytes/sample):

```
DPB_unit = 60 × 34 × 1024 = 2,088,960 bytes
NTL = 2057
DPB_unit × NTL = 4,296,990,720  →  32-bit truncation  →  2,023,424 bytes
```

GROOM_SIZE = **2,023,424 bytes** (kernel-confirmed: `alloc=2023424 gap=0` — no 16KB rounding).  
First OOB write: DPB[1] at stride DPB_unit = 2,088,960 bytes past DPB base.  
OOB offset: `2,088,960 - 2,023,424 = 65,536 bytes` past allocation end.

---

## 2. DART IOMMU Architecture

DPB is DMA memory accessed by AVE2 firmware through the **DART** (Device Address
Resolution Table — Apple's IOMMU). Mapped via `AVE_Client_DARTMapDataSurfaces`:

```
FwLog template (kc_26.6.1 offset 0x28ac1b):
  "FwLog %p %d | Phy 0x%lx Kernel 0x%lx DART 0x%llx | %d %d %d | %d %d"
```

Empirically observed (syslog, 2026-11-03):
```
Phy  0x10014d54000
DART 0x10000280000
alloc_size = 2,023,424 bytes
```

DART mapping covers exactly `[DART_base, DART_base + 2,023,424)`.  
DPB[1] write targets `DART_base + 2,088,960` — **65,536 bytes past** the DART mapping end.

---

## 3. DART Exception Handling (non-fatal, kext RE)

Firmware access to unmapped DART address → hardware raises `DARTHwException`.  
AppleAVE2 kext handler (VA `0x8530800`): logs the fault, **returns 0** (success).  
Write silently discarded by DART hardware — never reaches DRAM.

---

## 4. IPC Path — No Kernel VA Misuse (kext RE)

AVE2 kext IPC buffer management (`~0x85fbXXX`):
- `w1` = firmware-supplied buffer **INDEX** (0–3), bounds-checked against kext surface table
- Kernel VA resolved from kext's own `AVE_Client_DARTMapDataSurfaces` tables
- Firmware never supplies a kernel VA — no path for OOB access to influence a kernel pointer

---

## 5. Empirical Evidence

### 5a. All-zero backing buffer scan (2026-11-03 18:12)

```
[18:12:17] GROOM=2023424 DPB_UNIT=2088960 OOB_OFFSET=65536
[18:12:18] victim[0] id=302 @offset=65536 base_data=0000000000000000 nonzero_bytes=0
[18:12:34] victim[0] backing buffer all-zero (no OOB write detected)
```

16 IOSurface victims at OOB_OFFSET=65,536. All zeros after 5-frame encode. DART discarded.

### 5b. Frame 4 stall (2026-11-04 08:15, PoC v4)

```
frame 0–3: encode_st=0x0  (immediate)
frame 4:   encode_st=0x0  (120-second stall)
```

DPB[4] at `DART_base + 8,355,840` — far outside DART mapping → DART IRQ → firmware
DMA stall for 120s. Frames 1–3 OOB are within silent-discard range; frame 4 is not.

### 5c. Pool mismatch (additional)

DPB: `kmem_alloc_contig` (physically contiguous pool).  
IOSurface victims: regular pool.  
Pool segregation prevents physical adjacency even without DART.

---

## 6. Verdict: CLOSED

| Defense | Layer | Mechanism |
|---------|-------|-----------|
| DART IOMMU | Hardware | Unmapped DMA → silent discard or stall |
| DARTHwException non-fatal | Kext | Handler returns 0 → write silently lost |
| IPC bounds-checked index | Kext | Firmware supplies index only, never kernel VA |
| Pool isolation | Allocator | `kmem_alloc_contig` vs IOSurface — never physically adjacent |

**No exploit path without a DART bypass (no public bypass for A18/iOS 26) or a separate
AVE2 attack surface not involving DPB (e.g. IOKit SetSessionSettings — unexplored).**

---

## 7. Files

| File | Contents |
|------|----------|
| `ave2_groom_poc.py` | PoC v4 — feeder pattern, multi-frame, CFRelease, 1250 MB memory gate |
| `REPORT_ave2_heap_grooming.md` | Heap groom development log |
| `Latest.md` | Full session state, DPB analysis detail (lines 434–558) |
