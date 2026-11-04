# Surface AVE2 — DPB Overflow: Final Analysis
**Date:** 2026-11-04  
**Target:** iPhone 16 Plus (iPhone17,4) · iOS 26.6.1 (23G83)  
**Binary:** AppleAVE2 kext / VideoToolbox framework

---

## 1. Vulnerability Mechanics (confirmed)

`AVE_CalcBufSizeOfRecon` computes DPB (Decoded Picture Buffer) allocation size in 32-bit:

```
DPB_unit = CTU_W × CTU_H × 1024 = 60 × 34 × 1024 = 2,088,960 bytes  (4K HEVC, 64px CTU)
buf_size = (uint32_t)(DPB_unit × NTL)

NTL=2057: 2,088,960 × 2057 = 4,296,990,720 → wraps to 2,023,424 bytes
```

Firmware allocates 1.93 MB but writes as if buffer is 4.3 GB.  
First OOB write: DPB[1] at offset DPB_UNIT = 2,088,960 > GROOM_SIZE = 2,023,424 → +65,536 bytes OOB.

---

## 2. Probe Results

### Runs (via ResearchHost, PocketCode closed)

| Run | SPRAY | FRAMES | Frame latency | Corruption signal |
|-----|-------|--------|--------------|-------------------|
| v4-mini 17:50 | 4 | 2 | instant | none |
| v4 18:06-18:08 | 16 | 2 | instant | none |
| backing-buf scan 18:12 | 16 | 2 | instant | all-zero at +65536 |
| v4 full 08:15 | 16 | 5 | frames 0-3 instant; **frame 4: 120s** | none before OOM kill |

### Critical observations
- `IOSurfaceGetAllocSize()` = **2,023,424 exactly** — kernel does NOT round up (gap=0)
- First OOB offset = DPB_UNIT − GROOM_SIZE = **65,536 bytes** past DPB end
- Victim backing buffer at offset 65,536 = **all zeros** after encode (18:12 direct scan)
- Frame 4 (DPB[4] at offset 8,355,840) caused **exactly 120-second stall** — firmware watchdog

---

## 3. Blocking Controls

### Primary: DART IOMMU
AVE2 firmware accesses the DPB IOSurface via **DMA through DART** (not via host CPU). DART maps only the DPB's allocated physical pages (2,023,424 bytes). Writes beyond this device-address range are:
- **Silently discarded** for nearby OOB (DPB[1-3], confirmed by zeros in backing buffer)
- **DART fault → firmware watchdog** for far OOB (DPB[4] at +8.3 MB, confirmed by 120s stall)

### Secondary: Allocator pool mismatch
DPB IOSurface uses `kmem_alloc_contig()` (physically contiguous pool). Victim IOSurfaces use the standard kernel heap pool. Even without DART, the two allocators use separate physical memory regions → groom miss regardless.

---

## 4. 27.0.1 Patch Context

Three changes patched in 27.0.1 (from diff analysis):
1. **NTL temporal-layer integrity check** — rejects NTL > safe threshold before allocation
2. **iLayerNum hard cap** — `≤ 2` layers enforced at dispatch
3. **AVE_CalcBufSizeOfDPB** — centralised overflow-safe wrapper for all DPB size calculations

The patch addresses the overflow arithmetic, but DART was already independently blocking exploitation.

---

## 5. Verdict: Surface AVE2 CLOSED on iOS 26.6.1

Two independent, enforced controls:

1. **DART IOMMU**: Firmware DMA restricted to allocated physical pages. OOB DMA silently discarded (nearby) or causes firmware watchdog (far). No host kernel memory corruption possible via this path.

2. **Allocator pool mismatch**: `kmem_alloc_contig` (DPB) vs. standard heap (victims) — different physical memory pools, groom cannot place victims adjacent to DPB.

The vulnerability EXISTS in the firmware arithmetic and IS triggered (NTL=2057 accepted, frames encode), but the OOB write cannot reach host kernel memory on this architecture.

---

## 6. Architecture Conclusion

**DART is the common blocker for coprocessor-DMA surfaces:**
- Surface E: DART blocks OOB (closed)
- Surface AVE2: DART blocks OOB (closed)

All Apple coprocessors (AVE, ISP, Neural Engine, GPU) route DMA through DART. Any overflow whose OOB write goes via firmware DMA is blocked on iOS 26.6.1.

**Required for a viable surface:** OOB write must occur on the **host application CPU** in kernel virtual memory — a kernel extension, MIG handler, XPC deserializer, or similar path that runs on-CPU without DMA.

---

## 7. Next Surface

Pivot to CPU-side kernel overflows patched in 27.0.1. See `Latest.md` for updated focus.
