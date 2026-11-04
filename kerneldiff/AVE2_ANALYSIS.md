# AppleAVE2 CVE Research — Connecting Analysis

**Target device**: iPhone 16 Plus (iPhone17,4) · iOS 26.6.1 (23G83)  
**Goal**: Identify CPU-side kernel overflow in AppleAVE2 usable for kernel R/W primitive  
**CVEs patched in 26.7.2**: CVE-2026-112689, CVE-2026-112468/469/470 (all AVEVideoEncoder)

---

## Architecture: Why CPU-side Only

All AVE2 firmware DMA is routed through DART IOMMU. Any buffer overflow whose OOB write goes through firmware DMA is silently discarded (DART truncates to allocated physical pages). This was confirmed experimentally for:
- Surface E: DART blocks OOB (confirmed)
- AVE2 DPB (Recon): DART blocks OOB (confirmed, NTL=2057 test)

**Required**: OOB write must happen in kernel extension code running on the host application CPU, without DMA.

---

## CPU-side Buffer Map (26.6.1 CalcBufSizeOf functions)

| Buffer              | Backing    | NTL multiplier | Key arithmetic      | Status               |
|---------------------|------------|----------------|---------------------|----------------------|
| MBInputCtrl         | kalloc     | NO (per-frame) | smull (safe main)   | Safe                 |
| MBStats             | kalloc     | ?              | not analyzed        | pending              |
| CodedData           | kalloc     | ?              | not analyzed        | pending              |
| StaticAreaCBP0Cntr  | kalloc     | ?              | not analyzed        | pending              |
| StaticAreaQPModInfo | kalloc     | ?              | not analyzed        | pending              |
| Colocated           | kalloc     | NO (per-frame) | smull (safe)        | Safe                 |
| LFSRef              | kalloc     | UNKNOWN        | 32-bit mul, weak tbnz | **Candidate**     |
| HSCOutput           | kalloc     | ?              | not analyzed        | pending              |
| LFSResult           | kalloc     | UNKNOWN        | 32-bit mul          | **Candidate**        |
| LRSResult           | kalloc     | ?              | not analyzed        | pending              |
| SrcNeighborInfo     | kalloc     | ?              | not analyzed        | pending              |
| SrcNeighborPixel    | kalloc     | ?              | not analyzed        | pending              |
| SrcNeighborData     | kalloc     | NO             | 64-bit (safe)       | Safe                 |
| SrcNeighborFwData   | kalloc     | ?              | not analyzed        | pending              |
| EntropyCoding       | kalloc     | UNKNOWN        | 2× 32-bit mul chain | **Candidate**        |
| MCTFOutput          | kalloc     | UNLIKELY       | multiple 32-bit mul | Probably safe        |
| Recon (DPB)         | IOSurface  | YES (NTL)      | 32-bit overflow     | DART-blocked (closed)|

---

## CalcBufSizeOf Arithmetic Summary

All analyzed functions:
- **Main/modern paths** (level ≥ 30): use `smull` (64-bit) → SAFE at any resolution
- **Legacy paths** (level < 30): use 32-bit `mul` → overflow requires extreme resolutions
- **Resolution limit**: Even the smallest overflow threshold found (~53K × 53K for EntropyCoding) is far beyond any real VideoToolbox session

**Updated conclusion (2026-11-04)**: CVE-2026-112689 IS a frame dimension validation bypass. The fix in 26.7.2 added a new function that checks frame dimensions against codec-level macroblock limits BEFORE allocation. In 26.6.1 these dimensions flow unchecked into CalcBufSizeOf, potentially causing undersized allocations.

---

## CVE Pattern Analysis

### CVE-2026-112689 — Blackwing — "improved input validation" ✅ CONFIRMED (2026-11-04)
- **Exact fix located**: New function `sub_fffffff00853aa34` added in 26.7.2
- Called from `AVE_AVC_CheckInfo` (26.7.2 at 0x5244f4) after iNumViews/iLayerNum checks
- Validates frame dimensions at struct offsets `[x21, #0xa58]` / `[x21, #0xa5c]` against codec-level macroblock table in `__DATA_CONST.__const` (0xfffffff007dbfd88)
- In 26.6.1 (0x851c454): this call does NOT exist → dimensions flow directly to CalcBufSizeOf
- Error string added: `"frame dimension is out of range %d %d %d\n"` (3 dims = width, height, total_mbs?)
- Also added for HEVC (4 dims), plus "frame dimension doesn't match prepare/start" check

### CVE-2026-112468/469/470 — Hcamael + 章鱼哥 — "improved bounds checking" (3 CVEs, OOB write)
- Impact: "corrupt kernel memory" — these hit kernel heap buffers
- Fix: correct the bounds check in a write loop (not the allocation)
- 3 separate CVEs = 3 different buffer types with the same kind of write OOB
- Pattern: `for (i=0; i<wrong_count; i++) buf[i] = data` where wrong_count > allocated_count

### CVE-2026-112466 — Hcamael + 章鱼哥 — "improved input validation" (OOB read)
- Impact: "read kernel memory" — **KASLR bypass / kernel info leak**
- Fix: bounds check on input parameter before the read index is computed
- Likely: same code path as the write CVEs, but a different access (read before write in encode pipeline)
- **Chain role**: use OOB read first to leak kernel VAs, then use OOB write to corrupt known targets

### CVE-2026-112705 — Calif.io (Marco Schmitt, Andrey Chernykh, Josh Maine) — "improved bounds checking"
- Impact: "unexpected system termination" only — no kernel corruption
- Fix: bounds check on a write
- Likely a buffer in non-critical memory (stack local, or a user-space-visible region) — lower chain value
- 3-researcher team suggests a separate independent audit, not connected to Hcamael or Blackwing

### Hcamael's Full Chain (open on 26.6.1)
```
CVE-2026-112466 (OOB read)  → leak kernel VA → KASLR bypass
CVE-2026-112468/469/470     → OOB write to known kernel heap target
                            → type confusion / fake vtable
                            → kernel R/W primitive
```

---

## Diff Strategy (pending 26.7.2 extraction)

Once 26.7.2 kext is available:

```python
# Step 1: Find changed functions by comparing bytes
ave2_26 = open("23G83/kexts/com.apple.driver.AppleAVE2", "rb").read()
ave2_2672 = open("26_7_2/kexts/com.apple.driver.AppleAVE2", "rb").read()

# Since same source version base, function order should be same
# Diff the __TEXT_EXEC sections at their respective offsets
# Any changed bytes = patched function
```

**What to look for in diff:**
- `mul` → `smull` change (arithmetic fix)
- New `cmp wX, #N` before a `mul` (input validation)
- Changed loop bounds (write OOB fix)

---

## Full Chain (goal)

```
CVE-2026-112689 → undersized CPU-side buffer
   → exploit write loop (OOB)
   → kernel heap corruption
   → type confusion / fake vtable
   → kernel R/W primitive
   → AMFI bypass
   → SpringBoard code injection
   → show Mac battery in status bar
```

---

## Version Timeline

| Version | Build  | AVE2 source ver | Notes                                          |
|---------|--------|-----------------|------------------------------------------------|
| ≤26.5   | ?      | ?               | CVE-2026-64747 **OPEN** (Blackwing/Franco Belman) |
| 26.6    | ?      | ?               | CVE-2026-64747 fixed — "better size validation" in AVEVideoEncoder |
| 26.6.1  | 23G83  | 905.40.1.0.0    | **Target** — 26.6 fix applied; CVE-2026-112689/468/469/470 still open |
| 26.7.2  | 23H128 | 905.40.x?       | CVE-2026-112689/468/469/470 fixed              |
| 27.0.1  | 24A446 | 905.50+?        | Major rewrite — new encoder features + patches|

**Key insight**: Franco Belman (Blackwing) found TWO separate AVEVideoEncoder bugs:
- CVE-2026-64747 (26.6 fix): "better size validation" — one parameter left unvalidated
- CVE-2026-112689 (26.7.2 fix): "improved input validation" — a *different* parameter in adjacent/same code path

The progressive audit pattern suggests the two bugs are in the same function or call chain. The 26.6 fix plugged parameter A; parameter B was missed and found in the follow-up audit.

**Three-way diff strategy** (most informative):
1. iOS 26.5 kext → 26.6.1 kext: shows what 64747's fix added (reference template)
2. 26.6.1 kext → 26.7.2 kext: shows what 112689's fix added (the **target open surface**)

Pre-26.6 OTA not yet downloaded. `ipsw download ota --platform ios --version 26.5 --device iPhone17,4`
