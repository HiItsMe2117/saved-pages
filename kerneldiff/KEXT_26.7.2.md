# AppleAVE2 — iOS 26.7.2 (23H128, build iPhone17,4)

**Binary**: com.apple.driver.AppleAVE2  
**Source version**: 905.43.1 (905.40.1 base + security patches)  
**OTA**: `~/kerneldiff_ave2/iOS26.7.2_OTAs/iPhone17,4_23H128_KEY_[...].aea` (8.7 GB)  
**Kernelcache**: `~/kerneldiff_ave2/26_7_2/23H128__iPhone17,4/AssetData/boot/kernelcache.release.iphone17`  
**Kext**: `~/kerneldiff_ave2/26_7_2/kexts/com.apple.driver.AppleAVE2` (2.6 MB)

## Section Map (26.7.2 vs 26.6.1)

| Section       | 26.6.1 VA            | 26.7.2 VA            | 26.6.1 size | 26.7.2 size | Delta      |
|---------------|----------------------|----------------------|-------------|-------------|------------|
| __TEXT_EXEC   | 0xfffffff0084c24b0   | 0xfffffff0084ca550   | —           | —           | +0x80a0    |
| __text        | 0xfffffff0084c24b0   | 0xfffffff0084ca550   | 0x1a0ccc    | **0x1a3d8c** | **+0x30c0** |
| __cstring     | 0xfffffff00728cde0   | 0xfffffff00728cde0   | 0x414f2     | **0x42301**  | **+0xe0f** |
| __os_log      | 0xfffffff0072ce2d2   | 0xfffffff0072cf0e1   | 0x53818     | 0x54874     | +0x105c    |

**TEXT grew +12,480 bytes** (new validation code) · **cstring grew +3,599 bytes** (new error strings)

---

## Blackwing Progressive Audit Context

**CVE-2026-64747** (iOS 26.6 — ALREADY PATCHED on target 26.6.1):
- Researcher: Franco Belman, Blackwing Intelligence
- Fix: "better size validation" — same component, same researcher
- 26.6.1 kext already has this fix; 26.5 kext does NOT

**CVE-2026-112689** (iOS 26.7.2 — **OPEN on target 26.6.1**):
- Researcher: Franco Belman, Blackwing Intelligence (follow-up audit)
- Fix: "improved input validation" — adjacent/same code path as 64747
- The 26.6 fix plugged parameter A; 112689's fix plugged parameter B in the same function

**Pattern**: Two separate parameters in the same size calculation function, each unvalidated, found in sequential audits by the same researcher.

---

## CVE Patches in iOS 26.7.2 — AVEVideoEncoder (5 total, all OPEN on 26.6.1)

| CVE               | Researcher                                      | Type       | Impact                                   | Fix description                 |
|-------------------|-------------------------------------------------|------------|------------------------------------------|---------------------------------|
| CVE-2026-112705   | Marco Schmitt, Andrey Chernykh, Josh Maine (Calif.io) | OOB write | System termination only            | Improved bounds checking        |
| CVE-2026-112689   | Franco Belman (Blackwing Intelligence)          | OOB write  | **Terminate OR corrupt kernel memory**   | Improved input validation       |
| CVE-2026-112470   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112468   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112469   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112466   | Hcamael + 章鱼哥@aipy                            | **OOB read** | **Terminate OR read kernel memory**    | Improved input validation       |

**Key insight — Hcamael had a full chain:**
- CVE-2026-112466 (OOB read) = **KASLR bypass** / kernel memory leak
- CVE-2026-112470/468/469 (OOB write) = **kernel memory corruption**
- Read first → get kernel addresses → then write to known targets
- 4 CVEs from one team = same component, likely same code path, 4 distinct buffer types

**CVE-2026-112705 (Calif.io):**
- "System termination only" — no kernel corruption impact in Apple's notes
- Likely hits a buffer that's not on the kernel heap (or write lands in non-critical memory)
- Lower priority for exploit chain

---

## CVE-2026-112689 — Binary Patch Located (2026-11-04)

### Patch type: NEW function inserted

**New function in 26.7.2 (doesn't exist in 26.6.1)**:  
`sub_fffffff00853aa34` — frame dimension validation against codec-level table

**Three call sites** (all NEW in 26.7.2 — NONE exist in 26.6.1):

| Call site VA        | Codec     | w1 arg | w2 arg | Containing function |
|---------------------|-----------|--------|--------|---------------------|
| 0xfffffff008524700  | AVC       | #1     | #1     | AVE_AVC_CheckInfo   |
| 0xfffffff008524df0  | HEVC      | #?     | #?     | AVE_HEVC_CheckInfo  |
| 0xfffffff0085278cc  | HEVC var. | #4     | #2     | HEVC variant        |

**Implication**: BOTH AVC and HEVC dimension bypass are OPEN on 26.6.1. The PoC can target either codec.

**Call site**: `AVE_AVC_CheckInfo` at 0xfffffff0085244f4 (26.7.2)
- Was: `AVE_AVC_CheckInfo` at 0xfffffff00851c454 (26.6.1)
- Stack frame grew: 0x90 → 0xa0 (+16 bytes for new local variables)
- New error message: `"frame dimension is out of range %d %d %d\n"`

### New call inserted in 26.7.2 AVE_AVC_CheckInfo:

```asm
; 26.7.2 — AFTER existing iNumViews/iLayerNum checks pass:
0xfffffff0085246e8:  mov x0, x19   ; encoder state
0xfffffff0085246ec:  mov w1, #0x1  ; codec type AVC=1
0xfffffff0085246f0:  mov w2, #0x1  
0xfffffff0085246f4:  mov x3, x22   ; frame width-related [x21, #0xa58]
0xfffffff0085246f8:  mov x4, x23   ; frame height-related [x21, #0xa5c]
0xfffffff0085246fc:  mov w5, #0x1
0xfffffff008524700:  bl sub_fffffff00853aa34  ← NEW DIMENSION VALIDATION
0xfffffff008524704:  cbz w0, loc_fffffff008524830  ; success → continue
; else: "frame dimension is out of range" → return error
```

**HEVC call site (0x5278cc)** loads same struct fields before call:
```asm
0xfffffff0085278b4:  ldr w3, [x21, #0xa58]   ; same frame width field
0xfffffff0085278b8:  ldr w4, [x21, #0xa5c]   ; same frame height field
0xfffffff0085278bc:  mov x0, x19
0xfffffff0085278c0:  mov w1, #0x4             ; codec=HEVC
0xfffffff0085278c4:  mov w2, #0x2
0xfffffff0085278c8:  mov w5, #0x1
0xfffffff0085278cc:  bl sub_fffffff00853aa34
```

**This call does NOT exist in 26.6.1.** The function at 0x851c454 jumps directly to allocation after the iNumViews/iLayerNum checks.

### New checker function logic (sub_fffffff00853aa34):

1. Calls `sub_fffffff0085428ac` (table lookup) → pointer to codec-level dimension table
2. Table is in `__DATA_CONST.__const` at VA `0xfffffff007dbfd88`
3. Table indexed by: codec level (arg w0, max 34 entries × 72 bytes) + codec type (AVC/HEVC/etc.)
4. Iterates through table entries: `(min_a, max_b, flags)` per entry
5. If frame params don't satisfy ANY entry → returns `0xfffffc16` (error)
6. If match found → returns 0 (success)

### Dimension fields (struct offsets in VideoParams):
- Offset `0xa58` → width-related value (macroblock width? frame width?)
- Offset `0xa5c` → height-related value

### Codec type dispatch (sub_fffffff0085428ac):
- w1=1, w2=1 → table index 4 (AVC main)
- w1=1, w2=2 → table index 5 (AVC high?)
- w1=2 → table index 3
- w1=3 → table index 2
- w1=4 → table index 1 (HEVC)
- w1=5 → table index 0 (AV1)

### Error strings added in 26.7.2 (across all codecs):
```
"frame dimension is out of range %d %d %d\n"          ← AVC (3 dims)
"frame dimension is out of range %d %d %d %d\n"       ← HEVC (4 dims)
"frame dimension doesn't match between prepare [%d %d] and start [%d %d] %p %lld %d\n"
"frame dimension is out of range %p %lld %d %d %d\n"
"frame dimension out of range %p %lld %d %d %d %lld %lld\n"
```

---

## CVE-2026-112689 Exploit Path (open on 26.6.1)

The check at struct offsets `[x21, #0xa58]` / `[x21, #0xa5c]` does NOT exist in 26.6.1.  
Any frame dimensions passing the iNumViews/iLayerNum bounds flow unchecked into CalcBufSizeOf.

**Attack**: Provide frame dimensions outside the codec level's supported range → CalcBufSizeOf computes wrong buffer size → allocation too small → OOB write on kernel heap.

---

## Diff Summary (radiff2 results)

- **27 NEW functions in 26.7.2** (complete rewrites or entirely new validation code)
- Most significant cluster: VA range 0x851c454–0x852e0b8 in 26.6.1 → completely rewritten in 26.7.2
- Key NEW function: `sub_fffffff00853aa34` (dimension validator, 184 bytes)
- CalcBufSizeOf functions that CHANGED: LFSResult, EntropyCoding, MCTFOutput, Colocated (struct layout deltas, also possible fix in calc logic)

---

## CalcBufSizeOf Functions Status

| Function            | Status in 26.6.1 | 26.7.2 change     | Notes                              |
|---------------------|------------------|-------------------|------------------------------------|
| LFSRef              | Candidate        | **UNCHANGED**     | Byte-identical — NOT the CVE patch |
| LFSResult           | Candidate        | Changed (19 instr) | Struct layout + possible fix      |
| EntropyCoding       | Candidate        | Changed (15 instr) | Struct layout + possible fix      |
| MCTFOutput          | Candidate        | Changed (14 instr) | Struct layout + possible fix      |
| Colocated           | Safe (smull)     | Changed (20 instr) | Only struct layout delta           |
| SrcNeighborData     | Safe (64-bit)    | —                 | —                                  |
| All others          | Pending          | —                 | —                                  |

---

## CVE-2026-112468/469/470 — Write Loop Bounds Fix (2026-11-04 analysis)

### Fix type: TYPE-SYSTEM REFACTOR (not a simple CMP addition)

The "improved bounds checking" for the 3 OOB write CVEs is NOT a simple `CMP + B.GT` insertion into existing write loops. The fix is a large-scale type-system change:

**Evidence**:
- 306 new functions in 26.7.2 (by 16-instruction prologue comparison)
- Entire range 0x8530000–0x8540000 is BRAND NEW (90+ new functions, all with no 26.6.1 counterpart)
- Tiny new functions (~68–88 bytes) appear in CLUSTERS at: 0x8515f78, 0x8572238, 0x858b2ac, 0x85b2f7c, 0x864dcc8, 0x865c008 — multiple codec variants of the same constructors/destructors
- 736B new functions at 0x8541b84 and 0x8541e64 — complex object initializers
- These patterns = new bounded-buffer OBJECT TYPES being introduced

**What the fix likely does**: Replaces raw pointer + raw count with a NEW SAFE BUFFER TYPE that enforces `write_count ≤ allocated_count` internally. Write loops now call a method on the safe type rather than directly indexing a raw pointer.

**Why allocation is UNCHANGED**: CalcBufSizeOf functions remain byte-identical because the ALLOCATION SIZE FORMULA is correct. The bug was that the WRITE SIDE used a different (wrong) count, not that the allocation used a wrong size.

**Where the new code lives**: The 90+ new functions in 0x853xxxx are the new safe-buffer type implementations (constructors, destructors, method dispatch, codec-variant wrappers). The write loops in the encode path now call into these new types.

**Existing function changes**: 212 diffs in the 2347-instruction allocation function (0x84edaf8) are ALL struct layout changes — the new bounded-buffer type fields were added to the main encoder session struct, shifting all struct field offsets. These changes are CONSEQUENCES of the type-system fix, not the fix itself.

---

## Notes

- **THIS is the minimal diff**: only security patches in 905.43.1 vs 905.40.1
- The changes in LFSResult/EntropyCoding/MCTFOutput are **struct layout only** (confirmed: ALL 212 diffs in main allocation function are struct field offset changes)
- The CVE-2026-112468/469/470 fix is in the 90+ new functions in range 0x853xxxx
- The 27.0.1 kext is a MAJOR rewrite — not useful for isolating these CVE patches
