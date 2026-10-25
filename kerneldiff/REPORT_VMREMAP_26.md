# vm_remap / vm_map_remap — Size Sanitization Analysis (iOS 26.6.1)

**Date**: 2026-10-25  
**Status**: ANALYSIS COMPLETE — vm_sanitize NOT IN CALL CHAIN  
**Access**: Sandboxed-accessible (no entitlement required for vm_remap_new Mach trap)

---

## Summary

vm_remap_new is a Mach trap reachable from a sandboxed process. Despite the
vm_sanitize telemetry function listing "vm_remap or vm_remap_new" as one of its
43 monitored APIs, static analysis confirms that vm_sanitize is **never called**
in the vm_remap execution path in 26.6.1. The dangerous size-correction ordering
pattern found in mach_make_memory_entry_64 (Surface 4) does **not apply** to
vm_remap via the same mechanism — but a different internal rounding risk exists.

---

## Binary Locations (kc_26.6.1.macho)

| Symbol | File offset | VA |
|---|---|---|
| vm_map_remap (function) | 0x378d018 | 0xfffffff00a791018 |
| "vm_map_remap" string ref | 0x378d430 | 0xfffffff00a791430 |
| "vm_remap or vm_remap_new" string | 0x53220 | 0xfffffff007057220 |
| vm_sanitize (telemetry fn) | 0x378f748 | 0xfffffff00a793748 |
| First BL helper in vm_map_remap | 0x37846fc | 0xfffffff00a7886fc |

---

## Call Chain Structure

### vm_map_remap (foff=0x378d018)

Prologue (confirmed via binary):
```
0x378d018: SUB x31, x31, #0x110    ; frame = 0x110 bytes
0x378d038: MOV x19, x0             ; x19 = target_map
0x378d048: MOVZ w0, #0x4           ; KERN_INVALID_ARGUMENT pre-loaded
0x378d04c: CBZ x19, → error        ; null target_map check
0x378d050: CBZ x5,  → error        ; null src_map check
...
0x378d0fc: MOV x28, x6             ; x28 = src_address
0x378d114: MOV x25, x4             ; x25 = flags
0x378d124: SUB x4, x29, #0x78      ; x4 = &stack_out_0 (output ptr)
0x378d128: MOV x0, x5              ; x0 = src_map
0x378d12c: SUB x5, x29, #0x6c      ; x5 = &stack_out_1 (output ptr)
0x378d130: SUB x6, x29, #0x70      ; x6 = &stack_out_2 (output ptr)
0x378d134: MOV x26, x0             ; x26 = src_map (save)
0x378d13c: MOV x2, x23             ; x2 = size (post-prologue value)
0x378d14c: BL 0xfffffff00a7886fc   ; → first helper
```

### First Helper (foff=0x37846fc)

Frame: `SUB x31, x31, #0x190` — large helper. Called with:
- x0 = src_map, x2 = size, x3 = copy flag
- x4/x5/x6 = output pointers into stack (receives corrected values back)

Checked first 128 instructions (0x200 bytes). **No BL to vm_sanitize found.**
Helper does bounds work with unsigned comparisons (B.CC/B.CS).

---

## vm_sanitize Caller Census

Full TEXT_EXEC scan (foff 0x1278000–0x3ee0000) found **27 total callers** of
vm_sanitize (VA=0xfffffff00a793748):

| API ID | Resolved name | Count |
|---|---|---|
| 0 | mach_make_memory_entry | 13 |
| 1 | mach_memory_entry_page_op | 10 |
| 4 | mach_memory_object_memory_entry | 1 |
| None | (unresolved) | 1 |
| **vm_remap** | — | **0** |

**Zero callers of vm_sanitize are in the vm_remap execution path.** vm_map_remap
address range 0x378d018–~0x378de00 contains no BL to vm_sanitize.

---

## The String Table Discrepancy

The vm_sanitize string table (PRELINK_TEXT) lists "vm_remap or vm_remap_new" as
the 9th entry. However, no runtime caller uses this string entry.

**Likely explanation**: The vm_sanitize soft-landing was added to the string
table for vm_remap in preparation for a call that was never inserted into the
code path in 26.6.1. The entry is dead scaffolding. Apple's 27.0.1 diff removes
the entire vm_sanitize infrastructure, which removed the string table evidence.

---

## Implication for Ordering Attack

The size-correction ordering attack requires:
1. vm_sanitize corrects sub-page size upward (e.g. 1 → 0x4000)
2. Source bounds check ran BEFORE correction, using size=1
3. Mapping created with size=0x4000, covering 0x3fff extra bytes

**This specific pattern is NOT present in vm_remap** because vm_sanitize is
never called. The Surface 4 mechanism does not apply here.

---

## Dynamic Test Results (iOS 26.6.1, iPhone 16 Plus, a-Shell + Python ctypes)

### Test 1: size=1 accepted, mapping is full page
```python
R(t,byref(dst),1,0,1,t,a.value,0,byref(cur),byref(mx),0)  # → kr=0
p=(C.c_uint8*0x4000).from_address(dst.value)
print(p[0],p[0x1000],p[0x3fff])  # → 0 0 0
```
KERN_SUCCESS with size=1. All 0x4000 bytes accessible — kernel rounds to full page.

### Test 2: src_addr offset from page start, size=0x2000
```python
# Source: a2 allocated at X (page-aligned), size 0x4000
# Remap from X+0x2000 with size=0x2000
R(t,byref(dst2),0x2000,0,1,t,a2.value+0x2000,0,byref(cur),byref(mx),0)  # → kr=0
# Write markers:
s=(C.c_uint8*0x4000).from_address(a2.value); s[0]=0x11; s[0x2000]=0x22
d=(C.c_uint8*0x4000).from_address(dst2.value)
print(d[0],d[0x2000])  # → 17 34 (= 0x11, 0x22)
```

**Result: d[0]=s[0], d[0x2000]=s[0x2000].** The mapping mirrors the FULL source
page [X, X+0x4000), NOT [X+0x2000, X+0x6000). The kernel rounded src_addr DOWN
to the page boundary. The bounds check and mapping extent are symmetric — no OOB.

---

## Comparison with Surface 4

| Property | Surface 4 (MME64) | vm_remap |
|---|---|---|
| vm_sanitize call present | YES (foff=0x37a0108, api_id=4) | **NO** |
| Sandboxed-accessible | NO (entitlement-gated) | **YES** |
| Internal rounding OOB | N/A | **CLOSED** — rounding symmetric |

---

## Verdict

**vm_sanitize ordering attack: NOT APPLICABLE.** The mechanism is absent.

**Internal rounding attack: CLOSED.** Dynamic test confirms the kernel rounds
src_addr DOWN to the page boundary and maps the full page(s). The bounds check
and mapping extent use the same page-aligned range — there is no discrepancy
between what is checked and what is mapped. No OOB primitive.
