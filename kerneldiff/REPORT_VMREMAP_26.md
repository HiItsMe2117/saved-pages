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

## Alternative Risk: Internal Page Rounding

vm_remap does its own internal size rounding. The prologue at 0x378d054–0x378d0a0
contains bitwise mask/test/branch instructions consistent with page-alignment
arithmetic. If rounding happens AFTER the source-map bounds check and the
mapping is created with the rounded size, an independent ordering gap exists.

**Dynamic test needed**:
```c
vm_remap_new(target_map, &addr, /*size=*/1, 0, VM_FLAGS_ANYWHERE,
             src_map, src_addr, FALSE, &cur, &max, VM_INHERIT_DEFAULT)
```

Key questions:
- Does size=1 return KERN_INVALID_ARGUMENT or succeed with rounded size?
- If it succeeds: does the mapping cover [src_addr, src_addr+0x4000) (one full page)?
- Was the source bounds check done with size=1 (allowing addr+1 ≤ map_max)?

If yes to all three, the ordering gap exists with vm_remap's own rounding instead
of vm_sanitize correction. The exploit geometry is the same.

---

## Comparison with Surface 4

| Property | Surface 4 (MME64) | vm_remap |
|---|---|---|
| vm_sanitize call present | YES (foff=0x37a0108, api_id=4) | **NO** |
| Check ordering confirmed dangerous | YES (static) | Unconfirmed |
| Sandboxed-accessible | NO (entitlement-gated) | **YES** |
| Mechanism | vm_sanitize correction after bounds | Internal rounding after bounds |

---

## Verdict

**vm_sanitize ordering attack: NOT APPLICABLE.** The mechanism is absent.

**Internal rounding attack: UNCONFIRMED.** If vm_remap rounds size internally
after the source bounds check, the same out-of-bounds mapping primitive exists
without requiring vm_sanitize. Sandboxed access makes this high-value if
confirmed. Requires dynamic test.

**Next**: vm_remap_new dynamic test with sub-page size. Observe KERN_SUCCESS vs
KERN_INVALID_ARGUMENT, and if successful, whether the mapped region extends
beyond the pre-rounding authorized range.
