# mach_memory_entry_page_op: vm_sanitize Ordering Analysis (iOS 26.6.1)

*Generated 2026-10-26 | Static analysis of kc_26.6.1.macho*

---

## Summary

mach_memory_entry_page_op has **10 callers** to vm_sanitize (api_id=1) in 26.6.1.
Static analysis of all 10 call sites confirms the **Surface 4 ordering vulnerability does
NOT apply here**. The structural reason: Surface 4 depends on bounds checks firing BEFORE
vm_sanitize so the check uses the original (un-corrected) size. In page_op callers, the
only bounds validation is vm_sanitize itself — there is no pre-BL check against which a
corrected value could escape.

**Status: CLOSED — different call-site structure, no exploitable ordering gap.**

---

## vm_sanitize Calling Convention for page_op (api_id=1)

vm_sanitize entry (foff=0x378f748) saves:
```
0x378f778: MOV x22, x2   ; x22 = arg2 (limit/entry_size)
0x378f780: MOV x19, x3   ; x19 = arg3 = api_id (= 1 for page_op)
0x378f784: MOV x20, x0   ; x20 = arg0 (map/entry pointer)
0x378f7bc: MOV x26, x4   ; x26 = arg4 (output pointer — stack address)
```

Internal overflow check at function entry:
```
0x378f7b8: ADDS x8, x1, x22   ; check: arg1 (offset) + arg2 (limit) overflow?
0x378f7bc: MOV x26, x4
0x378f7c0: B.CS 0x378fda0     ; overflow → error return
0x378f7d0: SUBS x31, x10, x9  ; further range check inside vm_sanitize
0x378f7d4: B.LS 0x378fda0     ; out-of-range → error return
```

For page_op callers: **vm_sanitize performs both the overflow check (ADDS x8, x1, x22)
and the range validation (SUBS x31, x10, x9) internally.** The callers do not replicate
these checks before the BL.

Caller calling convention:
```
x0 = map/named_entry object
x1 = offset (page offset into the named entry)
x2 = limit (named entry size — upper bound for offset)
x3 = 1  (api_id = mach_memory_entry_page_op)
x4 = ADD sp, #N  (output pointer for corrected offset)
```

---

## All 10 Call Sites

### Pattern 1: Single-BL sites (6 callers)

Common shape — no pre-BL bounds check using the same values:

**0x3667d88 (VA=0xfffffff00a66bd88):**
```
0x3667d78: LDR x4, [sp, ...]      ; x4 = output ptr
0x3667d7c: MOV x1, x22            ; x1 = offset
0x3667d80: MOV x2, x19            ; x2 = limit (x19)
0x3667d84: MOVZ w3, #1
0x3667d88: BL vm_sanitize
0x3667d8c: CBZ w0, continue       ; check return code
```

**0x36bc4ac (VA=0xfffffff00a6c04ac):**
```
0x36bc498: BL <prep_helper>
0x36bc49c: [load entry]
0x36bc4a0: MOV x1, x22            ; x1 = offset
0x36bc4a4: MOV x2, x19            ; x2 = limit
0x36bc4a8: MOVZ w3, #1
0x36bc4ac: BL vm_sanitize
; No ADDS/B.CS before BL — no pre-correction overflow check
```

**0x3680d5c and 0x3680d74** (two consecutive BLs in same function, same x19 as limit):
```
0x3680d4c: ADD x4, sp, #0x24    ; output ptr
0x3680d50: MOV x1, x24
0x3680d54: MOV x2, x19          ; x2 = x19 (limit)
0x3680d58: MOVZ w3, #1
0x3680d5c: BL vm_sanitize        ; <- site 1
0x3680d60: [load entry again]
0x3680d64: ADD x4, sp, #0x10    ; new output ptr
0x3680d68: MOV x1, x23
0x3680d6c: MOV x2, x19          ; same limit
0x3680d70: MOVZ w3, #1
0x3680d74: BL vm_sanitize        ; <- site 2
0x3680d78: SUBS x19, x20, x21   ; post-BL: recomputes x19 (NOT a bounds check on result)
```

**0x3681b08 (VA=0xfffffff00a685b08):**
```
0x3681ab8: SUBS x1, x22, x21    ; loop termination guard (NOT a size bounds check)
0x3681abc: B.LS 0x3681adc       ; if empty range, skip loop body
  ... (loop body) ...
0x3681afc: MOV x1, x20          ; fresh arg1
0x3681b00: MOV x2, x21          ; x2 = x21 (limit)
0x3681b04: MOVZ w3, #1
0x3681b08: BL vm_sanitize
0x3681b0c: SUBS x2, x19, x22   ; post-BL: x2 recomputed from different regs
```
The pre-BL SUBS at 0x3681ab8 is a loop termination guard (x22 > x21 -> continue
iterating). It does NOT check offset+size bounds, and its inputs (x22, x21) are
not the same as vm_sanitize's inputs (x20, x21). No ordering gap.

**0x36cd8d8 (VA=0xfffffff00a6d18d8):**
```
0x36cd890: SUBS x2, x22, x25    ; loop guard (same pattern)
0x36cd894: B.LS 0x36cd8ac
  ...
0x36cd8cc: MOV x1, x21
0x36cd8d0: MOV x2, x23
0x36cd8d4: MOVZ w3, #1
0x36cd8d8: BL vm_sanitize
```

---

### Pattern 2: 3-BL cluster (callers 0x373eb2c, 0x373ebb0, 0x373ec04)

These three BL sites are in a single function that loops over multiple named entries.

**Pre-BL overflow check present:**
```
0x373eacc: MOVZ w9, #0x3FFF       ; page_mask (16KB - 1)
0x373ead0: LDR x8, [sp, ...]      ; x8 = accumulated offset from stack
0x373ead4: ADD x0, x26, x8        ; x0 = x26 + x8
0x373ead8: ADDS x9, x0, x9        ; OVERFLOW CHECK: (x26 + x8) + 0x3FFF
0x373eadc: B.CS 0x373ec28         ; overflow -> error
```

**BL site 1 (0x373eb2c):**
```
0x373eb1c: ADD x4, sp, #0x63      ; output ptr
0x373eb20: LDR x1, [sp, ...]      ; x1 = different value from stack (NOT x8)
0x373eb24: MOV x2, x26            ; x2 = x26 (same as overflow check)
0x373eb28: MOVZ w3, #1
0x373eb2c: BL vm_sanitize
```

**Apparent discrepancy:** The overflow check uses x8 (one stack slot), but the BL
passes x1 (a different stack slot) as the offset argument. They could diverge.

**Why this is NOT exploitable:**
1. The 0x373ead8 check is a range exhaustion guard — it verifies the accumulated end
   of a loop's range doesn't wrap, not a per-call offset+limit check.
2. vm_sanitize performs its own `ADDS x8_local, x1, x22` overflow check on entry.
   If the offset+limit passed to vm_sanitize would overflow, vm_sanitize returns error.
3. vm_sanitize validates offset against the named entry's actual bounds (loaded from
   the entry object at 0x378f7d0). A discrepancy in the pre-BL loop guard cannot
   grant access to pages outside those internally-held bounds.

---

## Structural Comparison: Surface 4 vs page_op

| Property | Surface 4 (MME64) | page_op callers |
|---|---|---|
| Bounds check BEFORE vm_sanitize | YES — ADDS x8,x2,x8 + B.CS | NO (loop guards only) |
| Values checked pre-BL | original child_size (pre-correction) | loop state, not offset+limit |
| vm_sanitize correction direction | SIZE rounded UP | OFFSET rounded DOWN |
| Post-BL uses corrected value | YES — entry created with corrected size | no entry creation path |
| Check values == BL arg values | YES (same x8 in check and BL) | NO (x8 != x1 in 3-BL cluster) |

---

## Root Cause Analysis

Surface 4 exploitability requires three conditions:
1. A bounds check fires BEFORE vm_sanitize using the original (small) value
2. vm_sanitize INCREASES the value (rounds sub-page size UP to page size)
3. The kernel USES the corrected (larger) value to create an entry, with no re-check

mach_memory_entry_page_op fails condition 1. The function does not bound-check
`offset < entry_size` prior to calling vm_sanitize — that validation happens INSIDE
vm_sanitize at 0x378f7d0 (SUBS x31, x10, x9; B.LS error).

Additionally, page_op rounds the OFFSET (aligns to page boundary), not a SIZE.
Rounding an offset DOWN makes the effective range smaller — the opposite of the
Surface 4 size-rounding-UP mechanism.

---

## Verdict

**mach_memory_entry_page_op: NOT VULNERABLE to Surface 4 ordering attack.**

All 10 vm_sanitize callers rely on vm_sanitize to perform bounds validation.
No caller replicates the dangerous pattern: check(original_size) -> vm_sanitize
(corrects to larger_size) -> create_entry(larger_size).

Next recommendation: cross-process XPC service scan for services accepting named
entry ports (Surface 4 shadow re-export phantom aliasing exploitation path).

---

## Call Site Reference Table

| foff | VA | Notes |
|---|---|---|
| 0x3667d88 | 0xfffffff00a66bd88 | Simple: MOV x1/x2 + BL |
| 0x367dd70 | 0xfffffff00a681d70 | Simple: MOV x1/x2 + BL |
| 0x3680d5c | 0xfffffff00a684d5c | Paired: 2 consecutive BLs, same limit x19 |
| 0x3680d74 | 0xfffffff00a684d74 | Paired: 2nd of pair |
| 0x3681b08 | 0xfffffff00a685b08 | Loop: pre-BL loop guard (not bounds check) |
| 0x36bc4ac | 0xfffffff00a6c04ac | Simple: no pre-BL overflow check |
| 0x36cd8d8 | 0xfffffff00a6d18d8 | Loop: loop guard pattern |
| 0x373eb2c | 0xfffffff00a742b2c | 3-BL cluster: pre-BL ADDS check, different args |
| 0x373ebb0 | 0xfffffff00a742bb0 | 3-BL cluster: 2nd BL |
| 0x373ec04 | 0xfffffff00a742c04 | 3-BL cluster: 3rd BL |
