# mach_make_memory_entry_64: Surface 5 Overflow Check Analysis

*Generated 2026-10-25 | iOS 26.6.1 target | Static analysis of kc_26.6.1.macho*

---

## Call Site Correction

foff=0x3707668 (previously cited) is inside vm_sanitize_run_test — the registration
loop over all 43 API name strings — NOT mach_make_memory_entry_64 itself.

Actual function body anchored by vm_memory_entry.c assert cluster:
  foff = 0x37a0cb4 / VA = 0xfffffff00a7a4cb4
  Prologue starts: ~0x379fd60

---

## Key Instruction Sequence

```
; Prologue ~0x379fd60 (STP/frame setup)
0x379fddc: LDR x8, [x1, #0x0]       ; x8 = *size (original, from caller pointer)
0x379fde0: CBZ x8, <error>           ; reject zero size
0x379fde4: CBZ x0, <error>           ; reject null map

; CHECK 1 — BEFORE any BL call
0x379fdec: ADDS x8, x2, x8           ; x2=offset, x8=*size → offset+size, carry on overflow
0x379fdf0: B.CS 0xfffffff00a7a3f98   ; overflow → error path

; 64 instructions later:
0x379feb4: BL 0xfffffff00a77a544     ; map lock / lookup

; CHECK 2 — second execution path
0x379ff54: ADDS x9, x2, x9           ; same pattern
0x379ff58: B.CS 0xfffffff00a7a3f98   ; overflow → error

0x37a0010: ADDS x8, x2, x8  + B.CS
0x37a00a8: ADDS x8, x2, x8  + B.CS

0x37a0108: BL 0xfffffff00a793748     ; possible vm_sanitize correction call

; CHECK 3 — POST-BL
0x37a015c: ADDS x2, x2, x9           ; offset + (corrected?) size
0x37a0160: B.CC 0xfffffff00a7a41fc   ; NO overflow → continue; fall-through → error

0x37a0204: ADDS x10, x2, x10  + B.CS ; further checks
```

---

## Finding: Pattern A — Overflow Check EXISTS Before vm_sanitize

First ADDS x8, x2, x8 + B.CS at 0x379fdec fires before any BL.
  x2 = offset (ARM64 calling convention arg3)
  x8 = original *size loaded from caller pointer

Checks offset + original_size, errors on overflow.

---

## Surface 5 Status: LARGELY CLOSED — Subtle Bypass Unconfirmed

### Basic attack — CLOSED

  offset = 0xFFFFFFFFFFFFF000, size = 0x2000
  Check 1: 0xFFFFFFFFFFFFF000 + 0x2000 = 0x10000000000001000 → CARRY SET → error

### Subtle bypass (sub-page size rounds up past wrap) — UNKNOWN

  offset = 0xFFFFFFFFFFFFE000
  size   = 0x1001  (sub-page, vm_sanitize rounds to 0x2000)

  Check 1: 0xFFFFFFFFFFFFE000 + 0x1001 = 0xFFFFFFFFFFFFF001 → NO CARRY → passes
  BL at 0x37a0108: vm_sanitize rounds 0x1001 → 0x2000
  Corrected sum: 0xFFFFFFFFFFFFE000 + 0x2000 = 0x10000000000000000 → OVERFLOWS

  Whether Check 3 (0x37a015c) catches this depends on whether x9 at that point
  holds the corrected size or a differently-derived value.
    x9 = corrected size → caught
    x9 = original size → gap survives

  Register identity at 0x37a015c requires dynamic testing on a 26.6.1 device.

---

## Surface Status Summary

| Scenario | Status |
|---|---|
| offset + original_size wraps | CLOSED — Check 1 at 0x379fdec |
| sub-page size corrected upward past wrap | UNKNOWN — Check 3 may or may not cover |
| Surface 4 (parent bounds check ordering) | HIGHEST PRIORITY — unaddressed |

---

## Next Step

Surface 4 (REPORT_VMSANITIZE_26.md) is now highest priority:
  parent covers [A, A+0x2000)
  child: offset=A+0x1800, size=0x1001 → vm_sanitize corrects to 0x2000
  child range → [A+0x1800, A+0x3800) escapes parent

  Does parent bounds check use pre-correction or post-correction child size?
  Requires same disassembly approach: find parent bounds check relative to BL at 0x37a0108.
