# vm_sanitize Soft-Landing Correction: 26.6.1 Attack Surface

*Generated 2026-10-25 | iOS 26.6.1 target | Static analysis*

---

## Executive Summary

`vm_sanitize_telemetry.c` is **confirmed present in 26.6.1 and entirely removed in 27.0.1**.
It implements a soft-landing corrector: rather than panicking on malformed VM API inputs,
it silently corrects them and lets execution continue, logging via ktriage.

Apple's removal in 27.0.1 signals they considered this a security liability.

**Primary target:** `mach_make_memory_entry_64` — creates named memory entries (IPC ports
over memory) used for VM remapping. Corrected-size entries that diverge from the caller's
expectation are potential OOB surfaces.

---

## Confirmed Binary Evidence (26.6.1)

Verified via binary grep on kc_26.6.1.macho:

```
foff=0x530ce  VA=0xfffffff0070570ce  "Failed to set up ktriage for VM sanitization. @%s:%d"
foff=0x53103  VA=0xfffffff007057103  "vm_sanitize_telemetry.c"   <- source filename
foff=0x5311b  VA=0xfffffff00705711b  "VM API - Unsanitary input passed to "  <- log prefix
foff=0x53140  VA=0xfffffff007057140  "mach_make_memory_entry"    <- first API name
foff=0x53457  VA=0xfffffff007057457  "vm_sanitize_run_test"      <- test harness name
```

All located in __PRELINK_TEXT (page 0xfffffff007057000).
All **absent** from 27.0.1.

ADRP scan found call site in TEXT_EXEC at:
  foff=0x3707668  VA=0xfffffff00a70b668  (references vm_sanitize string page)

---

## Full API Coverage: 43 Functions Soft-Landed

Extracted from the string table at foff=0x53140–0x53457:

| # | API name | Category |
|---|----------|----------|
| 1 | mach_make_memory_entry | Named entry ← **primary target** |
| 2 | mach_memory_entry_page_op | Named entry ops |
| 3 | mach_memory_entry_range_op | Named entry ops |
| 4 | mach_memory_entry_map_size | Named entry ops |
| 5 | mach_memory_object_memory_entry | External pager |
| 6 | vm_allocate(VM_FLAGS_FIXED) | Allocation |
| 7 | vm_allocate(VM_FLAGS_ANYWHERE) | Allocation |
| 8 | vm_deallocate | Deallocation |
| 9 | munmap | BSD mmap |
| 10 | vm_remap or vm_remap_new | Remap |
| 11 | map_with_linking_np | Private |
| 12 | vm_map | Map |
| 13 | mremap_encrypted | Encryption remap |
| 14 | vm_wire | Wiring |
| 15 | vm_map_wire | Wiring |
| 16 | vm_map_unwire | Wiring |
| 17 | vslock | BSD |
| 18 | vsunlock | BSD |
| 19 | vm_map_copy_overwrite | Copy |
| 20 | vm_map_copyin | Copy |
| 21 | vm_read | Read |
| 22 | vm_write | Write |
| 23 | mach_vm_inherit | Inherit |
| 24 | vm_inherit | Inherit |
| 25 | vm32_inherit | Inherit |
| 26 | vm_map_inherit | Inherit |
| 27 | minherit | BSD |
| 28 | mach_vm_protect | Protect |
| 29 | vm_protect | Protect |
| 30 | vm32_protect | Protect |
| 31 | vm_map_protect | Protect |
| 32 | mprotect | BSD |
| 33 | useracc | Access check |
| 34 | vm_map_msync | Sync |
| 35 | vm_map_machine_attribute | Machine attr |
| 36 | mincore | Page info |
| 37 | vm_map_page_range_info | Page info |
| 38 | vm_map_page_range_query | Page info |
| 39 | vm_behavior_set | Behavior |
| 40 | madvise | BSD |
| 41 | mach_vm_deferred_reclamation_buffer_init | Reclaim |
| 42 | mach_vm_range_create | Range |
| 43 | shared_region_map_and_slide_2_np | Shared region |

---

## Attack Surfaces in mach_make_memory_entry_64

### Prototype
```c
kern_return_t mach_make_memory_entry_64(
    vm_map_t         target_map,
    mach_vm_size_t  *size,       // IN/OUT — corrected size written back
    mach_vm_offset_t offset,
    vm_prot_t        permission,
    ipc_port_t      *object_handle,
    ipc_port_t       parent_entry
);
```

---

### Surface 5 (HIGHEST): offset + size integer wrap

**Trigger:**
```
offset = 0xFFFFFFFFFFFFF000
size   = 0x2000           (page-aligned; vm_sanitize checks size alone)
offset + size = 0x0000000000001000  (wraps around uint64)
```

**Question:** Does 26.6.1 vm_sanitize check `offset + size` overflow, or just `size`
independently? If only `size` is sanitized, kernel creates a named entry at
VA=0xFFFFFFFFFFFFF000 with a wrapped end address — entry covers a non-contiguous
range that bypasses any linear bounds check.

Apple removed the entire soft-landing layer in 27.0.1, suggesting they found exactly
this class of issue.

**Status:** UNCONFIRMED — needs ARM64 disassembly of the check at foff=0x3707668 area.

---

### Surface 4 (HIGH): parent_entry bounds check ordering

**Setup:**
```
parent_entry = named entry covering [A, A+0x2000)
child call: offset = A + 0x1800, size = 0x1001
```

**vm_sanitize correction:**
  size 0x1001 → rounded up → 0x2000

**Critical question:** Does parent bounds check use ORIGINAL size or CORRECTED size?

- If check uses original 0x1001: child_end = A+0x2801 > A+0x2000 → STILL FAILS
- If check uses corrected 0x2000: child_end = A+0x3800 >> parent end → FAILS
- BUT: edge case with exactly-page-multiple sizes near the boundary:

```
size = 0xFFF → corrected to 0x1000
child = [A+0x1800, A+0x2800)  →  child_end A+0x2800 > parent_end A+0x2000 → FAILS
```

The check ordering matters most when correction REDUCES size (downcorrection).
If vm_sanitize can reduce a size and the bounds check used the pre-correction value,
the resulting named entry could be smaller than what passed the check.

**Status:** UNCONFIRMED — order of operations needs disassembly.

---

### Surface 2 (MEDIUM): Sub-page correction widens coverage

**Trigger:** `offset = 0x500, size = 0x200`

**Correction:** size → 0x1000 (full page)

**Effect:** Named entry covers full page including bytes [0x700, 0x1000) never
explicitly requested. If caller uses original 0x200 for subsequent bounds
calculations, the named entry grants access to 0xE00 extra bytes.

**Status:** LOW — caller confusion, not kernel memory corruption.

---

## vm_sanitize NOT in SPTM

```
grep -c 'vm_sanitize' sptm_26.6.1_strings.txt  →  0
```

vm_sanitize is XNU-only. A bypass creates confused XNU state. SPTM still enforces
physical page type rules via retype. Full chain requires:

1. Confused named entry via vm_sanitize soft-land (Surface 5: offset+size wrap)
2. Use named entry in vm_remap_new to alias physical pages beyond authorized range
3. Kernel r/w primitive via alias
4. Forge SPTM dispatch table pointer
5. GENTER with controlled integer via 26.6.1's integer dispatch (open on target,
   replaced in 27.0.1)

---

## 27.0.1 Comparison

| Feature | 26.6.1 | 27.0.1 |
|---------|--------|--------|
| vm_sanitize_telemetry.c | **Present** | Removed |
| Bad input behavior | Correct + continue | Hard assert → panic |
| ktriage on bad input | Yes | No |
| vm_sanitize_run_test | **Present** (0x53457) | Removed |
| 43-API soft-landing | **Active** | Gone |

---

## Open Questions (Require Dynamic Testing on 26.6.1)

| # | Question | Which surface |
|---|----------|--------------|
| 1 | Does vm_sanitize check offset+size wrap? | Surface 5 |
| 2 | Parent bounds check before or after size correction? | Surface 4 |
| 3 | Does *size write-back match internal entry size? | All surfaces |
| 4 | Are all 43 APIs reachable from App Sandbox? | Scope |

---

## Next Step

Disassemble TEXT_EXEC at foff=0x3707668 (VA=0xfffffff00a70b668) to confirm which
vm_sanitize call site this is and trace the check/correction sequence.

---

## Files Referenced

- `kc_26.6.1.macho` — strings at foff 0x530ce–0x53457
- `kc_27.0.1.macho` — all vm_sanitize strings absent
- `REPORT_MME_SANITIZE.md` — prior finding that vm_sanitize removed in 27.0.1
- `REPORT_SPTM.md` — SPTM dispatch redesign (integer → named pairs)
- `STATE.md` — investigation log

**Priority: HIGH** — Present in 26.6.1, removed in 27.0.1, covers 43 VM APIs,
Surface 5 (offset+size wrap) is top candidate for dynamic confirmation.
