# vm_sanitize Soft-Landing: 26.6.1 Attack Surface

*Generated 2026-10-25 | iOS 26.6.1 target | Static analysis*

---

## Executive Summary

`vm_sanitize_telemetry.c` is confirmed present in 26.6.1 and entirely removed in 27.0.1.
It implements a soft-landing corrector: rather than panicking on malformed VM API inputs,
it silently corrects them and lets execution continue, logging via ktriage.
Apple's removal in 27.0.1 signals they considered this a security liability.

**Primary target:** `mach_make_memory_entry_64` — creates named memory entries (IPC ports
over memory) used for VM remapping. Corrected-size entries that diverge from the caller's
expectation are potential OOB surfaces.

---

## Confirmed Binary Evidence (26.6.1, file offsets in kc_26.6.1.macho)

```
0x530ce  Failed to set up ktriage for VM sanitization. @%s:%d
0x53103  vm_sanitize_telemetry.c         ← source filename
0x5311b  VM API - Unsanitary input passed to   ← log prefix
0x53140  mach_make_memory_entry          ← first API name listed
0x53457  vm_sanitize_run_test            ← test harness
```

All in __PRELINK_TEXT (VA 0xfffffff007057000). All absent in 27.0.1.

---

## 43 VM APIs Covered by Soft-Landing

```
mach_make_memory_entry       mach_memory_entry_page_op    mach_memory_entry_range_op
mach_memory_entry_map_size   mach_memory_object_memory_entry
vm_allocate(VM_FLAGS_FIXED)  vm_allocate(VM_FLAGS_ANYWHERE)  vm_deallocate
munmap                       vm_remap or vm_remap_new     map_with_linking_np
vm_map                       mremap_encrypted             vm_wire
vm_map_wire                  vm_map_unwire                vslock / vsunlock
vm_map_copy_overwrite        vm_map_copyin                vm_read / vm_write
mach_vm_inherit              vm_inherit / vm32_inherit / vm_map_inherit / minherit
mach_vm_protect              vm_protect / vm32_protect / vm_map_protect / mprotect
useracc                      vm_map_msync                 vm_map_machine_attribute
mincore                      vm_map_page_range_info       vm_map_page_range_query
vm_behavior_set              madvise
mach_vm_deferred_reclamation_buffer_init
mach_vm_range_create         shared_region_map_and_slide_2_np
```

---

## Attack Surfaces in mach_make_memory_entry_64

### Surface 5 — Integer Wrap: offset + corrected_size (HIGHEST)

```
offset = 0xFFFFFFFFFFFFF000
size   = 0x2000             (page-aligned — vm_sanitize won't correct size)
offset + size = 0x0000000000001000   (wraps to near-zero)
```

If vm_sanitize checks `size` independently but NOT `offset + size` wrap, the kernel creates
a named entry at VA=0xFFFFFFFFFFFFF000 with a wrapped end address. Apple removed this
entire layer in 27.0.1 — a strong signal they found this class dangerous.

**Open question:** Does 26.6.1's vm_sanitize check the combined `offset + size` for overflow,
or just `size` alone? Requires dynamic testing to confirm.

### Surface 4 — Parent Entry Bounds Check Ordering (HIGH)

```
parent_entry covers [A, A+0x2000)
child: offset = A+0x1800, size = 0x1001  → vm_sanitize corrects size to 0x2000
child range = [A+0x1800, A+0x3800)       ← escapes parent by 0x1800 bytes
```

**Critical question:** Does the parent bounds check run before or after size correction?
- If BEFORE: original size 0x1001 used for check, corrected size 0x2000 used for entry
  creation — classic check/use mismatch. The child entry escapes its parent.
- If AFTER: corrected size used for check → caught.

This is the most classically exploitable pattern if check ordering is wrong.

### Surface 2 — Sub-Page Size Correction Widens Coverage (MEDIUM)

```
offset = 0x500, size = 0x200
vm_sanitize corrects size → 0x1000 (full page alignment)
named entry covers full page including [0x700, 0x1000) never requested
```

If caller uses original 0x200 for subsequent bounds calculations, the named entry grants
access to 0xE00 extra bytes the caller didn't request.

---

## vm_sanitize is XNU-Only (Not in SPTM)

`grep -c 'vm_sanitize' sptm_26.6.1_strings.txt → 0`

vm_sanitize bypass creates confused XNU state. SPTM still enforces physical page type
via retype. A full exploit chain would be:

```
confused MME state (via vm_sanitize surface)
  → vm_remap to alias unauthorized physical pages
  → kernel r/w primitive
  → forge SPTM dispatch table pointer
  → GENTER with controlled integer (26.6.1 integer dispatch — still active)
```

---

## 26.6.1 vs 27.0.1 Comparison

| Feature | 26.6.1 | 27.0.1 |
|---|---|---|
| vm_sanitize_telemetry.c | **Present** | Removed |
| Bad input behavior | Correct + continue | Hard assert → panic |
| vm_sanitize_run_test | **Present** | Removed |
| 43 API soft-landing | **Active** | Gone |

---

## Open Questions (Require Dynamic Testing on 26.6.1)

1. **Does vm_sanitize check `offset + size` wrap, or just `size`?** → Surface 5 exploitability
2. **Parent bounds check before or after size correction?** → Surface 4 exploitability
3. **Does `*size` write-back use corrected size consistently?** → Caller confusion
4. **Are all 43 APIs reachable from App Sandbox?** → Most are Mach traps, likely yes

## Next Steps

- ARM64 disassembly of vm_sanitize macro expansion in `mach_make_memory_entry_64` TEXT_EXEC
  Specifically: CBZ/CBNZ on size parameter just before main function body
- Dynamic testing on 26.6.1 device: send boundary inputs, observe corrected outputs
- Cross-reference Surface 4 (parent bounds ordering) with vm_remap for physical aliasing
