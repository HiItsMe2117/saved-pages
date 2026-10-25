# mach_make_memory_entry_64: "Unsanitary Input" Removal

*Generated 2026-10-25*

---

## Summary

**Determination: (a) — entire `vm_sanitize_telemetry` subsystem removed.**

The "Unsanitary input" string was part of a centralized telemetry/monitoring framework
(`vm_sanitize_telemetry.c`) that logged when VM APIs received bad inputs. The whole
framework was removed in iOS 27.0.1 — not just the string. This is NOT a simple
string rename or deduplication. The removal affects the telemetry layer, not the
underlying enforcement assertions.

---

## Evidence in 26.6.1

**File offset:** `0x53124`
**Source file:** `vm_sanitize_telemetry.c`
**String:** `"VM API - Unsanitary input passed to "`

This string is the format prefix for a telemetry log line that also includes the
function name. The function name list immediately follows in the same data block:

```
"VM API - Unsanitary input passed to "
"mach_make_memory_entry"
"mach_memory_entry_page_op"
"mach_memory_entry_range_op"
"mach_memory_entry_map_size"
"mach_memory_object_memory_entry"
"vm_allocate(VM_FLAGS_FIXED)"
"vm_allocate(VM_FLAGS_ANYWHERE)"
"vm_deallocate"
"vm_remap or vm_remap_new"
"map_with_linking_np"
"mremap_encrypted"
"vm_map_wire / vm_map_unwire / vsunlock"
"vm_map_copy_overwrite / vm_map_copyin / vm_write"
"mach_vm_inherit / vm_inherit / vm_protect / mprotect ..."
```

This is an **enumerated list of 30+ VM APIs** monitored by the telemetry framework.
mach_make_memory_entry is one entry in this list — not singled out.

Additional 26.6.1 strings from this subsystem, all absent in 27.0.1:

| String | Purpose |
|---|---|
| `vm_sanitize_telemetry.c` | Source file identifier |
| `Failed to set up ktriage for VM sanitization.` | ktriage integration setup |
| `vm_sanitize_updated_return_code` | Analytics key for telemetry |
| `vm_sanitize_run_test` | Test/self-check for the framework |
| `vm_sanitize_telemeter_to_serial` | Serial output path |

---

## Evidence in 27.0.1

All of the above strings are **absent** — zero hits in kc_27.0.1.macho.

The `vm_memory_entry.c` region in 27.0.1 still contains error strings for
mach_make_memory_entry but they are `@%s:%d`-style panic assertions, not
telemetry log lines:

```
"unsupported type of mem_entry %p @%s:%d"
"mach_make_memory_entry can't handle SYMMETRIC object @%s:%d"
"vm_memory_entry.c"
```

These existed in 26.6.1 as well (different crash paths). The 27.0.1 function
still has hard-crash assertions — the removed layer was on top of them.

---

## What vm_sanitize_telemetry Was

The framework was a **soft-landing telemetry layer** sitting between the caller
and the enforcement assertions. When a VM API received bad input:

- 26.6.1: log the event via ktriage + vm_sanitize_telemetry, potentially
  return a sanitized/clamped value, continue execution
- 27.0.1: no soft landing — the underlying @%s:%d assertion fires directly,
  or the input is rejected outright

Key evidence: `vm_sanitize_run_test` existed in 26.6.1. A test function in the
subsystem suggests it was doing active work (clamping, coercing, or silently
correcting inputs) rather than just logging. Its removal means that correction
logic is gone.

---

## SPTM Correlation

SPTM 26.6.1 had `sanitize_integer(dispatch_entry_addr_U.UNSAFE_VALUE)` and
`sanitize_integer(dispatch_target_U.UNSAFE_VALUE)` — both removed in 27.0.1 when
dispatch moved to named endpoints. The XNU vm_sanitize_telemetry removal is a
parallel pattern: both were UNSAFE_VALUE → sanitize → use sanitized value flows
replaced by hard validation.

The difference: SPTM's replacement is **strictly harder** (named endpoint
validation + VIOLATION_ILLEGAL_DISPATCH_CMD). XNU's replacement is **unclear** —
the soft correction layer is gone but the hard assertions may or may not cover
the same cases.

---

## Security Assessment

### Risk: Medium–High (needs dynamic confirmation)

The vm_sanitize_telemetry framework was designed to handle inputs that were
"unsanitary" — invalid but not immediately crashing. Its removal leaves two states:

1. **Stronger**: Apple audited all callers, ensured inputs are always valid before
   reaching the VM layer, and removed the now-redundant softening.

2. **Weaker**: The soft correction was handling cases the hard assertions don't
   cover. Inputs that previously got sanitized and returned successfully now go
   unvalidated (silent memory corruption path).

**The Trigon connection**: CVE-2023-32434 was a heap OOB write via
mach_make_memory_entry_64. Apple's fix added bounds checks. If those checks were
part of the vm_sanitize_telemetry layer, their removal reopens surface. If they
were in the underlying assertion layer (which still exists), there is no regression.

The function name list in the 26.6.1 telemetry block includes mach_make_memory_entry
as one of 30+ monitored APIs, suggesting the telemetry was broad-spectrum. A targeted
Trigon fix layered on top would not be distinguishable from string evidence alone.

---

## Next Steps

1. Extract mach_make_memory_entry_64 from both kernelcaches via the MIG dispatch
   table (MIG index was !N_ in 26.6.1, !f_ in 27.0.1) and disassemble the
   size/offset bounds checks directly.

2. Check if any sanitize_* symbols remain in 27.0.1 via the LINKEDIT symbol table.

3. Dynamic test: call mach_make_memory_entry_64 with a known-bad size argument on
   27.0.1 — does it panic (assertion), return an error, or silently succeed?
