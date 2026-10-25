# New SPTM Call Gate: Table 9 Endpoint 0 (0x900000000)

*Generated 2026-10-25*

Table 9 is XNU's primary SPTM dispatch table (pmap/retype operations).
In iOS 26.6.1 endpoint 0 was a gap — no stub, unreachable from XNU.
In iOS 27.0.1 endpoint 0 has a live stub for the first time.

---

## Stub Location

| Field | Value |
|---|---|
| GENTER vmaddr (27.0.1) | `0xfffffff00b400594` |
| Stub start vmaddr (27.0.1) | `0xfffffff00b40057c` |
| Present in 26.6.1 | No (confirmed absent) |

## Stub Disassembly (27.0.1)

27.0.1 stub layout (confirmed for all table-9 stubs):
```
; stub_start (callers BL here):
  0xfffffff00b40057c: 97dd2e7f  ; BL <helper function>
  0xfffffff00b400580: d2800010  ; MOVZ X16, #0          (ep_id = 0)
  0xfffffff00b400584: f2c00130  ; MOVK X16, #9, lsl#32  (table_id = 9 → x16 = 0x900000000)
  0xfffffff00b400588: f0fe5448  ; ADRP X8, flag_page    (load SPTM-ready flag)
  0xfffffff00b40058c: 39728108  ; LDRB W8, [X8, off]
  0xfffffff00b400590: 35000068  ; CBNZ W8, .brk        (branch to BRK if flag != 0)
  0xfffffff00b400594: 00201420  ; GENTER               (dispatch to SPTM table=9, ep=0)
  0xfffffff00b400598: 14000002  ; (epilog)
  0xfffffff00b40059c: d4e00000  ; (epilog)
  0xfffffff00b4005a0: 97dd2e91  ; BRK #0               (CBNZ target: SPTM not ready)
```

## BL Callers

No direct BL callers found in `__TEXT_EXEC` or `__PRELINK_TEXT`.

This indicates callers use **BLR** (indirect branch via register) — the stub
address is stored in a pointer table in `__DATA` and loaded at runtime.

## Stub Pointer Search

No stored pointer found for the stub start in __DATA/__DATA_CONST.
The dispatch may go through a multi-level table (e.g., function array indexed
by endpoint ID) with address-space layout randomization applied.

## SPTM Context

Strings from `sptm_27.0.1_strings.txt` relevant to table-9/retype:
- `%s: FTE %p should be held exclusive by sptm_retype()`
- `%s: Only CPU pages may need a GMMU TLBI on retype`
- `uat_retype_in`
- `retype_params.type`
- `%s: retyping from XNU_IOMMU but not to XNU_DEFAULT %s`
- `uat_retype_out`
- `issue-gmmu-tlbis-at-retype`
- `xnu_ctrr_dispatch_table`
- `SPTM_CPUTRACE_ENDPOINTID_IS_MODE`
- `SPTM_CPUTRACE_ENDPOINTID_PA_CRV_ADDR`
- `SPTM_CPUTRACE_ENDPOINTID_PA_CRV_SIZE`
- `SPTM_CPUTRACE_ENDPOINTID_PA_SET_BASE`
- `SPTM_CPUTRACE_ENDPOINTID_PA_START`
- `SPTM_CPUTRACE_ENDPOINTID_PA_STOP`
- `SPTM_CPUTRACE_ENDPOINTID_VA_FRM_LOCK`

## Likely Function of Table-9 Endpoint-0

Table 9 contains XNU's calls into SPTM's page-type management path.
Other table-9 endpoints (1–12 in 27.0.1) handle pmap operations like
`sptm_retype_page`, `sptm_map_page`, and related calls.

Endpoint 0 was a gap in 26.6.1. The most likely candidates:

1. **SPTM_XNU_RETYPE** — XNU-facing retype operation (the SK parallel is
   `SK_TO_SPTM_ENDPOINTID_RETYPE`, newly added in 27.0.1). This would mean
   endpoint 0 is the canonical retype entry point, with higher endpoints for
   specialized retype variants.

2. **PHYS_TO_TYPE query** — a new read-only query: given a physical address,
   return its current SPTM page type. Useful for validation before retype.

3. **REGISTER_DISPATCH_TABLE for XNU** — analogous to
   `SK_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE`. XNU registers its table
   with SPTM during boot, and this was added as a named endpoint.

## Security Notes

- **Gap fill = new primitive.** In 26.6.1, calling this endpoint from XNU
  would have hit an undefined dispatch table slot — crash or rejection.
  In 27.0.1 it is valid and callable.

- **Retype is the crown jewel.** Page type enforcement is the primary mechanism
  SPTM uses to prevent type confusion between kernel, read-only, user, GPU,
  and secure memory. A retype endpoint that can be called with attacker-
  influenced arguments (physical address, target type) is a high-value primitive.

- **VIOLATION_ILLEGAL_RETYPE_PINNED** (see REPORT_SPTM.md, offset 0x0000c313)
  is the SPTM-side guard on the retype path — this XNU endpoint is the entry
  point on the XNU side of the same path.

- **SK parallel added simultaneously.** `SK_TO_SPTM_ENDPOINTID_RETYPE` was also
  added in 27.0.1. Two new callers of the retype path (XNU + SK) in one release
  suggests a refactoring of the retype surface, not just a feature add.

- **Next steps:**
  1. Identify what the `BL <helper>` at stub+0 calls — likely `_pmap_lock_` or
     a stack-setup trampoline
  2. Find BLR callers via __DATA pointer table (requires KASLR slide known)
  3. Cross-reference with 26.6.1 function that was at the equivalent table slot

