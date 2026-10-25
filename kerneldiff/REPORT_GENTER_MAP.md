# GENTER Call Site Map: iOS 26.6.1 → 27.0.1

*Generated 2026-10-25*

GENTER opcode: `20 14 20 00` — ARM64 instruction that traps XNU into GL2 (SPTM).

**Method:** All GENTER vmaddrs extracted from `__TEXT_EXEC`. Each stub decoded to
extract `x16` at call site (MOVZ + MOVK sequence). x16 encodes `(table_id << 32) | endpoint_id`.

---

## Summary

| | Count |
|---|---|
| 26.6.1 GENTER stubs | 150 |
| 27.0.1 GENTER stubs | 173 |
| **Delta** | **+23** |
| 26.6.1 unique dispatch IDs | 142 |
| 27.0.1 unique dispatch IDs | 166 |
| New dispatch IDs in 27.0.1 | **+28** |
| Removed dispatch IDs | **-4** |

## Finding 1: Centralized Stub Dispatch Array

All GENTER calls live in a single **stub dispatch array** in `__TEXT_EXEC`. No scattered
inline GENTER. Every XNU->SPTM call goes through a wrapper stub.

| | 26.6.1 | 27.0.1 |
|---|---|---|
| Stub array span | `0xfffffff00aebc2d8` to `0xfffffff00aebe4f8` | `0xfffffff00b3fd688` to `0xfffffff00b4008d0` |
| Span (bytes) | 8,736 | 12,872 |
| Most common stub spacing | 44 bytes (11 instrs) | 64 bytes (16 instrs) |

27.0.1 stubs are **larger** because each now includes a pre-GENTER `ADRP + LDRB + CBNZ`
guard. If the "SPTM ready" flag is not set, execution falls to `BRK #0`.

## Finding 2: Dispatch ID Encoding

Each stub loads a 64-bit value into `x16` before GENTER:

```
MOV  x16, #<endpoint_id>       ; low 32 bits
MOVK x16, #<table_id>, lsl #32 ; high 32 bits
GENTER
```

Example (both versions, last stub):
- table=9, endpoint=0xb: `x16 = 0x9_0000_000b`
- table=9, endpoint=0xc: `x16 = 0x9_0000_000c`
- table=9, endpoint=0x22: `x16 = 0x9_0000_0022`

## Finding 3: New Dispatch Table 0xe (16 endpoints) -- PRIMARY FINDING

**Dispatch table 0xe is entirely new in 27.0.1** with 16 endpoints (0x0..0xf).
In 26.6.1 the highest table ID in stubs is 0xd. Table 0xe appears for the first time
with 16 stubs covering endpoints 0 through 15.

| Table | 26.6.1 endpoints | 27.0.1 endpoints | Delta |
|---|---|---|---|
| 0x3 | 19 | 19 | 0 |
| 0x5 | 3 | 3 | 0 |
| 0x6 | 9 | 10 | +1 |
| 0x7 | 13 | 14 | +1 |
| 0x9 | subset 0..27 | subset 0..12 | +2, -2 |
| 0xa | 6 (sparse) | 5 | -1 |
| 0xb | 19 | 19 | 0 |
| 0xd | 16 | 16 | 0 |
| **0xe** | **0** | **16** | **+16 (NEW TABLE)** |

These 16 stubs correspond to one of the new named SPTM subsystems:
SPTM_NVME (12 endpoints), SPTM_CPUTRACE (12), or SPTM_HIB (6).
Given 16 stubs, likely NVME or CPUTRACE with extra initialization entries.

## Finding 4: New Low-Numbered Dispatch IDs (table=0)

| New ID | Endpoint | Notes |
|---|---|---|
| `0x1c` | 28 | Replaces removed 0x1b |
| `0x1f` | 31 | New |
| `0x20` | 32 | New |
| `0x32` | 50 | Extends max from 49 to 50 |

Removed: `0x1b` (27) -- renumbered to 0x1c.

## All New Dispatch IDs

| ID | Table | Endpoint |
|---|---|---|
| `0x1c` | 0 | 28 |
| `0x1f` | 0 | 31 |
| `0x20` | 0 | 32 |
| `0x32` | 0 | 50 |
| `0x600000009` | 6 | 9 |
| `0x70000000d` | 7 | 13 |
| `0x900000000` | 9 | 0 (was absent!) |
| `0x90000000c` | 9 | 12 |
| `0xe00000000` | 14 | 0 |
| `0xe00000001` | 14 | 1 |
| `0xe00000002` | 14 | 2 |
| `0xe00000003` | 14 | 3 |
| `0xe00000004` | 14 | 4 |
| `0xe00000005` | 14 | 5 |
| `0xe00000006` | 14 | 6 |
| `0xe00000007` | 14 | 7 |
| `0xe00000008` | 14 | 8 |
| `0xe00000009` | 14 | 9 |
| `0xe0000000a` | 14 | 10 |
| `0xe0000000b` | 14 | 11 |
| `0xe0000000c` | 14 | 12 |
| `0xe0000000d` | 14 | 13 |
| `0xe0000000e` | 14 | 14 |
| `0xe0000000f` | 14 | 15 |

## Removed Dispatch IDs

| ID | Table | Endpoint |
|---|---|---|
| `0x700000018` | 7 | 24 |
| `0x900000019` | 9 | 25 |
| `0x90000001b` | 9 | 27 |
| `0xa00000020` | 10 | 32 |

## Security Analysis

**Primary attack surface: table 0xe (16 new endpoints)**

All 16 stubs for table 0xe are entirely new code. XNU never called SPTM through
these stubs in iOS 26.6.1. Priority targets:

1. **`0xe00000000` (table 14, endpoint 0):** Likely init/register call for the new subsystem.
   Matches SPTM_NVME_ENDPOINTID_INIT or SPTM_CPUTRACE_ENDPOINTID_VA_INIT pattern.

2. **`0x900000000` (table 9, endpoint 0):** Endpoint 0 of the main pmap/retype table was
   ABSENT in 26.6.1 but present in 27.0.1. Gap-fill -- something that previously could
   not be called via endpoint 0 now can.

3. **`0x90000000c` (table 9, endpoint 12):** New retype/mapping operation in the core
   pmap dispatch path.

4. **Removed `0x700000018`:** Endpoint 24 in table 7 was removed. Check whether the
   functionality was merged into another endpoint OR whether its enforcement was dropped.

**SK_TO_SPTM endpoints not visible here:** The 3 new SK->SPTM endpoints (RETYPE,
PHYS_TO_TYPE, REGISTER_DISPATCH_TABLE) are called from the Secure Kernel binary,
not from XNU. They will not appear in this kernelcache analysis.

**New per-stub CBNZ guard:** Universal in 27.0.1, closes "call before initialize" timing bugs.

## Next Steps

1. Identify table 0xe subsystem: find which XNU kext calls these 16 stubs.
2. Trace callers of `0x900000000` (new table-9 endpoint 0).
3. Extract SK binary with `fetch_kc.py` searching for `sk.` to map SK->SPTM GENTER calls.
