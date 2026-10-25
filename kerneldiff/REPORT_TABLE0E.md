# Dispatch Table 0xe: Subsystem Identification

*Generated 2026-10-25 | iOS 27.0.1 kc_27.0.1.macho*

GENTER opcode `20 14 20 00` — each stub encodes `(table_id << 32) | endpoint_id` in x16.

---

## Summary

| Metric | Value |
|---|---|
| Table-0xe stubs | 16 (endpoints 0x0–0xf) |
| **Subsystem** | **`SPTM_NVME`** |
| **Calling kext** | **`com.apple.iokit.IONVMeFamily`** |
| NVMe string refs in IONVMeFamily | 2,027 (next highest: 60) |
| Direct BL callers | 0 (indirect dispatch via ptrauth pointers) |

Table 0xe is the **SPTM_NVME** subsystem — SPTM-mediated NVMe storage controller access.
IONVMeFamily is the exclusive kernel consumer of these 16 call gates.

---

## Table-0xe Stub Addresses

| Ep | Stub vmaddr | Dispatch ID | Likely endpoint |
|---|---|---|---|
| 0 | `0xfffffff00b3ffca0` | `0xe00000000` | SPTM_NVME_ENDPOINTID_INIT |
| 1 | `0xfffffff00b3ffce0` | `0xe00000001` | SPTM_NVME_ENDPOINTID_ADMIN_QUEUE_REGS |
| 2 | `0xfffffff00b3ffd20` | `0xe00000002` | SPTM_NVME_ENDPOINTID_IOCQ_REG |
| 3 | `0xfffffff00b3ffd60` | `0xe00000003` | SPTM_NVME_ENDPOINTID_IOSQ_REG |
| 4 | `0xfffffff00b3ffda0` | `0xe00000004` | SPTM_NVME_ENDPOINTID_IOQA_REG |
| 5 | `0xfffffff00b3ffde0` | `0xe00000005` | SPTM_NVME_ENDPOINTID_SHA_REG |
| 6 | `0xfffffff00b3ffe20` | `0xe00000006` | SPTM_NVME_ENDPOINTID_MAP_PAGES |
| 7 | `0xfffffff00b3ffe60` | `0xe00000007` | SPTM_NVME_ENDPOINTID_UNMAP_PAGES |
| 8 | `0xfffffff00b3ffea0` | `0xe00000008` | SPTM_NVME_ENDPOINTID_SET_SQ_ENTRY |
| 9 | `0xfffffff00b3ffee0` | `0xe00000009` | SPTM_NVME_ENDPOINTID_ENABLE_CG |
| 10 | `0xfffffff00b3fff20` | `0xe0000000a` | (unlisted — no VIOLATION guard in SPTM strings) |
| 11 | `0xfffffff00b3fff60` | `0xe0000000b` | (unlisted) |
| 12 | `0xfffffff00b400020` | `0xe0000000c` | (unlisted) |
| 13 | `0xfffffff00b400060` | `0xe0000000d` | (unlisted) |
| 14 | `0xfffffff00b3fffa0` | `0xe0000000e` | (unlisted) |
| 15 | `0xfffffff00b3fffe0` | `0xe0000000f` | (unlisted) |

SPTM_NVME has 10 named endpoints in SPTM strings. Endpoints 10–15 are additional unlisted
NVMe call gates — possibly queue management, error injection, or power state.

---

## String Evidence

```
PRELINK_TEXT hits (nvme/NVMe/NVME/IOFilter):
  2,027  com.apple.iokit.IONVMeFamily      ← 34× more than second place
     60  com.apple.security.sandbox        (policy references only)
     35  com.apple.kernel                  (wrapper functions)
```

---

## Calling Mechanism: Indirect Dispatch

No direct BL to any stub vmaddr exists in __TEXT_EXEC or __PRELINK_TEXT.
Each stub is called via a PAC-signed function pointer table in __DATA_CONST.

### Stub disassembly (ep1 example)

```
0xfffffff00b3ffcbc: PACIBSP
0xfffffff00b3ffcc0: STP x29, x30, [sp, #-16]!
0xfffffff00b3ffcc4: MOV x29, sp
0xfffffff00b3ffcc8: BL 0xfffffff00ab4bf78   ; disable_preemption wrapper
0xfffffff00b3ffccc: MOVZ x16, #0x1          ; endpoint = 1
0xfffffff00b3ffcd0: MOVK x16, #0xe, lsl#32  ; table = 0xe
0xfffffff00b3ffcd4: ADRP x8, sptm_ready_page
0xfffffff00b3ffcd8: LDRB w8, [x8, sptm_ready_offset]
0xfffffff00b3ffcdc: CBNZ w8, .genter_ok
                   BRK #0                   ; SPTM not ready → panic
.genter_ok:
                   GENTER
```

The `disable_preemption` wrapper at `0xab4bf78`:
- Saves x16 (dispatch ID) with `MOV x20, x16`
- Saves argument registers x0–x7
- Increments per-thread preemption-disable count from TPIDR_EL1
- Saves interrupt state (DAIF)

---

## Security Analysis

### Highest-value targets

1. **`SET_SQ_ENTRY` (ep 8, `0xe00000008`)** — writes an NVMe submission queue entry under
   SPTM validation. The `VIOLATION_NVME_INVALID_QTAIL` guard checks the queue tail index.
   An off-by-one in SPTM's bounds check, or a missed check on the queue base address, could
   allow an NVMe command directed at arbitrary physical memory.

2. **`MAP_PAGES` / `UNMAP_PAGES` (ep 6/7)** — DMA mapping path. If SPTM validates page type
   on MAP but not with equal strictness on UNMAP, there may be a TOCTOU window to retype a
   mapped page before the mapping is revoked.

3. **Endpoints 10–15 (unlisted)** — have no corresponding VIOLATION strings in the SPTM
   binary, suggesting they were added late or are expected unreachable under normal conditions.
   An endpoint with no validation guard is a priority investigation target.

---

## Conclusion

- **Table 0xe** = `SPTM_NVME`
- **Calling kext** = `com.apple.iokit.IONVMeFamily`
- **Call mechanism** = ptrauth-signed function pointer + preemption wrapper at `0xab4bf78`
- **Next steps**:
  1. Trace `SPTM_NVME_ENDPOINTID_SET_SQ_ENTRY` handler in sptm_27.0.1.bin for bounds checks
  2. Investigate endpoints 10–15 for missing VIOLATION guards
  3. Study MAP_PAGES/UNMAP_PAGES for TOCTOU window
