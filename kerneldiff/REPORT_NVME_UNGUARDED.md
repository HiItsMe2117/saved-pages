# SPTM NVMe Endpoints 10–15: Guard Analysis

*Generated 2026-10-25 | sptm_27.0.1.bin vs sptm_26.6.1.bin*

---

## Summary

Endpoints 10–15 in dispatch table 0xe (SPTM_NVME) are **not unguarded — they are
unreachable under normal operation**, gated by `validate_nvme_call_allowed` +
`nvme_instance->allowed_functions`. Calling them triggers `VIOLATION_NVME_ILLEGAL_CALL`.

Higher-priority target: `sptm_nvme_set_sq_entry` (ep 8) is **brand-new in 27.0.1**
with a fresh qtail state machine and the most complex validation logic in the NVMe
subsystem — highest probability of implementation bugs.

---

## Surprising Discovery: NVMe Was Already in SPTM 26.6.1

| Item | 26.6.1 | 27.0.1 | Delta |
|---|---|---|---|
| NVMe string count | 59 | 72 | +13 |
| VIOLATION_NVME count | 16 | 18 | +2 |
| Named ENDPOINTID strings | 0 | 10 | +10 |
| `SPTM_DISPATCH_TABLE_NVME` | absent | present | new |
| `sptm_nvme_set_sq_entry` | absent | present | **new handler** |
| VIOLATION_NVME_INVALID_QTAIL | absent | present | new |
| VIOLATION_NVME_ILLEGAL_QTAIL_STATE_TRANSITION | absent | present | new |

**What table-0xe actually means:** In 26.6.1, NVMe was called through the old
integer-based SPTM dispatch. In 27.0.1, NVMe was migrated to the named dispatch
table system (`SPTM_DISPATCH_TABLE_NVME`). The 16 table-0xe stubs in XNU are new
entry points to pre-existing SPTM handlers — plus one new one (SET_SQ_ENTRY).

---

## NVMe Handler Inventory

| ep | ENDPOINTID | Handler | New in 27? |
|---|---|---|---|
| 0 | INIT | nvme_bootstrap | no |
| 1 | ADMIN_QUEUE_REGS | sptm_nvme_bar_admin_queue_regs | no |
| 2 | IOCQ_REG | sptm_nvme_bar_iocq_reg | no |
| 3 | IOSQ_REG | sptm_nvme_bar_iosq_reg | no |
| 4 | IOQA_REG | sptm_nvme_bar_ioqa_reg | no |
| 5 | SHA_REG | sptm_nvme_ans_sha_reg | no |
| 6 | MAP_PAGES | sptm_nvme_map_pages | no |
| 7 | UNMAP_PAGES | sptm_nvme_unmap_pages | no |
| 8 | SET_SQ_ENTRY | sptm_nvme_set_sq_entry | **YES** |
| 9 | ENABLE_CG | (power management) | no |
| 10-15 | (unlisted) | none | n/a |

---

## Guard Pattern for Named Endpoints (0–9)

### `validate_nvme_call_allowed` + `allowed_functions` bitmask

Every NVMe endpoint passes through `validate_nvme_call_allowed`, which checks
`nvme_instance->allowed_functions`. This bitmask is set from devicetree property
`nvme-iboot-sptm-security` during `nvme_bootstrap`. Endpoints not in the bitmap
trigger `VIOLATION_NVME_ILLEGAL_CALL`.

### `func_state` ordering state machine (eps 1–5)

```
func_state[4] → sptm_nvme_bar_admin_queue_regs (ep 1)
func_state[5] → sptm_nvme_bar_ioqa_reg         (ep 4)
func_state[6] → sptm_nvme_bar_iosq_reg         (ep 3)
func_state[7] → sptm_nvme_bar_iocq_reg         (ep 2)
func_state[8] → sptm_nvme_ans_sha_reg          (ep 5)
```

Out-of-order calls trigger `VIOLATION_NVME_ILLEGAL_FUNC_CALL_STATE`.

### `qtail_state` queue-tail state machine (ep 8 only, NEW)

`sptm_nvme_set_sq_entry` uses `nvme_instance->qtail_state[q_id][q_tail]`.
States: `QTAIL_LIVE` / `QTAIL_BUSY`. Guards:
- `VIOLATION_NVME_INVALID_QTAIL`
- `VIOLATION_NVME_ILLEGAL_QTAIL_STATE_TRANSITION`

Both absent in 26.6.1 — entirely new code.

---

## Endpoints 10–15: Unreachable, Not Unguarded

`validate_nvme_call_allowed` blocks all unlisted endpoints via `VIOLATION_NVME_ILLEGAL_CALL`
(present in both versions — this was designed from the start as the catch-all).

Eps 10–15 are pre-allocated slots for future expansion. Not currently dangerous.
Flag for review when Apple adds handlers in a future release.

---

## Security Assessment

### Priority 1 — `sptm_nvme_set_sq_entry` (ep 8)

Only new NVMe handler in 27.0.1. Manages `qtail_state[q_id][q_tail]` — a 2D array
indexed by attacker-influenced values. If SPTM does not validate `q_id < max_queues`
and `q_tail < queue_length` BEFORE indexing, the pointer `&nvme_instance->qtail_state[q_id][q_tail]`
could escape the nvme_instance struct and corrupt adjacent SPTM memory at GL2.

### Priority 2 — `allowed_functions` bitmask integrity

Lives in `nvme_instance` in SPTM's `__DATA` segment. Any path giving XNU write
access to SPTM's data segment could flip bits and open all 16 endpoint slots,
including the currently-unimplemented 10–15.

### Priority 3 — `MAP_PAGES` / `UNMAP_PAGES` TOCTOU

DMA mapping path. Window between `MAP_PAGES` setting page type and IOMMU programming
completing, or between `UNMAP_PAGES` removing the mapping and type restoration.
A concurrent CPU core retype attempt during that window is worth exploring.

### Eps 10–15: Low risk now, flag for next release

Not a current attack surface. When Apple adds handlers for these slots in a future
release, pre-existing XNU stubs will call them immediately — new, less-reviewed
handler code with an existing entry path.
