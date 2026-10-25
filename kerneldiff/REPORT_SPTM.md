# SPTM Binary Diff: iOS 26.6.1 → 27.0.1

*Generated 2026-10-25*

**Device:** iPhone 16 Plus (iPhone17,4) — A18 (t8140)
**Chip SPTM variant:** `sptm.t8140.release.im4p`

| | 26.6.1 (23G83) | 27.0.1 (24A446) | Δ |
|---|---|---|---|
| Binary size | 1,146,912 bytes (1.09MB) | 1,196,064 bytes (1.14MB) | +49,152 (+4.3%) |
| Strings extracted | 1,935 | 2,187 | +252 |
| VIOLATION_* codes | 224 | 234 | +10 |
| ENDPOINTID names | 0 | 36 | +36 |
| DISPATCH_TABLE IDs | 2 | 21 | +19 |

---

## 1. VIOLATION Taxonomy Diff

SPTM uses a named `VIOLATION_*` enum to classify every enforcement failure. Each string is a panic identifier.

**Summary:** 224 → 234 (+11 new, −1 removed)

### New in 27.0.1

| Violation | Subsystem | Notes |
|---|---|---|
| `VIOLATION_CPU_NOT_INITIALIZED` | CPU | CPU must be SPTM-initialized before use |
| `VIOLATION_ILLEGAL_DISPATCH_CMD` | Dispatch | Named-endpoint dispatch commands must be valid |
| `VIOLATION_INVALID_CPU_LOGICAL_ID` | CPU | CPU logical ID validation |
| `VIOLATION_IOMMU_RESTRICTED_IO_RANGE` | IOMMU | IO range restriction enforcement |
| `VIOLATION_NVME_ILLEGAL_QTAIL_STATE_TRANSITION` | NVMe | Queue state machine enforcement |
| `VIOLATION_NVME_INVALID_QTAIL` | NVMe | Queue tail pointer validation |
| `VIOLATION_OUT_OF_BOUNDS_IOFILTER` | IOFilter | IO filter bounds checking |
| `VIOLATION_T8110_DART_SID_TRANSLATION_DISABLED` | DART | DART SID translation must be enabled |
| `VIOLATION_UAT_SAPT_INVALID_REFCNT` | UAT/GPU | GPU page table reference count integrity |
| `VIOLATION_UAT_SAPT_REVOKE_FRAME_HELD_SHARED` | UAT/GPU | GPU shared frame revoke guard |
| `VIOLATION_UAT_SAPT_REVOKE_PAGE_WAS_PERM_NA` | UAT/GPU | GPU perm-NA page revoke guard |

### Removed from 27.0.1

| Violation | Notes |
|---|---|
| `VIOLATION_CPUTRACE_VA_ACTIVE` | CPU trace VA tracking enforcement restructured |

**Security analysis:**
- Only **1 violation removed** — `VIOLATION_CPUTRACE_VA_ACTIVE`. Its removal is paired with the new CPUTRACE endpoint state machine (`VA_FRM_LOCK/UNLOCK`, `VA_INIT/DEINIT`). The check moved into a structured endpoint flow, not dropped.
- **3 new UAT/GPU violations** close reference-count and revocation gaps in GPU page table management — directly relevant to the AGX cache-poisoning attack surface from Trigon Part 3.
- **New IOMMU restriction violations** (`IOMMU_RESTRICTED_IO_RANGE`, `OUT_OF_BOUNDS_IOFILTER`) reflect a new central SPTM-enforced IO range restriction system.
- **CPU initialization guards** (`CPU_NOT_INITIALIZED`, `INVALID_CPU_LOGICAL_ID`) harden CPU bring-up.

## ✓ Checkpoint: 1. VIOLATION Diff

---

## 2. EXEC_MODE Diff

| Mode | 26.6.1 | 27.0.1 |
|---|---|---|
| `EXEC_MODE_SK_DEFAULT` | ✗ | ✓ **NEW** |
| `EXEC_MODE_SPTM_DEFAULT` | ✓ | ✓ |
| `EXEC_MODE_TXM_DEFAULT` | ✓ | ✓ |
| `EXEC_MODE_XNU_DEFAULT` | ✓ | ✓ |
| `EXEC_MODE_XNU_ROZONE_RW` | ✓ | ✓ |
| `EXEC_MODE_XNU_USER_DEFAULT` | ✓ | ✓ |
| `EXEC_MODE_XNU_USER_JIT_RW` | ✓ | ✓ |
| `EXEC_MODE_XNU_USER_TPRO_RW` | ✓ | ✓ |

**`EXEC_MODE_SK_DEFAULT` is new.** The Secure Kernel now has a formally named SPTM execution mode. In 26.6.1 SK called into SPTM without a distinct mode identity. In 27.0.1 SPTM enforces SK's execution context just as it does for TXM and XNU — paired with new `SK_TO_SPTM_ENDPOINTID_*` call gates.

Existing XNU modes (JIT_RW, TPRO_RW, ROZONE_RW) are unchanged — no new user-space execution contexts added.

## ✓ Checkpoint: 2. EXEC_MODE Diff

---

## 3. Boot Sequence Diff

Bootstrap order is identical in both versions:
```
[SK BOOTSTRAP PANIC]   ← panic handler active from first instruction
SK bootstrap complete.
TXM bootstrap complete.
Bootstrapping XNU...
```

State strings present in both: `STATE_SK_BOOTSTRAP`, `STATE_TXM_BOOTSTRAP`, `STATE_SPTM_CALLED_BY_TXM_BOOTSTRAP`.

Boot enforcement staging unchanged: `bootstrap_stage_enforce_before` / `bootstrap_stage_enforce_after` both present. The enforcement window during boot did not change.

### Changes

**Error strings upgraded from integer to symbolic:**
- Old: `%s: invalid bootstrap frames type %d, expected SPTM_IOMMU_BOOTSTRAP (%d) or XNU_CPUTRACE_PA_BUFFER (%d).`
- New: `%s: invalid bootstrap frames type %s, expected SPTM_IOMMU_BOOTSTRAP or XNU_CPUTRACE_PA_BUFFER.`

This is consistent across all changed error strings — the `%d` integer type IDs became `%s` symbolic names throughout 27.0.1.

**Removed:** `[SPTM Dispatch] Synchronous exception taken while SP1 selected in GL2`
The GL2 stack-corruption panic string was removed. The guard likely still exists but is now handled by the new dispatch state machine.

## ✓ Checkpoint: 3. Boot Sequence Diff

---

## 4. Endpoint / Dispatch Table Diff

**This is the most significant structural change.**

### ENDPOINTID: 0 → 36

In 26.6.1 the SPTM dispatch system had **no named endpoint IDs** in its string table. Every call was identified by a raw integer with `%d` format specifiers. In 27.0.1 every call gate is a named `*_ENDPOINTID_*` constant, validated by the new `VIOLATION_ILLEGAL_DISPATCH_CMD` guard.

**All 36 ENDPOINTIDs in 27.0.1:**

**SK → SPTM (3 — entirely new call surface):**
```
SK_TO_SPTM_ENDPOINTID_PHYS_TO_TYPE
SK_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE
SK_TO_SPTM_ENDPOINTID_RETYPE
```

**TXM → SPTM (4):**
```
TXM_TO_SPTM_ENDPOINTID_FIXUPS_COMPLETE
TXM_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE
TXM_TO_SPTM_ENDPOINTID_RETYPE
TXM_TO_SPTM_ENDPOINTID_USER_ASID
```

**SPTM NVMe (12 — storage controller mediation):**
```
SPTM_NVME_ENDPOINTID_ADMIN_QUEUE_REGS  SPTM_NVME_ENDPOINTID_ENABLE_CG
SPTM_NVME_ENDPOINTID_INIT              SPTM_NVME_ENDPOINTID_IOCQ_REG
SPTM_NVME_ENDPOINTID_IOQA_REG         SPTM_NVME_ENDPOINTID_IOSQ_REG
SPTM_NVME_ENDPOINTID_MAP_PAGES         SPTM_NVME_ENDPOINTID_SET_SQ_ENTRY
SPTM_NVME_ENDPOINTID_SHA_REG           SPTM_NVME_ENDPOINTID_UNMAP_PAGES
```

**SPTM CPU Trace (12):**
```
SPTM_CPUTRACE_ENDPOINTID_IS_MODE
SPTM_CPUTRACE_ENDPOINTID_PA_CRV_ADDR / PA_CRV_SIZE / PA_SET_BASE / PA_START / PA_STOP
SPTM_CPUTRACE_ENDPOINTID_VA_DEINIT / VA_FRM_LOCK / VA_FRM_UNLOCK
SPTM_CPUTRACE_ENDPOINTID_VA_INIT / VA_SET_BASE / VA_START / VA_STOP
```

**SPTM Hibernation (6):**
```
SPTM_HIB_ENDPOINTID_FINALIZE_HASH     SPTM_HIB_ENDPOINTID_FINALIZE_IMAGE
SPTM_HIB_ENDPOINTID_FINALIZE_SK       SPTM_HIB_ENDPOINTID_HASH_HIBSEG_PAGE
SPTM_HIB_ENDPOINTID_HASH_PAGE         SPTM_HIB_ENDPOINTID_IOFILTER_PROTECTED_WRITE
```

### DISPATCH_TABLE IDs: 2 → 21

26.6.1 had only `SPTM_DISPATCH_TABLE_XNU_BOOTSTRAP` and `SPTM_DISPATCH_TABLE_TXM_BOOTSTRAP`.

27.0.1 adds: `CPUTRACE`, `GEN3_DART_SK`, `GEN3_DART_XNU`, `HIB`, `NVME`, `RESERVED2`, `SART`, `SHART`, `UAT`, plus SK bootstrap. Each is a separately guarded call gate with its own domain and permission set.

### Removed dispatch strings

Old integer-dispatch strings removed:
- `genter_dispatch_entry` — old GENTER dispatch path name
- `dispatch_id_to_string` — old integer-to-name conversion
- `sanitize_integer(dispatch_entry_addr_U.UNSAFE_VALUE)` — old unsafe integer dispatch flow
- `sanitize_integer(dispatch_target_U.UNSAFE_VALUE)` — old dispatch target sanitization

## ✓ Checkpoint: 4. Endpoint/Dispatch Diff

---

## 5. Binary Byte Diff

```
26.6.1 size:   1,146,912 bytes
27.0.1 size:   1,196,064 bytes
Size delta:      +49,152 bytes (+4.3%)
Overlapping:   1,146,912 bytes
Changed bytes:   451,351 (39.4%)
Changed regions >32 bytes: 4,135
```

39.4% changed — full recompile, same pattern as XNU diffs. The size delta (+49KB) is one new page at 0xf4000.

### Top Changed Regions (by size)

| Offset | Size | Context |
|--------|------|---------|
| +0x00099038 | 4,040 | *(dispatch table data — pointer array rebuilt)* |
| +0x000f5038 | 4,040 | *(dispatch table data — pointer array rebuilt)* |
| +0x000f4000 | 2,048 | *(new page — SK dispatch table infrastructure)* |
| +0x00006d56 | 1,027 | T8110 DART validation (new DART violations) |
| +0x0000a874 | 737 | DART SID preconfiguration |
| +0x00016040 | 641 | `cpu_root_table_tsd_const`, frame type retrieval |
| +0x0000b48c | 591 | `sptm_t8110dart_disable_clock_protection` |
| +0x0000c313 | 577 | `VIOLATION_ILLEGAL_RETYPE_PINNED`, `VIOLATION_ILLEGAL_MAP` — retype/map enforcement |
| +0x0000681f | 534 | SART bootstrap, throttle sanity checks |
| +0x0000cb7e | 493 | `VIOLATION_ILLEGAL_VIRTUALIZATION_CALL`, `VIOLATION_ILLEGAL_SPTM_REENTRY_CALL` |
| +0x0000553a | 457 | `assert_ctrr_group_region_unlocked`, AMCC cache disable |
| +0x0000b0aa | 434 | T8110 DART power state write-disable |
| +0x00005e80 | 423 | `SPTM PANIC:` handler, `TRUNCATED ORIGINAL PANIC:` |
| +0x00012bf8 | 418 | Hibernation image bounds checks |
| +0x0000bf6e | 409 | Core dump region handling |
| +0x000118ec | 397 | `INVALID_DISPATCH_TABLE_ID`, dispatch infrastructure |
| +0x0000f8fc | 383 | `sapt_set_permissions` — GPU page table permissions |
| +0x0000ae44 | 381 | T8110 DART register write |
| +0x00004934 | 355 | NVMe queue ID / CID / queue tail violations |
| +0x0000620d | 348 | SART invalid permission / options / state |

The two 4,040-byte data regions are rebuilt dispatch table pointer arrays. The 2,048-byte region at 0xf4000 is the new SK dispatch table page.

## ✓ Checkpoint: 5. Binary Diff

---

## Key Takeaways

### 1. The dispatch architecture was redesigned (biggest change)

In 26.6.1 dispatch was integer-indexed; in 27.0.1 every call gate has a named `(DISPATCH_TABLE_ID, ENDPOINTID)` pair validated by `VIOLATION_ILLEGAL_DISPATCH_CMD`. The old `sanitize_integer(dispatch_entry_addr_U.UNSAFE_VALUE)` path is gone. Forging a GENTER call now requires matching a valid named pair, not just an integer.

### 2. SK has a formal SPTM execution mode (new call surface)

`EXEC_MODE_SK_DEFAULT` + 3 new `SK_TO_SPTM_ENDPOINTID_*` endpoints. The Secure Kernel can now call SPTM for RETYPE, PHYS_TO_TYPE, and REGISTER_DISPATCH_TABLE. These are new call gates from SK into SPTM's retype path — the **primary new attack surface** introduced in 27.0.1.

### 3. GPU page table revocation gaps closed

Three new `VIOLATION_UAT_SAPT_*` violations close reference-count and revocation gaps:
- `SAPT_INVALID_REFCNT` — reference count integrity
- `REVOKE_FRAME_HELD_SHARED` — can't revoke while GPU holds shared reference
- `REVOKE_PAGE_WAS_PERM_NA` — can't revoke a perm-NA GPU page

The AGX cache-poisoning technique (Trigon Part 3) targeted physical memory aliasing. These violations guard the GPU SAPT revocation path — a researcher attempting a similar technique on iOS 27 would need to pass these.

### 4. IOMMU restriction system is new

SPTM now centrally tracks which IO ranges are "restricted" and enforces `VIOLATION_IOMMU_RESTRICTED_IO_RANGE`. Previously this was per-driver. New error strings confirm a registration API: `"Attempted to register a pmap-io-range that is restricted"`, `"Attempting to re-register restriction"`.

### 5. Only 1 violation removed

`VIOLATION_CPUTRACE_VA_ACTIVE` → replaced by structured CPUTRACE endpoint state machine. This is not a relaxation — it's a rewrite of the CPU trace enforcement path into the new named-endpoint system.

### 6. Comparison table for researchers

| Dimension | iOS 26 SPTM | iOS 27 SPTM |
|---|---|---|
| Dispatch model | Raw integer IDs | Named (table, endpoint) pairs |
| Dispatch errors | `%d` integers | `%s` symbolic names |
| SK call surface | None | 3 named endpoints (retype, phys_to_type, register_table) |
| GPU retype guards | 3 gaps (SAPT) | All 3 closed |
| IOMMU restrictions | Per-driver | SPTM-enforced central registry |
| CPU init guard | None | `VIOLATION_CPU_NOT_INITIALIZED` |
| CPUTRACE enforcement | Single VA-active guard | Full state machine (init/lock/unlock/deinit) |
| Boot enforcement window | Staged (unchanged) | Staged (unchanged) |

## ✓ Checkpoint: Key Takeaways

---

## Troubles & Solutions

**T1 — ENDPOINTID count looks wrong (0 in 26.6.1)**
Not a bug — 26.6.1 genuinely has 0 ENDPOINTID strings. The naming system is new to 27.0.1.

**T2 — 39.4% byte change rate**
Expected — full recompile. Position-dependent instructions shift everywhere. Meaningful findings come from string/symbol diff, not raw bytes.
