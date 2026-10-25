# SPTM NVMe SET_SQ_ENTRY: Bounds Check Analysis

*Generated 2026-10-25 | sptm_27.0.1.bin (1,196,064 bytes)*

---

## What SET_SQ_ENTRY Does

`sptm_nvme_set_sq_entry` (file offset `0x0b8654`) is called by `IONVMeFamily` to
write an NVMe submission queue tail pointer and mark queue slots for dispatch.
SPTM mediates the write to prevent IONVMeFamily from directing NVMe DMA at
arbitrary physical memory.

**Call signature (inferred):**
```c
void sptm_nvme_set_sq_entry(nvme_instance_t *inst, uint32_t q_id,
                             paddr_t queue_base, uint32_t q_tail, ...);
```

---

## Guards Present

### 1. Instance state guard (bit flags at `[nvme_instance+20]`)
```
0x0b867c: TBZ x9, #8, 0x0b8884   ; → VIOLATION if bit 8 clear (not CALLABLE)
0x0b8684: TBZ x9, #0, 0x0b88d4   ; → panic "ANS SHA flag was not set"
```
Both checks fire before any arguments are used.

### 2. Queue ID validation
```
0x0b86ac: CMP x1, x10            ; compare q_id against max_queues
0x0b86b0: B.NE 0x0b89f8          ; → VIOLATION_NVME_ILLEGAL_QUEUE_ADDRESS path
```

### 3. Physical address range check (NON-LINEAR MODE ONLY)
```
0x0b86cc: LDR x11, [x8, #3432]   ; safe range low bound
0x0b86d4: LDR x12, [x10, #504]   ; IOMMU range low
0x0b86dc: LDR x13, [x10, #512]   ; IOMMU range high
0x0b86f0: CMP x10, x11  → B.CC   ; PA vs low
0x0b8700: CMP x10, x17  → B.CC   ; PA vs high
0x0b8708: CMP x10, x12  → B.CC   ; IOMMU range check
0x0b8710: CMP x10, x13  → B.CS   ; → VIOLATION_NVME_ILLEGAL_QUEUE_ADDRESS
```
Two allowed ranges validated: a registered NVMe safe range and an IOMMU range.

### 4. Queue tail state machine (`validate_qtail` at `0x0c5828`)
`validate_qtail` reads `qtail_state[q_id]` byte via:
```
0x0c5904: LDRB w8, [x24, #0xc08]
```
Then checks state flags with TBZ/TBNZ. `VIOLATION_NVME_INVALID_QTAIL` fires on
invalid state transitions — **this is a state-machine check, not a numeric
bounds check on the index**.

---

## Missing Validations (Security-Relevant)

### GAP 1 — LINEAR MODE BYPASSES PA RANGE CHECK

```
0x0b86c4: CBZ w10, 0x0b8768   ; if linear queueing mode → SKIP PA checks
```

When `nvme-linear-sq` is set, the PA range validation at `0x0b86cc–0x0b8714`
is skipped entirely. The function falls through to:
```
0x0b8770: STR x0, [x8, #4096]  ; store queue pointer (unvalidated)
0x0b87a0: STR w10, [x8, #0]    ; write q_tail to SQ memory
```
**In linear queueing mode, `queue_base` is not checked against any safe range.**
If a compromised `IONVMeFamily` can set this mode flag in the `nvme_instance`
structure before calling into SPTM, the entire PA validation is conditionally bypassed.

### GAP 2 — q_tail NOT NUMERICALLY BOUNDS-CHECKED

No instruction of the form `CMP w_qtail, #MAX_DEPTH` exists.
`validate_qtail` reads `qtail_state[q_tail]` via the `q_tail` offset itself —
**the bounds check IS the memory access**. An out-of-range `q_tail` reads past
the array end, potentially passing the state check with garbage data.

### GAP 3 — SQ ENTRY CONTENT NOT VALIDATED

`STR w10, [x8, #0]` at `0x0b87a0` writes to queue memory without inspecting
the 64-byte NVMe SQE payload (opcode, NSID, PRP list, CDW10–CDW15).
SPTM trusts queue address safety; protocol correctness is not checked.

---

## Code Evidence

| Offset | Instruction | Meaning |
|--------|-------------|---------|
| `0x0b8654` | `PACIBSP` | Function entry |
| `0x0b867c` | `TBZ x9, #8` | Instance CALLABLE check |
| `0x0b86ac` | `CMP x1, x10` | q_id range check |
| `0x0b86c4` | `CBZ w10, 0xb8768` | **LINEAR MODE — skips PA validation** |
| `0x0b86f0` | `CMP x10, x11` | PA lower bound (non-linear only) |
| `0x0b8700` | `CMP x10, x17` | PA upper bound |
| `0x0b8748` | `BL 0x0e00f4` | State machine check per slot |
| `0x0b8770` | `STR x0, [x8, #4096]` | Store queue pointer |
| `0x0b87a0` | `STR w10, [x8, #0]` | **Write q_tail to SQ memory** |
| `0x0c5904` | `LDRB w8, [x24, #0xc08]` | qtail_state byte (bounds = the read itself) |

---

## Exploitation Relevance

**Linear mode bypass (Gap 1)** is the highest-value finding. `nvme-linear-sq`
originates from the device tree (string at `0x5010: nvme-linear-sq`). If a
compromised `IONVMeFamily` can manipulate the `nvme_instance` structure field
that caches this flag before calling `SPTM_NVME_ENDPOINTID_SET_SQ_ENTRY`, the
PA range validation is completely bypassed — NVMe DMA could be directed at
arbitrary physical memory.

**q_tail unbounded read (Gap 2)** is a secondary risk: large `q_tail` walks
`qtail_state[]` out of bounds before the state check, with outcomes depending
on what memory follows the array.

---

## Next Steps

1. Determine where `nvme-linear-sq` flag is stored in `nvme_instance` at runtime.
2. Verify whether `nvme_instance` is in XNU-writable memory during `IONVMeFamily` operation.
3. Measure `nvme_instance->qtail_state` array size and identify what follows it.
