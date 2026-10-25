# nvme_instance Writability: Linear Mode PA Bypass Assessment

*Generated 2026-10-25 | iOS 27.0.1*

---

## The Bypass (Re-Analyzed)

REPORT_NVME_SQENTRY.md identified a CBZ at `sptm+0x0b86c4`:

```
CBZ w10, 0x0b8768   ; when w10==0, branch to 0x0b8768
```

After tracing the full instruction sequence, the correct direction is:

| w10 | linear_sq state | Path |
|---|---|---|
| 0 (CBZ branches) | NOT set (default mode) | 0x0b8768: simple CMP + STR |
| nonzero (fall-through) | SET | 0x0b86c8: full PA range check loop |

Default non-linear mode skips the PA range check block. This is architecturally correct:
non-linear mode DMA pages are validated individually through the IOMMU/DART layer at map
time. Linear mode queues a single contiguous buffer requiring an explicit base+extent
range check that non-linear mode does not need. The log string
"%s: SET_SQ_ENTRY called in linear queueing mode" is informational, not an error path.

---

## nvme_instance Memory Type: SPTM-Private

nvme_instance is allocated and managed entirely within SPTM:

1. SPTM reads `nvme-linear-sq` from the EDT (embedded device tree) via
   `read_edt_properties` during `nvme_bootstrap` at boot time.
2. IONVMeFamily calls INIT endpoint (0xe00000000) to register queue params;
   SPTM validates and stores them inside nvme_instance.
3. nvme_instance resides in SPTM-private memory — not XNU-accessible.
4. No VIOLATION guards a direct XNU write because XNU has no memory path to the struct.

### EDT source confirms read-only from IONVMeFamily

Both controller classes read nvme-linear-sq from the device tree at probe time, not
at GENTER call time:
- `AppleANS2DARTNVMeController::probe` reads `nvme-linear-sq` (DTB property)
- `AppleANS3CGv2Controller::probe` reads `nvme-linear-sq-disable` (boot-arg override)
- `AppleANS3NVMeController::probe` calls `EnableLinearSQ()` based on probe result

IONVMeFamily does not write nvme_instance directly. It calls EnableLinearSQ() which
triggers INIT via GENTER, and SPTM records the mode internally.

### Flag location in struct

nvme_instance+0x10 bits[0..17]:
- zero  -> non-linear mode (CBZ branches to simpler path, no PA range check)
- nonzero -> linear mode (falls through to PA range check 0x0b86cc-0x0b8714)

Confirmed by: LDR w9, [x8, #0x10] at 0x0b86a4, UBFIZ w10, w9, #14, #18 at 0x0b86a8.

---

## IONVMeFamily Write Path: None (probe-time only)

No direct writes to nvme_instance found from IONVMeFamily PRELINK_TEXT.
nvme-linear-sq appears only in probe contexts (device tree reads, one-time at boot).

### EnableLinearSQ() is a virtual method — conditional attack vector

EnableLinearSQ() is virtual on at least 3 controller classes (AppleANS2DART, ANS3CGv2,
ANS3). An attacker with kext-level code execution could call it on a live controller
object. However this triggers INIT-endpoint SPTM validation (validate_nvme_queue_addr,
validate_nvme_queue_len) before recording the mode.

---

## Exploitability Verdict

NOT DIRECTLY EXPLOITABLE from XNU user space.

nvme_instance is SPTM-private. XNU cannot write it. Linear mode is set from EDT at
boot — not from GENTER arguments.

Conditional chain (3 stages):
1. Achieve kext-level code execution via separate vulnerability
2. Call EnableLinearSQ() on a live controller to set linear mode in SPTM's nvme_instance
3. Submit SET_SQ_ENTRY with malicious queue base PA through the now-enabled range check

The q_tail walk-off (Gap 2 from REPORT_NVME_SQENTRY.md) is more directly exploitable —
fires in ALL modes, no stage 1 needed if IONVMeFamily exposes q_tail to user space.

---

## Revised Gap Priority

| Gap | Prerequisite | Impact | Priority |
|---|---|---|---|
| q_tail walk-off (Gap 2) | IONVMeFamily kext access | SPTM memory read as state byte | HIGH |
| Linear mode PA bypass (Gap 1) | kext exec + EnableLinearSQ | Arbitrary DMA at GL2 | MEDIUM (3-stage) |
| SQ content unchecked (Gap 3) | Normal IONVMeFamily call | Command replay | LOW |

---

## Next Steps

1. q_tail walk-off: find max valid q_tail and whether IONVMeFamily exposes q_tail
   from user space (ioctl / IOSurface path). If yes: no stage 1 needed.
2. EnableLinearSQ INIT validation: can it be called after probe with forged parameters?
3. nvme-sptm EDT property (found in AppleANS3CGv2Controller::probe context):
   what does it gate? Potentially selects SPTM-mediated vs non-SPTM NVMe path.
