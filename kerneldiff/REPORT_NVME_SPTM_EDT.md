# nvme-sptm EDT Property: AppleANS3CGv2Controller::probe Analysis

*Generated 2026-10-25 | iOS 26.6.1 and 27.0.1*

---

## Summary

`nvme-sptm` is a **presence-check boolean EDT property** read during
`AppleANS3CGv2Controller::probe`. It is not a 27.0.1 addition — it exists identically
in 26.6.1. **SPTM-mediated NVMe was already opt-in via EDT in 26.6.1.**

The property gates whether the driver uses the SPTM path. The `nvme-iboot-sptm-security`
property (also present in 26.6.1) sources the `allowed_functions` bitmask that controls
which SPTM NVMe endpoints are callable.

---

## String Evidence

| String | 26.6.1 hits | 27.0.1 hits | Notes |
|---|---|---|---|
| `nvme-sptm` | 1 | 1 | In probe function, both versions |
| `nvme-iboot-sptm-security` | 1 | 1 | Sources allowed_functions bitmask |
| `nvme-linear-sq` | 2 | 2 | Stable across versions |
| `nvme-linear-sq-disable` | 1 | 1 | Boot-arg disables LinearSQ |
| `nvme-sppl` | 1 | 1 | Alongside nvme-sptm in probe |
| `nvme-secure-bar` | 1 | 1 | Separate secure register BAR property |
| `Enabling LSQ` | 1 | 1 | Log string for EnableLinearSQ() |

**Conclusion: no new EDT properties added in 27.0.1 for NVMe/SPTM.** The integration
predates 27.0.1. The table-0xe stubs are a dispatch architecture migration, not new functionality.

---

## Probe Function Context

From `AppleANS3CGv2Controller.cpp` (recovered from embedded debug path):

```
virtual IOService *AppleANS3CGv2Controller::probe(IOService *, SInt32 *)
  nvme-linear-sq-disable          <- boot-arg check: disable LinearSQ
  nvme-sppl                       <- SPPL presence check (semantics unknown)
  nvme-sptm                       <- SPTM-mediated path presence check
  %s::%d:Found (%s) provider and coastguard, returning score %d
  virtual void AppleANS3CGv2Controller::EnableLinearSQ()
```

Probe checks EDT properties in sequence. If nvme-sptm absent, driver falls back to
non-SPTM path. On A18 (iPhone 16 Plus) iBoot always sets this property.

**26.6.1 vs 27.0.1 probe difference:** 26.6.1 probe has `nvme-linear-sq` (bare)
as a separate EDT read with "Enabling LSQ" log. 27.0.1 probe string layout differs
slightly but nvme-sptm is present identically in both.

---

## nvme-iboot-sptm-security: allowed_functions Bitmask

Read during `AppleANS2NVMeController` initialization alongside:
`dual-spi-nand`, `gib-pcie-up`, `nvme-secure-bar`, `nvme-tl-wa`,
`nvme-secure-reg-layout`, `nvme-ans-sha-present`, `nvme-queue-entries`

Passed to SPTM at boot, before SPTM-ready flag. Not writeable at runtime.

---

## AppleNVMeFWNamespaceUC: Entitlement-Gated User Client

Exposes firmware namespace ops: `writeFWImage`, `writeDescriptorTable`, `rollbackFWImage`.
Gated by `com.apple.AppleNVMeFWNamespace.allow`. Does NOT use SET_SQ_ENTRY path.
Not a direct q_tail exposure — targets firmware namespace, not submission queues.

---

## Security Assessment

**SPTM NVMe path is NOT opt-in at runtime.** `nvme-sptm` is read from device tree
set by iBoot and sealed by Secure Boot. Cannot be changed at runtime.

**allowed_functions bitmask is fixed at boot.** Cannot unlock endpoints 10-15
without breaking Secure Boot.

**Non-SPTM path only on older hardware.** Devices without `nvme-sptm` in EDT use
legacy NVMe with no GL2 protection at all.

**nvme-sppl is unknown.** Appears alongside nvme-sptm in all versions examined.
Could gate an intermediate protection layer — potential downgrade path worth investigating.

**writeFWImage overlap check needed.** AppleNVMeFWNamespaceUC::writeFWImage is
entitlement-gated but writes to firmware namespace pages — check if those pages
overlap with NVMe submission queue pages in SPTM's view.

---

## Next Steps

1. Identify `nvme-sppl` semantics — intermediate protection layer or legacy flag?
2. q_tail user-space exposure (parallel investigation: REPORT_QTAIL_USERSPACE.md)
3. Check if firmware namespace pages overlap SQ pages in SPTM memory map
