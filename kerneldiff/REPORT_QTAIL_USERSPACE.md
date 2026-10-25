# q_tail User-Space Exposure: IONVMeFamily IOUserClient Analysis

*Generated 2026-10-25 | kc_27.0.1.macho IONVMeFamily @ fileoff 0x9c78f0 (68KB)*

---

## Summary

**q_tail is NOT directly reachable from user space.** IONVMeFamily's user clients are
entitlement-gated and none expose queue tail parameters. The q_tail walk-off (Gap 2) requires
kernel-level code execution to trigger. However, the `nvme-sptm` EDT property analysis
surfaced a significant gating finding.

---

## IOUserClient Presence

IONVMeFamily has **four** IOUserClient subclasses, all entitlement-gated:

| Class | Methods | Entitlement |
|---|---|---|
| `AppleNVMeUserClient` | `Sanitize` only | `com.apple.AppleNVMeSanitize.allow` |
| `AppleNVMeFWNamespaceUC` | `writeFWImage`, `writeDescriptorTable`, `rollbackFWImage` | `com.apple.AppleNVMeFWNamespace.allow` |
| `AppleNVMeUpdateUC` | `FirmwareActivate`, `FinalizeFWUpdate`, `UpdateMspBfhParams`, `FirmwareDownload` | (update entitlement) |
| `AppleNVMeEAN` | EAN read/write | (EAN entitlement) |

None expose q_tail, queue indices, or submission queue parameters.
`CheckEntitlementForSelector` rejects unknown selectors with a warning log.

---

## q_tail Parameter Path

q_tail enters SET_SQ_ENTRY only through kernel-internal paths:
- `AppleANS2CGv2Controller::NVMeCoastGuardSetTCBEntry(tcb_queue_entry *, AppleNVMeRequest *)`
- `AppleANS2CGNVMeController::NVMeCoastGuardSetTCBEntry(tcb_queue_entry *, AppleNVMeRequest *)`

Both take a `tcb_queue_entry *` which is kernel-allocated. No shared-memory path found.
No `IOMemoryDescriptor::withAddressRange` or `createMappingInTask` near NVMe queue context.

---

## nvme-sptm EDT Property — AppleANS3CGv2Controller::probe()

`AppleANS3CGv2Controller::probe()` checks three EDT properties in sequence:

```
nvme-linear-sq-disable  → if set: "NVMe LinearSQ disabled through boot-arg", skip LSQ
nvme-sppl               → if present: probe wins with PPL-era coastguard path
nvme-sptm               → if present: probe wins with SPTM-era coastguard path
```

`nvme-sptm` in the device tree is what activates SPTM NVMe mediation entirely.
On a device where this property is absent, AppleANS3CGv2Controller loses probe and
the SPTM enforcement layer never loads — all three SET_SQ_ENTRY gaps become irrelevant
because SET_SQ_ENTRY is never called.

This property is set by secure-boot-verified firmware. Not user-space settable.

Additionally `nvme-linear-sq-disable` boot-arg gates linear-SQ at the IOKit level
before SPTM is involved — a second gate independent of the SPTM-side nvme_instance flag.

---

## AppleANS2DARTNVMeController (older/fallback path)

`AppleANS2DARTNVMeController::probe()` checks `nvme-linear-sq` (no -disable suffix) and
`nvme-ans-dart`. When matched, `EnableLinearSQ()` runs unconditionally during
`InitializeNVMe()` ("Enabling LSQ"). This older controller does NOT use SPTM mediation
(no pmap_iommu_ioctl), so SPTM gaps do not apply to it.

---

## Exploitability Verdict

| Gap | User-space reachable | Required level |
|---|---|---|
| Gap 1 — Linear mode PA bypass | No | Boot-time / kext compromise |
| Gap 2 — q_tail walk-off | **No** | Kernel code execution |
| Gap 3 — SQ content unchecked | No | Kernel code execution |

All three gaps require kernel execution first. The attack chain is:
1. Gain kernel code execution (separate vuln)
2. Reach IONVMeFamily execution context
3. Forge tcb_queue_entry with out-of-range q_tail
4. Call NVMeCoastGuardSetTCBEntry → GENTER SET_SQ_ENTRY → walk-off in SPTM qtail_state

---

## nvme-sptm: Security Implication

If boot chain is compromised and nvme-sptm is removed from EDT:
- SPTM NVMe layer never loads
- All NVMe I/O bypasses SPTM enforcement entirely
- Relevant only post-boot-chain compromise; not a standalone attack surface
