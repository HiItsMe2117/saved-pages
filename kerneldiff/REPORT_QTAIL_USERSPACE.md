# q_tail User-Space Exposure: IONVMeFamily IOUserClient Analysis

*Generated 2026-10-25 | iOS 27.0.1 kc_27.0.1.macho*

---

## Summary

**q_tail is NOT directly reachable from user space.**

The SET_SQ_ENTRY call chain is kernel-internal: the direct caller is
`NVMeCoastGuardSetTCBEntry(tcb_queue_entry *, AppleNVMeRequest *)`, which takes
kernel-owned structs. No IOUserClient external method passes a queue tail index
from user space into the NVMe submission queue path.

However, the investigation surfaced important structural information about the
SPTM path selection and the nvme-sptm EDT property.

---

## IONVMeFamily Region

| Field | Value |
|---|---|
| Fileset entry | `com.apple.iokit.IONVMeFamily` |
| File offset | `0x9c78f0` |
| Size | 68KB |
| vmaddr | `0xfffffff0079cb8f0` |

---

## IOUserClient Subclasses (all entitlement-gated)

| Class | Methods | Entitlement Required |
|---|---|---|
| `AppleNVMeUserClient` | `Sanitize` | `com.apple.AppleNVMeSanitize.allow` |
| `AppleNVMeUpdateUC` | `FirmwareActivate`, `FinalizeFWUpdate`, `UpdateMspBfhParams`, `FirmwareDownload` | Firmware update entitlement |
| `AppleNVMeFWNamespaceUC` | `writeFWImage`, `writeDescriptorTable`, `rollbackFWImage` | `com.apple.AppleNVMeFWNamespace.allow` |
| `AppleNVMeEANUC` | EAN read/write/erase/swap | `com.apple.AppleNVMeEAN.allow` |

None of these methods have any path to the NVMe submission queue tail.
All are firmware management operations. No external method accepts a queue ID
or queue tail index.

---

## q_tail Call Chain (kernel-only)

The direct caller of SPTM_NVME_ENDPOINTID_SET_SQ_ENTRY (table 0xe, ep 8):

```
NVMeCoastGuardSetTCBEntry(tcb_queue_entry *, AppleNVMeRequest *)
    -> pmap_iommu_ioctl(NVME_PPL_IOCTL_SET_SQ_ENTRY, ...)
        -> [SPTM stub: table=0xe, ep=8, GENTER]
```

tcb_queue_entry and AppleNVMeRequest are kernel-internal structs.
The q_tail value flows from NVMe command dispatch within the kernel only.

**Exploiting Gap 2 requires kernel code execution as a precondition.**

---

## nvme-sptm EDT Property: AppleANS3CGv2Controller::probe

nvme-sptm appears alongside nvme-sppl in AppleANS3CGv2Controller::probe
as OR conditions — if EITHER is present in the device tree, the SPTM-mediated
NVMe controller wins the IOKit probe.

```
probe() string sequence:
  nvme-linear-sq-disable  -> boot-arg to disable linear SQ
  nvme-sppl               -> old PPL-based path selector (legacy)
  nvme-sptm               -> new SPTM-based path selector
  "Found (%s) provider and coastguard, returning score %d"
  EnableLinearSQ()        -> called if linear SQ enabled
```

nvme-sppl = PPL-era (iOS 26 style); nvme-sptm = SPTM-era (iOS 27, table-0xe).
Both properties cause AppleANS3CGv2Controller to win. The iPhone 16 Plus (A18)
device tree has nvme-sptm set at provisioning time.

**Downgrade risk:** Devices with nvme-sppl but NOT nvme-sptm use the pre-SPTM
NVMe path — all VIOLATION_NVME_* guards and table-0xe enforcement are inactive.
Affects older silicon or modified device trees, not A18.

---

## EnableLinearSQ() Virtual Method

Three controller classes implement it:
- AppleANS2DARTNVMeController::EnableLinearSQ() - DART path
- AppleANS3CGv2Controller::EnableLinearSQ()     - SPTM path (A18)
- AppleANS3NVMeController::EnableLinearSQ()     - older ANS3

All called from probe() during IOKit matching — before driver is user-accessible.
To call EnableLinearSQ() after init requires kernel exec + vtable control.

---

## Exploitability Verdict

| Gap | User-space reachable | Condition to exploit |
|---|---|---|
| Gap 1: Linear mode PA bypass | NO | Kernel exec + vtable control + SPTM write primitive |
| Gap 2: q_tail walk-off | NO | Kernel exec required |
| Gap 3: SQ content unchecked | NO | Kernel exec required |

All three SET_SQ_ENTRY gaps are post-compromise primitives, not entry points.

---

## Post-Compromise Value

With kernel code execution already achieved:
1. q_tail walk-off -> read arbitrary SPTM GL2 memory as a state byte
2. EnableLinearSQ() -> linear mode -> DMA to arbitrary physical memory
   (three-step chain: kernel exec -> vtable call -> DMA primitive)
3. nvme_instance in SPTM-private memory: still cannot flip linear flag without
   a separate SPTM write primitive even with kernel exec

---

## nvme-sppl Legacy Path

Devices with nvme-sppl (not nvme-sptm) in device tree bypass ALL SPTM NVMe
enforcement. Relevant for older A-series devices or custom DTs.

