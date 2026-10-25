# iOS 26.6.1 vs 26.1 Kernelcache Diff
*Generated 2026-10-25 05:39:41*

**Device:** iPhone 16 Plus (iPhone17,4)
**Newer:** iOS 26.6.1 build 23G83 — KernelManagement_host-487.100.11
**Older:** iOS 26.1   build 23B85 — KernelManagement_host-487.0.4

> Analysis method: Python mmap (memory-mapped I/O) for both 70MB files,
> segment-by-segment processing to stay within the iPhone-hosted VM's RAM budget.

---
Parsed: 26.6.1 → 302 fileset entries, 26.1 → 300 fileset entries

## 1. Segment Layout Comparison

| Segment | 26.1 fileoff | 26.1 size | 26.6.1 fileoff | 26.6.1 size | Δ size |
|---------|-------------|-----------|----------------|-------------|--------|
| `__DATA` | 0x042f8000 | 3,040K | 0x0416c000 | 3,120K | +81,920 |
| `__DATA_CONST` | 0x00c38000 | 5,840K | 0x00c78000 | 5,904K | +65,536 |
| `__DATA_SPTM` | 0x011ec000 | 240K | 0x0123c000 | 240K |  |
| `__LINKEDIT` | 0x045f0000 | 752K | 0x04478000 | 768K | +16,384 |
| `__PRELINK_INFO` | 0x04078000 | 2,560K | 0x03ee8000 | 2,576K | +16,384 |
| `__PRELINK_TEXT` | 0x00008000 | 12,480K | 0x00008000 | 12,736K | +262,144 |
| `__TEXT` | 0x00000000 | 32K | 0x00000000 | 32K |  |
| `__TEXT_BOOT_EXEC` | 0x04070000 | 32K | 0x03ee0000 | 32K |  |
| `__TEXT_EXEC` | 0x01228000 | 47,392K | 0x01278000 | 45,472K | -1,966,080 |

## ✓ Checkpoint: Segment Layout — 05:39:42


## 2. __TEXT_EXEC Diff (Main Kernel Code)

26.6.1: fileoff=0x01278000 size=44MB vmaddr=0xfffffff00827c000
26.1:   fileoff=0x01228000 size=46MB vmaddr=0xfffffff00822c000

*(vmaddr delta: 0x50000 — kernel linked 0x50000 higher in 26.6.1.)*
*(ADRP instructions embed the target page VA in a 21-bit immediate; every ADRP will differ*
*between kernels linked at different bases. numpy vectorised normalisation zeroes the*
*ADRP immediate before comparing so only genuine instruction changes are counted.)*

- **11,368** of 11,368 pages differ at raw byte level (includes ADRP noise)
- **11,368** pages differ after ADRP normalization — genuine code changes

### Top 20 Changed Pages (ADRP-normalised)

| # | Page | __TEXT_EXEC offset | File off (26.6.1) | Norm-diff bytes | Nearby string |
|---|------|--------------------|-------------------|-----------------|---------------|
| 1 | 1 | `+0x001000` | `0x01279000` | 4096 | — |
| 2 | 2 | `+0x002000` | `0x0127a000` | 4096 | — |
| 3 | 3 | `+0x003000` | `0x0127b000` | 4096 | — |
| 4 | 4 | `+0x004000` | `0x0127c000` | 4096 | — |
| 5 | 5 | `+0x005000` | `0x0127d000` | 4096 | — |
| 6 | 6 | `+0x006000` | `0x0127e000` | 4096 | — |
| 7 | 9 | `+0x009000` | `0x01281000` | 4096 | — |
| 8 | 12 | `+0x00c000` | `0x01284000` | 4096 | — |
| 9 | 13 | `+0x00d000` | `0x01285000` | 4096 | — |
| 10 | 16 | `+0x010000` | `0x01288000` | 4096 | — |
| 11 | 19 | `+0x013000` | `0x0128b000` | 4096 | — |
| 12 | 20 | `+0x014000` | `0x0128c000` | 4096 | — |
| 13 | 21 | `+0x015000` | `0x0128d000` | 4096 | — |
| 14 | 27 | `+0x01b000` | `0x01293000` | 4096 | — |
| 15 | 29 | `+0x01d000` | `0x01295000` | 4096 | — |
| 16 | 31 | `+0x01f000` | `0x01297000` | 4096 | — |
| 17 | 35 | `+0x023000` | `0x0129b000` | 4096 | — |
| 18 | 38 | `+0x026000` | `0x0129e000` | 4096 | — |
| 19 | 39 | `+0x027000` | `0x0129f000` | 4096 | — |
| 20 | 40 | `+0x028000` | `0x012a0000` | 4096 | — |

## ✓ Checkpoint: TEXT_EXEC Diff — 05:40:14


## 3. mach_make_memory_entry_64 Deep Dive

String occurrences: **3** in 26.6.1, **3** in 26.1

**26.6.1 occurrences:**
- `0x000b6116` `__PRELINK_TEXT`+0xae116 (VA=0xfffffff0070ba116): `emoryEntry·221·1222·mach_make_memory_entry_64 actualSize @%s:%d·IOMemo`
- `0x00bf64ee` `__PRELINK_TEXT`+0xbee4ee (VA=0xfffffff007bfa4ee): `nfo_64·vm_region_64·mach_make_memory_entry_64·vm_map_64_external·vm_pu`
- `0x044a2f03` `__LINKEDIT`+0x2af03 (VA=0xfffffff00b4a6f03): `unhold_cred···!N_··_mach_make_memory_entry_64···!P_··_mach_memory_entr`

**26.1 occurrences:**
- `0x000ad318` `__PRELINK_TEXT`+0xa5318 (VA=0xfffffff0070b1318): `emoryEntry·221·1222·mach_make_memory_entry_64 actualSize @%s:%d·IOMemo`
- `0x00bb5c7b` `__PRELINK_TEXT`+0xbadc7b (VA=0xfffffff007bb9c7b): `nfo_64·vm_region_64·mach_make_memory_entry_64·vm_map_64_external·vm_pu`
- `0x0461af02` `__LINKEDIT`+0x2af02 (VA=0xfffffff00b61ef02): `unhold_cred···!O_··_mach_make_memory_entry_64···!Q_··_mach_memory_entr`

### MIG name-table context comparison

**26.6.1** MIG table area (`__PRELINK_TEXT` + 0xbee4ee, VA=0xfffffff007bfa4ee):
```
  00bf648a  6e 66 6f 00 76 6d 5f 6d 61 70 70 65 64 5f 70 61   nfo.vm_mapped_pa
  00bf649a  67 65 73 5f 69 6e 66 6f 00 76 6d 5f 72 65 67 69   ges_info.vm_regi
  00bf64aa  6f 6e 5f 72 65 63 75 72 73 65 00 76 6d 5f 72 65   on_recurse.vm_re
  00bf64ba  67 69 6f 6e 5f 72 65 63 75 72 73 65 5f 36 34 00   gion_recurse_64.
  00bf64ca  6d 61 63 68 5f 76 6d 5f 72 65 67 69 6f 6e 5f 69   mach_vm_region_i
  00bf64da  6e 66 6f 5f 36 34 00 76 6d 5f 72 65 67 69 6f 6e   nfo_64.vm_region
  00bf64ea  5f 36 34 00 6d 61 63 68 5f 6d 61 6b 65 5f 6d 65   _64.mach_make_me
  00bf64fa  6d 6f 72 79 5f 65 6e 74 72 79 5f 36 34 00 76 6d   mory_entry_64.vm
  00bf650a  5f 6d 61 70 5f 36 34 5f 65 78 74 65 72 6e 61 6c   _map_64_external
  00bf651a  00 76 6d 5f 70 75 72 67 61 62 6c 65 5f 63 6f 6e   .vm_purgable_con
  00bf652a  74 72 6f 6c 00 76 6d 5f 6d 61 70 5f 65 78 65 63   trol.vm_map_exec
  00bf653a  5f 6c 6f 63 6b 64 6f 77 6e 00 76 6d 5f 72 65 6d   _lockdown.vm_rem
  00bf654a  61 70 5f 6e 65 77 5f 65 78 74 65 72 6e 61 6c 00   ap_new_external.
  00bf655a  76 6d 5f 72 65 61 6c 6c 6f 63 61 74 65 00 70 72   vm_reallocate.pr
  00bf656a  6f 63 65 73 73 6f 72 5f 73 65 74 5f 73 74 61 74   ocessor_set_stat
  00bf657a  69 73 74 69 63 73 00 70 72 6f 63 65 73 73 6f 72   istics.processor
  00bf658a  5f 73 65 74 5f 74 61 73 6b 73 00 70 72 6f 63 65   _set_tasks.proce
  00bf659a  73 73 6f 72 5f 73 65 74 5f 69 6e 66 6f 00 70 72   ssor_set_info.pr
  00bf65aa  6f 63 65 73 73 6f 72 5f 73 65 74 5f               ocessor_set_
```

**26.1** MIG table area (`__PRELINK_TEXT` + 0xbadc7b, VA=0xfffffff007bb9c7b):
```
  00bb5c17  6e 66 6f 00 76 6d 5f 6d 61 70 70 65 64 5f 70 61   nfo.vm_mapped_pa
  00bb5c27  67 65 73 5f 69 6e 66 6f 00 76 6d 5f 72 65 67 69   ges_info.vm_regi
  00bb5c37  6f 6e 5f 72 65 63 75 72 73 65 00 76 6d 5f 72 65   on_recurse.vm_re
  00bb5c47  67 69 6f 6e 5f 72 65 63 75 72 73 65 5f 36 34 00   gion_recurse_64.
  00bb5c57  6d 61 63 68 5f 76 6d 5f 72 65 67 69 6f 6e 5f 69   mach_vm_region_i
  00bb5c67  6e 66 6f 5f 36 34 00 76 6d 5f 72 65 67 69 6f 6e   nfo_64.vm_region
  00bb5c77  5f 36 34 00 6d 61 63 68 5f 6d 61 6b 65 5f 6d 65   _64.mach_make_me
  00bb5c87  6d 6f 72 79 5f 65 6e 74 72 79 5f 36 34 00 76 6d   mory_entry_64.vm
  00bb5c97  5f 6d 61 70 5f 36 34 5f 65 78 74 65 72 6e 61 6c   _map_64_external
  00bb5ca7  00 76 6d 5f 70 75 72 67 61 62 6c 65 5f 63 6f 6e   .vm_purgable_con
  00bb5cb7  74 72 6f 6c 00 76 6d 5f 6d 61 70 5f 65 78 65 63   trol.vm_map_exec
  00bb5cc7  5f 6c 6f 63 6b 64 6f 77 6e 00 76 6d 5f 72 65 6d   _lockdown.vm_rem
  00bb5cd7  61 70 5f 6e 65 77 5f 65 78 74 65 72 6e 61 6c 00   ap_new_external.
  00bb5ce7  70 72 6f 63 65 73 73 6f 72 5f 73 65 74 5f 73 74   processor_set_st
  00bb5cf7  61 74 69 73 74 69 63 73 00 70 72 6f 63 65 73 73   atistics.process
  00bb5d07  6f 72 5f 73 65 74 5f 74 61 73 6b 73 00 70 72 6f   or_set_tasks.pro
  00bb5d17  63 65 73 73 6f 72 5f 73 65 74 5f 74 68 72 65 61   cessor_set_threa
  00bb5d27  64 73 00 70 72 6f 63 65 73 73 6f 72 5f 73 65 74   ds.processor_set
  00bb5d37  5f 73 74 61 63 6b 5f 75 73 61 67 65               _stack_usage
```

### Searching for pointer to MIG string → nearby function pointer

**26.6.1** — looking for pointer to VA 0xfffffff007bfa4ee:
  (no pointer found in mapped segments)

**26.1** — looking for pointer to VA 0xfffffff007bb9c7b:
  (no pointer found in mapped segments)


## ✓ Checkpoint: mach_make_memory_entry_64 Deep Dive — 05:40:29


## 4. SPTM / PPL Analysis

__DATA_SPTM 26.6.1: vmaddr=0xfffffff008240000 vmsize=0x3c000 fileoff=0x0123c000 filesize=245760
__DATA_SPTM 26.1:   vmaddr=0xfffffff0081f0000 vmsize=0x3c000 fileoff=0x011ec000 filesize=245760

| Term | 26.1 count | 26.6.1 count | Δ |
|------|-----------|--------------|---|
| `sptm` | 44 | 63 | **+19** |
| `SPTM` | 18 | 17 | **-1** |
| `ppl` | 42456 | 42781 | **+325** |
| `PPL` | 57 | 52 | **-5** |
| `SPTM_` | 0 | 0 | 0 |
| `sptm_` | 27 | 46 | **+19** |
| `PPL_DISPATCH` | 0 | 0 | 0 |
| `PPL_PANIC` | 0 | 0 | 0 |
| `pmap_ppl` | 1 | 1 | 0 |
| `sptm.t8140` | 0 | 0 | 0 |
| `page_protect` | 3 | 3 | 0 |
| `PPL_ENTER` | 0 | 0 | 0 |
| `SPTM_ENTER` | 0 | 0 | 0 |

**`SPTM`** count changed: 26.1=18, 26.6.1=17

**`sptm`** count changed: 26.1=44, 26.6.1=63

**`PPL`** count changed: 26.1=57, 26.6.1=52

**`ppl`** count changed: 26.1=42456, 26.6.1=42781


## ✓ Checkpoint: SPTM/PPL Analysis — 05:42:06


## 5. Security-Relevant String Diff

Streaming scan for strings ≥ 24 chars matching security keywords...
- Security strings unique to **26.6.1**: **1045**
- Security strings unique to **26.1**: **1483**
- Strings present in both: 7730

### New in 26.6.1 (not in 26.1):

```
  + !vmrl_is_kernel_pmap(flags)
  + "AppleH16CamIn::%s: ispAddress is out of bounds\n" @%s:%d
  + "ApplePMGR: %s:%u " "Die %u, Deadline: 0x%llx, AbsTime: 0x%llx PMP Failed to Come Online within %llu ticks" @%s:%d
  + "AppleProResHW (0x%x): %s(): ProResHW is hung, client timed out (duration = %llu msec) attempting to transition to power state %lu" @%s:%d
  + "AppleThunderboltNHIDARTVMAllocator::init - slide cannot be non-zero (found %d)" @%s:%d
  + "AppleThunderboltNHIGenericACIO(%d)::setARMIODevicePowerState - armio_device->enablePsdService( %d, %d, 0x%08x ) status=0x%08x failed\n" @%s:%d
  + "AppleThunderboltUSBType2UpAdapter(%x:%llx:%x)::requestTerminate - ERROR: terminatePhase1 on workloop thread not permitted.\n" @%s:%d
  + "failed to set sandbox info callbacks" @%s:%d
  + %s: Found inconsistent state in soon to be deleted L%d table: %d valid, %d compressed, %d non-empty, refcnt=%d, L%d tte=%#llx, pmap=%p, bpte=%p @%s:%d
  + %s: pmap %p (tte 0x%llx): wired count overflow @%s:%d
  + %s: pmap %p VA [0x%llx, 0x%llx) (wiredcnt %p) wired count underflow @%s:%d
  + %s: pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u @%s:%d
  + %s: vm_page_t %p on pmap delayed free pt queue for at least %d sec; wiredcnt leak? @%s:%d
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDevice.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceInterface.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceTest.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMHIDInterface.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMParserTest.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMSPITest.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferDevice.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferTest.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserDevice.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserTest.h
  + /AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSTransferTest.h
  + /Library/Caches/com.apple.aned/
  + /Library/Caches/com.apple.xbs/059D1497-84D3-4191-9FB0-8B5B31D266AF/TemporaryDirectory.2Ux1GJ/Sources/AppleS8000/AppleS8000AES.cpp
  + /Library/Caches/com.apple.xbs/059D1497-84D3-4191-9FB0-8B5B31D266AF/TemporaryDirectory.2Ux1GJ/Sources/AppleS8000/AppleS8000AES.h
  + /Library/Caches/com.apple.xbs/06216286-E3CA-4B33-B6CA-2AAA6D369250/TemporaryDirectory.lUIOvk/Sources/AppleARMPMU/AppleARMPMUCharger.cpp
  + /Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/AppleARMIISAudio/core/helper/IISAudioDeviceHelper.cpp
  + /Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/IsolatedStreamECProxy/IOService/IISAudioIsolatedOutputStreamECProxy.cpp
  + /Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/IsolatedStreamECProxy/IOService/IISAudioIsolatedStreamECProxy.cpp
  + /Library/Caches/com.apple.xbs/12391FD8-DF81-421F-A835-095FC7556FC2/TemporaryDirectory.diJ8B9/Sources/AppleFSCompression/Common/ChunkCompression.cpp
  + /Library/Caches/com.apple.xbs/12391FD8-DF81-421F-A835-095FC7556FC2/TemporaryDirectory.diJ8B9/Sources/AppleFSCompression/Compressors/Zlib/compressorKext.c
  + /Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/ADMAFamily/ADMAChannelInterface.cpp
  + /Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/AudioDMAChannelStateMachine.cpp
  + /Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/AudioDMAController.cpp
  + /Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/IOInterruptQueueEventSource.cpp
  + /Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/AudioConfigDataHelper.cpp
  + /Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunction.cpp
  + /Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunctionUtility.cpp
  + /Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/IORegistryEntryHelper/AudioKextIORegistryHelper.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCBinaryLog/AppleSMCACAMDriver.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCBinaryLog/AppleSMCBinaryLogDriver.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbedded.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedCharger/AppleSMCCharger.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedCharger/AppleSMCChargerUtil.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedFunctions.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedPMU/AppleSMCPMU.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCHighVoltageCharger/AppleSMCHighVoltageCharger.cpp
  + /Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCKeysEndpoint.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/ADCDevice/AppleUSBADCAudioDevice.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioController.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioDevice.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioNub.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AUATapStreams.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioControlInterface.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioDevice.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioDictionary.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioEngine.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioIsocFrameList.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioIsocPipe.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioStream.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Control.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Device.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Engine.cpp
  + /Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Stream.cpp
  + /Library/Caches/com.apple.xbs/22519F58-1FC1-425A-945A-D9D57224EFCA/TemporaryDirectory.vB6jmR/Sources/IOAVFamily/IOAV.cpp
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelLib.cpp
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelTransport.cpp
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonMem.c
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonUtil.c
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/LibCall.c
  + /Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/LibSerialization.c
  + /Library/Caches/com.apple.xbs/241210ED-6927-49FD-AF4B-841A9C1D4502/TemporaryDirectory.HjK1O1/Sources/AppleSSE/AppleSSE/AppleSSE.cpp
  + /Library/Caches/com.apple.xbs/241210ED-6927-49FD-AF4B-841A9C1D4502/TemporaryDirectory.HjK1O1/Sources/AppleSSE/AppleSSE/AppleSSEUserClient.cpp
  + /Library/Caches/com.apple.xbs/24C8B80F-84C6-49EC-9312-1F2144A79065/TemporaryDirectory.oHF4LS/Sources/AppleARMPlatform/AppleARMSPMI.cpp
  + /Library/Caches/com.apple.xbs/260D124E-81CA-4027-8671-E02EB2285211/TemporaryDirectory.ffVMS4/Sources/IOSurfaceAccelerator_kexts/AXI2AFControl/IosaAxi2AfControl.cpp
  + /Library/Caches/com.apple.xbs/260D124E-81CA-4027-8671-E02EB2285211/TemporaryDirectory.ffVMS4/Sources/IOSurfaceAccelerator_kexts/AppleM2ScalerCSCDriver.cpp
  + /Library/Caches/com.apple.xbs/260D124E-81CA-4027-8671-E02EB2285211/TemporaryDirectory.ffVMS4/Sources/IOSurfaceAccelerator_kexts/AppleM2ScalerCSCDriverFilters.cpp
  + /Library/Caches/com.apple.xbs/260D124E-81CA-4027-8671-E02EB2285211/TemporaryDirectory.ffVMS4/Sources/IOSurfaceAccelerator_kexts/AppleM2ScalerCSCDriverFilters.h
  ... +965 more
```

### Removed in 26.6.1 (present in 26.1 only):

```
  - "AMFI: unable to update legacy context: %u" @%s:%d
  - "AppleDialogPMU::%s failed to alloc %d bytes" @%s:%d
  - "AppleProResHW (0x%x): %s(): ProResHW is hung, client timed out attempting to transition to power state %lu" @%s:%d
  - %s: Found inconsistent state in soon to be deleted L%d table: %d valid, %d compressed, %d non-empty, refcnt=%d, wiredcnt=%d, L%d tte=%#llx, pmap=%p, bpte=%p @%s:%d
  - %s: Unknown pmap_lock_mode. pmap=%p, mode=%d @%s:%d
  - %s: pmap %p VA [0x%llx, 0x%llx) (ptd info %p) wired count underflow @%s:%d
  - %s: pmap %p refcount %p overflow @%s:%d
  - %s: pmap %p refcount %p underflow @%s:%d
  - %s: pmap mismatch, ptdp=%p, pmap=%p, va=%p, level=%u, ptep=%p @%s:%d
  - %s: unsupported on non-PPL systems @%s:%d
  - %s: unsupported on non-PPL systems, ledger=%p @%s:%d
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDevice.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceInterface.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceTest.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMHIDInterface.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMParserTest.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMSPITest.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferDevice.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferTest.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserDevice.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserTest.h
  - /AppleInternal/Library/BuildRoots/4~CAp-ugCs-J_6PCd4ZOWZSVaGty0y7ownVNnd_zU/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.1.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSTransferTest.h
  - /AppleInternal/Library/Frameworks/Virtualization.framework/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/com.apple.Virtualization.VirtualMachine
  - /Applications/AAUIViewService.app/AAUIViewService
  - /Applications/Camera.app/Camera
  - /Applications/Camera.app/Extensions/LockScreenCamera.appex/LockScreenCamera
  - /Applications/CheckerBoard.app/CheckerBoard
  - /Applications/DiagnosticsService.app/PlugIns/Diagnostic-4002.appex/Diagnostic-4002
  - /Applications/Family.app/Family
  - /Applications/HomeUIService.app/HomeUIService
  - /Applications/InputUI.app/InputUI
  - /Applications/MessagesViewService.app/MessagesViewService
  - /Applications/MobileSafari.app/XPCServices/com.apple.Safari.SandboxBroker.xpc/com.apple.Safari.SandboxBroker
  - /Applications/MobileSlideShow.app/MobileSlideShow
  - /Applications/MomentsUIService.app/MomentsUIService
  - /Applications/MusicUIService.app/MusicUIService
  - /Applications/PeopleViewService.app/PeopleViewService
  - /Applications/SMS Filter.app/PlugIns/extensionFilter.appex/extensionFilter
  - /Applications/SharedWebCredentialViewService.app/SharedWebCredentialViewService
  - /Applications/SoftwareUpdateUIService.app/SoftwareUpdateUIService
  - /Applications/Spotlight.app/Spotlight
  - /Applications/TrustMe.app/TrustMe
  - /Library/Caches/com.apple.xbs/Binaries/AppleImage4/install/Symbols/Image4
  - /Library/Caches/com.apple.xbs/Binaries/xnu/install/TempContent/Objects/EXPORT_HDRS/bsd/skywalk/nexus_common.h
  - /Library/Caches/com.apple.xbs/Binaries/xnu/install/TempContent/Objects/EXPORT_HDRS/bsd/skywalk/packet_common.h
  - /Library/Caches/com.apple.xbs/Sources/AppleA7IOP/AppleA7IOP.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleA7IOP/AppleASCWrapCommon.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleA7IOP/AppleASCWrapV6SISP.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleA7IOP/AppleIOPBufferWriter.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleARMIISAudio/src/kext/IsolatedStreamECProxy/IOService/IISAudioIsolatedStreamECProxy.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleARMPMU/AppleARMPMUCharger.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleARMPlatform/AppleARMSPMI.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleAudioKextLibs/AudioConfigDataHelper.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunction.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunctionUtility.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBaseband/AppleBaseband/AppleBasebandPCIEDevice.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCI/AppleBasebandPCI.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/AppleBasebandPCIControl.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/AppleBasebandPCIInterface.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/MAV/AppleBasebandPCIBHIDevice.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/MAV/AppleBasebandPCIBHIInterface.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/MAV/AppleBasebandPCIMAVControl.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/MAV/AppleBasebandPCIMHIDevice.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/MAV/AppleBasebandPCIMHIInterface.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCIIOCommand.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCIMemoryCommand.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCIMemoryPolicy.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCIRequest.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCISkywalkMemorySegment.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCISkywalkMemorySegment.h
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCISkywalkPacket.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/Memory/AppleBasebandPCISkywalkPacketBufferPool.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/UserClient/AppleBasebandPCIControlUserClient.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIControl/UserClient/AppleBasebandPCIUserClient.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIPDPManagerBase.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIPDPQMAPRSC.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIPDPQMAPSkywalk.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIPDPSkywalkInterface.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIQMAPControl.cpp
  - /Library/Caches/com.apple.xbs/Sources/AppleBasebandPCI/AppleBasebandPCIPDP/AppleBasebandPCIQMAPProvider.cpp
  ... +1403 more
```


## ✓ Checkpoint: String Diff — 05:46:02


## 6. Kext-Level Changes

- **Changed kexts:** 300
- **Unchanged kexts:** 0
- **New in 26.6.1:** 2
- **Removed in 26.6.1:** 0

**New kexts in 26.6.1:**
  - `com.apple.driver.AppleThunderboltUSBType2DownAdapter`
  - `com.apple.driver.AppleThunderboltUSBType2UpAdapter`

**Changed kexts (by diff byte count):**

| Kext | Diff bytes | Size Δ | Code size |
|------|-----------|--------|-----------|
| `sandbox` | 1,750,611 | -49,798 | 1878K |
| `AppleAVD` | 850,651 | +20,528 | 894K |
| `kernel` | 850,259 | +46,168 | 998K |
| `AppleAVE2` | 582,394 | +11,198 | 862K |
| `IOThunderboltFamily` | 493,958 | +33,248 | 536K |
| `AppleM2ScalerCSCDriver` | 452,952 | +19,470 | 551K |
| `apfs` | 298,533 | +5,111 | 314K |
| `AppleH16ANEInterface` | 269,554 | +15,712 | 294K |
| `FairPlayIOKit` | 265,799 | +13,632 | 276K |
| `AppleThunderboltNHI` | 226,624 | +4,290 | 241K |
| `AppleH16CameraInterface` | 191,082 | +9,401 | 230K |
| `IOgPTPPlugin` | 135,363 | +2,688 | 144K |
| `IOAccessoryManager` | 130,764 | -31 | 136K |
| `AppleHPM` | 111,579 | +2,656 | 121K |
| `corecrypto` | 110,770 | -352 | 122K |
| `AppleSARService` | 104,378 | -91 | 125K |
| `AppleSEPManager` | 103,333 | +3,674 | 107K |
| `AppleT8130TypeCPhy` | 90,962 | +9,828 | 103K |
| `AGXG17P` | 83,917 | +309 | 92K |
| `IOAVFamily` | 78,243 | +48 | 147K |
| `AppleBasebandM20` | 76,990 | +399 | 81K |
| `IOUSBHostFamily` | 70,157 | +6,888 | 83K |
| `AppleSEPCredentialManager` | 63,528 | +4,992 | 71K |
| `AppleImage4` | 59,944 | -101 | 67K |
| `ApplePMGR` | 59,455 | +736 | 64K |
| `AppleSynopsysUSB40XHCI` | 58,982 | -1,088 | 63K |
| `IODisplayPortFamily` | 58,705 | 0 | 76K |
| `ApplePearlSEPDriver` | 58,647 | +2,008 | 64K |
| `ApplePPMCPMS` | 55,881 | -96 | 68K |
| `IONVMeFamily` | 55,875 | +2,731 | 62K |
| `AppleARMPlatform` | 55,767 | +57 | 65K |
| `AppleJPEGDriver` | 50,223 | +1,896 | 62K |
| `AppleMobileFileIntegrity` | 49,856 | -776 | 53K |
| `IOPCIFamily` | 47,992 | +1,856 | 54K |
| `AppleHIDTransport` | 47,870 | +2,021 | 52K |
| `IOTimeSyncFamily` | 47,039 | +2,672 | 52K |
| `AppleDisplayCrossbar` | 43,632 | +957 | 46K |
| `kext` | 42,896 | +1,285 | 49K |
| `AppleProResHW` | 42,478 | +608 | 52K |
| `AppleUSBXHCI` | 39,549 | +736 | 43K |
| `AppleUSBXDCIARM` | 39,527 | +1,512 | 48K |
| `AppleSynopsysUSBXHCI` | 38,908 | -192 | 45K |
| `AppleSMC` | 38,698 | +913 | 42K |
| `AKSAnalytics` | 38,693 | -129 | 43K |
| `IOGPUFamily` | 35,319 | +48 | 44K |
| `IOMobileGraphicsFamily` | 32,634 | -164 | 37K |
| `AppleBasebandPCI` | 31,930 | +1,344 | 37K |
| `AppleHapticsSupportLEAP` | 30,806 | +205 | 33K |
| `ASIOKit` | 30,640 | +3,424 | 35K |
| `AppleHIDTransportSPI` | 30,359 | -800 | 33K |
| `AppleConvergedIPCOLYBTControl` | 30,344 | +992 | 34K |
| `AudioDMAController-T8140` | 29,841 | +460 | 32K |
| `IOHIDFamily` | 29,169 | +2,714 | 35K |
| `RTBuddy` | 28,627 | +768 | 42K |
| `AppleEmbeddedAudio` | 28,556 | -128 | 31K |
| `AppleT8140MCC` | 27,974 | +679 | 31K |
| `AppleConvergedPCI` | 27,066 | +945 | 30K |
| `AppleThunderboltDPOutAdapter` | 24,845 | +51 | 115K |
| `AppleProcessorTrace` | 24,470 | +2,480 | 29K |
| `AppleMobileDispH17P-DCP` | 24,285 | -1,424 | 31K |
| `AppleFirmwareKit` | 24,125 | +106 | 26K |
| `AppleMultitouchDriver` | 22,826 | -128 | 25K |
| `corecapture` | 22,469 | +208 | 26K |
| `IOHDCPFamily` | 21,912 | +442 | 24K |
| `IOPAudioDriverFamily` | 21,191 | +608 | 24K |
| `AppleARMIISAudio` | 20,367 | +1,072 | 24K |
| `AppleSmartBatteryManagerEmbedded` | 20,026 | -17 | 36K |
| `AppleOLYHAL` | 19,549 | +5,960 | 27K |
| `AppleEmbeddedAudioLibs` | 18,898 | +616 | 21K |
| `IOSurface` | 18,691 | +387 | 25K |
| `AppleM68Buttons` | 18,307 | +480 | 23K |
| `IOPAudioVoiceTriggerDevice` | 17,007 | +328 | 19K |
| `AppleMultitouchSPI` | 16,982 | -128 | 19K |
| `AppleSEPKeyStore` | 16,657 | +776 | 21K |
| `AppleLockdownMode` | 16,293 | +505 | 20K |
| `AppleUSBHub` | 14,802 | +16 | 17K |
| `IOMobileGraphicsFamily-DCP` | 14,730 | +128 | 30K |
| `AppleT8140CLPC` | 14,552 | +1,736 | 18K |
| `AppleSPURose` | 14,445 | +1,008 | 17K |
| `AppleStockholmControl` | 14,370 | -400 | 19K |
| `AppleSmartIO2` | 13,738 | +504 | 19K |
| `ExclavesAudioKext` | 13,303 | +8,543 | 23K |
| `DCPAVFamilyProxy` | 13,199 | -287 | 15K |
| `AppleALSColorSensor` | 13,004 | +143 | 15K |
| `AppleUSBAudio` | 12,787 | +1,272 | 16K |
| `AppleIOPADMAStream` | 12,588 | +193 | 14K |
| `AppleCS42L79Audio` | 12,415 | +48 | 20K |
| `AppleDiskImages2` | 12,240 | +192 | 15K |
| `AppleSMCWirelessCharger` | 11,914 | +359 | 14K |
| `AppleUSBXDCI` | 11,811 | +240 | 33K |
| `lifs` | 11,706 | -160 | 15K |
| `IOGameControllerFamily` | 11,370 | +26 | 13K |
| `AppleHIDTransportFIFO` | 10,433 | +126 | 12K |
| `AppleSPMIPMU` | 9,400 | +848 | 11K |
| `AppleMultiFunctionManager` | 9,172 | +71 | 10K |
| `AppleMikeyBusAudio` | 9,118 | +63 | 17K |
| `AppleHIDTransportMailbox` | 8,994 | +126 | 11K |
| `IOPAudioLPMicDevice` | 8,980 | +189 | 11K |
| `AppleSPMI` | 8,839 | +16 | 11K |
| `AppleInputDeviceSupport` | 8,181 | +576 | 10K |
| `AppleC26Charger` | 8,053 | -25 | 9K |
| `AppleARMPMU` | 8,052 | +63 | 13K |
| `AppleT8110DART` | 7,732 | +195 | 12K |
| `IOAudioCodecs` | 7,616 | -88 | 11K |
| `IOSkywalkFamily` | 7,470 | +11,040 | 23K |
| `AppleGenericMultitouch` | 7,364 | +128 | 32K |
| `IOUSBDeviceFamily` | 6,652 | -32 | 20K |
| `IOBiometricFamily` | 6,608 | +472 | 13K |
| `EXBrightKext` | 6,581 | +228 | 18K |
| `AppleThunderboltUSBUpAdapter` | 6,188 | -2 | 13K |
| `EXDisplayPipeH17P` | 6,174 | +1,015 | 11K |
| `AppleEmbeddedMikeyBus` | 6,077 | +192 | 9K |
| `AppleTypeCPhy` | 6,025 | +219 | 12K |
| `AppleDCP` | 5,711 | +304 | 8K |
| `IOPAudioClientManagerDevice` | 5,477 | +189 | 7K |
| `AppleBluetoothDebug` | 5,331 | +126 | 7K |
| `AudioDMAFamily` | 4,681 | -132 | 6K |
| `AppleBasebandPCIMAVControl` | 4,600 | +754 | 16K |
| `IONetworkingFamily` | 4,450 | -19 | 6K |
| `AppleS8000AES` | 4,336 | +114 | 6K |
| `AppleGPIOICController` | 4,281 | +644 | 6K |
| `AppleSPIMC` | 4,096 | +1,301 | 7K |
| `AppleProxDriver` | 3,985 | +221 | 5K |
| `AOPAudio2` | 3,797 | +45 | 5K |
| `AppleA7IOP` | 3,643 | +282 | 5K |
| `AppleSSE` | 3,627 | +128 | 7K |
| `AppleFSCompressionTypeZlib` | 3,453 | +38 | 15K |
| `AppleSART` | 3,127 | +189 | 4K |
| `AppleSEPGenericTransfer` | 3,087 | +189 | 4K |
| `ncm` | 3,044 | +57 | 5K |
| `IOPEmbeddedAudio` | 2,857 | +189 | 4K |
| `AppleHIDKeyboard` | 2,796 | +8 | 6K |
| `AppleAOPHaptics` | 2,741 | +128 | 4K |
| `IOPAudioIsolatedIOBufferDevice` | 2,733 | +128 | 4K |
| `AppleCallbackPowerSource` | 2,713 | +61 | 5K |
| `AppleT6020PCIePIODMA` | 2,708 | +2 | 4K |
| `IOSCSIArchitectureModelFamily` | 2,670 | +18 | 7K |
| `IOPAudioIOBufferDevice` | 2,582 | +126 | 4K |
| `AppleDCPDPTXProxy` | 2,571 | +12 | 8K |
| `AudioSharedDARTMapperProxy` | 2,279 | +244 | 4K |
| `IOPAudioLEAPControlDevice` | 2,206 | +4 | 3K |
| `DiskImages` | 2,197 | +626 | 4K |
| `AppleEpochManager` | 2,187 | +128 | 3K |
| `AppleBasebandPCIMAVPDP` | 2,139 | +252 | 5K |
| `IOSlowAdaptiveClockingFamily` | 2,109 | -120 | 3K |
| `AGXFirmwareKextG17PRTBuddy` | 2,106 | +227 | 4K |
| `UDIFDiskImage` | 2,053 | -88 | 14K |
| `AppleIISController` | 2,012 | +63 | 4K |
| `AppleAstrisGpioProbe` | 1,956 | -144 | 3K |
| `ExclaveSEPManagerProxy` | 1,929 | +63 | 3K |
| `pthread` | 1,892 | -8 | 3K |
| `IODARTFamily` | 1,857 | 0 | 9K |
| `AppleEmbeddedUSBHost` | 1,727 | +2,509 | 5K |
| `AppleH16PhotonDetector` | 1,705 | -14 | 3K |
| `IOPHaptics` | 1,534 | +126 | 3K |
| `AppleHIDTransportSCMCommon` | 1,492 | +126 | 3K |
| `XrtHostedXnu` | 1,486 | +14 | 2K |
| `AppleIDAMInterface` | 1,469 | +63 | 3K |
| `AppleUSBHostBillboardDevice` | 1,349 | +424 | 2K |
| `IOPAudioPCMAssetManagerDevice` | 1,285 | +126 | 2K |
| `AUC` | 1,282 | +64 | 3K |
| `AppleA7IOP-ASCWrap-v6` | 1,155 | +128 | 2K |
| `IISAudioIsolatedStreamECProxy` | 1,120 | +774 | 3K |
| `FileBackingStore` | 1,068 | +104 | 2K |
| `AppleSPUSphere` | 1,053 | +653 | 2K |
| `AppleUSBDeviceAudioController` | 912 | +142 | 2K |
| `AppleUSBHostPacketFilter` | 893 | +8 | 4K |
| `IOPAudioHapticsLEAPControlDevice` | 867 | +63 | 2K |
| `ecm` | 854 | -136 | 2K |
| `ApplePhoneBTM` | 806 | -112 | 21K |
| `AppleAOP2` | 757 | +3,767 | 5K |
| `IOPAudioAssetManagerDevice` | 754 | +126 | 2K |
| `AppleDAPF` | 635 | +63 | 2K |
| `IOSCSIBlockCommandsDevice` | 608 | +454 | 5K |
| `ApplePMPFirmware` | 565 | +15 | 2K |
| `AppleS5L8920XPWM` | 479 | +83 | 2K |
| `AppleHIDALSService` | 408 | -13 | 1K |
| `AppleTemperatureSensor` | 398 | -32 | 5K |
| `DMAChannelProxy` | 304 | +69 | 3K |
| `CoreTrust` | 280 | 0 | 16K |
| `cdc` | 216 | +64 | 2K |
| `AppleTriStar` | 166 | 0 | 16K |
| `AppleAOPAudio` | 164 | 0 | 51K |
| `IOMikeyBusFamily` | 159 | 0 | 7K |
| `AppleSPU` | 158 | -40 | 28K |
| `AppleTypeCPhyAUSBC` | 158 | 0 | 6K |
| `AppleThunderboltIP` | 155 | 0 | 178K |
| `AppleTopCaseHIDEventDriver` | 155 | 0 | 9K |
| `AppleOnboardSerial` | 153 | 0 | 8K |
| `AppleT8103TypeCPhy` | 150 | 0 | 100K |
| `AppleT8140ANEHAL` | 150 | 0 | 4K |
| `AppleThunderboltDPAdapterFamily` | 150 | 0 | 55K |
| `AppleAuthCP` | 149 | 0 | 16K |
| `AppleThunderboltUSBDownAdapter` | 149 | 0 | 2K |
| `IOHIDPowerSource` | 149 | 0 | 4K |
| `AppleIPAppender` | 148 | -16 | 3K |
| `AppleUSBTopCaseDriver` | 148 | 0 | 1K |
| `AppleEmbeddedLightSensor` | 147 | 0 | 23K |
| `ApplePMP` | 147 | 0 | 6K |
| `AppleUSBDeviceMux` | 147 | 0 | 6K |
| `AppleEmbeddedPCIE` | 146 | 0 | 40K |
| `AppleIDV` | 146 | 0 | 6K |
| `AppleThunderboltDPInAdapter` | 146 | 0 | 10K |
| `SecureRTBuddyProxy` | 146 | -128 | 5K |
| `AppleEmbeddedAudioResourceManager` | 145 | 0 | 11K |
| `AppleMobileApNonce` | 145 | 0 | 8K |
| `mDNSOffloadUserClient-Embedded` | 145 | 0 | 6K |
| `AppleUSBCommon` | 145 | 0 | 2K |
| `IOSerialFamily` | 145 | 0 | 3K |
| `AppleThunderboltPCIDownAdapter` | 144 | 0 | 6K |
| `AppleT8140` | 143 | 0 | 17K |
| `AppleT8140PMGR` | 143 | 0 | 9K |
| `IOPAudioSpeaker` | 143 | 0 | 2K |
| `IOStorageFamily` | 143 | 0 | 8K |
| `AppleGameControllerPersonality` | 142 | 0 | 1K |
| `ApplePTD` | 142 | 0 | 8K |
| `AppleDialogPMU` | 141 | 0 | 3K |
| `AppleHapticsSupportNVM` | 141 | 0 | 2K |
| `AppleThunderboltPCIUpAdapter` | 141 | 0 | 18K |
| `IOAudio2Family` | 141 | 0 | 2K |
| `AppleEffaceableStorage` | 140 | 0 | 6K |
| `AppleUSBHostiOSDevice` | 140 | 0 | 3K |
| `AppleH10PearlCameraInterface` | 139 | 0 | 3K |
| `AppleThunderboltEDMSource` | 139 | 0 | 7K |
| `IOUSBMassStorageDriver` | 139 | 0 | 12K |
| `AppleActuatorDriver` | 138 | 0 | 7K |
| `ApplePIODMA` | 138 | 0 | 4K |
| `tmpfs` | 138 | 0 | 3K |
| `AppleEventLogHandler` | 137 | 0 | 3K |
| `ApplePhotonDetector` | 137 | 0 | 3K |
| `AppleS5L8940XI2C` | 137 | 0 | 3K |
| `AppleSynopsysMIPIDSI` | 137 | 0 | 11K |
| `AppleT8140PCIe` | 137 | 0 | 19K |
| `ExclaveKextClient` | 136 | 0 | 3K |
| `AppleARMWatchdogTimer` | 136 | 0 | 6K |
| `AppleInterruptControllerV3` | 136 | 0 | 4K |
| `asix` | 136 | 0 | 5K |
| `IOCECFamily` | 136 | 0 | 2K |
| `IOReportFamily` | 136 | 0 | 2K |
| `AppleFAN53740` | 135 | 0 | 1K |
| `AppleUSBEthernetDevice` | 135 | 0 | 4K |
| `AppleUSBLightningAdapter` | 135 | 0 | 9K |
| `KernelBacked` | 135 | 0 | 2K |
| `AppleEmbeddedUSB` | 134 | 0 | 5K |
| `AppleSEPHDCPManager` | 134 | 0 | 5K |
| `AppleUSBDeviceNCM` | 134 | 0 | 4K |
| `AppleUSBHostCompositeDevice` | 134 | 0 | 3K |
| `AppleUSBHostDeviceSupport` | 134 | 0 | 1K |
| `AOPTouchKext` | 133 | 0 | 2K |
| `AppleFirmwareUpdateKext` | 133 | 0 | 3K |
| `AppleT8030SOCTuner` | 133 | 0 | 2K |
| `AppleUSBCardReader` | 133 | 0 | 6K |
| `AppleDiagnosticDataAccessReadOnly` | 132 | 0 | 2K |
| `AppleEmbeddedGPS` | 132 | 0 | 2K |
| `AppleEmbeddedTempSensor` | 132 | 0 | 12K |
| `AppleUSBMassStorageInterfaceNub` | 132 | 0 | 2K |
| `DCPDPFamilyProxy` | 132 | 0 | 2K |
| `RAMBackingStore` | 132 | 0 | 1K |
| `CoreAnalyticsFamily` | 132 | 0 | 15K |
| `AppleUSBHostMergeProperties` | 131 | 0 | 1K |
| `IOAccessoryPortUSB` | 131 | 0 | 3K |
| `IOCryptoAcceleratorFamily` | 131 | 0 | 2K |
| `IOStreamFamily` | 131 | 0 | 1K |
| `AppleDockChannel` | 130 | 0 | 6K |
| `IOSlaveProcessor` | 130 | 0 | 1K |
| `AppleCSEmbeddedAudio` | 129 | 0 | 3K |
| `AppleGPIOCanary` | 129 | 0 | 1K |
| `IOUserEthernet` | 129 | 0 | 4K |
| `AppleEffaceableBlockDevice` | 128 | 0 | 1K |
| `AppleEmbeddedTouchEEPROM` | 128 | 0 | 3K |
| `AppleS8000DWI` | 128 | 0 | 2K |
| `AppleUSBMike` | 128 | 0 | 7K |
| `ReadWriteDiskImage` | 128 | 0 | 1K |
| `IOUSBHostHIDDevice` | 128 | 0 | 6K |
| `EXBrightCalibrationConsumer` | 127 | 0 | 3K |
| `AppleEverestErrorHandler` | 127 | 0 | 5K |
| `AppleS5L8960XNCO` | 127 | 0 | 1K |
| `IONetworkFamily` | 127 | 0 | 1K |
| `AppleUSBEthernetHost` | 126 | 0 | 4K |
| `ppp` | 126 | 0 | 8K |
| `AppleSamsungSerial` | 125 | 0 | 1K |
| `AppleSerialShim` | 125 | 0 | 1K |
| `l2tp` | 125 | 0 | 4K |
| `IOTextEncryptionFamily` | 124 | 0 | 2K |
| `AppleNANDConfigAccess` | 124 | 0 | 1K |
| `AppleMatch` | 124 | 0 | 1K |
| `AppleBSDKextStarter` | 122 | 0 | 1K |
| `AppleUVDMDriver` | 122 | 0 | 6K |
| `IOMIPIFamily` | 121 | 0 | 2K |
| `AppleParrot` | 120 | 0 | 1K |
| `networking` | 119 | 0 | 2K |
| `AppleBluetoothModule` | 117 | 0 | 11K |
| `AppleUVDM` | 116 | 0 | 2K |
| `AppleAudioClockLibs` | 114 | 0 | 2K |
| `AudioDMACLLTEscalationDetector-Stub` | 114 | 0 | 1K |
| `Compression` | 106 | -80 | 1K |
| `AppleBluetoothDebugService` | 105 | 0 | 1K |
| `IOPortFamily` | 75 | 0 | 16K |
| `Libm` | 72 | 0 | 28K |
| `AGXFirmwareKextRTBuddy64` | 71 | 0 | 16K |

## ✓ Checkpoint: Kext-Level Diff — 05:46:35


## 7. Detailed Hex Diff — Top 10 Changed Regions


### Region 1 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x001000`
- File offsets: 26.1=`0x01229000`, 26.6.1=`0x01279000`
- Link-time VA: 26.1=`0xfffffff00822d000`, 26.6.1=`0xfffffff00827d000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  01229000  00 01 02 03 04 05 06 07 00 01 02 03 04 05 06 07   ................
  01229010  00 01 02 03 04 05 06 07 00 01 02 03 04 05 06 07   ................
  01229020  00 01 02 03 04 05 06 07 08 00 01 02 03 04 05 06   ................
  01229030  07 08 00 01 02 03 04 05 06 07 08 00 01 02 03 04   ................
NEW (26.6.1):
  01279000  40 8e 38 d4 08 22 0c 91 09 86 41 f9 f1 03 08 aa   @.8.."....A.....
  01279010  31 9d e2 f2 31 09 3f d7 60 05 00 36 bf 0a 00 f1   1...1.?.`..6....
  01279020  a4 1a 40 fa 01 07 00 54 9f 06 00 f1 c1 06 00 54   ..@....T.......T
  01279030  28 00 80 52 68 26 06 39 60 ba 40 f9 10 00 40 f9   (..Rh&.9`.@...@.
```

### Region 2 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x002000`
- File offsets: 26.1=`0x0122a000`, 26.6.1=`0x0127a000`
- Link-time VA: 26.1=`0xfffffff00822e000`, 26.6.1=`0xfffffff00827e000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  0122a000  00 04 00 14 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5   ..... ... ... ..
  0122a010  1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5   . ... ... ... ..
  0122a020  1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5   . ... ... ... ..
  0122a030  1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5   . ... ... ... ..
NEW (26.6.1):
  0127a000  cf 1b b1 94 48 74 ff d0 0a 5d 3c 91 48 74 ff d0   ....Ht...]<.Ht..
  0127a010  08 9d 3b 91 89 26 80 52 e9 ab 00 a9 e8 03 00 f9   ..;..&.R........
  0127a020  40 74 ff d0 00 60 3d 91 94 1e b1 94 7f 23 03 d5   @t...`=......#..
  0127a030  f4 4f be a9 fd 7b 01 a9 fd 43 00 91 13 a4 40 f9   .O...{...C....@.
```

### Region 3 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x003000`
- File offsets: 26.1=`0x0122b000`, 26.6.1=`0x0127b000`
- Link-time VA: 26.1=`0xfffffff00822f000`, 26.6.1=`0xfffffff00827f000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  0122b000  e0 07 bf a9 40 42 38 d5 1f 20 00 f1 81 00 00 54   ....@B8.. .....T
  0122b010  00 11 3c d5 40 00 d8 37 da 0b 00 14 01 52 38 d5   ..<.@..7.....R8.
  0122b020  41 06 f8 36 e2 0f bf a9 21 14 66 92 02 00 b3 d2   A..6....!.f.....
  0122b030  3f 00 02 eb 20 03 00 54 02 80 b2 d2 3f 00 02 eb   ?... ..T....?...
NEW (26.6.1):
  0127b000  08 01 1d 91 08 01 40 f9 00 2d 40 f9 10 00 40 f9   ......@..-@...@.
  0127b010  f1 03 00 aa 31 b4 f9 f2 30 1a c1 da 08 8e 49 f8   ....1...0.....I.
  0127b020  30 35 e6 f2 10 09 3f d7 a8 5a 45 b9 15 00 08 8b   05....?..ZE.....
  0127b030  76 0a 40 f9 c8 62 40 91 08 21 1d 91 08 01 40 f9   v.@..b@..!....@.
```

### Region 4 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x004000`
- File offsets: 26.1=`0x0122c000`, 26.6.1=`0x0127c000`
- Link-time VA: 26.1=`0xfffffff008230000`, 26.6.1=`0xfffffff008280000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  0122c000  6c 65 63 74 65 64 00 00 9f 24 03 d5 e1 03 00 aa   lected...$......
  0122c010  40 00 00 10 09 e1 21 14 41 73 79 6e 63 68 72 6f   @.....!.Asynchro
  0122c020  6e 6f 75 73 20 65 78 63 65 70 74 69 6f 6e 20 74   nous exception t
  0122c030  61 6b 65 6e 20 77 68 69 6c 65 20 53 50 31 20 73   aken while SP1 s
NEW (26.6.1):
  0127c000  88 46 41 b9 08 23 03 b8 68 74 ff b0 00 c5 c2 3d   .FA..#..ht.....=
  0127c010  e0 1b 80 3d 00 63 83 3c 08 00 80 12 08 63 04 b8   ...=.c.<.....c..
  0127c020  1f a3 04 f8 1f 23 05 f8 1f a3 05 f8 88 02 46 39   .....#........F9
  0127c030  08 01 00 12 08 23 06 b8 80 2e 40 f9 10 00 40 f9   .....#....@...@.
```

### Region 5 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x005000`
- File offsets: 26.1=`0x0122d000`, 26.6.1=`0x0127d000`
- Link-time VA: 26.1=`0xfffffff008231000`, 26.6.1=`0xfffffff008281000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  0122d000  00 00 01 8b 80 10 20 00 00 00 01 8b 80 10 20 00   ...... ....... .
  0122d010  00 00 01 8b 80 10 20 00 00 00 01 8b 80 10 20 00   ...... ....... .
  0122d020  00 00 01 8b 80 10 20 00 00 00 01 8b 80 10 20 00   ...... ....... .
  0122d030  00 00 01 8b 80 10 20 00 00 00 01 8b 80 10 20 00   ...... ....... .
NEW (26.6.1):
  0127d000  89 86 42 f9 a9 be 0e f9 89 8a 42 f9 a9 c2 0e f9   ..B.......B.....
  0127d010  89 8e 42 f9 a9 c6 0e f9 89 92 42 f9 a9 ca 0e f9   ..B.......B.....
  0127d020  89 96 42 f9 a9 ce 0e f9 89 9a 42 f9 a9 d2 0e f9   ..B.......B.....
  0127d030  89 9e 42 f9 a9 d6 0e f9 89 a2 42 f9 a9 da 0e f9   ..B.......B.....
```

### Region 6 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x006000`
- File offsets: 26.1=`0x0122e000`, 26.6.1=`0x0127e000`
- Link-time VA: 26.1=`0xfffffff008232000`, 26.6.1=`0xfffffff008282000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  0122e000  00 fc 3c d5 e0 fb 04 f9 20 d2 ff f0 00 78 6f 39   ..<..... ....xo9
  0122e010  60 00 00 b4 e0 d0 3b d5 e0 d3 01 f9 e0 03 00 91   `.....;.........
  0122e020  02 8c 01 a9 04 94 02 a9 06 9c 03 a9 08 a4 04 a9   ................
  0122e030  0a ac 05 a9 0c b4 06 a9 0e bc 07 a9 10 c4 08 a9   ................
NEW (26.6.1):
  0127e000  89 da 4b f9 15 09 c9 9a 80 e6 4b f9 16 3f 91 94   ..K.......K..?..
  0127e010  88 d6 4b f9 09 01 15 8b 29 01 40 39 69 00 00 34   ..K.....).@9i..4
  0127e020  29 05 00 51 09 69 35 38 88 c2 57 b9 e8 18 00 35   )..Q.i58..W....5
  0127e030  80 e6 4b f9 d8 41 91 94 7f 32 02 f9 68 3a 42 f9   ..K..A...2..h:B.
```

### Region 7 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x009000`
- File offsets: 26.1=`0x01231000`, 26.6.1=`0x01281000`
- Link-time VA: 26.1=`0xfffffff008235000`, 26.6.1=`0xfffffff008285000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  01231000  0f 00 00 b9 f0 43 43 f8 90 00 00 b4 f1 03 13 aa   .....CC.........
  01231010  f1 a9 eb f2 30 1a c1 da 70 01 00 f9 28 01 00 b9   ....0...p...(...
  01231020  6e 01 00 b4 e8 d2 01 91 e9 0f 80 52 0b 01 40 39   n..........R..@9
  01231030  cb 01 00 39 cb 00 00 34 ce 05 00 91 08 05 00 91   ...9...4........
NEW (26.6.1):
  01281000  08 82 26 91 09 d2 44 f9 e0 03 13 aa f1 03 08 aa   ..&...D.........
  01281010  f1 f9 fe f2 31 09 3f d7 a9 02 40 f9 28 81 04 91   ....1.?...@.(...
  01281020  3f 21 01 b9 14 08 00 34 20 09 29 1e 8b 06 00 11   ?!.....4 .).....
  01281030  7f 09 00 71 4a 00 80 52 4a 95 94 1a 7f 11 00 71   ...qJ..RJ......q
```

### Region 8 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x00c000`
- File offsets: 26.1=`0x01234000`, 26.6.1=`0x01284000`
- Link-time VA: 26.1=`0xfffffff008238000`, 26.6.1=`0xfffffff008288000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  01234000  16 00 80 52 8e ff ff 17 5f 24 03 d5 00 10 40 f9   ...R...._$....@.
  01234010  01 01 80 52 91 f5 1b 14 5f 24 03 d5 00 80 00 91   ...R...._$......
  01234020  21 10 40 f9 02 01 80 52 22 f5 1b 14 5f 24 03 d5   !.@....R"..._$..
  01234030  08 10 40 f9 08 05 40 f9 09 0d 40 f9 29 05 00 91   ..@...@...@.)...
NEW (26.6.1):
  01284000  a0 00 00 b4 ff 46 00 39 ff 46 01 39 ff 62 00 f9   .....F.9.F.9.b..
  01284010  0a 00 00 14 60 03 40 f9 10 00 40 f9 f1 03 00 aa   ....`.@...@.....
  01284020  31 b4 f9 f2 30 1a c1 da 08 8e 42 f8 f0 50 e7 f2   1...0.....B..P..
  01284030  10 09 3f d7 7f 03 00 f9 d0 02 40 f9 f1 03 16 aa   ..?.......@.....
```

### Region 9 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x00d000`
- File offsets: 26.1=`0x01235000`, 26.6.1=`0x01285000`
- Link-time VA: 26.1=`0xfffffff008239000`, 26.6.1=`0xfffffff008289000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  01235000  8c 01 11 0b 8c 09 00 11 0b 32 0b 9b a9 11 09 aa   .........2......
  01235010  29 4d 2a 8b 69 25 0f 9b 8a 0c 80 52 3f 90 01 71   )M*.i%.....R?..q
  01235020  2a 30 8a 1a 4a 91 01 11 29 7d 0a 9b 29 fd 42 d3   *0..J...)}..).B.
  01235030  6a b8 9e d2 0a 85 ab f2 ea 51 d8 f2 aa 1e e5 f2   j........Q......
NEW (26.6.1):
  01285000  31 b4 f9 f2 30 1a c1 da 11 20 80 d2 10 02 11 8b   1...0.... ......
  01285010  08 02 40 f9 a1 74 ff d0 21 fc 11 91 e0 03 19 aa   ..@..t..!.......
  01285020  e2 03 1a aa 70 64 f8 f2 10 09 3f d7 50 03 40 f9   ....pd....?.P.@.
  01285030  f1 03 1a aa 31 b4 f9 f2 30 1a c1 da 08 8e 42 f8   ....1...0.....B.
```

### Region 10 — 4,096 bytes changed
- __TEXT_EXEC offset: `+0x010000`
- File offsets: 26.1=`0x01238000`, 26.6.1=`0x01288000`
- Link-time VA: 26.1=`0xfffffff00823c000`, 26.6.1=`0xfffffff00828c000`
- Nearby string (26.6.1): —
- Nearby string (26.1):   —

```
OLD (26.1):
  01238000  41 01 1b 32 03 01 09 aa e4 e3 01 91 e0 03 16 aa   A..2............
  01238010  8f c5 03 94 a0 07 00 34 88 06 80 52 1f 18 00 71   .......4...R...q
  01238020  00 01 80 1a e8 77 40 b9 09 29 0b 53 2a 01 0b 12   .....w@..).S*...
  01238030  6a 03 0a aa 29 01 0a 12 49 01 09 aa 2a 01 6c b2   j...)...I...*.l.
NEW (26.6.1):
  01288000  88 ab 8f 52 60 02 08 8b 81 42 80 52 25 03 8f 94   ...R`....B.R%...
  01288010  1a 8b 0a b9 88 ee 8f 52 60 02 08 8b 81 42 80 52   .......R`....B.R
  01288020  20 03 8f 94 28 74 ff f0 08 55 15 91 08 53 06 f9    ...(t...U...S..
  01288030  1a ab 0c b9 88 32 90 52 60 02 08 8b 81 42 80 52   .....2.R`....B.R
```


## ✓ Checkpoint: Detailed Hex Diff — 05:46:36


## 8. Troubles & Solutions


### Wrong LC_FILESET_ENTRY constant
**Problem:** Used `0x80000041` — got 0 fileset entries from a 302-entry fileset.

**Solution:** Dumped all LC type codes from the binary. Correct constant: `0x80000035`. The 0x80000041 value is wrong for modern iOS; 0x80000035 per XNU source.

### ZIP64 sentinel `0xFFFFFFFF` offsets in IPSW
**Problem:** Both the central-directory file offset AND each file's local_offset were `0xFFFFFFFF` (ZIP64 sentinels). fetch_kc.py read them literally → wrong offsets, no kernelcache found.

**Solution:** Implemented ZIP64 EOCD locator (sig `0x07064b50`) and ZIP64 extra-field parsing (tag `0x0001`) in the central directory. Both now in fetch_kc.py.

### Kernelcache is double-compressed
**Problem:** Raw IPSW range-request bytes are deflate-compressed (ZIP method=8). After inflating, result is IM4P ASN.1 containing LZFSE-compressed Mach-O.

**Solution:** Two-step decompression: (1) zlib inflate for ZIP layer, (2) hand-written IM4P ASN.1 parser → LZFSE payload, (3) lzfse binary for final decompression. All in fetch_kc.py + unwrap_im4p.py.

### lzfse stdin pipe fails silently
**Problem:** `lzfse -decode -i - -o outfile` with stdin input returns non-zero, no output.

**Solution:** Write LZFSE payload to a temp file first: `lzfse -decode -i tmpfile -o outfile`. Fixed in unwrap_im4p.py.

### No apt-get (Alpine Linux, not Debian/Ubuntu)
**Problem:** `apt-get install lzfse` → command not found.

**Solution:** Machine is Alpine Linux. Use `apk add lzfse`. Also `apk add py3-pip` for pip.

### pip blocked by PEP 668
**Problem:** `pip install lzfse` refused with system-packages error.

**Solution:** Use `pip install lzfse --break-system-packages`. lzfse 0.4.2.post1 installed.

### GNU nm doesn't support Mach-O
**Problem:** `nm kernelcache.macho` → 'file format not recognized'. GNU Binutils 2.45.1.

**Solution:** Wrote extract_symbols.py: custom Python Mach-O / MH_FILESET / nlist_64 parser.

### Production kernel has nsyms=0
**Problem:** com.apple.kernel (XNU itself) has LC_SYMTAB.nsyms=0 — completely stripped. __LINKEDIT also has filesize=0.

**Solution:** Identify functions via: (1) nearby panic/log strings, (2) MIG name-table pointer scan, (3) KDK dSYM for full symbols.

### OOM on git push with binary files
**Problem:** Committed ~140MB of .macho/.im4p/.lzfse files. `git push` died: `pack-objects died of signal 9`.

**Solution:** `git reset HEAD~1`, added kerneldiff/.gitignore for *.macho/*.im4p/*.lzfse, recommitted scripts only.

### OOM running full analysis (first attempt)
**Problem:** Loading both 70MB files with `f.read()` = 140MB RAM + Python overhead → process killed (exit 137).

**Solution:** Switched to `mmap.mmap(f.fileno(), 0, access=ACCESS_READ)` — OS pages data in/out. Also switched to streaming string scan (64K blocks) instead of whole-file bytes.

### Previous session scratchpad lost
**Problem:** All prior-session work (scripts, downloaded kernelcaches) was in /tmp/scratchpad which is session-specific. Everything gone after crash.

**Solution:** All scripts now committed to git (~/code/saved-pages/kerneldiff/). STATE.md documents IPSW URLs and current progress. Binary artifacts regenerable in ~5 min from the scripts.


## ✓ Checkpoint: Troubles & Solutions — 05:46:36


## 9. Device & Tool Limitations


This machine is an **Alpine Linux x86 VM hosted on an iPhone** (PocketCode app).
CPU is emulated/slow; RAM is the tightest limit — exceeding it kills all tabs.

| Tool | Status | Notes |
|------|--------|-------|
| `apt-get` | ❌ | Alpine only has `apk` |
| `apk` | ✅ | `apk add lzfse` works |
| `pip` / `pip3` | ✅ after `apk add py3-pip` | Needs `--break-system-packages` |
| `lzfse` binary | ✅ `apk add lzfse` v1.0-r0 | Must use file args, not stdin |
| `img4tool` | ❌ Not in Alpine | Python IM4P ASN.1 parser instead |
| GNU `nm` | ✅ but ❌ Mach-O | Custom Python parser |
| `jtool2` / `otool` | ❌ | macOS-only; Python parser instead |
| `capstone` disasm | ✅ via pip | `pip install capstone --break-system-packages` (not yet installed) |
| `macholib` | ❌ Not installed | Custom parser |
| `radare2` / `ghidra` | ❌ Too heavy | Not feasible on this hardware |
| Dev servers / builds | ❌ | Too much RAM; use Vercel for web projects |

**RAM budget:** ~200MB usable for analysis processes.
Two 70MB mmap'd files + Python overhead ≈ 180MB — feasible with streaming.
Loading both files with `f.read()` hits OOM. Always use `mmap`.

**Network:** curl works for range requests. No wget. HTTPS works.
**Disk:** /root/code/ persists. /tmp/scratchpad/ is session-scoped (lost on crash).


## 10. Summary & Findings


### Key Findings

1. **Structure:** 302 kexts in 26.1, 304 in 26.6.1 (2 new Thunderbolt USB Type 2 kexts).
   26.6.1 __TEXT_EXEC shrank by **~1.9MB** (-1,966,080 bytes). Every other segment grew.

2. **mach_make_memory_entry_64:** Appears in both kernels in identical locations
   (IOKit debug string, MIG name table, fixup info). The function itself is in
   __TEXT_EXEC (XNU kernel proper, stripped). Without KDK symbols, exact VA
   requires following the MIG pointer table as documented above.

3. **SPTM segment:** `__DATA_SPTM` has filesize=0 in both IPSWs — the SPTM firmware
   (`sptm.t8140.release.im4p`) ships as a separate file inside the IPSW `Firmware/`
   directory. Analysing SPTM changes requires extracting and diffing that file.

4. **All 11,368 __TEXT_EXEC pages changed** — even after ADRP normalisation.
   This is NOT a narrow security patch: the entire kernel was recompiled between 26.1
   and 26.6.1 (5+ releases apart). File-position comparison has no meaning here because
   the __TEXT_EXEC region shrank by 1.96MB, shifting all subsequent code. To diff a
   *specific function* you need either KDK symbols or string-anchored disassembly.
   The hex dumps in Section 7 show completely different code at corresponding file offsets.

5. **String diff:** 1,045 new strings, 1,483 removed strings. Security highlights:
   - `!vmrl_is_kernel_pmap(flags)` — new pmap assertion in 26.6.1
   - New pmap wired-count overflow/underflow panic strings (stricter accounting)
   - `"failed to set sandbox info callbacks"` — new in 26.6.1 (sandbox hardening)
   - Removed: `"%s: unsupported on non-PPL systems"` × 2 → PPL fully replaced by SPTM
   - Removed: `"%s: Unknown pmap_lock_mode"` — pmap lock-mode API refactored
   - AMFI: `"AMFI: unable to update legacy context"` removed (legacy path cut)

### Kext Highlights

| Finding | Details |
|---------|---------|
| `sandbox` changed most | 1.75MB diff bytes, shrank 50KB — significant sandbox policy rewrite |
| `corecrypto` changed | 110K bytes diff, -352 bytes — crypto primitive update |
| `AppleImage4` changed | 60K bytes diff — Image4/secure boot parser update |
| `kernel` (XNU proper) grew | +46KB, 850K diff bytes — core kernel changes |
| `apfs` changed | 298K diff — filesystem subsystem changes |
| 0 kexts fully unchanged | Every kext in the collection was recompiled |

### Next Steps

- **SPTM diff:** `Firmware/sptm.t8140.release.im4p` exists in both IPSWs.
  Range-request it, unwrap IM4P, binary-diff the two payloads.
- **KDK symbols:** `developer.apple.com/download` → Kernel Debug Kit for 26.6.1 / 26.1.
  Provides dSYM with full symbol table → map VAs to function names.
- **Capstone disassembly:** `pip install capstone --break-system-packages`
  then disassemble the top changed regions for instruction-level diff.
- **MIG table walk:** Follow pointer from MIG name table → function pointer array
  → `mach_make_memory_entry_64` VA → extract function bytes for disassembly.

---
*Report written by analyse.py — 2026-10-25 05:46:36*
