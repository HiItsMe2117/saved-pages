# iOS 26.6.1 → 27.0.1 Kernelcache Diff (SPTM-Targeted)
*Generated 2026-10-25 11:51:18*

**Device:** iPhone 16 Plus (iPhone17,4)
**Older:** iOS 26.6.1 (23G83) — KernelManagement_host-487.100.11
**Newer:** iOS 27.0.1 (24A446) — KernelManagement_host-514.2.2
**Kernel build jump:** 487 → 514 (+27 minor versions)

---

## 1. Segment Layout Comparison

| Segment | 26.6.1 fileoff | 26.6.1 size | 27.0.1 fileoff | 27.0.1 size | Δ bytes |
|---------|---------------|-------------|----------------|-------------|---------|
| `__DATA` | 0x0416c000 | 3120K | 0x046ac000 | 3008K | -114,688 |
| `__DATA_CONST` | 0x00c78000 | 5904K | 0x00dcc000 | 6240K | +344,064 |
| `__DATA_SPTM` | 0x0123c000 | 240K | 0x013e4000 | 304K | +65,536 |
| `__LINKEDIT` | 0x04478000 | 768K | 0x0499c000 | 784K | +16,384 |
| `__PRELINK_INFO` | 0x03ee8000 | 2576K | 0x04430000 | 2544K | -32,768 |
| `__PRELINK_TEXT` | 0x00008000 | 12736K | 0x00008000 | 14096K | +1,392,640 |
| `__TEXT` | 0x00000000 | 32K | 0x00000000 | 32K | 0 |
| `__TEXT_BOOT_EXEC` | 0x03ee0000 | 32K | 0x04428000 | 32K | 0 |
| `__TEXT_EXEC` | 0x01278000 | 45472K | 0x01430000 | 49120K | +3,735,552 |

**__PPLTEXT in 26.6.1:** NO — already absent
**__PPLTEXT in 27.0.1:** NO — PPL fully removed ✓
**__DATA_SPTM:** 240K → 304K (Δ +64K)


## ✓ Checkpoint: 1. Segment Layout — 11:51:18

## 2. GENTER Instruction Count (`20 14 20 00`)

| Location | 26.6.1 count | 27.0.1 count | Delta |
|----------|-------------|-------------|-------|
| `__TEXT_EXEC` (kernel) | 150 | 173 | +23 |
| `__PRELINK_TEXT` (kexts) | 1 | 1 | +0 |
| **Total** | **151** | **174** | **+23** |

### GENTER sites near anchor strings (26.6.1 __TEXT_EXEC)



## ✓ Checkpoint: 2. GENTER Count — 11:51:21

## 3. SPTM/GXF/PPL/TXM String Diff

Matched strings (SPTM/PPL/GXF/TXM keywords):
- 26.6.1: 10470 | 27.0.1: 10804
- New in 27.0.1: **1422** | Removed: **1088**

### New SPTM-related strings in 27.0.1
```
"AppleBTM: %s:%u " "AppleBTM: unable to read vddmain data from PMU. ret: 0x%08X" @%s:%d
"AppleBTM: %s:%u " "Invalid specLen %d" @%s:%d
"AppleBTM: %s:%u " "Offset %d is not within results_buffer bounds" @%s:%d
"AppleBTM: %s:%u " "getPmuSampleSpec returned NULL" @%s:%d
"AppleDiagnosticDataAccess does not support partial region data for NAND backed regions" @%s:%d
"AppleOLYHAL Panic: AppleBCMWLAN dext init failure unrecoverable after %u chip resets" @%s:%d
"ApplePPM: %s:%u " "Both pmgr and AON PTD enabled in EDT, target must enable exactly one PTD path" @%s:%d
"ApplePPM: %s:%u " "Couldn't add object for client id %u in _multiClientList" @%s:%d
"ApplePPM: %s:%u " "Incorrect size for EDT property!" @%s:%d
"ApplePPM: %s:%u " "Input ptr currEnv is invalid" @%s:%d
"ApplePPM: %s:%u " "Input ptr prevEnv is invalid" @%s:%d
"ApplePPM: %s:%u " "Invalid clientId %d in multiClientList" @%s:%d
"ApplePPM: %s:%u " "Invalid multi-client-thermal-dup clientID %d" @%s:%d
"ApplePPM: %s:%u " "Legacy PTD requires ApplePMGRNub provider" @%s:%d
"ApplePPM: %s:%u " "PTD multi-read failed: 0x%x" @%s:%d
"ApplePPM: %s:%u " "PTD write failed: 0x%x" @%s:%d
"ApplePPM: %s:%u " "_multiEMAMaxTracker not initialized for index=%d" @%s:%d
"ApplePPM: %s:%u " "currData is null" @%s:%d
"ApplePPM: %s:%u " "currValues is null" @%s:%d
"ApplePPM: %s:%u " "disablePTDEntryInterrupt returned 0x%08x" @%s:%d
"ApplePPM: %s:%u " "enablePTDEntryInterrupt returned 0x%08x" @%s:%d
"ApplePPM: %s:%u " "handleRangeInterrupt called with unexpected range %u (expected %u)" @%s:%d
"ApplePPM: %s:%u " "interrupt source not initialized" @%s:%d
"ApplePPM: %s:%u " "invalid entry at index %u in multiClientList" @%s:%d
"ApplePPM: %s:%u " "invalid index =%d" @%s:%d
"ApplePPM: %s:%u " "max_out is null" @%s:%d
"ApplePPM: %s:%u " "numEntriesPPMToSMC %u exceeds kOutboundBufferSize %u" @%s:%d
"ApplePPM: %s:%u " "peakPowerEnv is null" @%s:%d
"ApplePPM: %s:%u " "ptML lookup failed: 0x%x" @%s:%d
"ApplePPM: %s:%u " "ptML returned unexpected identifier for PPM->SMC range: 0x%x" @%s:%d
"ApplePPM: %s:%u " "ptML returned unexpected identifier for SMC->PPM range: 0x%x" @%s:%d
"ApplePPM: %s:%u " "ptML returned zero entries for PPM->SMC range" @%s:%d
"ApplePPM: %s:%u " "ptML returned zero entries for SMC->PPM range" @%s:%d
"ApplePPM: %s:%u " "pwrLogValues not initialized %d\n" @%s:%d
"ApplePPM: %s:%u " "writePTDEntry %d returned 0x%08x" @%s:%d
"AppleS8000AESAccelerator::_distribute_dkey: DKey distribution failure (aes-version=%u)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d)" @%s:%d
"AppleThunderboltNHIReceiveRingGenericACIO(%d)<%d>::shouldDoubleBuffer - " "double buffering detected (o=0x%x, l=0x%x, seg=0x%llx)\n" @%s:%d
"AppleThunderboltNHITransmitRing(%d)<%d>::shouldDoubleBuffer - " "double buffering detected (o=0x%x, l=0x%x, seg=0x%llx)\n" @%s:%d
"AppleThunderboltNHITransmitRingGenericACIO(%d)<%d>::shouldDoubleBuffer - " "double buffering detected (o=0x%x, l=0x%x, seg=0x%llx)\n" @%s:%d
"Image4: attempted to get ASMB without PPL context" @%s:%d
"Image4: attempted to get chosen without PPL context" @%s:%d
"Image4: attempted to get darwin-data without PPL context" @%s:%d
"Image4: attempted to get defaults without PPL context" @%s:%d
"Image4: attempted to get expert without PPL context" @%s:%d
"Image4: attempted to get manifest properties without PPL context" @%s:%d
"Image4: attempted to get product without PPL context" @%s:%d
"Image4: attempted to initialize PPL expert without a PPL" @%s:%d
"Image4: attempted to roll nonce without PPL context" @%s:%d
"Image4: attempted to roll nonce without PPL mutable buffer" @%s:%d
"Image4: attempted to set nonce digest without PPL context" @%s:%d
"Image4: attempted to set nonce digest without PPL mutable buffer" @%s:%d
"Image4: nonce digest too large for PPL: %lu" @%s:%d
"Image4: unable to setup /chosen node in PPL" @%s:%d
"Image4: unable to setup /chosen/manifest-properties node in PPL" @%s:%d
"Image4: unable to setup /defaults node in PPL" @%s:%d
"Image4: unable to setup /product node in PPL" @%s:%d
"Image4: unexpected length of PPL mutable buffer: %lu" @%s:%d
%s: OSDynamicCast failed, client_object is not AppleLIFSUserClient
%s: insufficient number of ASIDs (%u) supplied by SPTM @%s:%d
%s: provider is not AppleAuthCPRelayInterface
%s: sptm_page_is_sk_shared_realtime(%p, %p) failed @%s:%d
%s::%s() Final domain configuration applied: domainID='%c%c%c%c', iopDomainID='%c%c%c%c'
%s::%s:%d: Failed to initialize super class, AppleSARInterface
%s::%s:%d: Forced HSAR cluster count override: requested=%u applied=%u (0=clear)
%s::%s:%d: PTD %s numberOfEntries (%zu) exceeds maximum (%zu), rejecting request ( please check with ApplePTD kext on unepxected number of entries )
%s::%s:%d: Service is not AppleBasebandPTD type!
%s::%s:%d: Use case detection override applied to regulatory bitmask: %u
( inSideBarVersion == 0 ) || ( fOwner->metaCast("AppleNVMeNamespaceDevice") != NULL )
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDevice.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceInterface.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceTest.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMHIDInterface.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMParserTest.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMSPITest.h
/AppleInternal/Library/BuildRoots/4~CY3yugDEsti_6TO6aE9DSxLIfLkfo6qnkmwPx8E/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS27.0.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferDevice.h
```

### Removed SPTM-related strings (were in 26.6.1)
```
"%s:%u:" "pActionType == kAppleOLYHALPortInterfacePowerActionTypeHardReset" @%s:%d
"AppleBCMWLAN Dext didn't respawn within %u milliseconds\n" @%s:%d
"ApplePPM: %s:%u " "CPU power profile wrong! total(%d, %d, %d), leftover(%d, %d, %d), max(%d, %d, %d), profile(%d, %d, %d)" @%s:%d
"ApplePPM: %s:%u " "No support for sending budget limits to userspace clients" @%s:%d
"ApplePPM: %s:%u " "budget update failure" @%s:%d
"ApplePPM: %s:%u " "inconsistent inputs (%p, %d, %d)" @%s:%d
"ApplePPM: %s:%u " "index %d, count %u" @%s:%d
"ApplePPM: %s:%u " "must create %s entity in subclass" @%s:%d
"ApplePPM: %s:%u " "writePTDEntry %i returned 0x%08x" @%s:%d
"AppleS8000AESAccelerator::_distribute_dkey: DKey distribution failure" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d, Perf %d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d, Perf %d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d, Perf %d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Ids %d/%d/%d/%d/%d/%d/%d/%d/%d, Perf %d/%d)" @%s:%d
"AppleSocHot: Hot Hot Hot (%08X/%d %08X/%d %08X/%d %08X/%d %08X/%d, Perf %d/%d)" @%s:%d
"IOMFB: cannot find AppleMobileFileIntegrity" @%s:%d
%s: libsptm_init failed: %u @%s:%d
*** AppleMultitouchSPI::killDevice - %s ***
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDevice.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceInterface.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMDeviceTest.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMHIDInterface.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMParserTest.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMSPITest.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferDevice.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSMTransferTest.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserDevice.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSParserTest.h
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/standalone/hidspi/include/hidspi/HSTransferTest.h
/Library/Caches/com.apple.xbs/059D1497-84D3-4191-9FB0-8B5B31D266AF/TemporaryDirectory.2Ux1GJ/Sources/AppleS8000/AppleS8000AES.cpp
/Library/Caches/com.apple.xbs/059D1497-84D3-4191-9FB0-8B5B31D266AF/TemporaryDirectory.2Ux1GJ/Sources/AppleS8000/AppleS8000AES.h
/Library/Caches/com.apple.xbs/06216286-E3CA-4B33-B6CA-2AAA6D369250/TemporaryDirectory.lUIOvk/Sources/AppleARMPMU/AppleARMPMUCharger.cpp
/Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/AppleARMIISAudio/core/helper/IISAudioDeviceHelper.cpp
/Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/IsolatedStreamECProxy/IOService/IISAudioIsolatedOutputStreamECProxy.cpp
/Library/Caches/com.apple.xbs/0990A85E-B1D3-4C32-8FC1-536642F52678/TemporaryDirectory.egh5pa/Sources/AppleARMIISAudio/src/kext/IsolatedStreamECProxy/IOService/IISAudioIsolatedStreamECProxy.cpp
/Library/Caches/com.apple.xbs/12391FD8-DF81-421F-A835-095FC7556FC2/TemporaryDirectory.diJ8B9/Sources/AppleFSCompression/Common/ChunkCompression.cpp
/Library/Caches/com.apple.xbs/12391FD8-DF81-421F-A835-095FC7556FC2/TemporaryDirectory.diJ8B9/Sources/AppleFSCompression/Compressors/Zlib/compressorKext.c
/Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/ADMAFamily/ADMAChannelInterface.cpp
/Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/AudioDMAChannelStateMachine.cpp
/Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/AudioDMAController.cpp
/Library/Caches/com.apple.xbs/187643ED-D799-4F14-87B7-DEF111791EA5/TemporaryDirectory.RCGAPz/Sources/AudioDMAController/v4p0/Kext/Source/IOInterruptQueueEventSource.cpp
/Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/AudioConfigDataHelper.cpp
/Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunction.cpp
/Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/AppleAudioDeviceCommandFunction/AudioDeviceCommandFunctionUtility.cpp
/Library/Caches/com.apple.xbs/18AB9830-C4BA-45E9-ADE4-33383EE93687/TemporaryDirectory.OdrmnW/Sources/AppleAudioKextLibs/src/kext/AppleEmbedAudioLibs/IORegistryEntryHelper/AudioKextIORegistryHelper.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCBinaryLog/AppleSMCACAMDriver.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCBinaryLog/AppleSMCBinaryLogDriver.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbedded.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedCharger/AppleSMCCharger.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedCharger/AppleSMCChargerUtil.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedFunctions.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCEmbeddedPMU/AppleSMCPMU.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCHighVoltageCharger/AppleSMCHighVoltageCharger.cpp
/Library/Caches/com.apple.xbs/1FD2D79B-6A4C-43F1-9874-92C64C44E4A0/TemporaryDirectory.rk8Fc3/Sources/AppleSMC/AppleSMCKeysEndpoint.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/ADCDevice/AppleUSBADCAudioDevice.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioController.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioDevice.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/IDAM/AppleUSBDeviceAudioNub.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AUATapStreams.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioControlInterface.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioDevice.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioDictionary.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioEngine.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioIsocFrameList.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioIsocPipe.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/AppleUSBAudioStream.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Control.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Device.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Engine.cpp
/Library/Caches/com.apple.xbs/21A473B4-991E-486F-A679-D9BD0B4C0EE9/TemporaryDirectory.QmYGxI/Sources/AppleUSBAudio/KEXT/IOAudio2/Audio2Stream.cpp
/Library/Caches/com.apple.xbs/22519F58-1FC1-425A-945A-D9D57224EFCA/TemporaryDirectory.vB6jmR/Sources/IOAVFamily/IOAV.cpp
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelLib.cpp
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelTransport.cpp
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonMem.c
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonUtil.c
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/LibCall.c
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/LibSerialization.c
/Library/Caches/com.apple.xbs/241210ED-6927-49FD-AF4B-841A9C1D4502/TemporaryDirectory.HjK1O1/Sources/AppleSSE/AppleSSE/AppleSSE.cpp
/Library/Caches/com.apple.xbs/241210ED-6927-49FD-AF4B-841A9C1D4502/TemporaryDirectory.HjK1O1/Sources/AppleSSE/AppleSSE/AppleSSEUserClient.cpp
/Library/Caches/com.apple.xbs/24C8B80F-84C6-49EC-9312-1F2144A79065/TemporaryDirectory.oHF4LS/Sources/AppleARMPlatform/AppleARMSPMI.cpp
```

### "page enforcement failed" location
- Not found in either kernel (lives in separate SPTM/TXM binary)


## ✓ Checkpoint: 3. String Diff — 12:12:54

## 4. `mach_make_memory_entry` Analysis

- Occurrences in 26.6.1: 7
- Occurrences in 27.0.1: 6

### 26.6.1
- `0x00053140` __PRELINK_TEXT+0x4b140: `- Unsanitary input passed to ·mach_make_memory_entry··mach_memory_entry_page_op··mach_memory_entry_range_op··m`
- `0x00055a86` __PRELINK_TEXT+0x4da86: `ntry that is a submap. @%s:%d·mach_make_memory_entry can't handle SYMMETRIC object @%s:%d·io_reprioritize_req·`
- `0x000b6116` __PRELINK_TEXT+0xae116: `erence.IOMemoryEntry·221·1222·mach_make_memory_entry_64 actualSize @%s:%d·IOMemoryDescriptor.cpp·getKernelRese`
- `0x00bf6451` __PRELINK_TEXT+0xbee451: `e·vm_remap_external·task_wire·mach_make_memory_entry·vm_map_page_query·mach_vm_region_info·vm_mapped_pages_inf`
- `0x00bf64ee` __PRELINK_TEXT+0xbee4ee: `m_region_info_64·vm_region_64·mach_make_memory_entry_64·vm_map_64_external·vm_purgable_control·vm_map_exec_loc`
- `0x00bf6712` __PRELINK_TEXT+0xbee712: `egion_recurse·mach_vm_region·_mach_make_memory_entry·mach_vm_purgable_control·mach_vm_page_info·mach_vm_page_r`
- `0x044a2f03` __LINKEDIT+0x2af03: `_mach_gss_unhold_cred···!N_··_mach_make_memory_entry_64···!P_··_mach_memory_entry_ownership···!R_·$_mach_msg_d`

### 27.0.1
- `0x000592dc` __PRELINK_TEXT+0x512dc: `)·VM-MAP-COPY(0x%lx, %lluKiB)·mach_make_memory_entry can't handle SYMMETRIC object @%s:%d·io_reprioritize_req·`
- `0x000bdd8d` __PRELINK_TEXT+0xb5d8d: `erence.IOMemoryEntry·221·1222·mach_make_memory_entry_64 actualSize @%s:%d·IOMemoryDescriptor.cpp·getKernelRese`
- `0x00d4d776` __PRELINK_TEXT+0xd45776: `e·vm_remap_external·task_wire·mach_make_memory_entry·vm_map_page_query·mach_vm_region_info·vm_mapped_pages_inf`
- `0x00d4d813` __PRELINK_TEXT+0xd45813: `m_region_info_64·vm_region_64·mach_make_memory_entry_64·vm_map_64_external·vm_purgable_control·vm_map_exec_loc`
- `0x00d4da21` __PRELINK_TEXT+0xd45a21: `egion_recurse·mach_vm_region·_mach_make_memory_entry·mach_vm_purgable_control·mach_vm_page_info·mach_vm_page_r`
- `0x049c72fe` __LINKEDIT+0x2b2fe: `_mach_gss_unhold_cred···!f_··_mach_make_memory_entry_64···!h_··_mach_memory_entry_ownership···!j_·$_mach_msg_d`

### MIG dispatch index (`_mach_make_memory_entry_64` in LINKEDIT)

- **26.6.1**: `old_cred···!N_··_mach_make_memory_entry_64···!P_··_mach_memory_ent`
- **27.0.1**: `old_cred···!f_··_mach_make_memory_entry_64···!h_··_mach_memory_ent`


## ✓ Checkpoint: 4. mach_make_memory_entry Analysis — 12:12:54

