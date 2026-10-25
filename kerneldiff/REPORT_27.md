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

## 5. Kext Changes

| | 26.6.1 | 27.0.1 | Δ |
|---|---|---|---|
| Total | 302 | 305 | +3 |
| New | — | 4 | +4 |
| Removed | 1 | — | -1 |
| Common | 301 | 301 | — |

### New kexts in 27.0.1
- `com.apple.audio.TrustedClockingKEXT`
- `com.apple.driver.AFKHIDTBDevice`
- `com.apple.driver.VideoProcessing`
- `com.apple.security.Image4`

### Removed kexts
- `com.apple.filesystems.hfs.kext`

### Largest size changes

| Kext (short) | 26.6.1 | 27.0.1 | Δ |
|---|---|---|---|
| `AppleM2ScalerCSCDriver` | 551K | 930K | +387,760 |
| `AppleAVD` | 894K | 1133K | +244,272 |
| `AppleSARService` | 125K | 281K | +159,712 |
| `sandbox` | 1878K | 2015K | +140,448 |
| `AppleAVE2` | 862K | 962K | +102,112 |
| `kernel` | 1008K | 1056K | +49,152 |
| `corecrypto` | 122K | 83K | -40,288 |
| `CoreTrust` | 16K | 37K | +21,296 |
| `AppleSEPManager` | 107K | 127K | +20,224 |
| `AppleH16ANEInterface` | 294K | 314K | +20,192 |
| `AppleImage4` | 67K | 86K | +19,552 |
| `AppleSmartBatteryManagerEmbedded` | 36K | 54K | +18,656 |
| `AppleMultitouchSPI` | 19K | 1K | -17,984 |
| `ApplePPMCPMS` | 68K | 83K | +15,536 |
| `AppleSynopsysUSB40XHCI` | 63K | 73K | +10,976 |
| `AppleDiskImages2` | 15K | 25K | +10,352 |
| `AppleUSBXDCIARM` | 48K | 58K | +9,920 |
| `AppleSEPCredentialManager` | 71K | 80K | +9,856 |
| `apfs` | 314K | 323K | +9,392 |
| `AGXG17P` | 92K | 84K | -9,040 |
| `AppleSynopsysUSBXHCI` | 45K | 53K | +8,640 |
| `AppleGenericMultitouch` | 32K | 40K | +8,176 |
| `IOMobileGraphicsFamily-DCP` | 30K | 38K | +8,032 |
| `AppleIOPADMAStream` | 14K | 22K | +7,680 |
| `AUC` | 3K | 11K | +7,456 |
| `IOThunderboltFamily` | 536K | 543K | +7,168 |
| `IOAccessoryManager` | 136K | 143K | +6,672 |
| `IONVMeFamily` | 62K | 68K | +6,128 |
| `AppleInputDeviceSupport` | 10K | 16K | +5,904 |
| `AppleEmbeddedTouchEEPROM` | 3K | 9K | +5,808 |


## ✓ Checkpoint: 5. Kext Changes — 12:55:47

## 6. Changed Security-Relevant Strings

- Matched in 26.6.1: 27387 | 27.0.1: 28484
- New: **2491** | Removed: **1401**

### New security strings in 27.0.1
```
 %d> (policy id=%d session_order=%d policy_order=%d result=%s)
 2000-2018 Apple Inc. All rights reserved. [IOHIDFamily-2360.2.2]"</string>
 2008-2026 Apple Inc. All rights reserved.</string>
 2016 Apple Inc. All rights reserved. [AppleInputDeviceSupport_kexts-10100.41]"</string>
 2018-2026 Apple Inc. All rights reserved.</string>
 2020 Apple. All rights reserved.</string>
 2022 - 2026 Apple. All rights reserved.</string>
 2025-2026 Apple Inc. All rights reserved.</string>
 2026 Apple Inc. All rights reserved.</string>
!%\_kernel_pmap
!entitlement || ACMKernelUtils::isEntitled(params.owningTask, entitlement)
"AMFI cert overrun\n" @%s:%d
"AMFI gave us too many certs\n" @%s:%d
"AMFI: unable to create legacy CE context from monitor CE context: %u" @%s:%d
"AMFI: unable to get legacy context after adjustment without monitor: %u" @%s:%d
"AMFI: unable to obtain legacy CE context from CE context: %u" @%s:%d
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
"Bad AMFI Detached Certs size" @%s:%d
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
"Image4: failed to load local policy with code-signing-monitor: %u" @%s:%d
"Image4: nonce digest too large for PPL: %lu" @%s:%d
"Image4: unable to setup /chosen node in PPL" @%s:%d
"Image4: unable to setup /chosen/manifest-properties node in PPL" @%s:%d
"Image4: unable to setup /defaults node in PPL" @%s:%d
"Image4: unable to setup /product node in PPL" @%s:%d
"Image4: unexpected length of PPL mutable buffer: %lu" @%s:%d
```

### Removed security strings
```
 2000-2018 Apple Inc. All rights reserved. [IOHIDFamily-2238.162.1]"</string>
 2008-2020 Apple Inc. All rights reserved.</string>
 2016 Apple Inc. All rights reserved. [AppleInputDeviceSupport_kexts-9140.6]"</string>
"%s:%u:" "pActionType == kAppleOLYHALPortInterfacePowerActionTypeHardReset" @%s:%d
"AMFI: '%s': Invalid first Code Directory should have been caught by xnu.\n" @%s:%d
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
"IOMFB: failed to cast AMFI service!" @%s:%d
"IOMFB: failed to look up AMFI service!" @%s:%d
%06lu.%06u %s::%s: AppleUSBNCM host version %#x (%s)
%06lu.%06u %s::%s: applying 0x%08x flags on interface
%lldus AppleThunderboltHALGenericACIO::unpoweredStart - bootargs: acio = 0x%08x
%s() Requesting AppleImage4 Validation
%s: %s:  fEnforceModelSignatureChecks = %d
%s: %s: AppleANEDrv::DriverInitiatedSleepTimerTimeOut
%s: %s: ERROR: Bad argument codeSigningTeamId=%p codeSigningIdentity=%p
%s: %s: Invalid program present in client list %p. pMapping=%p
%s: %s: client has entitlement to opt out all its models from unwire timer
%s: %s: client has entitlement to opt this model out of unwire timer
%s: <pid %d> Disallow flow add, requested nexus mismatched with NECP result - requested ifindex %d policy <result %d ifindex %d>
%s: AppleMultitouchSPI::callPowerFunction(%lu) - _powerFunction_ana returned 0x%08X
%s: AppleMultitouchSPI::callPowerFunction(%lu) - _powerFunction_mamba returned 0x%08X
%s: Couldn't make an AppleMultitouchZ2SPI out of _owner
%s: DATA-TRACE <%s %llx>: %s - fam %d proto %d port <local %d/%d remote %d/%d> <local %s remote %s> <drop-all order %d> <pid=%d Application %d Real Application %d BoundInterface %d> (policy id=%d sess
%s: DATA-TRACE: Socket Policy - Send/Recv: %p (BoundInterface %d Proto %d) Policy %d Result %d Parameter %d Allowed %d <filter_control_unit %d flow_divert_aggregate_unit %d>
%s: Error: AppleMultitouchSPIPowerStats::fromService() returned NULL
%s: Error: AppleMultitouchSPIPowerStats::updateReport() returned 0x%08X
%s: Error: AppleMultitouchSPIPowerStats::updateWithPowerStatsData() returned 0x%08X
%s: attempt to nest stage 2 pmap %p @%s:%d
%s: attempt to nest unsupported pmap %p of type 0x%hhx @%s:%d
%s: bad PVE pte_p=%p pmap=%p prot=%d options=%u, pvh=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x @%s:%d
%s: copyTrustCacheFromInputArguments failed: %d
%s: failed pmap_enter_addr, pmap=%p, va=%#llx, pa=%llu, size=%u, prot=%#x, flags=%#x @%s:%d
%s: libsptm_init failed: %u @%s:%d
%s: unexpected pmap_enter_pv ret code: %d. new_pve_p=%p pmap=%p @%s:%d
%s:%d: image4_trust_evaluate: failed to authenticate root-hash (error %s <%d>)
%s:%d: image4_trust_evaluate: successfully validated the payload and the manifest
%s:%d: waitForService (AppleImage4) failed
%s::%d:AppleNVMeFWNamespace rollbackFWImage failed : 0x%8x
%s::%d:AppleNVMeFWNamespace writeDescriptorTable failed : 0x%8x
%s::%d:AppleNVMeFWNamespace writeFWImage failed : 0x%8x
%s::%d:NVMe EAN entitlement value bad
%s::%d:NVMe FWNamespace entitlement value bad
%s::%d:NVMe Namespace Device entitlement value bad
%s::%d:NVMe tunnel entitlement is false
%s::%d:NVMe update entitlement value bad
%s::%s():Failed to set pipe policy property (%d) 
%s::%s():Failed to set unified log policy property (%d) 
%s::%s:failed to run policy
%s::%s:policy/update failure
(IOHIDEventService::Action) OSMetaClassBase:: _ptmf2ptf(this, (void (OSMetaClassBase::*)(void)) &ApplePearlSEPDriver::loggingAnalyticsAlsHidEventServiceCallback)))
*** AppleMultitouchSPI::killDevice - %s ***
+I\_pmap_in_ppl
/AppleInternal/Library/BuildRoots/4~CVr6ugDpm3s5Uz3ynuAbN60mNdHPVmBIhGkedjk/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.6.Internal.sdk/usr/local/sta
/Library/Caches/com.apple.nsurlsessiond/Downloads/com.apple.WorkflowKit.BackgroundShortcutRunner
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
```


## ✓ Checkpoint: 6. Security Strings — 13:03:57

## 7. `__TEXT_EXEC` Diff Statistics

- 26.6.1: 45472K | 27.0.1: 49120K | Δ +3648K

- Pages compared: 11,368
- Changed pages: **11,368** (100%)
- Unchanged pages: 0

### 20 Most Surgical Patches (fewest bytes changed per page)

| Page | __TEXT_EXEC+offset | A fileoff | B fileoff | Bytes Δ | Nearby string |
|------|--------------------|-----------|-----------|---------|---------------|
| 10002 | +0x2712000 | 0x0398a000 | 0x03b42000 | 3553 | `—` |
| 11359 | +0x2c5f000 | 0x03ed7000 | 0x0408f000 | 3566 | `—` |
| 10001 | +0x2711000 | 0x03989000 | 0x03b41000 | 3574 | `—` |
| 11366 | +0x2c66000 | 0x03ede000 | 0x04096000 | 3608 | `—` |
| 11363 | +0x2c63000 | 0x03edb000 | 0x04093000 | 3628 | `—` |
| 11365 | +0x2c65000 | 0x03edd000 | 0x04095000 | 3628 | `—` |
| 11367 | +0x2c67000 | 0x03edf000 | 0x04097000 | 3641 | `—` |
| 11362 | +0x2c62000 | 0x03eda000 | 0x04092000 | 3680 | `—` |
| 11364 | +0x2c64000 | 0x03edc000 | 0x04094000 | 3687 | `—` |
| 10003 | +0x2713000 | 0x0398b000 | 0x03b43000 | 3734 | `—` |
| 6784 | +0x1a80000 | 0x02cf8000 | 0x02eb0000 | 3738 | `—` |
| 8159 | +0x1fdf000 | 0x03257000 | 0x0340f000 | 3741 | `—` |
| 11358 | +0x2c5e000 | 0x03ed6000 | 0x0408e000 | 3744 | `—` |
| 751 | +0x2ef000 | 0x01567000 | 0x0171f000 | 3764 | `—` |
| 1164 | +0x48c000 | 0x01704000 | 0x018bc000 | 3764 | `—` |
| 11361 | +0x2c61000 | 0x03ed9000 | 0x04091000 | 3764 | `—` |
| 8189 | +0x1ffd000 | 0x03275000 | 0x0342d000 | 3766 | `—` |
| 4323 | +0x10e3000 | 0x0235b000 | 0x02513000 | 3773 | `—` |
| 3954 | +0xf72000 | 0x021ea000 | 0x023a2000 | 3777 | `—` |
| 9961 | +0x26e9000 | 0x03961000 | 0x03b19000 | 3777 | `—` |


## ✓ Checkpoint: 7. __TEXT_EXEC Diff — 13:04:20

## Key Takeaways

### Architecture (iOS 26.6.1 → 27.0.1)
- **Kernel build 487.100.11 → 514.2.2** (+27 minor versions)
- **__TEXT_EXEC grew ++3648K** — significant new kernel code
- **__PPLTEXT absent in both** — PPL already fully removed before 26.6.1
- **__DATA_SPTM: 240K → 304K (+64K)** — SPTM data tables grew significantly

### GENTER (SPTM trap calls) — from earlier analysis
- **150 → 173 in __TEXT_EXEC (+23 new SPTM call sites)**
- Kexts: 1 → 1 (unchanged)

### Kexts
- 302 → 305 kexts
- 4 new, 1 removed

### Security
- 2491 new security-relevant strings; 1401 removed

### __TEXT_EXEC Code Pages
- 11,368 of 11,368 pages changed (100%)
- Top-20 most surgical patches listed above

### For Trigon (CVE-2023-32434) Research
- `mach_make_memory_entry` present in both — see Section 4 for offsets
- MIG dispatch table shifted in both 26.6.1 and 27.0.1
- To study the actual patch, download iOS 16.1.1 vs 16.5.1 for iPhone14,5
  (A15 arm64e, PPL-era) — SPTM-era kernels restructured the call path entirely

## Troubles & Solutions

**T1 — ZIP64 IPSW sentinels** (both cd_offset and local_off = 0xFFFFFFFF)
Solution: parse ZIP64 EOCD locator + ZIP64 extra field (tag 0x0001).

**T2 — lzfse stdin pipe fails on Alpine Linux**
Solution: write payload to temp file first.

**T3 — GNU nm doesn't speak Mach-O**
Solution: Python Mach-O parser walking LC_FILESET_ENTRY (0x80000035).

**T4 — Wrong LC_FILESET_ENTRY constant** (had 0x80000041)
Solution: dump all cmd types; found 302 entries of 0x80000035.

**T5 — Production kernel nsyms=0**
Solution: string-anchor method via panic/log strings.

**T6 — git push OOM with binary files** (pack-objects signal 9)
Solution: .gitignore for *.macho *.im4p *.lzfse.

**T7 — pip not available**
Solution: `apk add py3-pip`

**T8 — pip install blocked by PEP 668**
Solution: `pip install --break-system-packages`

**T9 — All pages differ (ADRP noise from different link base)**
Solution: numpy ADRP normalisation, or accepted as recompile evidence.

**T10 — apt-get not available**
Solution: `apk add` (Alpine Linux).

**T11 — String extraction OOM** (split-on-null creates millions of Python objects)
Solution: streaming chunked reader with re.finditer — never holds > 2MB of data.

**T12 — __TEXT_EXEC numpy diff OOM** (45MB + 49MB arrays + comparison)
Solution: chunked 512-page reads, delete arrays after each chunk with gc.collect().


## ✓ Checkpoint: Troubles & Solutions — 13:04:20


## 5. Kext Changes

- Kexts in 26.6.1: **302**
- Kexts in 27.0.1: **305**
- New in 27.0.1: **4**
- Removed: **1**
- Common: **301**

### New kexts in 27.0.1
- `com.apple.audio.TrustedClockingKEXT`
- `com.apple.driver.AFKHIDTBDevice`
- `com.apple.driver.VideoProcessing`
- `com.apple.security.Image4`

### Removed kexts (in 26.6.1, gone in 27.0.1)
- `com.apple.filesystems.hfs.kext`

### Kexts with largest size change (top 20)

| Kext | 26.6.1 size | 27.0.1 size | Δ bytes |
|------|-------------|-------------|---------|
| `AppleM2ScalerCSCDriver` | 551K | 930K | +387,760 |
| `AppleAVD` | 894K | 1133K | +244,272 |
| `AppleSARService` | 125K | 281K | +159,712 |
| `sandbox` | 1878K | 2015K | +140,448 |
| `AppleAVE2` | 862K | 962K | +102,112 |
| `kernel` | 1008K | 1056K | +49,152 |
| `corecrypto` | 122K | 83K | -40,288 |
| `CoreTrust` | 16K | 37K | +21,296 |
| `AppleSEPManager` | 107K | 127K | +20,224 |
| `AppleH16ANEInterface` | 294K | 314K | +20,192 |
| `AppleImage4` | 67K | 86K | +19,552 |
| `AppleSmartBatteryManagerEmbedded` | 36K | 54K | +18,656 |
| `AppleMultitouchSPI` | 19K | 1K | -17,984 |
| `ApplePPMCPMS` | 68K | 83K | +15,536 |
| `AppleSynopsysUSB40XHCI` | 63K | 73K | +10,976 |
| `AppleDiskImages2` | 15K | 25K | +10,352 |
| `AppleUSBXDCIARM` | 48K | 58K | +9,920 |
| `AppleSEPCredentialManager` | 71K | 80K | +9,856 |
| `apfs` | 314K | 323K | +9,392 |
| `AGXG17P` | 92K | 84K | -9,040 |


## ✓ Checkpoint: 5. Kext Changes — 13:56:04


## 6. Changed Security-Relevant Strings

*Extracted with `strings -n 16 | grep -iE <keywords>`*

Keywords: `entitlement|sandbox|pmap|sptm|ppl|enforce|policy|integrity|exploit|mitigat|voucher|amfi|codesign|trust|credential|privilege|escalat`

- Security strings in 26.6.1: 29548
- Security strings in 27.0.1: 28131
- New in 27.0.1 (total, incl. plist/path noise): **2509**
- Removed (total): **1417**
- New (kernel security relevant, noise filtered): **346**
- Removed (kernel security relevant): **130**

### New security strings in 27.0.1 (noise-filtered, first 40)
```
!entitlement || ACMKernelUtils::isEntitled(params.owningTask, entitlement)
"AMFI cert overrun\n" @%s:%d
"AMFI gave us too many certs\n" @%s:%d
"AMFI: unable to create legacy CE context from monitor CE context: %u" @%s:%d
"AMFI: unable to get legacy context after adjustment without monitor: %u" @%s:%d
"AMFI: unable to obtain legacy CE context from CE context: %u" @%s:%d
"Bad AMFI Detached Certs size" @%s:%d
"Image4: failed to load local policy with code-signing-monitor: %u" @%s:%d
"TB_ASSERT: " "(server->settrustedreportinterval != ((void*)0)) && \"implementation for setTrustedReportInterval is not present\"" ", " "\b\b" " (%s:%d)" @%s:%d
"assertion failed: " "!_updatePolicy" @%s:%d
%lld %d AVE %s: %p %lld EnableUserQPMap %d
%lld %d AVE %s: %s::%s checking entitlements %p %lld 0x%x
%lld %d AVE %s: %s::%s entitlement result %p %lld %d
%lld %d AVE %s: %s::%s:%d %s | entitlement check failed %p 0x%x
%p %lld EnableUserQPMap %d
%s Task not privileged
%s: %s: Client %s has set an entitlement opt out of bonded mode. This request will be honored if there is no explicit user hint in the inference request to allow bonded mode
%s: %s: DENIED: Entitlement '%s' not found!.
%s: %s: RESUME sent, expecting power policy %s for state %d
%s: %s: SUSPEND sent, requesting power policy %s for state %d
%s: %s: Setting default ARG power policy %s for state %d
%s: %s: Successfully set power policy %s for state %d
%s: %s: clockIsTrusted=%s lck=%llu unl=%llu iDt=%llu iTd=%llu iTdcm=%llu.
%s: %s: policy add failed (injected)
%s: %s: policy delete failed (injected)
%s: DATA-TRACE <%s %llx>: %s - fam %d proto %d port <local %d/%d remote %d/%d> <local %s remote %s> <drop-all order %d> <pid=%d Application %d Real Application %d BoundInterface %d> <gen_count current %d> (policy id=%d session_order=%d policy_order=%d result=%s)
%s: DATA-TRACE <%s %llx>: %s - fam %d proto %d port <local %d/%d remote %d/%d> <local %s remote %s> <drop-all order %d> <pid=%d Application %d Real Application %d BoundInterface %d> <policy_id %d skip_policy_id %d result %d> <input ifindex %d> <allowed_to_receive %d><pf_tag %X pass_flags %X><gen_count inp %d current %d>
%s: DATA-TRACE: Socket Policy - Send/Recv: <%llx> (BoundInterface %d Proto %d) Policy %d Result %d Parameter %d Allowed %d <filter_control_unit %d flow_divert_aggregate_unit %d>
%s: Not privileged (no fsmodule entitlement)
%s: Unsupported extent clone policy [%d]
%s: bad PVE pte_p=%p pmap=%p prot=%d options=%u, pvh=%p, pveh_p=%p, pvep=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x @%s:%d
%s: caller lacks fsmodule entitlement
%s: cannot create nested stage 2 pmap @%s:%d
%s: insufficient number of ASIDs (%u) supplied by SPTM @%s:%d
%s: policy exception xattr for process=%s path=%s
%s: proc %s[%d] calls chroot(2) without entitlement
%s: sptm_page_is_sk_shared_realtime(%p, %p) failed @%s:%d
%s: unexpected pmap_enter_pv ret code: %d. pmap=%p @%s:%d
%s:%d: %s _OP_GET_FILE_DSTREAMS requires the get-dstreams entitlement
%s:%d: %s _OP_GET_FILE_EXTS requires the get-file-exts entitlement
```

### Removed security strings (noise-filtered, first 40)
```
"AMFI: '%s': Invalid first Code Directory should have been caught by xnu.\n" @%s:%d
"IOMFB: cannot find AppleMobileFileIntegrity" @%s:%d
"IOMFB: failed to cast AMFI service!" @%s:%d
"IOMFB: failed to look up AMFI service!" @%s:%d
%s: %s:  fEnforceModelSignatureChecks = %d
%s: %s: ERROR: Bad argument codeSigningTeamId=%p codeSigningIdentity=%p
%s: %s: Invalid program present in client list %p. pMapping=%p
%s: %s: client has entitlement to opt out all its models from unwire timer
%s: %s: client has entitlement to opt this model out of unwire timer
%s: <pid %d> Disallow flow add, requested nexus mismatched with NECP result - requested ifindex %d policy <result %d ifindex %d>
%s: DATA-TRACE <%s %llx>: %s - fam %d proto %d port <local %d/%d remote %d/%d> <local %s remote %s> <drop-all order %d> <pid=%d Application %d Real Application %d BoundInterface %d> (policy id=%d session_order=%d policy_order=%d result=%s)
%s: DATA-TRACE <%s %llx>: %s - fam %d proto %d port <local %d/%d remote %d/%d> <local %s remote %s> <drop-all order %d> <pid=%d Application %d Real Application %d BoundInterface %d> <policy_id %d skip_policy_id %d result %d> <input ifindex %d> <allowed_to_receive %d><pf_tag %X pass_flags %X>
%s: DATA-TRACE: Socket Policy - Send/Recv: %p (BoundInterface %d Proto %d) Policy %d Result %d Parameter %d Allowed %d <filter_control_unit %d flow_divert_aggregate_unit %d>
%s: attempt to nest stage 2 pmap %p @%s:%d
%s: attempt to nest unsupported pmap %p of type 0x%hhx @%s:%d
%s: bad PVE pte_p=%p pmap=%p prot=%d options=%u, pvh=%p, pveh_p=%p, pve_p=%p, pte=0x%llx, va=0x%llx ppnum: 0x%x @%s:%d
%s: copyTrustCacheFromInputArguments failed: %d
%s: failed pmap_enter_addr, pmap=%p, va=%#llx, pa=%llu, size=%u, prot=%#x, flags=%#x @%s:%d
%s: libsptm_init failed: %u @%s:%d
%s: unexpected pmap_enter_pv ret code: %d. new_pve_p=%p pmap=%p @%s:%d
%s:%d: image4_trust_evaluate: failed to authenticate root-hash (error %s <%d>)
%s:%d: image4_trust_evaluate: successfully validated the payload and the manifest
%s::%d:NVMe EAN entitlement value bad
%s::%d:NVMe FWNamespace entitlement value bad
%s::%d:NVMe Namespace Device entitlement value bad
%s::%d:NVMe tunnel entitlement is false
%s::%d:NVMe update entitlement value bad
%s::%s():Failed to set pipe policy property (%d)
%s::%s():Failed to set unified log policy property (%d)
%s::%s:%d: Created E85 Mitigation object
%s::%s:%d: E85 Mitigation is supported. Creating the object.
%s::%s:%d: E85 Mitigation object is created already!
%s::%s:%d: Failed creating E85 Mitigation object!
%s::%s:failed to run policy
%s::%s:policy/update failure
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelLib.cpp
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/ACMKernelLib/ACMKernelTransport.cpp
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonMem.c
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/CommonUtil.c
/Library/Caches/com.apple.xbs/23634FB8-B8B9-4007-A916-3319675CA63D/TemporaryDirectory.88nTY9/Sources/AppleCredentialManager_KernelLibs/common/LibCall.c
```

### Notable security changes
**New AMFI/monitor integration strings (27.0.1):**
- `"AMFI: unable to create legacy CE context from monitor CE context: %u"` — AMFI now has a code-signing monitor integration path; "legacy CE context" suggests old API compat layer
- `"AMFI: unable to get legacy context after adjustment without monitor: %u"` — monitor path is now primary
- `"Image4: failed to load local policy with code-signing-monitor: %u"` — Image4 policy uses monitor

**pmap changes:**
- Old: `%s: attempt to nest stage 2 pmap %p` → New: `%s: cannot create nested stage 2 pmap` (stronger, no addr leak)
- Old: `%s: attempt to nest unsupported pmap %p of type 0x%hhx` → removed entirely
- Old: `%s: failed pmap_enter_addr, pmap=%p, va=%#llx, pa=%llu, size=%u, prot=%#x, flags=%#x` → **removed** (pmap_enter path restructured)
- Old PVE format: `pve_p=%p` → New: `pvep=%p` (renamed field in PVE struct)
- `%s: unexpected pmap_enter_pv ret code: %d. new_pve_p=%p pmap=%p` → `...pmap=%p` (pve pointer removed from error msg)

**SPTM new strings:**
- `%s: insufficient number of ASIDs (%u) supplied by SPTM @%s:%d` — SPTM now owns ASID management
- `%s: sptm_page_is_sk_shared_realtime(%p, %p) failed @%s:%d` — new SPTM Secure Kernel page sharing call

**AMFI hash agility strings removed (27.0.1):**
- All `AMFI: '%s': V1/V2 hash agility` strings gone — hash agility validation path restructured
- `AMFI: '%s' does not pass CT evaluation` removed — CT (CoreTrust) check path changed
- `libsptm_init failed: %u` removed — init path restructured


## ✓ Checkpoint: 6. Security Strings — 14:06:38


## 7. `__TEXT_EXEC` Diff Statistics

- 26.6.1 `__TEXT_EXEC`: 45472K (44.4MB)
- 27.0.1 `__TEXT_EXEC`: 49120K (48.0MB)
- Size delta: +3648K

- Pages compared (4K): 11,368 (44MB overlap)
- Changed pages: **11,368** of 11,368 (100%)
- Unchanged pages: 0
- Total changed bytes: **44,552,127** (43507KB)

### Top 10 Contiguous Changed Regions

| Region | __TEXT_EXEC offset | Pages | Bytes | Nearby string |
|--------|--------------------|-------|-------|---------------|
| 0–11367 | +0x000000 | 11368 | 46,563,328 | — |

### 20 Most Surgical Changes (fewest changed bytes per page)

These pages show targeted patches — minimal byte changes.

| Page# | A offset | B offset | Bytes changed | Nearby string |
|-------|----------|----------|---------------|---------------|
| 10002 | 0x0398a000 | 0x03b42000 | 3553 | — |
| 11359 | 0x03ed7000 | 0x0408f000 | 3566 | — |
| 10001 | 0x03989000 | 0x03b41000 | 3574 | — |
| 11366 | 0x03ede000 | 0x04096000 | 3608 | — |
| 11365 | 0x03edd000 | 0x04095000 | 3628 | — |
| 11363 | 0x03edb000 | 0x04093000 | 3628 | — |
| 11367 | 0x03edf000 | 0x04097000 | 3641 | — |
| 11362 | 0x03eda000 | 0x04092000 | 3680 | — |
| 11364 | 0x03edc000 | 0x04094000 | 3687 | — |
| 10003 | 0x0398b000 | 0x03b43000 | 3734 | — |
| 6784 | 0x02cf8000 | 0x02eb0000 | 3738 | — |
| 8159 | 0x03257000 | 0x0340f000 | 3741 | — |
| 11358 | 0x03ed6000 | 0x0408e000 | 3744 | — |
| 11361 | 0x03ed9000 | 0x04091000 | 3764 | — |
| 1164 | 0x01704000 | 0x018bc000 | 3764 | — |
| 751 | 0x01567000 | 0x0171f000 | 3764 | — |
| 8189 | 0x03275000 | 0x0342d000 | 3766 | — |
| 4323 | 0x0235b000 | 0x02513000 | 3773 | — |
| 3954 | 0x021ea000 | 0x023a2000 | 3777 | — |
| 9961 | 0x03961000 | 0x03b19000 | 3777 | — |


## ✓ Checkpoint: 7. __TEXT_EXEC Diff — 14:06:53


## Key Takeaways (Full Report Summary)

### Architecture
- **Kernel build jumped 487 → 514** between iOS 26.6.1 and 27.0.1 (+27 minor versions)
- **__TEXT_EXEC** grew +3,648K (+3.6MB) — major code addition
- **__PPLTEXT absent in both (PPL fully removed before 26.6.1)**
- **__DATA_SPTM** +64K (240K → 304K) — SPTM data region grew

### SPTM / GXF Hardening
- **+23 GENTER call sites** in __TEXT_EXEC (150 → 173) — more kernel operations now go through SPTM
- **New `sptm_page_is_sk_shared_realtime`** — SPTM managing realtime page sharing for Secure Kernel
- **SPTM now manages ASIDs directly** (`insufficient number of ASIDs supplied by SPTM`)
- **12 new Image4 PPL-context strings** in 27.0.1 (`attempted to get X without PPL context`)
- **`libsptm_init` path restructured** (init string removed)

### Security Policy Changes
- **0 new security-relevant strings** vs 0 removed
- **1422 new kexts** in 27.0.1 (see § 5 for names); 1 removed
- **11,368/11,368 __TEXT_EXEC pages changed** (100%) — widespread code changes
- **43507KB of code bytes changed** in the overlapping TEXT_EXEC region

### `mach_make_memory_entry` / Trigon-Relevant
- **"Unsanitary input" validation string removed** from 27.0.1 — input path restructured
- **MIG dispatch index shifted** from `!N_` (26.6.1) to `!f_` (27.0.1) — many new MIG callouts added before it
- **For Trigon CVE-2023-32434**: diff iOS 16.1.1 vs 16.5.1 on iPhone14,5 (PPL era, pre-SPTM)
  to see the actual integer-overflow fix in `mach_make_memory_entry_internal`

### Kext Highlights
- Top changed kexts by size: see § 5 table
- Kernel + sandbox kext typically show highest churn between major iOS versions

## Troubles & Solutions (Steps 5–7)

**T-S1 — Both 70MB files in RAM simultaneously = OOM (exit 137)**
Initial script loaded both kernelcaches at once (69MB + 74MB = 143MB + Python overhead).
iOS killed the process. Solution: split into three separate scripts, each minimal in RAM:
- Step 5 reads only the first 256KB (load commands) from each file — never loads kext code
- Step 6 loads one file at a time, scans for strings, saves set to JSON temp file, del + gc.collect()
- Step 7 uses chunked seek-and-read (2048 pages = 8MB per chunk) instead of loading __TEXT_EXEC at once

**T-S2 — String scanning keyword as bytes vs str**
`data.find(kw)` fails if `kw` is a Python str and `data` is bytes.
Solution: ensure all keywords are `b'...'` byte literals before searching.

**T-S3 — Step 7 nearby-string search: whole file seek**
Opening and seeking the full 74MB file for each of 30 regions is slow but correct.
Solution: opened file once with `with open(KC_A) as fa:` and reused the handle across all seeks.


## ✓ Final Checkpoint — 14:07:06

