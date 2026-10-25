# Secure Kernel Binary: SK→SPTM GENTER Calls

*Generated 2026-10-25 | iOS 27.0.1*

---

## Summary

The SK binary is **not extractable as a standalone file from the IPSW**. SK is bootstrapped by SPTM during secure boot via a GENTER instruction at SPTM binary offset `0x9f90c`. The SK code lives in SPTM's sealed memory space, loaded and launched by SPTM itself.

Key finding: SPTM contains a bootstrap sequence that writes SK's initial execution state into system registers and then executes GENTER to start SK — SPTM is SK's parent process.

---

## IPSW Investigation

### Files searched

| Filename | Type | GENTER hits | Notes |
|---|---|---|---|
| `Firmware/sptm.t8140.release.im4p` | SPTM binary | **1** (bootstrap) | Parent that starts SK |
| `Firmware/txm.iphoneos.release.im4p` | TXM binary | 0 | Has GEXIT (0x00201440), not GENTER |
| `Firmware/ansf.t8140.release.im4p` | ANS NVMe firmware | 0 | AppleStorageFirmwareASP3 (coprocessor) |
| `Firmware/rans.t8140.release.im4p` | ANS NVMe variant | 0 | Same firmware, NFMT variant |
| `Firmware/image4/exclavecore_bundle.t8140.RELEASE.im4p` | ExclaveCore bundle | 3 | L4 hypercalls, not SPTM |
| Kernelcache `kc_27.0.1.macho` | MH_FILESET | 173 stubs | XNU->SPTM calls (already mapped) |

No standalone sk.*.im4p exists in the IPSW.

---

## ExclaveCore Bundle Analysis

The ExclaveCore bundle contains 4 ARM64 Mach-O binaries. Binary 2 (at bundle offset 0x72401b, 23MB) contains 3 GENTER calls, but these are **L4 microkernel hypercalls**, not SPTM dispatch calls:

- ExclaveCore is built on an **L4 microkernel** (liblibc_plat_cl4, L4_Type_*, L4_Ec_GetState)
- The GENTER instruction is repurposed as the L4 system call trap in this context
- No MOVZ/MOVK x16 pattern (SPTM dispatch encoding) precedes these GENTER calls
- ExclaveCore is a separate security domain from the SPTM/SK architecture

Key ExclaveCore strings: L4_Type_EVP_Hypercall, ExclavePlatform_exclavecore, [xrt] liblibc_plat_cl4_init

---

## TXM Binary

TXM (557KB, 0 GENTER calls) does not call SPTM via GENTER. It has one GXF-family opcode:

  0x61b84: 00201440  ; GEXIT -- TXM returns to GL1

TXM is called by SPTM and returns via GEXIT. The TXM->SPTM endpoint names in the SPTM
binary represent calls TXM makes through a trampoline or shared-memory protocol.

---

## SPTM Bootstrap GENTER -- SK Launch

The single GENTER in the SPTM binary reveals how SK is started:

  0x9f8e0: WFE                  ; CPU idle until SK ready
  0x9f8e4: MOVZ x1, #0x1
  0x9f8e8: MSR <sysreg>, x1     ; Write SK initial state to system register
  0x9f8ec: ADRP x1, ...
  0x9f8f0: ADD  x1, x1, #...
  0x9f8f4: MSR <sysreg>, x1     ; Write SK entry point
  0x9f8f8: ADRP x1, ...
  0x9f8fc: ADD  x1, x1, #...
  0x9f900: MSR <sysreg>, x1     ; Write SK stack pointer
  0x9f904: ISB                  ; Sync register writes
  0x9f908: ADD  x1, SP, #0      ; SK argument: SPTM stack frame
  0x9f90c: GENTER               ; Launch SK
  0x9f910: WFE                  ; Wait after SK launch

SPTM writes SK's entry point, stack pointer, and initial register state into system
registers, then executes GENTER to transfer execution to SK. SK's binary code is stored
within SPTM's sealed memory space and is not visible from the IPSW.

---

## Architecture: SK Within SPTM's Boot Chain

  Secure Boot
      SPTM loaded (sptm.t8140.release.im4p)
          SPTM bootstraps TXM
          SPTM bootstraps XNU
          SPTM bootstraps SK  <- SK lives inside SPTM's image
              SK calls back into SPTM via GENTER
                  SK_TO_SPTM_ENDPOINTID_RETYPE
                  SK_TO_SPTM_ENDPOINTID_PHYS_TO_TYPE
                  SK_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE

SPTM strings confirming SK embedding:
- [SK BOOTSTRAP PANIC]
- [SK HIB PANIC] SK panic during SPTM hibernation hook
- SK bootstrap complete.

---

## SK->SPTM Dispatch IDs: Theoretical Analysis

Since the SK binary is not extractable, dispatch IDs for SK->SPTM calls are derived from
SPTM endpoint names and the dispatch table architecture:

| Endpoint Name | Notes |
|---|---|
| SK_TO_SPTM_ENDPOINTID_RETYPE | Parallel to XNU table-9 retype |
| SK_TO_SPTM_ENDPOINTID_PHYS_TO_TYPE | Physical address->type query |
| SK_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE | SK registers its table during bootstrap |

From REPORT_SPTM.md: DISPATCH_TABLE_IDs include GEN3_DART_SK -- dedicated DART table for SK.

---

## Security Notes

1. SK is SPTM's protected child process. SK code lives in SPTM's sealed memory.
   An attacker cannot modify SK without first breaking SPTM.

2. REGISTER_DISPATCH_TABLE from SK is high-value. If SPTM's table validation has a
   type confusion bug, a forged dispatch table registration could be possible.
   This call is during boot but the registration window may have a race.

3. SK has a hibernation hook ([SK HIB PANIC] string). Race conditions between SK's
   hibernation hook and SPTM's SPTM_HIB_ENDPOINTID_IOFILTER_PROTECTED_WRITE
   are in a less-tested code path.

4. Next steps:
   - Search SPTM binary for GEN3_DART_SK table index to find SK dispatch table ID
   - Reverse the MSR writes at SPTM+0x9f908 to find SK's entry address within SPTM image
   - Map SPTM handler code for SK_TO_SPTM_ENDPOINTID_* endpoints

---

## Files on disk (NOT in git)
- ansf_27.0.1.bin -- ANS NVMe coprocessor firmware (4.97MB)
- rans_27.0.1.bin -- ANS NVMe NFMT variant (4.97MB)
- txm_27.0.1.bin -- TXM binary (544KB)
- exclave_27.0.1.im4p -- ExclaveCore bundle (32MB)
