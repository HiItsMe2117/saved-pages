# iOS 26.6.1 Exploit Chain — CVE Research Notes
## Target: iPhone16+ on iOS 26.6.1

---

## STATUS: ALL CHAIN CVEs PRESENT ON TARGET

| CVE | Component | Type | Patched In | Present on 26.6.1 |
|-----|-----------|------|------------|-------------------|
| CVE-2026-65409 | Foundation | Type Confusion | 26.7 | YES |
| CVE-2026-65410 | AVEVideoEncoder (26.x) | OOB Write | 26.7 | YES |
| CVE-2026-84607 | AVEVideoEncoder | Race → Kernel Code Exec | 26.7 | YES |
| CVE-2026-84616 | AVEVideoEncoder | ? | 26.7 | YES |
| CVE-2026-112705 | AppleAVE2 (27.x) | OOB Write | 26.7.2 + 27.2 | YES |
| CVE-2026-112706 | CoreMedia/mediaplaybackd | FD Leak | 26.7.2 + 27.2 | YES |
| CVE-2026-28968 | Kernel | OOB Write | 26.7 + 27.0 | YES |
| CVE-2026-113912 | CoreAudio | OOB Access | 26.7 + 26.7.2 | YES |
| CVE-2026-86969 | CoreAudio | OOB Write | 26.7.2 | YES |
| CVE-2026-113907 | CoreAudio | Buffer Overflow | 26.7.2 | YES |

---

## CVE-2026-65409 — Foundation Type Confusion

- **Class:** CWE-843 (Type Confusion)
- **Credit:** Bruce Dang, Calif.io + Claude + Anthropic Research
- **Vector:** Malicious PDF → iMessage (0-click) or Signal (1-click)
- **Likely path:** Foundation NSKeyedUnarchiver / CFAttributedString / PDF renderer object graph decode
- **Primitive:** Arbitrary code execution within app sandbox
- **Fix:** "improved memory handling" — type check added to dispatch
- **Chain role:** Stage 1 — initial foothold in sandbox

---

## CVE-2026-112706 — CoreMedia / mediaplaybackd FD Leak

- **Credit:** Adriatik Raci, Rodolphe BRUNETTI (@eisw0lf) Lupus Nova, Chris Bailey
  (NOT Calif.io — they used it, didn't find it)
- **XPC service:** `com.apple.coremedia.mediaplaybackd.bytestream.xpc`
- **Flaw:** `create` message sends `CreationURL` with arbitrary `file://` path;
  `mediaplaybackd` opens it with its own elevated entitlements, no sandbox path check
- **Primitive:** Read FD for any path mediaplaybackd can open (media DBs, playlists, protected paths)
- **Not write:** Read + directory enum + existence oracle only
- **Public PoC:** MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak
- **Chain role:** Stage 2 — sandbox escape / filesystem access

---

## CVE-2026-112705 — AppleAVE2 OOB Write (iOS 27.x)
## CVE-2026-65410 — AVEVideoEncoder OOB Write (iOS 26.x equivalent)

- **CVE-2026-112705 credit:** Marco Schmitt, Andrey Chernykh, Josh Maine, Calif.io
- **CVE-2026-65410 credit:** Calif.io + Claude + Anthropic Research
- **Kext:** `com.apple.driver.AppleAVE2` (913.43.1 in iOS 27.0.1)
- **Trigger path:** VideoToolbox → VTCompressionSessionCreate → VTSessionSetProperty(kVTCompressionPropertyKey_NumberOfTemporalLayers, 16463) → first encode → videocodecd → kernel crash
- **Threshold:** NTL=16463 triggers, NTL=16462 safe
- **Panic fingerprint (iOS 27.0.1):** Kernel data abort, PC at `__TEXT_EXEC+0xDA78` = VA `0xfffffff0086c7ce8`, far=0x59, x19=0x1
- **Crash instruction:** `stp x0, x0, [x0]` — circular list initializer using a corrupted pointer (0x59) from OOB-overwritten adjacent object
- **Internal field:** `pInfo->sSessionCfg.sEnc.sAlgCfg.sGOP.iNumOfTemporalLayer`
- **Function:** `AVE_GOP_DecideNumOfTemporalLayer`
- **Type:** Fixed-offset constant fill OOB write (deterministic)
- **Fix (26.7):** ~22 integer-overflow guards added to buffer-size calculation functions
- **Public PoC:** MchinaMd57764/AVETemporalPoC-CVE-2026-112705 (DoS only), TequilaDash/AVETemporalPoC, Lak453/CVE-2026-112705-poc
- **Chain role:** Stage 3 — kernel privilege escalation (data-only MIE bypass)

### CVE-2026-84607 — AVEVideoEncoder Race Condition → Kernel Code Exec (VERY HIGH VALUE)

- **CVSS:** 7.8 HIGH (AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H)
- **Impact:** "A sandboxed app may be able to execute arbitrary code with kernel privileges"
- **Credit:** Ruslan Dautov
- **Public PoC:** Ping-2o/ios.CVE-2026-84616-84607
- **Fix:** Per-frame state-consistency check comparing client encoder type vs session stored type
- **Chain role:** Potential standalone kernel code exec (no need for data-only path)

---

## CVE-2026-28968 — Kernel OOB Write (iOS 26.x kernel privesc)

- **Credit:** Svetoslav Stolarov, Josh Maine Calif.io, genter0, Dun
- **Fix:** "improved bounds checking"
- **Chain role:** iOS 26.x kernel escalation (same slot as CVE-2026-112705 in iOS 27.x chain)

---

## CVE-2026-113912 — CoreAudio OOB Access *** DIRECTLY RELEVANT TO SURFACE C ***

- **Credit:** anonymous, 章鱼哥@aipy, Roman Zabicki, **Anna Groza (@pwnlambda) of Calif.io**
- **Patched:** 26.7 (updated 2026-10-26), 26.7.2
- **Trigger:** "Processing a maliciously crafted media file"
- **Fix:** "improved bounds checking"
- **SIGNIFICANCE:** Calif.io credit + CoreAudio + OOB access = may be the same or adjacent
  to the AURemoteIOServer ASBD integer overflow we are probing with Surface C.
  The "media file" trigger could be an audio session initialization with crafted ASBD params.
- **TODO:** Diff CoreAudio between 26.6.1 and 26.7 binaries to find exact change

---

## MIE / ARM MTE Deep Notes

- **Granule:** 16 bytes
- **Tag:** 4-bit, stored in pointer bits 59:56 (TBI)
- **Apple mode:** EMTE synchronous only (mismatch = immediate fault, no async race)
- **Allocators:** kalloc_type (kernel), xzone malloc (userland), libpas (WebKit)

**Data-only bypass (generalizes across all Calif chain bugs):**
1. Bug yields OOB write primitive (from integer overflow in bounds check)
2. Tags are correct for the SOURCE buffer — no tag mismatch during the write
3. Write lands in ADJACENT struct (ucred, task_t, proc_t, etc.)
4. Overwrite fields: cr_uid=0, sandbox bitmask clear, cs_flags patch
5. Result: root + sandbox disabled + code-signing off — NO POINTER FORGING

**MIE bypass path for our AVE2/Surface C bugs:**
```
overflow → undersized alloc → OOB write into adjacent heap obj
→ corrupt ucred/task fields (data, not pointers)
→ no tag mismatch → elevation complete
```

---

## SPTM / TXM Architecture Notes

- **SPTM at GL2** — only entity that can write page tables
- **TXM at GL0** — validates code signing, trust cache
- **XNU at EL1** — cannot touch page tables directly
- **Kernel r/w does NOT bypass:** page table modification, trust cache, code signing
- **Chollima suite:** kernel r/w achieved, SPTM bypass NOT achieved → rootless only
- **Only known public SPTM bypass:** "Rocket" — iOS 16.6-17.3.1 (PPL era), no public GL2 bypass on A15+

---

## ASBD Integer Overflow Math (Surface C Probe Target)

```
mBytesPerFrame = 0xFFF001
frames_per_buffer = 0x1000

alloc_size = (frames_per_buffer * mBytesPerFrame + 15) in 32-bit arithmetic
           = (0x1000 * 0xFFF001 + 15) & 0xFFFFFFFF
           = (0xFFF001000 + 15) & 0xFFFFFFFF
           = 0x0000100F

alloc_aligned = 0x100F rounded up to 16 = 0x1010? or to page = 0x1000
```

Actual audio stride would write ~16 GB → heap OOB write in AURemoteIOServer daemon.

**Probe confirmation:** Complex reply to Initialize with OOL[0].sz = 0x1000 = overflow confirmed.

---

## Exploit Chain on iOS 26.6.1

```
[0-click PDF via iMessage]
    ↓ CVE-2026-65409 (Foundation type confusion → sandbox code exec)
[Sandboxed code exec]
    ↓ CVE-2026-113912 (CoreAudio OOB) OR CVE-2026-112706 (mediaplaybackd fd leak)
[Sandbox escape / data access]
    ↓ CVE-2026-84607 (AVE race → kernel code exec) HIGH VALUE
    ↓   OR CVE-2026-28968 / CVE-2026-65410 (AVE OOB + data-only MIE bypass)
[Kernel r/w → root credentials]
    ↓ [SPTM wall — no public bypass]
[Root access, rootless jailbreak]
```

---

## Binary Analysis Status

### AVE2 (iOS 26.6.1 = 2.6MB, iOS 27.0.1 = 2.9MB — +328KB for overflow guards)

**26.6.1 key VAs:**
- `AVE_GOP_DecideNumOfTemporalLayer` string @ VA `0xfffffff0072afef0` (file `0x65e90`)
- Assertion string `(iNumOfTemporalLayer-1)<=7` @ VA `0xfffffff00729ef58` (file `0x54ef8`)
- Crash stub 2 (the crash target) @ `0xfffffff0084c9850`:
  ```
  cbz  x0, panic
  stp  x0, x0, [x0]   ← CRASH with x0=0x59
  str  x0, [x0, #0x10]
  str  wzr, [x0, #0x18]
  ret
  ```
- Primary GOP allocation function starts @ `0xfffffff0084c32c0`
- UMULL at `0x84c33c0`: `umull x1, w24, w8` (w8=0x30) — computes `NTL * 48` SAFELY (64-bit)
- UMULH overflow check at `0x84c319c`: RE-allocation path HAS overflow guard, sets poison `MIN_INT64`
- `kalloc_data` call (initial alloc) at `0x84c33cc` — `0xfffffff00ad7a148`
- `kalloc_data` call (re-alloc with guard) at `0x84c31c8` — `0xfffffff00ad7a160`
- Loop: initializes NTL elements at `alloc_ptr + i*0x30` via `0x84c9d04`

**Key insight:** UMULL at `0x84c33c0` is safe for NTL=16463 (result=790224 bytes). Bug is in a DIFFERENT size computation — likely in a secondary field calculation or a 32-bit multiply elsewhere that feeds the crash.

**27.0.1 crash sites (stp x0,x0,[x0]):** `0x86c7cc4`, `0x86c7ce8` (confirmed), `0x86c80050`, `0x86c8324`
**26.6.1 crash sites:** `0x84c9834`, `0x84c9858`, `0x84c9bac`, `0x84c9e6c`
**Mapping:** 27.0.1 crash `0x86c7ce8` (2nd) → 26.6.1 `0x84c9858` (2nd)

**Remaining to find:**
- [ ] Secondary multiplication that uses a 32-bit wrap (not UMULL) to produce undersized allocation
- [ ] WHY NTL=16463 triggers but 16462 doesn't — likely specific bitfield boundary
- [ ] Get 26.7 kernelcache diff (OTAs are AEA-encrypted; need full IPSW extraction)

### CoreAudio / AURemoteIOServer
- [ ] Need to pull binary from iPhone via ResearchHost
- [ ] Find IPCAUSharedMemoryBase::InitClient
- [ ] Compare pre/post 26.7 patch

### Foundation / CVE-2026-65409
- [ ] Analyze macOS proxy binary in DSC
- [ ] Find object type dispatch + PDF parsing path

### CoreMedia / CVE-2026-112706
- [ ] Find mediaplaybackd on Mac / iOS
- [ ] Find CreationURL handling code

---

## Useful References

- MchinaMd57764/AVETemporalPoC-CVE-2026-112705
- MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak
- Ping-2o/ios.CVE-2026-84616-84607
- 8ksec.io/mie-deep-dive-kernel
- 8ksec.io/darksword-kernel-escalation
- arxiv.org/html/2510.09272v1 (SPTM/TXM paper)
- tin-z.github.io/ios-exploit-starterpack/en/sptm-txm
