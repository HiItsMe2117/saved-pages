# Surface C — AURemoteIOServer ASBD Overflow: Final Analysis
**Date:** 2026-11-04  
**Target:** iPhone 16 Plus (iPhone17,4) · iOS 26.6.1 (23G83)  
**Binary:** AudioToolbox / libEmbeddedSystemAUs.dylib (from DeviceSupport symbols)

---

## 1. Vulnerability Mechanics (confirmed)

`IPCAUSharedMemoryBase::InitPhase1` at `AudioToolbox:0x1bc3395dc` does a 32-bit size calculation:

```asm
LDR W13, [X20, #0x58]      // W13 = numFrames (from IPCAUSharedMemoryBase struct)
LDR W11, [X11, #0x18]      // W11 = ASBD.mBytesPerFrame
MADD W11, W11, W13, W10    // W11 = mBytesPerFrame × numFrames + 15  ← 32-bit wrap!
AND  W11, W11, #0xFFFFFFF0 // align to 16 bytes
MUL  W11, W11, W12          // × mChannelsPerFrame
```

For NTL=2057 with numFrames=0x1000 (page-frame default):
- `mBytesPerFrame=0xFFF001 → (0x1000 × 0xFFF001 + 15) & 0xFFFFFFFF = 0x100F → aligned = 0x1000`
- Allocates 4 KB but strides at ~16 GB → classic heap OOB write in audiomxd

The server binary (AudioToolbox) contains **no** `MinimalSafetyCheck`.  
Confirmed: `nm AudioToolbox | grep MinimalSafety` → no output.

---

## 2. Client-Side Guard (`ausdk::ASBD::MinimalSafetyCheck`)

Located in `libEmbeddedSystemAUs.dylib` at **VA 0x23d508a2c** (CLIENT process only).

Exact disassembly of the threshold logic:
```asm
MOVZ W12, #16960           // W12 = 0x4240
MOVK W12, #0x000F, LSL#16  // W12 = 0x000F4240 = 1,000,000
LDR  W11, [X8, #0x18]      // W11 = ASBD.mBytesPerFrame
CMP  W11, W12
B.CS 0x23d508ac4            // if mBytesPerFrame ≥ 1,000,000 → FAIL (return false)
```

Additionally checked against 1,000,000:
- `ASBD.mBytesPerPacket`
- `ASBD.mFramesPerPacket`

Checked against 1,024:
- `ASBD.mChannelsPerFrame` (≤ 1,023 after SUB #1)
- `ASBD.mBitsPerChannel`

The `DispatchSetProperty` caller (`ausdk::AUBase::DispatchSetProperty` at `0x23d506730`) returns `kAudioUnitErr_FormatNotSupported (-10868)` on any false return.  
**Confirmed by test:** `AudioUnitSetProperty(bpf=0xFFF001)` → -10868.

---

## 3. The Blocking Gap

| Parameter | Attack need | SafetyCheck max | Result |
|---|---|---|---|
| mBytesPerFrame × 0x1000 overflow | ≥ 1,048,576 | ≤ 999,999 | **BLOCKED** |
| mBytesPerFrame × numFrames overflow (alt) | mBpF × nF ≥ 2³² | mBpF ≤ 999,999 | Needs nF ≥ 4,296 |

For the alternative (numFrames-based) approach:
- mBytesPerFrame = 999,999 passes MinimalSafetyCheck
- numFrames ≥ 4,296 needed (999,999 × 4,296 = 4,295,795,704 > 2³²)
- numFrames is passed as a direct parameter in the MIG Initialize message (0x157c3)
- BUT: reaching the Initialize handler requires a reply port in the MIG message

---

## 4. EXC_GUARD Blocker (Primary Defense)

AURemoteIOServer message path has **strict-reply port guards** on audiomxd's IPC space.

Exhaustive testing (all T-variants logged in AppGroup/Library/):

| Attempt | msgh_bits local port | Result |
|---|---|---|
| T0 | None (no local port) | kr=0, passes — but NO reply, no nc_hndl |
| T1 | MAKE_SEND_ONCE | EXC_GUARD port 0x2507 gen 7 |
| T3 | MAKE_SEND | EXC_GUARD |
| T5a | explicit null voucher | EXC_GUARD |
| T6a | T0→consume→reset→T1 | EXC_GUARD |
| T0×20 → T1 | pre-warm 20× then ONCE | EXC_GUARD (IPC counter never advanced) |

T0 (no reply port) always passes, confirming the server IS running and accepting messages.  
T0 never delivers a reply, so nc_hndl cannot be obtained.  
Conclusion: **any reply port right inserted into audiomxd's IPC space triggers the guard**.

This is `mach_msg_strict_reply` enforced at the kernel level (EXC_GUARD subcode MOD_REPLY). The guard fires before the message even reaches audiomxd's MIG handler.

---

## 5. MIG Initialize Handler Analysis

**Entry point:** `_AUIOServer_AURemoteIO_subsystem` table at `0x1f30a67c0`  
Entry size: 40 bytes; Initialize (msg 0x157c3 = index 3) stub VA: **0x1bc581c98**

The Initialize MIG stub checks:
- `msgh_size == 60` (exact check)
- NDR mig_vers == 1
- Payload: nc_hndl (4B) + numFramesIn (4B) + numFramesOut (4B) + ... ≤ 36B body

No ASBD in the Initialize message itself — the ASBD is set via SetProperty (0x157c5)
before Initialize is called. SetProperty goes through `ausdk::ASBD::MinimalSafetyCheck`.

There is a `CMP W9, #31; B.HI ...` check — this compares msgh_size (> 31 = valid).
No explicit cap on numFrames seen in the stub header checks.

---

## 6. Verdict: Surface C CLOSED on iOS 26.6.1

Two independent, enforced controls block every known path:

1. **EXC_GUARD (kernel-level)**: Strict-reply port guards on audiomxd IPC space.  
   Any attempt to obtain nc_hndl (required before Initialize) via raw MIG triggers EXC_GUARD.  
   The official API path uses `AudioUnitInitialize()` which calls SetProperty first (guarded by #2).

2. **MinimalSafetyCheck (client-side)**: Caps mBytesPerFrame at 999,999 < 1,048,576 (minimum overflow value with numFrames=0x1000). Numframes-based bypass still requires raw MIG (blocked by #1).

The vulnerability DOES exist in audiomxd's server code — the 32-bit MADD is unpatched — but it is architecturally unreachable from an un-entitlemented app context in iOS 26.6.1 without a separate EXC_GUARD bypass.

---

## 7. Potential Future Paths

If an independent EXC_GUARD bypass were found:
- **numFrames vector**: mBytesPerFrame=999,999 (passes check) + numFrames=4,296+ (no server-side cap seen) → `999,999 × 4,296 = 4,295,795,704` overflows to `828,408 bytes` → OOB stride of ~4 GB
- This path skips MinimalSafetyCheck entirely since numFrames is not an ASBD field

This is NOT exploitable without the EXC_GUARD bypass, which we do not have.

---

## 8. Next Surface

Pivot to **AVE2 DPB overflow** (see `REPORT_ave2_heap_grooming.md`):
- No EXC_GUARD: official VideoToolbox API (VTCompressionSession), no raw MIG
- No ASBD safety check: overflow is in AVE2 firmware NTL×DPB_unit calculation
- Confirmed unpatched in 26.6.1 (patch added in 27.0.1 per diff analysis)
- Heap groom PoC v4 written and partially validated
