# AURemoteIOServer: Integer Overflow in IPCAUSharedMemoryBase::InitClient

**Status:** CANDIDATE — disassembly confirmed, empirical probe PENDING  
**Severity:** Critical (heap OOB write in daemon with no sandbox)  
**Date:** 2026-11-01

---

## Summary

`IPCAUSharedMemoryBase::InitClient` in `libEmbeddedSystemAUs.dylib` computes a ring-buffer
allocation size using **32-bit arithmetic** on ASBD fields from the caller's Initialize message.
A crafted `mBytesPerFrame` value causes the multiply to wrap to a tiny result, producing an
undersized heap allocation while the daemon later writes audio data at full stride → heap OOB
write in the AURemoteIOServer daemon.

---

## Call Chain (server-side)

```
mach_msg(Initialize, msg_id=0x157c3)
  └─ __XInitialize (AudioToolbox, 0x1bc581648)
       └─ RemoteIOClient::ConnectToDevice(ASBD1, ASBD2)
            └─ AURemoteIO::ChangeHardwareFormats(ASBD1, ASBD2, ...) [libEmbeddedSystemAUs]
                 ├─ IPCAUSharedMemoryBase::InitClient(ASBD2, channels=1, frames=0x1000, &token)
                 │    [0x23d511de4 → 0x23d512730]
                 └─ IPCAUSharedMemoryBase::InitClient(ASBD1, channels=1, frames=0x1000, &token)
                      [0x23d511de4 → 0x23d512838]
```

**Both call sites hardcode `channels=1, frames=0x1000`.** ASBD pointer comes from our message.

---

## Overflow Mechanics

`IPCAUSharedMemoryBase::InitClient` (libEmbeddedSystemAUs, VA 0x23d512984):

```
# Store hardcoded frames into SharableMemoryBlock+0x58
str w23, [x19, #0x58]    ; x23 = arg frames = 0x1000 (hardcoded at call site)

# Size computation loop per element (ASBD fields copied into element at +0x18/+0x1c):
ldr w12, [x12, #0x18]    ; w12 = element+0x18 = ASBD.mBytesPerFrame   ← OUR FIELD
ldr w14, [x19, #0x58]    ; w14 = SharableMemoryBlock+0x58 = 0x1000
madd w12, w14, w12, w11  ; w12 = (0x1000 × mBytesPerFrame) + 15   ← 32-BIT OVERFLOW
and  w12, w12, #0xfffffff0
mul  w12, w12, w13        ; w12 × mChannelsPerFrame                ← SECOND WRAP
add  x8, x8, w12          ; x8 → ClientToken+0xc → SharableMemoryBlock::InitClient(token)
```

**No validation of `mBytesPerFrame` occurs before this computation.**
`ChangeHardwareFormats` passes `x23 = ASBD2` (from Initialize req[0x50]) directly as the ASBD arg.

---

## Proof of Overflow

| mBytesPerFrame | 0x1000 × mBPF + 15 | 32-bit result | aligned | × channels | allocation |
|---|---|---|---|---|---|
| 0x100001 | 0x100001000 + 15 | 0x100f | 0x1000 | 0x1000 | **4 KB** |
| 0xFFF001 | 0xFFF001000 + 15 | 0x100f | 0x1000 | 0x1000 | **4 KB** |
| 0x80001 | 0x80001000 + 15 | 0x100f | 0x1000 | 0x1000 | **4 KB** |
| 0x4 (normal PCM) | 0x4000 + 15 | 0x400f | 0x4000 | 0x4000 | 16 KB (correct) |

With `mBytesPerFrame = 0xFFF001` and `mChannelsPerFrame = 1`:
- Allocation = **0x1000 bytes** (4 KB)
- Actual audio data written per period = 0x1000 frames × 0xFFF001 bytes/frame ≈ **16 GB**
- Net: **heap OOB write with ~16 GB extent** in AURemoteIOServer

---

## Attack Parameters

Initialize message ASBD2 (at req[0x50]):
```
mSampleRate    = 44100.0
mFormatID      = 0x6C70636D  (lpcm — must reach ChangeHardwareFormats; try compressed too)
mFormatFlags   = 0x2c        (float, packed, little-endian — bit 5 NOT set = interleaved path)
mBytesPerPacket = 0xFFF001   (= mBytesPerFrame for 1 frame/packet)
mFramesPerPacket = 1
mBytesPerFrame  = 0xFFF001   ← CRAFTED (overflow trigger)
mChannelsPerFrame = 1
mBitsPerChannel = 32
```

Flag bit 5 (non-interleaved): if set, the computation uses `w13 = 1` instead of reading
`mChannelsPerFrame`. Leave bit 5 clear to use our `mChannelsPerFrame`.

---

## Probe Script

See `surface_c_probe_b_overflow.py` for the empirical probe.

Expected result on success:
- AURemoteIOServer crashes (SIGSEGV/malloc heap corruption) on Initialize or StartIO
- Or: Initialize succeeds with anomalous small OOL descriptors in reply
- Or: Server returns an error if `SharableMemoryBlock::InitClient` validates size > 0

---

## Files Referenced

- `libEmbeddedSystemAUs.dylib`: `IPCAUSharedMemoryBase::InitClient` at 0x23d512984
- `libEmbeddedSystemAUs.dylib`: `AURemoteIO::ChangeHardwareFormats` at 0x23d511de4
  - Call sites to `InitClient`: 0x23d512730 and 0x23d512838
- `AudioToolbox.framework`: `__XInitialize` at 0x1bc581648
- `surface_c_probe_a.py`: Stage A (NewClient → nc_hndl)
- `surface_c_probe_b_overflow.py`: Stage B overflow probe
