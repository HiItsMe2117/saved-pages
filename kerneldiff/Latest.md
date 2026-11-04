# iOS Security Research — Latest State

*Last updated: 2026-11-01 | Target: iOS 26.6.1 (iPhone 16 Plus, iPhone17,4)*

---

## Goal

Full sandbox escape chain on own device (iOS 26.6.1), submitted to Apple Security Research.
Near-term visible milestone: inject seconds into the SpringBoard status bar clock.
Full chain target: reach `locationd` (location services daemon).

---

## Device / Environment

- iPhone 16 Plus (iPhone17,4) running iOS 26.6.1 (build 23G83)
- Research runs from PocketCode/tctiSH (Linux VM on-device)
- Native Python via `mcp__native_python__run_native_python` MCP — ctypes + Mach traps
- Each call costs ~3 MB; always thread-wrap blocking IPC calls with ≤3s timeout
- No `task_for_pid`, no process enumeration, no `IOServiceOpen` — sandbox blocks all three

---

## Kernel Diff Summary (26.6.1 vs 27.0.1)

Full analysis in `STATE.md` and the REPORT_*.md files.

Key: **26.6.1 is the exploit target**. 27.0.1 diffs reveal what's open.

| What changed in 27.0.1 | Implication for 26.6.1 |
|---|---|
| `vm_sanitize_telemetry.c` entirely removed — 30+ VM APIs lost soft-landing correction layer | **Gap open on 26.6.1**: bad inputs corrected+continued instead of panicking |
| `mach_make_memory_entry_64` "Unsanitary input" string removed | Soft-landing inputs accepted on 26.6.1 |
| GENTER: 150→173 stubs; table 0xe NEW (NVMe, 16 eps) | NVMe attack chain gated on kernel exec first |
| `sptm_page_is_sk_shared_realtime` new in 27.0.1 | SK realtime page sharing not hardened on 26.6.1 |

---

## Primitive Map

### Confirmed Working (user-space, sandboxed app)

| Primitive | Status | Notes |
|---|---|---|
| `mach_make_memory_entry_64` + `mach_vm_map` phantom alias | **CONFIRMED** | Two VAs share one physical page; write at VA1 visible at VA2. **Requires `MAP_MEM_VM_SHARE` flag (`permission \| 0x10000000`)** — without it, MMME64 creates a copy, not an alias. |
| Phantom alias via secondary re-export | **CONFIRMED** | Creating a named entry from a mapped view of a named entry also aliases. |
| Full OOB chain phantom aliasing | **DISPROVED (2026-11-01)** | The "Surface 4 OOB named entry" was confirmed kr=0 only — data reads conclusively show offset rounds to page boundary; no accessible OOB. Phantom alias works but does NOT cover OOB pages. |
| CFPreferences cross-domain write | **CONFIRMED** | Any app can write to any domain (e.g. `com.apple.springboard`). Requires respring to take effect. |
| Darwin `notify_post` | **CONFIRMED** | No restriction on name; no sandbox block. |
| IOHIDEventSystemClient connect (61 services) | **CONFIRMED** | `com.apple.iohideventsystem` reachable from sandbox. |
| vm_region scanning (own process) | **CONFIRMED** | Finds shared-rw pages; found UIKit heartbeat page in prior session. |

### Confirmed Blocked

- `task_for_pid` (any pid) — KERN_FAILURE
- `IOServiceOpen` on IOHIDDevice/IOHIDSystem — blocked
- Process enumeration (`proc_listpids`, `sysctl KERN_PROC`) — blocked
- `killall` / SIGTERM to SpringBoard — blocked

---

## Attack Surfaces

### Surface A — vm_sanitize gap (kernel exec path)

**Status:** EMPIRICALLY DISPROVED on iPhone 16 (16K pages) — 2026-11-01.

- `vm_sanitize_telemetry.c` removed from 27.0.1 → the correction layer present in 26.6.1
- **Static analysis suggested** an OOB via MMME64: offset=0x4001, size_in=0x3FFF on 2-page parent passes bounds check (0x4001+0x3FFF=0x8000≤parent_size), then vm_sanitize rounds size 0x3FFF→0x4000, giving a child that theoretically covers [parent+0x4001, parent+0x8001) — 1 byte OOB.

**EMPIRICAL RESULT (2026-11-01, direct data reads):**

vm_sanitize rounds **BOTH** offset (floor to 16K boundary) AND size (ceil to 16K boundary). It is NOT "size only" correction. Tested exhaustively:

| offset | size_in | Mapped from | data[0] | data[0x3FFF] | OOB? |
|--------|---------|-------------|---------|--------------|------|
| 0x4001 | 0x3FFF  | page 1      | 0xBB    | 0xBB         | **NO** — offset rounds to 0x4000 |
| 0x8001 | 0x3FFF  | page 2      | 0xCC    | 0xCC         | **NO** — offset rounds to 0x8000 |
| 0x1000 | 0x1001  | page 0      | 0xAA    | 0xAA         | **NO** — offset rounds to 0x0000 |
| Sub-page offsets (stacking chain × 8 iters) | — | page 0 always | 0xAA | 0xAA | **NO** — offsets never accumulate |

On 16K page devices, `trunc_page(0x4001) = 0x4000` (floor). vm_sanitize effectively does:
```
new_offset = trunc_page(old_offset)         // always page-aligned, loses sub-page bits
new_size   = round_page(old_size + (old_offset - new_offset))  // covers same end byte, rounded up
```
Net result: child always covers exactly [page_floor(offset), page_floor(offset)+new_size) — always within the parent's page boundaries when bounds check passes.

**"Stacking amplification" also disproved:** Each MMME64 call with sub-page offset (e.g. 0x1000) independently rounds to 0x0000. After 8 stacking iterations with offset=0x1000 each, all children still map to page 0 of the original allocation. Offsets do NOT accumulate byte-by-byte.

**Confirmed primitives that still work:**
- MMME64 with any valid page-aligned offset → kr=0 ✓ (expected behavior)
- sz_out always rounds to 16K ✓
- mach_vm_map of child_ne → kr=0 ✓
- MAP_MEM_VM_SHARE alias (phantom alias) ✓

**Root cause of static analysis error:** The XNU diff showed size correction (`0x3FFF → 0x4000`) but the analyst assumed offset was kept exact. On 16K page hardware, offset ALSO gets corrected (floor to page boundary), consuming the sub-page delta and preventing any accessible OOB.

**This surface is CLOSED on 16K page devices.** Might apply on macOS/4K-page targets.

**Next candidate for vm_sanitize gaps:** Surface 5 (offset+size wrap-around) — call site in TEXT_EXEC at foff=0x3707668. Needs separate investigation.

---

### Surface B — backboardd IODataQueue substitution (sandbox escape)

**Status:** Partially probed this session. Blocked on `io_hideventsystem_open` MIG signature.

**Attack plan (from REPORT_XPC_NAMEDENTRY.md):**
1. Write forged IODataQueue headers (`head`, `tail`, `dataSize`) into a local buffer
2. Wrap buffer in a named entry port (`ne`) via `mach_make_memory_entry_64`
3. Send `ne` to backboardd as the queue backing during session open
4. backboardd maps `ne`, interprets forged headers → OOB write in backboardd's process
5. From backboardd: pivot to SpringBoard (has `task_for_pid-allow` entitlement)

**What we know from this session:**
- `com.apple.iohideventsystem` reachable via bootstrap_look_up ✓
- Service port: `0x1bdf3`
- `io_hideventsystem_open` VA: `0x1b79deda4`
- Calling with (svc, 0, &conn) or (svc, 0, ne_port, &conn) or (svc, 0, buf_va, size, &conn) all return `0x1000000c` = **MACH_SEND_INVALID_MEMORY**
- Message is COMPLEX (`msgh_bits = 0x80001513`): MACH_MSGH_BITS_COMPLEX | COPY_SEND | MAKE_SEND_ONCE
- Send size: 104 bytes, receive size: 108 bytes
- IODataQueue pages don't appear as `shared=True` in vm_region after ScheduleWithRunLoop (may use IOSurface or different mechanism)

**UPDATE (2026-10-29 — session interrupted mid-probe, captured from screenshot):**

`io_hideventsystem_open` does NOT need to be called directly. `IOHIDEventSystemClientCreate` (type=Monitor=1) + `IOHIDEventSystemClientScheduleWithRunLoop` triggers it internally via ObjC dispatch. This unblocks the attack — no MIG layout needed.

**Findings from interrupted probe:**
- `IOHIDEventSystemClientCreate` works from sandbox, memory cost ~2.7 MB
- After activation (ScheduleWithRunLoop + CFRunLoopRunInMode 2s), two port candidates in struct:
  - `+0x20 = 0x209e3` — **connection port** (large port name → allocated after open, likely MIG conn)
  - `+0x30 = 0x291`  — **service port** (small → allocated early via bootstrap_look_up)
- Memory cost for activation: ~8.1 MB (higher than expected; plan for 10 MB budget per probe)

**Ian Beer direction — DEAD (probed 2026-10-29):**
- Scanned 2048 bytes of IOHIDEventSystemClientRef struct before/after activation
- Only 1 SEND right found at `+0x020`; value and count unchanged by activation
- `mach_vm_map` on that port → `kr=0x1d = KERN_INVALID_RIGHT` — plain service send right, not a named entry
- backboardd does NOT hand the client a named entry for the DataQueue on iOS 26.6.1

**Forward injection — stub fully decoded (2026-10-30):**

ARM64 stub at 0x1ae26ada4 mapped in-process via ctypes byte-reads:

| Field | Value | How set |
|---|---|---|
| msgh_bits | 0x80131513 (COMPLEX + COPY_SEND + MAKE_SEND_ONCE + voucher_COPY_SEND) | +132–140 (MOVZ/MOVK/STR) + fn_172 (voucher) |
| msgh_remote_port | server port (x19) | +128 STNP |
| msgh_local_port | reply port from mach_reply_port() | +128 STNP |
| msgh_voucher_port | 0x1d03 (mach voucher) | fn_172 at stub+172 (0x1b0febbb0) |
| msgh_id | **unknown** — not set by any decoded instruction | see below |
| descriptor_count | 4 | +56 MOVZ w8,4 → +60 STP |

Key arg-to-descriptor mapping:
- **x3** → `STUR x3, [sp+0x2c]` → msg+0x28 (8 bytes! = 64-bit pointer → **OOL descriptor address candidate**)
- **x5** → `STUR x5, [sp+0x3c]` → msg+0x38 (8 bytes! = second OOL pointer candidate)
- x7 → `STR w7, [sp+0x4c]` → msg+0x48 (32-bit inline data)
- x6 → `STR w6, [sp+0x68]` → msg+0x64 (32-bit inline data, last field)

**x3/x5 are struct pointers, not raw OOL addresses (confirmed by crash, 2026-10-30):**
Calling the stub with x3=0 (NULL) **crashes the process** (SIGBUS/SIGSEGV) — not MACH_SEND_INVALID_MEMORY. The stub dereferences x3 in-process before the message reaches the kernel. x3 points to a struct; the OOL buffer address lives INSIDE that struct. x5 likely the same.
- Earlier calls returned MACH_SEND_INVALID_MEMORY only when x3 happened to be a non-zero value from the Python interpreter's register state (garbage from 3-4 arg CFUNCTYPE calls)
- Baseline (all zeros, explicit 8-arg call) → crash

**fn_172 = voucher setup** (confirmed by probe): when called with zeroed buffer, writes:
- msg+0x00 |= 0x00130000 (OR in voucher COPY_SEND disposition)
- msg+0x10 = 0x1d03 (msgh_voucher_port = allocated mach_voucher)

**msgh_id is unknown.** Not set by fn_124 (= mach_reply_port()) or fn_172. Must be in the undecoded STP instructions in the stub (+76 ORR/+80/+88 STP cluster). CMP at stub+272 checks reply_id == 71 → request_id = 71 (if reply = request, non-standard) or -29 (if reply = request+100, impossible). Empirical send will resolve this.

**fn_124 identity (2026-10-30 probe):** VA 0x1b0feb3e0 = GOT stub (ADRP x16 / ADD x16, x16, #offset / BR x16 / BRK #1) — 16-byte stub format, three consecutive stubs at that address. The stub does NOT dereference any argument registers. It just looks up the target function from the GOT and branches. fn_124 is NOT the crash source.

**Why the crash happens:** Unknown — fn_124 doesn't dereference x3, and fn_172 worked fine in isolation. The crash likely comes from the target function fn_124 jumps to (which we haven't read) OR from the mach_msg call with malformed descriptors. The BL at +124 → GOT stub → real function: that real function might dereference x3/x5. **Mac terminal tool not available this session (MCP disconnected)** — can't jtool2 to find the real function target.

**msgh_id = 71** is confirmed by CMP at stub+272 (checks reply_id == 71; request_id = reply_id for this MIG family).

**Direct mach_msg to `com.apple.iohideventsystem` → CRASH (2026-10-30):** Even a simple 28-byte non-complex message with msgh_id=71 terminates the process. The service enforces termination on unauthorized senders. Only the ObjC library path (ScheduleWithRunLoop) is usable.

**Post-activation struct scan (2026-10-30 deep probe):**

Three 'MUTX'-magic ObjC objects appear after activation:
- `struct+0x0040` → heap ptr (not page-aligned), `'MUTX'` at offset 16, capacity=8360 at offset 28
- `struct+0x0120` → heap ptr (not page-aligned), `'MUTX'` at offset 16, capacity=8360 at offset 28
- **`struct+0x0180` → page-aligned heap ptr, `'MUTX'` at offset 16, capacity=8360 at offset 28**

Deep read of the page-aligned MUTX object (512 bytes):
- isa at +0x00 (class = IOHIDQueueClient or similar)
- `'MUTX'` magic at offsets 0x10, 0x24, 0x48, 0x4c — four embedded `OS_unfair_lock` sites
- capacity = 8360 (0x20A8) at offset 0x1C
- 0xFFFFFFFF sentinel pair at offsets 0x38-0x3F
- PAC-signed kernel pointer at offset 0x40 (= 0xFFFFFFFEF8187FEF) — backboardd-side object, not directly usable
- Inner pointer at offset 0x150 = 0x101000000 → confirmed to be ARM64 executable code (NOT queue data)
- Bytes 0x60-0x14F: entirely zeroed

**Key open question:** The raw IODataQueue memory (head=0, tail=0, entries[]) was NOT found as a heap pointer in the struct scan. The queue backing is likely associated with a Mach named-entry port in our task namespace.

**Probe results (2026-10-30 — this session):**

Port scan approach (type-based):
- Scanned for IKOT_NAMED_ENTRY with type=0x1A → 0 results (wrong constant)
- Scanned for type=0x1C → 1 new port (`0x293fb` in run 1, `0x29603` in run 2)
- Run 1 (from screenshot, previous Claude instance): port `0x293fb` mach_vm_map **SUCCESS**, layout `{queueSize=0x8000, head=0x0, tail=0x0, reserved=0x0}` — **IOSharedDataQueue confirmed**. Forge was in progress when user interrupted.
- Run 2 (current): port `0x29603` (same type 0x1C) mach_vm_map **FAILED** kr=4 (KERN_INVALID_RIGHT). Cause unclear — may be protection mismatch or right type (send-once vs send).
- After 5+ activation calls the MCP Python process became unresponsive (memory at ~1700 MB).

**IKOT type 0x1C on iOS 26.6.1 is the queue named entry type** (not 0x1A). Classic XNU constant shifted by 1 or more — does not match older header values.

**IOSharedDataQueue header layout (from successful map):**
- +0: `queueSize` (u32) = 0x8000 = 32768 bytes
- +4: `head` (u32) = 0 (consumer position)
- +8: `tail` (u32) = 0 (producer position)
- +12: `reserved` (u32) = 0
- This is IOSharedDataQueue (NOT classic IODataQueue — different header order)

**CLOSED — queue is IOCircularDataQueue, not IODataQueue (confirmed 2026-10-30 via Mac terminal + otool on device IOKit binary):**

The IOKit binary from device symbols (`iPhone17,4 26.6.1 (23G83)/Symbols/.../IOKit`) shows:
- `IOHIDEventSystemClientScheduleWithRunLoop` calls `IOCircularDataQueueCreateWithConnection`
- `CreateWithConnection` calls `_io_connect_map_shared_memory("IOCircularQueueDescription")` — kernel creates the shared memory and maps it into our address space; we do NOT provide the queue backing
- `Enqueue` bounds check: `shared_mem + index * slot_stride + 0x20 < shared_mem + queue_handle[0x20]` — uses backboardd's LOCAL field, NOT a value from shared memory → forge of write_head does not bypass the check
- PAC-authenticated shared memory pointer at `queue_handle + 0x10` (key `0xaa79`)
- Atomic CAS (`caspal`) on `shared_mem[0x10:0x18]` for thread safety

**Port scan findings explained:** Queue mapped via `io_connect_map_shared_memory`, not a named entry port in our namespace. All 6 new ports after activation returned errors because none are named-entry memory objects.

**Residual primitive:** TOCTOU on reader side — after backboardd writes entry, `[entry+0x08]` holds `(slot_index | entry_size)` — we can race to inflate `entry_size` before `GetNext` memcpy → OOB read in our own process = ASLR bypass (info-leak), not code exec in backboardd.

**Surface B is effectively closed for the direct backboardd crash path.** Pivot to Surface C (audiohald XPC) which still allows us to provide our own memory.

---

### Surface C — AURemoteIOServer MIG shmem substitution (HIGH)

**Status: CLOSED — 2026-11-04. See `REPORT_surface_c_final.md` for full details.**

Two independent, enforced controls block every known path on iOS 26.6.1:
1. **EXC_GUARD (kernel-level)**: Strict-reply port guards on audiomxd. ANY reply port in a raw MIG message → `EXC_GUARD` on port 0x2507. Exhaustively tested across all T-variants (T0–T6a, T0×20). T0 (no reply) passes but delivers no nc_hndl.
2. **MinimalSafetyCheck (client-side, `ausdk::ASBD::MinimalSafetyCheck` at libEmbeddedSystemAUs.dylib:0x23d508a2c)**: Caps `mBytesPerFrame` at 999,999. Minimum overflow value is 1,048,576 (for the `mBytesPerFrame × 0x1000 + 15` server-side MADD). Gap: 1,048,576 > 999,999 → all overflow ASBDs rejected before reaching audiomxd.

The server IS unpatched (no overflow check in `IPCAUSharedMemoryBase::InitPhase1`), but it is architecturally unreachable. A potential numFrames-based bypass (mBytesPerFrame=999,999 + numFrames≥4,296 → product overflows 32-bit) exists but also requires a reply port (EXC_GUARD).

**PIVOT to CPU-side kernel overflow surfaces (AVE2 also CLOSED — DART blocks DPB OOB write, confirmed empirically 2026-11-04).**

**CRITICAL CORRECTION (2026-11-01):** `com.apple.audio.AURemoteIOServer` uses **raw Mach messages via MIG** — not XPC, not NSXPCConnection. Our previous probe script (`xpc_connection_create_mach_service` + `xpc_dictionary`) was aimed at the wrong protocol and cannot work.

**Do NOT confuse with `com.apple.audio.AUHostingService.arm64e`** — that IS an NSXPCConnection service (protocol `AUHostingServiceProtocol`, class `AURemoteHost`) used for third-party Audio Unit plugin hosting. Completely separate from RemoteIO.

**Correct architecture (from `AudioToolbox.framework` iOS 26.6.1 device symbols, Mac terminal analysis):**

- Service: `com.apple.audio.AURemoteIOServer` — raw Mach port, MIG interface
- MIG subsystem: `_AUIOServer_AURemoteIO_subsystem` at `0x1f30a67c0` (in AudioToolbox binary)
- Server dispatcher: `_AURemoteIO_server` / `_AURemoteIO_server_routine`
- Entry size: 0x28 bytes per routine in dispatch table
- Bounds check: 16 valid message IDs (CMN/B.HS pattern in server_routine)

**Full MIG routine list (from `strings` + `nm` on AudioToolbox):**
| Routine | Notes |
|---|---|
| `AUIOServer_NewClient` | Establish session, get personality handle |
| `AUIOServer_Initialize` | Trigger `DoPrepareSharedBuffer` → shared audio memory setup |
| `AUIOServer_SetProperty` | Set audio property (potentially accepts memory token) |
| `AUIOServer_GetProperty` | Read property |
| `AUIOServer_GetPropertyInfo` | Property metadata |
| `AUIOServer_StartIO` | Begin audio I/O |
| `AUIOServer_StopIO` | Stop I/O (sync) |
| `AUIOServer_StopIOAsync` | Stop I/O (async) |
| `AUIOServer_BypassIO` | Bypass audio processing |
| `AUIOServer_Cleanup` | Cleanup session resources |
| `AUIOServer_DisposeClient` | Remove client |
| `AUIOServer_DisposeInstance` | Remove instance |
| `AUIOServer_FormatChangeAcknowledge` | Ack format change notification |
| `AUIOServer_GetCurrentFormats` | Query active stream formats |
| `AUIOServer_GetServerPID` | Get server's PID |
| `AUIOServer_GetWorkgroupPort` | Get workgroup Mach port |
| `AUIOServer_NeedToReinitialize` | Query if re-init needed |

**Shared memory architecture (PULL model from SERVER → CLIENT):**
- `RemoteIOClient::IONodeClient::DoPrepareSharedBuffer()` is called at client side during Initialize
- It calls `IPCAUSharedMemoryBase::InitServer(ASBD*, channels=1, maxFrames=0x1000, SharableMemoryBlock::ServerToken&)`
- `InitServer` allocates the audio ring buffer and exports it as a Mach memory entry → `ServerToken`
- The `ServerToken` (Mach memory entry port) is sent to AURemoteIOServer via the MIG reply
- AURemoteIOServer calls `IPCAUSharedMemoryBase::InitClient(ASBD*, channels, frames, SharableMemoryBlock::ClientToken&)` to map it
- Result: both sides share one physical page for lockless ring-buffer audio I/O

**Attack plan (corrected for MIG):**
1. Surface 4 OOB → shadow named entry `ne` (already confirmed working: `ne=107811` from Stage 1 probe)
2. Send `AUIOServer_NewClient` MIG message to service port → receive session handle
3. Send `AUIOServer_Initialize` MIG message with our shadow `ne` as the `ServerToken` in the body
4. AURemoteIOServer calls `InitClient` on our `ne` → maps our shadow page as its audio ring buffer
5. Write forged ring buffer cursors to `q[0x3000]` → AURemoteIOServer reads OOB

**MIG message IDs (CONFIRMED from `_AURemoteIO_server_routine` at 0x1bc581f44 + client-side stubs):**
- `NewClient`  = **0x157c1** (COMPLEX request, size=0x3c; non-complex reply, size=0x28)
- `Initialize` = **0x157c3** (non-complex request, size=0x78; COMPLEX reply on success, size=0xa4, 3 OOL)
- Server bounds check: accepts msg_id ∈ [0x157c0, 0x157cf] (16 slots, stride 0x28)
- Reply msg_id = request_msg_id + 0x64

**`__XNewClient` argument extraction (confirmed from disasm at 0x1bc581d8c):**
- Validates: COMPLEX bit set, size==0x3c, descriptor_count==1
- Validates: descriptor type==0 (PORT), disposition==17 (MOVE_SEND)
  - Checked as `ldrh [req+0x26] << 16 == 0x110000` (disposition=0x11, type=0x00)
- Validates: `req[0x3c]`=audit_trailer.type==0 (kernel appends automatically)
- Validates: `req[0x40]`=audit_trailer.size > 0x1f (audit trailer = 40 bytes ✓)
- Args to `_AUIOServer_NewClient(audit_token_ptr, ne_port, w2, w3, w4, &reply_handle)`:
  - x0 = sp = pointer to audit_token (32 bytes from trailer at req[0x50..0x6f])
  - **x1 = req[0x1c] = descriptor.name = our shadow ne** (2nd arg, stored at sp+0x20)
  - x2 = req[0x30] (w2, inline arg)
  - x3 = req[0x34] (w3 = client_type; 5=tap needs entitlement, 0=standard)
  - x4 = req[0x38] (w4, inline arg → passed to `AQMESession` as uint, NOT our port)
  - x5 = reply+0x24 (output ptr for session_handle)
- Bytes req[0x28..0x2f] (8 bytes) are NOT read — padding
- On success: reply.msgh_size = 0x28, ret_code at reply[0x20], session_handle at reply[0x24]

**`__XInitialize` argument extraction (confirmed from disasm at 0x1bc581680):**
- Validates: NOT complex (bit 31 must be clear), size==0x78
- Validates: audit_trailer.type==0, trailer_size>0x1f (same as NewClient)
- Args: w23=req[0x20] (= session_handle from NewClient), w25=req[0x24], ASBD1 at req[0x28], ASBD2 at req[0x50]
- On SUCCESS: reply is COMPLEX, msgh_size=0xa4=164, descriptor_count=3
  - Three 16-byte OOL descriptors (64-bit format: addr(8)+flags(4)+size(4)) at reply[0x1c..0x4b]
  - Each: deallocate=1, copy=PHYSICAL_COPY=1, type=MACH_MSG_OOL_DESCRIPTOR=1
  - Kernel fills descriptor.address in-place with OUR task's mapped VA on receive
  - OOL[0].size = RemoteIOClient+0x368 (audio ring buffer size)

**CORRECTED ATTACK MODEL (2026-11-01 static analysis — deep disassembly):**

Our shadow ne is stored at `IONodeClient+0xc` and is a **control/notification channel** back to our
process (server sends us hardware-format-change notifications there). It is **NOT** mapped as the
ring buffer. Full disassembly trace confirms:

1. `_AUIOServer_NewClient` stores our ne at `[IONodeClient+0xc]` then calls `IONodeClientC2()`
2. `IONodeClientC2` ← `AQIONodeClientC2`: NO write to `[this+0xc]`; ne survives intact
3. `__XInitialize` → `ConnectToDevice` → `DoPrepareSharedBuffer`:
   - Calls `IPCAUSharedMemoryBase::InitServer(ASBD, channels=1, maxFrames=0x1000, &ServerToken)`
   - This creates a **new** allocation, stores token at `IONodeClient+0x118`
   - Our ne is NEVER passed to `InitServer`
4. Reply sends 3 OOL regions from the fresh ring buffer (server's memory, not ours)
5. `SharableMemoryBlock::InitClient` at `IONodeClient+0x190` maps the server's OOL regions

**IONodeClient+0xc role:** control port to our process. Server uses it to notify us of format changes,
hardware resets, etc. No ring buffer mapping occurs through it.

**NEW ATTACK ANGLE — ASBD integer overflow in `IPCAUSharedMemoryBase::InitClient`:**

`IPCAUSharedMemoryBase::InitClient` (libEmbeddedSystemAUs, 0x23d512984) computes buffer sizes from
ASBD fields using **32-bit arithmetic**:
```
madd w12, w14, w12, w11  ; (num_frames * bytesPerFrame) + 15  — 32-bit, can wrap!
and  w12, w12, #0xfffffff0
mul  w12, w12, w13        ; × numChannels                      — 32-bit, second wrap!
add  x8, x8, x12          ; accumulate → passed to realloc()
```
If our ASBD's `mSamplesPerPacket`/`mBytesPerFrame`/`mBytesPerPacket` fields yield large enough
values at the Initialize → `ChangeHardwareFormats` → `InitClient` path, a 32-bit overflow could
produce a small `x8` while the actual write window is large → heap OOB write in AURemoteIOServer.

`ChangeHardwareFormats` (0x23d511de4) stores our ASBD's sampleRate at `AURemoteIO+0x2d8/0x2e0`,
then retrieves AUScope elements and propagates ASBD fields into the `InitClient` computation.
Next investigation: trace exactly which ASBD fields reach `w12/w14/w13` in `InitClient`.

**ROOT CAUSE OF HANG/CRASH (found 2026-11-01, static analysis):**

`req[0x38]` (w28 = "session personality" arg to `AQMESession`) must be **non-zero**:
```
_AUIOServer_NewClient (0x1bc343718):  cbz w28, 0x1bc3439a8   # "!ses" = unspecified session
```
When w28=0:
- Server sets error code 0x21736573 (`"!ses"`) but does NOT update `reply[0x4]` (msgh_size)
- `_AURemoteIO_server` pre-initializes reply[0x4]=0x24 (36 bytes) before calling `__XNewClient`
- `__XNewClient` only sets reply[0x4]=0x28 on SUCCESS; error path skips it
- Reply IS sent (36 bytes), but contains error — caller sees ret≠0 and bails OR server startup OOM
- a-Shell crash was OOM: server launches fresh, consumes RAM, pushes us over iOS limit at ~1402 MB baseline

**Fix applied (2026-11-01, `surface_c_probe_a.py`):**
- `req[0x34]=0` (client_type=standard, no entitlement needed)
- `req[0x38]=1` (session_id=1, any non-zero → passes cbz, creates AQMESession)
- `mach_msg` options: `0x103` (SEND|RCV|TIMEOUT), timeout=5000ms (was 0 = infinite)

**What happens with non-zero session_id (traced from disasm):**
1. `AQMESession(personality=1, pid=caller_pid)` created at sp+0x90 ← server-side session
2. `operator new(0x578)` allocates IONodeClient object at x25
3. `ne_port` (our shadow ne) → stored at `IONodeClient[0xc]`
4. `AT::SessionFacade::global()` vtable[0x108] → registers session
5. Returns session_handle in reply[0x24]

**Probe scripts:** `surface_c_probe_a.py` + `surface_c_probe_b.py` (two-stage, split for memory).
Stage A: shadow ne + NewClient → nc_hndl. Stage B: Initialize with nc_hndl → parse OOL descriptors.

**Device probe (service accessible, confirmed earlier session):**
- `com.apple.audio.AURemoteIOServer`: `bootstrap_look_up` kr=0x0 ✓
- `com.apple.audio.SystemSoundServer-iOS`: kr=0x0 ✓ (backup target)

**Backup target if AURemoteIOServer is too hardened:**
`com.apple.audio.SystemSoundServer-iOS` — also kr=0x0, likely simpler protocol

---

### Surface D — SpringBoard status bar seconds (clock demo)

**Status:** CFPreferences approach was WRONG. Real mechanism found via SecondHand source (LeminLimez, GitHub).

**How it actually works:**
SpringBoard uses a private UIKit class `UIStatusBarServer` with a `StatusBarOverrideData` struct. To show seconds, you override the `timeString` field (e.g. `"9:41:22"`) and post it:

```objc
StatusBarOverrideData *overrides = [UIStatusBarServer getStatusBarOverrideData];
overrides->overrideTimeString = 1;
strcpy(overrides->values.timeString, "9:41:22");  // format with seconds
[UIStatusBarServer postStatusBarOverrideData:overrides];
[UIStatusBarServer permanentizeStatusBarOverrideData];
```

There is NO CFPreferences key for this. The `UIStatusBarShowingClockSeconds` key we wrote is irrelevant.

**Two paths in SecondHand:**
1. **TrollStore path** (elevated entitlements): calls `UIStatusBarServer` directly — affects system-wide status bar
2. **MacDirtyCow path**: writes `StatusBarOverrideData` struct to `/var/mobile/Library/SpringBoard/statusBarOverridesEditing` — SpringBoard reads it on refresh

**Why we can't do it yet from sandbox:**
`UIStatusBarServer postStatusBarOverrideData:` from a sandboxed app only affects our own in-app status bar. To affect the system-wide bar we need either:
- TrollStore entitlements (requires privileged install), OR
- Privileged write to `/var/mobile/Library/SpringBoard/statusBarOverridesEditing`

**This is exactly what the sandbox escape chain is for.** Once we execute code in SpringBoard's context (via backboardd pivot), calling `[UIStatusBarServer postStatusBarOverrideData:]` there affects the global status bar — that's the seconds demo milestone.

**Struct layout (iOS 16.x, may differ on 26.x — verify offsets before use):**
- `timeString` field: char[64] at a fixed offset in `StatusBarRawData`
- `overrideTimeString`: 1-bit flag in `StatusBarOverrideData`
- Full struct in SecondHand: `SecondHand/StatusMagic/iOS16_1/StatusSetter16_1.m`

---

### Surface E — AVE2 32-bit DPB buffer-size overflow (CLOSED — DART blocks write)

**Status:** Definitively closed 2026-11-04. DART IOMMU blocks the OOB write. IPC path RE confirms no kernel VA misuse path. Full kext analysis complete.

**Root cause (26.6.1, `AppleAVE2` kext, offset ~0x28a000–0x28d000 in kernelcache):**

`DPB buffer size = DPB_unit × NTL` computed in **32-bit arithmetic** in firmware. At 4K HEVC:
- `DPB_unit = CTU_W × CTU_H × 1024 = 60 × 34 × 1024 = 2,088,960 bytes`
- Overflow threshold: **NTL ≥ 2057** (not 2056; `floor(2^32 / 2,088,960) = 2056`, which is the last safe value)
- NTL=2057: `2057 × 2,088,960 = 4,296,990,720 → truncates to 2,023,424 bytes (~2 MB) in 32-bit`
- Firmware then allocates the ~2 MB wrapped size, but writes reference frames as if the buffer were ~4.3 GB → **OOB write**

**DPB is kernel-visible — CONFIRMED by static analysis:**

Strings in `kc_26.6.1.macho` AVE kext region (0x28b382, 0x28b3ef):
- `pcaLFSResult[%d].IOSurfaceBuffer == NULL` — DPB low-resolution surfaces use `IOSurface`
- `pcaLRSResult[%d].IOSurfaceBuffer == NULL` — low-res RC surfaces also IOSurface
- `pcaRecon[AVE_RVRA_Org][layerIdx][k]` — reconstruction frames indexed by layer+frame

`IOSurface` is kernel-managed shared memory (not firmware-private). Kernel VA tracked alongside firmware DART mapping — confirmed by FwLog template at 0x28ac1b:
```
FwLog %p %d | Phy 0x%lx Kernel 0x%lx DART 0x%llx | %d %d %d | %d %d
```
The OOB write exits the 2 MB wrapped allocation and **corrupts kernel-visible IOSurface memory**.

**Bounds checks on ref-frame COUNT do NOT cover buffer SIZE path:**

At 0x28b0ca: `num_ref_frame <= ((16) > (16) ? (16) : (16))` — caps frame COUNT at 16.
The `DPB_unit × NTL` buffer SIZE calculation is a separate allocation path — no 64-bit promotion or upper-bound check found in 26.6.1 strings.

**27.0.1 changes (static diff — what Apple added to fix it):**

| Location in 27.0.1 | Change |
|---|---|
| `0x2ec8bb` (NEW — not in 26.6.1) | `(iLayerNum == 1) \|\| (iaCnt[1] == iTotalPendingFrameNum)` — frame-counter consistency assertion for multi-layer encoding |
| `0x31080e` (CHANGED) | Added `iNumRefsSTR > 0` to slice reference assertion (was `iPOC > 0 && iTemporalLayer >= 0 && piRefNum != nullptr`) |

The new `(iLayerNum == 1) || (iaCnt[1] == iTotalPendingFrameNum)` assertion fires when a multi-layer session has inconsistent pending-frame counts — this would catch the corrupted state caused by the OOB write, providing an integrity check. The size-check fix itself is likely in the binary (no assert string), but 27.0.1 adds catch assertions downstream.

**Near-threshold stall zone (discovered empirically):**

NTL 1500–2056 produce legitimate allocations of ~3–4.3 GB without overflowing 32-bit. The AVE2 firmware stalls attempting to allocate these — observed 15+ min for NTL=2000. After iOS process kill, AVE2 firmware continues running (no reset). Skip the entire range; jump directly from NTL ≤ 500 to NTL ≥ 2057.

**Dynamic probe status (2026-11-03):**

| NTL | Result |
|---|---|
| 1 | `encode_st=0x0 no_overflow(0x1fe000)` — baseline ✓ |
| 2000 | `encode_st=0x0 no_overflow(0xf9060000)` — 4.19 GB stall, 15 min, completed |
| 2056 | STARTING logged at 14:04:05 — not overflow (4.29 GB), force-killed ~5 min later; firmware still running |
| **2057** | **FAST** — completed in ~0.05s, `encode_st=0x0 OVERFLOW→0x001ee000` ✓ OOB path confirmed |

**Heap groom findings (2026-11-03, empirical):**

- **DPB physical address:** `0x10014d54000` — read from AVE2 FwLog syslog (`Phy 0x10014d54000 DART 0x10000280000`)
- **Actual IOSurface allocation:** 2,031,616 bytes (16KB aligned). Kernel rounds `GROOM_SIZE=2,023,424` up to 0x1F0000. Victim starts 8,192 bytes AFTER DPB's physical end — small gap, but DPB[1] OOB write extends 2,088,960 bytes past DPB base so it covers the victim.
- **Feeder pattern required:** Old groom order (spray→free half→place victims→trigger) filled ALL holes before encode → DPB went to new memory, no victims adjacent. Fix: free ALL spray first, trigger encode, wait 20ms (DPB claims freed pages), THEN place victims immediately after.
- **Multi-frame required for OOB:** Frame 0 only writes DPB[0] at offset 0 (in-bounds). Frame 1 writes DPB[1] at offset 2,088,960 > 2,023,424 → first OOB write. Need `NUM_FRAMES ≥ 2`; using 5.
- **IOSurfaceRelease absent:** Symbol not exported on iOS 26.6.1. Use `CF.CFRelease(surf)` — IOSurfaceRef is CFType-compatible.
- **VTCompressionSessionInvalidate hangs:** After multi-frame NTL=2057 encode, firmware waits for complete GOP. `Invalidate` blocks indefinitely (MCP timeout). Do NOT call it.
- **Allocator test:** 10/10 freed IOSurface pages deterministically reused by next allocation (confirmed via KVA tracking). Feeder pattern is reliable.
- **AVE2 firmware error loop:** After groom v1 (single frame, groom miss), firmware emitted `<decode: bad range for [%p]>` heartbeat errors every 5s for 14+ min — DART mapping corrupted. Required device reboot to clear.
- **Memory pressure:** PocketCode RSS 1552–1559 MB causes jetsam kill of ResearchHost during spray. Must close all background apps before running groom. Using SPRAY_COUNT=16, VICTIM_COUNT=16 (32 MB peak).

**PoC file:** `kerneldiff/ave2_groom_poc.py` (v4 — feeder pattern, multi-frame, CFRelease, no Invalidate)
**Ladder file:** `kerneldiff/ave2_overflow_poc.py` (v4 — corrected threshold, skip stall zone)

**CVEs:** CVE-2026-112466/468/469/470/689 (same 32-bit overflow pattern, different buffer size fields)

---

**DEFINITIVE CLOSURE (2026-11-04 — kext RE + PoC empirical):**

**Layer 1 — DART IOMMU blocks the write (empirical, v6/v7 PoC):**
- 0xAA pre-fill detection: 16 victim surfaces filled with 0xAA, NTL=2057 encode fired (st=0, 2 frames)
- All 16 victims polled for 16 seconds: 0xAA unchanged throughout
- Classic alternating groom + victims-first + IOSurfaceLookup: same result
- Root cause: DPB is mapped in DART at [DART_base, DART_base+2,023,424). The firmware DPB[1] write targets DART_base+2,088,960 — 65,536 bytes past the DART mapping end. DART IOMMU hardware raises `DARTHwException` and blocks the access.

**Layer 2 — DART exception is non-fatal (kext RE):**
- `DARTHwException` handler at kext VA `0x8530800` logs the fault (IsWrite, Addr, AXI ID, L0-L3 page table indices) and returns 0 (success).
- Firmware continues executing after the fault.

**Layer 3 — IPC completion path does NOT use firmware-supplied kernel VAs (kext RE):**

Key function at kext VA `0x84fcbb8` (`AVE_CHM_[recon buffer fill]`):
```
args: x19=IPC_cmd_struct  x20=DPB_surface  x21=buf_offsets  x22=output_descriptor
calls 0x85fbd44(x0=DPB_surface, w1=[x19,#0x28])  ; w1 = firmware-supplied buffer INDEX
```

Function at `0x85fbd44`:
```
0x85fbd6c: cmp w1, #0x4        ; BOUNDS CHECK: index >= 4?
0x85fbd70: b.hs error_path     ; YES → return NULL, never use index
0x85fbd74: ldr x8, [x20, #0xf0] ; load surface bitmask from kext's OWN object
0x85fbd80: ...
0x85fbda0: ldr x8, [x10]       ; dereference kext's OWN buffer_entry pointer
0x85fbda8: ldr x8, [x8, #0x20] ; kernel VA from kext's OWN buffer table (NOT firmware IPC)
```

The kernel VA stored in `x22` (Phy/Kernel/DART addresses logged in `FwLog`) all come from the kext's own buffer management tables, populated during `AVE_Client_DARTMapDataSurfaces`. The firmware IPC message provides only a bounds-checked index (0–3).

**CONCLUSION: Surface E is closed. DART is the definitive defense. No IPC kernel VA misuse path exists in the kext.**

Requires: (a) DART bypass/manipulation vulnerability, OR (b) an entirely different AVE2 attack surface that does not involve the DPB overflow path.

---

## NVMe GL2 DMA Chain (post kernel-exec only)

```
kernel exec → vtable control → EnableLinearSQ()
  → linear mode in nvme_instance
    → SET_SQ_ENTRY skips PA range check
      → DMA to arbitrary physical memory at GL2
```

Full analysis in STATE.md. Requires kernel exec as precondition.

---

## Next Steps (priority order)

**← RESUME HERE 2026-11-04 (session 3) → CVE-2026-112689 patch LOCATED in binary.**

**KEY FINDING (session 3):**
- `AVE_AVC_CheckInfo` in 26.6.1 (VA 0xfffffff00851c454) does NOT validate frame dimensions
- In 26.7.2 (VA 0xfffffff0085244f4): NEW call to `sub_fffffff00853aa34` after iNumViews/iLayerNum checks
- `sub_fffffff00853aa34`: validates frame width/height (struct fields 0xa58/0xa5c) against codec-level macroblock table at `__DATA_CONST.__const` VA 0xfffffff007dbfd88
- Error string: `"frame dimension is out of range %d %d %d\n"` — added in 26.7.2, absent in 26.6.1
- TEXT section grew +12,480 bytes; cstring grew +3,599 bytes (all added validation code)

**IMMEDIATE NEXT STEP:** Identify which CalcBufSizeOf function uses frame fields 0xa58/0xa5c and what happens with extreme dimensions (causing overflow). Then draft PoC.

**Reference files**: KEXT_26.6.1.md, KEXT_26.7.2.md, AVE2_ANALYSIS.md

**AVE2 final closure report: `REPORT_surface_ave2_final.md` (2026-11-04)**

### CPU-Side Overflow Candidates (ranked, 2026-11-04)

| Rank | Surface | Path | Why CPU-side | Status |
|------|---------|------|-------------|--------|
| 1 | **AVE2 CalcBufSizeOf OOB — CVE-2026-112466/468/469/470/689** | VideoToolbox → AVE2 kext | CPU-side kalloc buffers, no DART | **Active — pending 26.7.2 kext diff** |
| 2 | **CoreAudio OOB write — CVE-2026-86969** | App → CoreAudio kext/daemon | App-triggered, kernel corruption | **UNEXPLORED — alternative if AVE2 stalls** |
| 3 | **FigXPC / CVE-2026-112706** | XPC → mediaplaybackd | Runs in daemon on host CPU; no DMA | **UNEXPLORED** |
| 4 | **AVE2 IOKit SetSessionSettings (MIG method 7)** | IOKit user client → kext handler | CPU-side, no DART; ziVA lineage | **UNEXPLORED — IOServiceOpen blocked from sandbox** |
| 5 | **Surface C numFrames bypass** | Raw MIG → audiomxd | Server overflow confirmed in disasm; EXC_GUARD blocker | **Needs EXC_GUARD bypass first** |

**Rank 1 — AVE2 CalcBufSizeOf (5 CVEs, all open on 26.6.1):**
- Full CVE list from 26.7.2 Apple security notes (confirmed):
  - CVE-2026-112466 (Hcamael): **OOB read → read kernel memory** = KASLR bypass
  - CVE-2026-112468/469/470 (Hcamael): **OOB write → corrupt kernel memory**
  - CVE-2026-112689 (Blackwing): **OOB write → corrupt kernel memory** (input validation)
  - CVE-2026-112705 (Calif.io): OOB write, termination only (lower priority)
- Hcamael chain: 112466 (read = KASLR bypass) + 112468/469/470 (write = corruption)
- **Next step:** 26.7.2 kext binary diff to find which functions changed

**Rank 2 — CoreAudio OOB write (CVE-2026-86969, Nik Tsytsarkin / Meta Red Team X):**
- App-triggered OOB write → corrupt **kernel memory**
- CoreAudio reachable from sandbox (AURemoteIOServer + SystemSoundServer-iOS both kr=0)
- Subsystem unknown — could be in kext (`AppleHDA`/audio kext) or in kernel path via audiomxd
- Also in 26.7.2: CVE-2026-113907 (process memory, lower value), CVE-2026-112638 (radio range)
- **Explore if AVE2 diff stalls** — may be simpler (no DART, no IOMMU consideration)

**Rank 3 — FigXPC (CVE-2026-112706):**  
- `mediaplaybackd` XPC, host CPU, no DART  
- GAP_ANALYSIS: "Fix was incomplete in iOS 27.0 — auxiliary opcodes still affected on iOS 26.5" → likely 26.6.1 too  
- Public PoC: MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak  
- Low memory footprint: just an XPC call, no AV hardware warmup  
- XPC service names confirmed in kernelcache strings: `com.apple.coremedia.mediaplaybackd.*`

**Rank 4 — AVE2 IOKit SetSessionSettings:**  
- `AppleAVE2UserClient` confirmed in kernelcache strings  
- IOKit MIG dispatch runs on host CPU in kernel — no DART involved  
- `IOServiceOpen` blocked from sandbox, BUT: could be reachable via VideoToolbox → VTD XPC proxy  
- ziVA (2017) + CVE-2019-8795 both exploited method 7 on older iOS  

0. **Surface C MIG probe (AURemoteIOServer)** — attack model corrected 2026-11-01:

   **Attack model revision (2026-11-01 — disassembly of full call chain):**
   - Our ne at `IONodeClient+0xc` is a **notification port**, not mapped as ring buffer
   - Server creates its own ring buffer; sends 3 OOL regions in reply
   - Original attack (shadow ne → server maps it OOB) is INVALID

   **New attack path — ASBD integer overflow (CONFIRMED by disasm, empirical probe PENDING):**

   `ChangeHardwareFormats` calls `IPCAUSharedMemoryBase::InitClient(ASBD2, channels=1, frames=0x1000)`
   with `frames=0x1000` **hardcoded at BOTH call sites** (0x23d512730, 0x23d512838). ASBD2 comes
   from our Initialize message at req[0x50]. In `InitClient`:

   ```
   # No validation of mBytesPerFrame
   ldr  w12, [element, #0x18]  ; ASBD.mBytesPerFrame  ← OUR FIELD
   ldr  w14, [shmBlock, #0x58] ; = 0x1000 (hardcoded frames)
   madd w12, w14, w12, w11     ; (0x1000 × mBytesPerFrame) + 15  — 32-BIT OVERFLOW
   and  w12, w12, #0xfffffff0
   mul  w12, w12, w13           ; × mChannelsPerFrame
   add  x8,  x8,  x12           ; → ClientToken+0xc → realloc()
   ```

   With `mBytesPerFrame=0xFFF001`:
   - `(0x1000 × 0xFFF001) + 15` = 0xFFF001000 + 15 → 32-bit = **0x1000** (4 KB allocation!)
   - Actual ring-buffer write stride = 0x1000 frames × 0xFFF001 bytes/frame = **~16 GB**
   - Result: **heap OOB write with ~16 GB write window in AURemoteIOServer**

   Probe: `surface_c_probe_b_overflow.py`. Full report: `REPORT_AUREMOTEIO_INTOVERFLOW.md`.

   **Expected observable signals:**
   - Server crash (SIGSEGV/malloc abort) on Initialize or StartIO → confirms overflow + write
   - Or: Initialize reply OOL[0].sz == 0x1000 → allocation IS the overflowed size

   **BLOCKED — probe not runnable at current memory baseline (2026-11-01):**
   Root cause: snapshot restores kill AURemoteIOServer; bootstrap_look_up re-triggers launchd launch.
   Server init spikes system (audio hardware context + IOKit) at ~1357 MB baseline → PocketCode OOM.

   **To unblock:** need system baseline ≤ ~1100 MB. Close all apps + restart PocketCode cold.
   Or use `SystemSoundServer-iOS` as backup (lighter, also kr=0).

1. **Surface 5 investigation** — offset+size wrap-around call site in TEXT_EXEC at foff=0x3707668. This was the other vm_sanitize gap candidate. Needs fresh disasm + probe.

2. **IOSurface test** — check if IOSurface.framework is accessible from sandbox; IOSurface cross-process shared memory has historically had exploitable bugs and doesn't require IOKit service opens.

3. **Surface D demo** — once in SpringBoard context: `[UIStatusBarServer postStatusBarOverrideData:]` with seconds in timeString

---

## Key Addresses (this session)

| Symbol | VA |
|---|---|
| `io_hideventsystem_open` | `0x1b79deda4` |
| `IOHIDEventSystemClientCreate` | resolved via dyld |
| `IOHIDEventSystemClientSetDispatchQueue` | `0x1b79f8edc` |
| `io_hideventsystem` service port | `0x1bdf3` (runtime — changes every boot; always re-lookup via `bootstrap_look_up(bp, "com.apple.iohideventsystem", &svc)`) |

---

## Files

| File | Contents |
|---|---|
| `STATE.md` | Full kernel diff state, NVMe chain, SPTM analysis |
| `REPORT_XPC_NAMEDENTRY.md` | Named entry attack surface map, Surface B/C plans, test code |
| `REPORT_VMSANITIZE_26.md` | vm_sanitize gap analysis on 26.6.1 |
| `REPORT_MME_SANITIZE.md` | mach_make_memory_entry_64 sanitize removal diff |
| `REPORT_SPTM.md` | SPTM binary analysis |
| `REPORT_27.md` | 26.6.1 → 27.0.1 full kernel diff |
| `ave2_overflow_poc.py` | Surface E dynamic probe — NTL ladder, AppGroup file logging |
| `AVE2_ARCH.md` | **AppleAVE2 kext architecture notes** — segment map, pointer encoding, all 17 CalcBufSizeOf VAs, MBInputCtrl partial reversal, CVE mapping |
| `KEXT_26.6.1.md` | **26.6.1 kext deep analysis** — all 17 CalcBufSizeOf analyzed, arithmetic summary, LFSRef caller table |
| `KEXT_26.7.2.md` | **26.7.2 kext notes** — CVE table, diff methodology, pending extraction |
| `KEXT_27.0.1.md` | **27.0.1 kext notes** — function rename table (LFSRef→LFSOutput, DPB extracted, 5 new types) |
| `AVE2_ANALYSIS.md` | **Connecting analysis** — CVE patterns, why CalcBufSizeOf arithmetic is NOT the bug, diff strategy |
| `Latest.md` | **This file** — single source of truth for current state |

*Kernelcaches and kexts on disk at `~/kerneldiff_ave2/` (NOT in git):*
- `23G83__iPhone17,4/kexts/com.apple.driver.AppleAVE2` — 26.6.1 kext + .a2s cache
- `26_7_2/` — 26.7.2 kernelcache (extract kext: `ipsw kernel extract <kc> "com.apple.driver.AppleAVE2" --output 26_7_2/kexts`)
- `27_0_1/kexts/com.apple.driver.AppleAVE2` — 27.0.1 kext (extracted, major rewrite)
- OTA files: `iOS26.7.2_OTAs/*.aea` (8.7 GB), `iOS27.0.1_OTAs/*.aea` (9.1 GB)
