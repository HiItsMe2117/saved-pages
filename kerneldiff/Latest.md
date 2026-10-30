# iOS Security Research — Latest State

*Last updated: 2026-10-30 | Target: iOS 26.6.1 (iPhone 16 Plus, iPhone17,4)*

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
| Full OOB chain phantom aliasing | **CONFIRMED** | Phantom alias works through the Surface 4 OOB named entry path. |
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

### Surface A — vm_sanitize gap (kernel exec path) ← TOP PRIORITY

**Status:** Static analysis complete (REPORT_VMSANITIZE_26.md, REPORT_MME_SANITIZE.md).
Dynamic test not yet run.

- `vm_sanitize_telemetry.c` removed from 27.0.1 → the correction layer that clamped bad inputs (offset+size wrap, parent bounds) is absent in 26.6.1
- **Surface 5** (offset+size wrap): top candidate — call site in TEXT_EXEC at foff=0x3707668
- **Surface 4** (parent bounds ordering): second candidate

**Probed 2026-10-28 — SURFACE 4 BUG CONFIRMED:**

**Setup:** 2-page (0x8000) parent, filled: page1=0xAA, page2=0xBB.

**Winning call:**
```
mach_make_memory_entry_64(task, &size=0x3FFF, offset=0x4001, VM_PROT_RW, &child, parent)
  → KERN_SUCCESS, size_out=0x4000
```

**Why this is a bug:**
- Bounds check uses ORIGINAL size 0x3FFF: `0x4001+0x3FFF = 0x8000 = parent_end` → passes
- vm_sanitize then corrects `0x3FFF → 0x4000` (rounds up to page)
- Child entry covers `[parent+0x4001, parent+0x8001)` — **1 byte OOB past parent end**
- Confirmed: child maps to 0x4000 bytes, last byte readable = oob[0] accessible

**Limitation (current):** The 1-byte OOB is sub-page granular. The extra byte falls on the same 16KB physical page as parent[0x7FFF] — no physical-page escape yet.

**Path to amplification:** Use child entry as a new parent; repeat the call with the same trick. Each stacking step slips the effective range by 1 byte further. After N iterations the entry extends N bytes past the original parent — once N ≥ 16KB page size (0x4000), the child reaches a physical page NOT in the original parent allocation → **physical OOB read/write primitive**.

**Also confirmed (Surface 2):** Sub-page size (even size=1) gets rounded to 0x4000, KERN_SUCCESS, valid entry. Harmless by itself (still within same page) but usable as a building block.

**Next step:** Implement the stacking amplification loop — create child1 from parent, then child2 from child1, etc., measuring how far the OOB extends. Stop before it reaches another allocation to avoid crash.

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

**RESUME POINT FOR NEXT SESSION:**
1. Reconnect use-mac-terminal MCP first
2. jtool2 disasm on IOKit stub at 0x1ae26ada4 (256 bytes) for full decode
3. Decode ADRP x16 at 0x1b0feb3e0 to find what fn_124 actually calls (the real function after GOT lookup)
4. Safe on-device alternative: pass x3=mapped_zeroed_page (not NULL) to see if crash disappears → confirms x3 dereference; if it still crashes → problem is elsewhere
5. Check free -m first; budget 10 MB per probe

**msgh_id = 71** is confirmed by CMP at stub+272 (checks reply_id == 71; request_id = reply_id for this MIG family).

---

### Surface C — XPC xpc_shmem_t substitution (HIGH)

**Status:** Active probe in progress (2026-10-29). XPC connection to `com.apple.mediaserverd` attempted with our named entry as the shmem backing.

- `xpc_shmem_create(addr, size)` → named entry port wrapped in XPC dict
- Receiving service: `xpc_shmem_map(shmem, &ptr)` → `mach_vm_map(..., named_entry_port, ...)`
- Substitute our Surface-4 `ne` (or phantom alias `ne`) → service maps our shadow page → TOCTOU
- Target confirmed reachable: `com.apple.mediaserverd`

**COW gotcha (important for ne construction):**
Writing to the shadow buffer BEFORE calling MMME64 triggers copy-on-write. If you then use `MAP_MEM_VM_SHARE` to export a named entry, it re-exports the pre-COW physical page (the original clean page) — your write is not visible.

**Fix:** Write to the buffer first, THEN create the named entry with plain `permission=3` (no `MAP_MEM_VM_SHARE`) to lock the COW'd page into the entry. Then the alias works as expected.

**Probe results (2026-10-29):**
- Connection to `com.apple.mediaserverd` from sandbox: **SUCCESS** (conn non-NULL)
- `xpc_shmem_create` on our aliased buffer: **SUCCESS** (shmem object non-NULL)
- Service received message and replied: **YES** (non-NULL reply, not connection-refused)
- Reply type: `0x203044698` (unknown private type, NOT `XPC_TYPE_ERROR` or `XPC_TYPE_DICT`)
- Reply has 1 key: `XPCErrorDescription` — the service rejected the unknown message format, not the connection itself
- **Conclusion:** XPC channel is open from sandbox. The service expects a specific protocol message, not a bare `data: shmem` key. We need the correct message format for mediaserverd's shmem-based audio buffer operations.

**Protocol research findings (2026-10-29):**
- `mediaserverd` binary is dyld-cache-only — no on-disk binary, can't do string search without Mac
- ObjC runtime introspection found: **`_AFAudioPowerXPCSharedMemory`** (`initWithXPCObject:`) — AudioFoundation wrapper that receives an XPC shmem from a service. Prefix "AF" = AudioFoundation.
- Also found: `PLXPCShMemData` (`initWithXPCShmem:length:`) — Photos library receives shmem via XPC
- `com.apple.mediaserverd` not in any launchd plist — likely an alias or renamed endpoint

**Better target: `com.apple.audio.audiohald`**
From REPORT_XPC_NAMEDENTRY.md: CoreAudio shares an audio ring buffer with audiohald. The ring buffer tracks read/write cursors in the shared region (IODataQueue pattern). The CLIENT provides its input ring buffer (named entry), the server provides the output ring. Cursors in the shared region → if we forge them after mapping, audiohald reads outside the buffer → heap corruption in audiohald.

No entitlement needed for audio client role. `_AFAudioPowerXPCSharedMemory.initWithXPCObject:` confirms the XPC shmem path is active in the audio stack.

**Next step:** Probe `com.apple.audio.audiohald` — connect, send our named entry as the input ring buffer, confirm it gets mapped.

Other target: `com.apple.coremedia.remotepipeline`, `com.apple.coremedia.mediaplaybackd.bytestream.xpc`

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

**← RESUME HERE →**
1. **Surface C / audiohald** — XPC ne substitution to `com.apple.audio.audiohald`:
   - `com.apple.mediaserverd` probe done (channel open, wrong protocol)
   - Next: connect to audiohald, send named entry as input ring buffer, confirm it maps

3. **Surface 4 stacking amplification** — use child entry as parent; repeat ~0x4000 times for physical OOB primitive

4. **Surface D demo** — once in SpringBoard context: `[UIStatusBarServer postStatusBarOverrideData:]` with seconds in timeString

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
| `Latest.md` | **This file** — single source of truth for current state |

*Kernelcaches on disk (NOT in git — regenerate if missing):*
`kc_26.6.1.macho`, `kc_27.0.1.macho`, `sptm_26.6.1.bin`, `sptm_27.0.1.bin`
