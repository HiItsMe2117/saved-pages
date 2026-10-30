# iOS Security Research — Latest State

*Last updated: 2026-10-29 | Target: iOS 26.6.1 (iPhone 16 Plus, iPhone17,4)*

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
- Base call cost ~3 MB; IOHIDEventSystemClient activation costs ~14 MB — always check `free -m` first, stop if available < 100 MB
- Always thread-wrap blocking IPC/XPC calls with ≤3s timeout; set explicit argtypes for CF functions (float args fail without them)
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
| IOHIDEventSystemClient connect (61 services) | **CONFIRMED** | `com.apple.iohideventsystem` reachable from sandbox. `IOHIDEventSystemClientCreate(NULL, 1)` + `ScheduleWithRunLoop` establishes connection internally — no manual MIG call needed. |
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

**Status:** Both attack sub-paths probed on 2026-10-29. Ian Beer direction dead. Forward injection blocked pending Mac disassembly.

**Attack plan (from REPORT_XPC_NAMEDENTRY.md):**
1. Write forged IODataQueue headers (`head`, `tail`, `dataSize`) into a local buffer
2. Wrap buffer in a named entry port (`ne`) via `mach_make_memory_entry_64`
3. Send `ne` to backboardd as the queue backing during session open
4. backboardd maps `ne`, interprets forged headers → OOB write in backboardd's process
5. From backboardd: pivot to SpringBoard (has `task_for_pid-allow` entitlement)

**Established facts:**
- `com.apple.iohideventsystem` reachable via bootstrap_look_up ✓
- `io_hideventsystem_open` VA: `0x1b79deda4`; send size 104 bytes, COMPLEX (`msgh_bits = 0x80001513`)
- `IOHIDEventSystemClientCreate(NULL, 1)` + `ScheduleWithRunLoop` + `CFRunLoopRunInMode(mode, 2.0, False)` triggers `io_hideventsystem_open` internally — no manual MIG call needed. **Note:** CFRunLoopRunInMode requires explicit argtypes (`c_void_p, c_double, c_bool`) or Python crashes on the float arg.

**Ian Beer direction — DEAD (probed 2026-10-29):**
- Scanned 2048 bytes of `IOHIDEventSystemClientRef` struct before and after activation
- Only 1 SEND right exists at `+0x020`; it does not change after activation (port name is boot-session-specific, but count stays at 1)
- `mach_vm_map` on that port → `kr=0x1d = KERN_INVALID_RIGHT` — it is a plain service send right, not a named entry
- backboardd does NOT hand the client a named entry for the DataQueue on iOS 26.6.1

**Forward injection path — blocked (needs Mac):**
- Direct calls to `io_hideventsystem_open` with guessed args all return `MACH_SEND_INVALID_MEMORY (0x1000000c)` — confirms the 104-byte message contains an OOL memory descriptor at an offset we don't yet know
- Need `jtool2` / `otool -tv` on Mac to find the OOL descriptor offset; then we can craft the message manually with our forged IODataQueue buffer in the right slot

**BLOCKER:** MIG layout of `io_hideventsystem_open` → needs Mac disassembly

---

### Surface C — XPC xpc_shmem_t substitution (HIGH)

**Status:** `com.apple.mediaserverd` probe complete (2026-10-29) — channel open but wrong protocol. Pivoted to `com.apple.audio.audiohald`. Audiohald probe next.

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
1. **Surface C — audiohald probe** (`com.apple.audio.audiohald`):
   - Connect via XPC; create named entry from forged IODataQueue buffer (write data first, then MMME64 with `permission=3`, no MAP_MEM_VM_SHARE — avoids COW gotcha)
   - Wrap as `xpc_shmem_create`; send as audio input ring buffer
   - Confirm audiohald maps it; then forge `head`/`tail` past `dataSize` → OOB read/write in audiohald

2. **Surface 4 stacking amplification** — create child1 from parent, child2 from child1, etc.; after ~0x4000 iterations the child reaches a physical page outside the original allocation → physical OOB primitive

3. **Surface B forward injection** (needs Mac first) — get `io_hideventsystem_open` OOL descriptor offset from jtool2/otool; craft the 104-byte MIG message manually with our forged IODataQueue in the right OOL slot

4. **Surface D demo** — once executing in SpringBoard context: `[UIStatusBarServer postStatusBarOverrideData:]` with custom `timeString` including seconds

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
