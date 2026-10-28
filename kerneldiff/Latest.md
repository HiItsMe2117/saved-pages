# iOS Security Research — Latest State

*Last updated: 2026-10-28 | Target: iOS 26.6.1 (iPhone 16 Plus, iPhone17,4)*

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
| `mach_make_memory_entry_64` + `mach_vm_map` phantom alias | **CONFIRMED** | Two VAs share one physical page; write at VA1 visible at VA2. Prior session. |
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

**Next step:** craft `mach_make_memory_entry_64` call with offset+size that wraps to hit Surface 5 on 26.6.1. Pure local call, no IPC, safe to probe incrementally.

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

**BLOCKER:** Exact MIG argument layout of `io_hideventsystem_open` unknown.
**NEXT STEP:** Disassemble `io_hideventsystem_open` from the extracted IOKit binary.

```bash
# Pull from device:
scp -P 10022 root@localhost:/System/Library/Frameworks/IOKit.framework/IOKit ./IOKit_ios
# Disassemble:
jtool2 -d io_hideventsystem_open ./IOKit_ios
# or: otool -tv ./IOKit_ios | grep -A 80 "io_hideventsystem_open:"
```

Need from disassembly:
1. Arg count before `bl mach_msg`
2. Whether it sends a named entry port (port descriptor) or OOL memory
3. Whether the reply returns a named entry to the client

**Alternative (Ian Beer 2018 direction):** The server may send its own named entry TO us in the reply. In that case: map the server's named entry, overwrite head/tail directly, trigger OOB write in backboardd. No need to substitute our own `ne`.

---

### Surface C — XPC xpc_shmem_t substitution (HIGH)

**Status:** Plan documented in REPORT_XPC_NAMEDENTRY.md. Not yet probed dynamically.

- `xpc_shmem_create(addr, size)` → named entry port wrapped in XPC dict
- Receiving service: `xpc_shmem_map(shmem, &ptr)` → `mach_vm_map(..., named_entry_port, ...)`
- Substitute our Surface-4 `ne` → service maps our shadow page → TOCTOU

Targets: `com.apple.mediaserverd`, `com.apple.coremedia.remotepipeline`

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

1. **Disassemble `io_hideventsystem_open`** (needs Mac) → unblock Surface B backboardd path
2. **Probe Surface A vm_sanitize** — `mach_make_memory_entry_64` with offset+size wrap on 26.6.1
3. **Verify SpringBoard CFPreferences key name** — grep SpringBoard binary strings for clock/seconds
4. **Surface C xpc_shmem** — craft XPC message with `ne` substitution to `com.apple.mediaserverd`
5. **Respring** to test CFPreferences status bar seconds (need correct key name first)

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
