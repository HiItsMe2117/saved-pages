# Ground Truth — iOS 26.6.1 / A18 Security Research
> Owner: Cody. Claude reads this; Claude does not edit without explicit instruction.
> Purpose: anchor Claude to verified facts, override training-data priors.
> Format: each fact has a Source and a Confidence. Claude treats "empirical" as highest authority.

---

## Device

| Field | Value | Source |
|---|---|---|
| Device | iPhone 16 Plus | empirical |
| Model identifier | iPhone17,4 | empirical |
| iOS version | 26.6.1 | empirical |
| Build | 23G83 | empirical |
| Chip | A18 | empirical |
| ResearchHost entitlements | `get-task-allow`, `kernel.increased-memory-limit`, `kernel.extended-virtual-addressing` | empirical |

---

## Privilege Level Architecture

> Claude's priors here are UNRELIABLE — fill in from binary/firmware analysis.

| Component | Privilege Level | Notes | Source |
|---|---|---|---|
| SPTM | ??? | EL2? EL3? Apple-specific? Verify from firmware | UNVERIFIED |
| XNU kernel | EL1 | Standard ARM | trusted prior |
| Userspace | EL0 | Standard ARM | trusted prior |
| `hv_vcpu.c` / hypervisor | ??? | In kernelcache or separate blob? | UNVERIFIED |
| PPL (Page Protection Layer) | ??? | Merged into SPTM on A18? Still separate? | UNVERIFIED |

---

## Known-Patched CVEs (on 26.6.1)

| CVE | Description | Patch introduced | Confirmed patched on 26.6.1 | Source |
|---|---|---|---|---|
| CVE-2025-24257 | IOGPUFamily sel=9 `bitmap_mask` integer underflow | iOS 18.4 | YES (capacity≥64 check present) | empirical + BH2025 |
| CVE-2026-112689 | AVE2 TOCTOU OOB write (our original target) | iOS 26.7.2 | NO — STILL VULNERABLE on 26.6.1 | empirical (sandbox blocks it) |
| CVE-2026-39868 | IOGPUFamily double-free | iOS 26.5.2 | YES | prior research notes |
| CVE-2026-65346 | IOGPUFamily memory corruption | iOS 26.6.1 | YES (patched IN this build) | prior research notes |

---

## AGX / IOGPUFamily — Empirically Confirmed

| Fact | Value | Source |
|---|---|---|
| Connection type for AGXDeviceUserClient | type=1 | empirical |
| Number of selectors | 56 (0–55) | binary (session-17) |
| Only selector passing with zero-content input | sel=8 | empirical |
| sel=8 with zeroed input (handle=0) | kIOReturnNoResources | empirical |
| sel=8 with nonzero handle at [0x048] | kIOReturnError | empirical |
| All other selectors (0–7, 9–54) | BadArgument regardless of size or content | empirical |
| Gate self[0x100].bit0 on fresh connection | 1 (open) — set by vtable[186] call during client init | binary (session-17) |
| Bounds check in outer dispatcher | `cmp w1, #55; b.hi` → 56 valid selectors (0–55) | binary (session-17) |
| iOS 26.6.1 sel=9 struct format | CHANGED from iOS 18.3 — BH2025 field positions don't work | empirical |

> **BINARY CORRECTION (session-13):** Prior GROUND_TRUTH entries claiming sel=8 reads `[0x014]` as a page count with overflow check `(u32)(page_count × 0x1000) ≥ 0x800000` are **incorrect**. Binary analysis confirms:
> - AGXDeviceUserClient sel=8 (`0xfffffff009bf32bc`) is an event subscription manager; it reads only IOUserClient internal fields (`uc[0x24]`, `uc[0x28]`), never dereferences the input struct.
> - No `ldr wN, [xM, 0x14]` instruction exists anywhere in the IOGPUFamily binary.
> - No `cmp wN, 0x800, lsl #12` instruction exists in the binary.
> - The page_count field is at **input[0x50]** in `IOGPUDeviceUserClient::s_new_resource` (a **different user client** opened via type=0).
> - The page pool lookup treats page_count as an array **index** (multiplied by 8), not by 0x1000.
> - **Action required:** Re-run on-device probes testing IOGPUDeviceUserClient type=0 to find the actual overflow.

## AGXDeviceUserClient Selector Table (binary, corrected session-17)

Extracted from TABLE_A (file offset 0x562d8). Entry format: `IOExternalMethodDispatch` (24 bytes):
`fn(8) | sc_in(4) | si_sz(4) | sc_out(4) | so_sz(4)`. All sizes uint32; `0xffffffff` = unlimited.

**56 entries total (sel 0–55).** Dispatch via outer function at `0x9bf99a0`; sel selected via `self[0x103].bit0` (TABLE_A if 1, TABLE_B if 0).

| sel | fn VA | sc_in | si_sz | sc_out | so_sz | Notes |
|-----|-------|-------|-------|--------|-------|-------|
| 0 | 0xfffffff009bf2bb4 | 0 | 0x0 | 0 | 64 | |
| 1 | 0xfffffff009bf2cc4 | 0 | 0x0 | 0 | 64 | |
| 2 | 0xfffffff009bf2cf4 | 0 | 0x0 | 0 | 536 | |
| 3 | 0xfffffff009bf2dc4 | 0 | 0x0 | 0 | 8 | |
| 4 | 0xfffffff009bf2df4 | 0 | 0x0 | 0 | 32 | |
| 5 | 0xfffffff009bf2ecc | 0 | 0x0 | 0 | 16 | |
| 6 | 0xfffffff009bf2f2c | 0 | unltd | 0 | 16 | si_sz=unlimited; BTI entry inside larger fn |
| 7 | 0xfffffff009bf322c | 1 | 0x0 | 0 | 0 | |
| 8 | 0xfffffff009bf32bc | 0 | unltd | 0 | unltd | EVENT SUBSCRIPTION; reads uc state only |
| 9 | 0xfffffff009bf3440 | 1 | 0x0 | 0 | 0 | |
| 10 | 0xfffffff009bf3454 | 2 | 0x0 | 0 | 0 | |
| 11 | 0xfffffff009bf346c | 2 | 0x0 | 1 | 0 | |
| 12 | 0xfffffff009bf348c | 2 | 0x0 | 0 | 16 | |
| 13 | 0xfffffff009bf34b4 | 1 | 0x0 | 0 | 0 | |
| 14 | 0xfffffff009bf34c8 | 2 | 0x0 | 0 | 16 | |
| 15 | 0xfffffff009bf34e8 | 1 | 0x0 | 0 | 0 | |
| 16 | 0xfffffff009bf34fc | 0 | 0x0 | 0 | 8 | |
| 17 | 0xfffffff009bf350c | 0 | 0x0 | 0 | 4 | |
| 18 | 0xfffffff009bf351c | 1 | 0x0 | 0 | 0 | |
| 19 | 0xfffffff009bf3530 | 1 | 0x0 | 0 | 24 | |
| 20 | 0xfffffff009bf3548 | 1 | 0x0 | 0 | 0 | |
| 21 | 0xfffffff009bf4d24 | 0 | 0x0 | 0 | 48 | STUB |
| 22 | 0xfffffff009bf356c | 0 | 0x0 | 0 | unltd | so_sz=unlimited; unexplored |
| 23 | 0xfffffff009bf357c | 0 | 0x0 | 1 | 0 | |
| 24 | 0xfffffff009bf358c | 2 | 0x0 | 0 | 0 | |
| 25 | 0xfffffff009bf3644 | 4 | unltd | 1 | 0 | 4 scalars + unlimited struct; primary target |
| 26 | 0xfffffff009bf38d0 | 1 | 0xc | 1 | 0 | |
| 27–34, 36–54 | 0xfffffff009bf4d24 | varies | varies | varies | varies | STUB |
| 35 | 0xfffffff009bf3cfc | 2 | 0x0 | 0 | 0 | |
| 55 | 0xfffffff009bf4d18 | 0 | 0x0 | 0 | 0 | fn → `ret` opcode (BTI-less; would panic if called) |

**Key notes (session-17):**
- **sel=6**: BTI entry inside larger fn at `0x9bf2f2c`; si_sz=unlimited, so_sz=16; unexplored create path
- **sel=8**: so_sz=unlimited in addition to si_sz=unlimited; reads only `uc[0x24]`/`uc[0x28]`, never the input struct
- **sel=22**: so_sz=unlimited, no input required; unexplored
- **sel=55**: fn=`0x9bf4d18` starts with bare `ret` (not BTI C); calling via BRAA on arm64e would trigger BTI fault → kernel panic

## AGXDeviceUserClient Outer Dispatcher (session-17, fully decoded)

Located at `0xfffffff009bf99a0` (BTI C — indirect call entry). Called by IOKit externalMethod base.

```
0x9bf99a0: bti c                                    — indirect call entry
0x9bf99a4: movz/movk → w8 = 0xe00002c2             — pre-load kIOReturnBadArgument
0x9bf99ac: ldrb w9, [x0, #0x100]                   — read self[0x100] gate byte
0x9bf99b0: tbz  w9, #0, →return_0xe00002d8          — gate.bit0==0 → bail (not BadArg; 0xe00002d8)
0x9bf99b4: cmp  w1, #55 / b.hi →BadArgument        — bounds: sel>55 → error (56 valid: 0–55)
0x9bf99bc: ldr  x9, [x2, #0x10] / cbnz →async_path — async ref check
0x9bf99c4: ldrb w8, [x0, #0x103]                   — read self[0x103] mode flag
0x9bf99c8: movz w9, #24                            — entry size 24 bytes
0x9bf99cc: UMULL x9, w1, w9                        — x9 = sel × 24 (TABLE byte offset)
0x9bf99d4: adrp/add → x10 = TABLE_A base 0x80fcea8
0x9bf9a08: tst w8, #1 / csel x3, TABLE_A[sel], TABLE_B[sel], NE
0x9bf9a2c: braa x16, x17                           — TAIL CALL → IOKit dispatch helper(global[0x550], discrim=0xb352)
```

**self[0x100] gate**: bit0=1 on a fresh connection (set by `self→vtable[186](self)` call at `0x9bf6898`, result stored to `self[0x100]`). Cleared to 0 by teardown at `0x9bf97bc` (`strb wzr, [x19, 0x100]`). Gate-check thunk at `0x9bf9868`.

**self[0x103] mode flag**: bit0=1 → TABLE_A (normal), bit0=0 → TABLE_B (alternate). How it is set: unknown.

**TABLE geometry** (DATA_CONST.__const):
- TABLE_B: `0xfffffff0080fc968` (56 entries × 24B — alternate mode)
- TABLE_A: `0xfffffff0080fcea8` (56 entries, sel 0–55)
- TABLE_C: `0xfffffff0080fd538` (IOGPUDeviceUserClient, 14 entries)
- Second dispatcher (IOGPUDeviceUserClient) at `0x9bf9a58`: uses W2 as selector, `cmp w2, #13`

---

## IOGPUDeviceUserClient — Binary (session-13, updated session-14)

Opened via type=**1** on service **"IOGPUDevice"** (session-14 binary analysis of `fcn.fffffff009c16634`). Has 14 selectors (0–13). TABLE_C/D are zero-initialized at kext load time (dynamic init via __mod_init_func). The 14 `s_*` selector functions (from debug strings):

> **Session-14 Binary Findings** (IOGPUDevice::newUserClient — `0xfffffff009c16634`):
> - Function checks `cmp x1, 1; b.ne → kIOReturnNotReady` — ONLY type=1 is accepted
> - On type=1: calls `fcn.fffffff009c0b00c(service→field[0x48], 1, secID)` to allocate IOGPUDeviceUserClient
> - **Entitlement gate** at `fcn.fffffff009c133bc`: loads AMFI service via `fcn.fffffff009c13ce4`, checks property `com.apple.private.iogpu.disable_wired_collector`; if NOT found → returns 0 → `newUserClient` returns `0xe00002e2` (kIOReturnNotReady)
> - Empirical probe needed to verify ResearchHost can pass this gate

| sel | Function | Notes |
|-----|----------|-------|
| 0 | s_new_command_queue | |
| 1 | s_delete_command_queue | |
| 2 | s_new_resource | reads input[0x50]=page_count; input size ≥ 0x58; empirical investigation needed |
| 3 | s_async_signal_mtlLateEvalevent | |
| 4 | s_query_mtlLateEvalevent | |
| 5 | s_submit_command_buffers | |
| 6 | s_create_vniodesc | |
| 7 | s_create_io_command_queue | |
| 8 | s_destroy_io_command_queue | |
| 9 | s_set_io_notification_queue | |
| 10 | s_submit_io_commands | |
| 11 | s_create_io_command_buffer | |
| 12 | s_destroy_io_command_buffer | |
| 13 | s_try_cancel_io_command_buffer | |

> **Connection type=1 on service "IOGPUDevice"** (session-14 binary confirmed). Entitlement gate `com.apple.private.iogpu.disable_wired_collector` may block access — empirical probe pending.

---

## XPC Surface

| Fact | Value | Source |
|---|---|---|
| Services tested | 76 bootstrap-reachable / 627 total | empirical |
| Services accepting XPC traffic | 0 | empirical |
| Rejection mechanism | `xpc_connection_set_peer_code_signing_requirement` | empirical |

---

## IOKit — Other Surfaces

| Service | Open result | Notes | Source |
|---|---|---|---|
| IOSurfaceRoot type=0 | OPEN | Heap grooming | empirical |
| AppleKeyStore type=0,1 | OPEN | sel=0,1,16 succeed; output all zeros | empirical |
| AppleSEPManager | BadArg on type=0 open | Exists; may need specific type | empirical |
| AppleAVE2Driver | kIOReturnNotPermitted | Sandbox blocked | empirical |
| All hypervisor-named services | Not found | No IOKit surface for hypervisor | empirical |

---

## iOS 26 Hypervisor — UNVERIFIED (Claude speculation, verify on Mac)

> Claude's understanding of this is first-principles ARM speculation. Treat as hypothesis only.

- SPTM added guest-VM interface: `sptm_guest_enter/exit/dispatch` (needs verification)
- Stage-2 page table management present in iOS 26 (needs verification)  
- Gate: `com.apple.private.hypervisor` entitlement + `/product/has-virtualization` device tree flag (needs verification)
- `hv_vcpu.c` in kernelcache — UNVERIFIED, check on Mac

---

## Open Questions for Mac Binary Analysis

1. ~~What connection type opens IOGPUDeviceUserClient?~~ **ANSWERED (session-14): type=1 on "IOGPUDevice" service.**
2. Does the entitlement gate `com.apple.private.iogpu.disable_wired_collector` block ResearchHost? Empirical probe needed.
3. What selector creates a resource handle (output struct contains non-zero handle)?
4. What is the `kalloc_type` tag for the allocated object in s_new_resource → which zone, what are its neighbors?
5. What is the entry_size in the page-pool lookup? (determines OOB write granularity — `ubfiz x9,x1,3,0x20` = ×8 confirmed, but each entry's content matters)
6. Is SPTM at EL2 or EL3? Is PPL merged into SPTM on A18?
7. Is `hv_vcpu.c` in the kernelcache or a separate firmware blob?

---

## Maker-Checker Log
> When Claude proposes a primitive or chain step, a checker agent verifies it.
> Format: [date] Claim | Verdict | Reason

- [2026-11-05] "sel=8 page_count overflow bypasses size check" | **RETRACTED** | session-13 binary analysis: sel=8 never reads input struct; no `ldr wN,[xM,0x14]` exists in binary; prior "empirical confirmed" was based on a probe result not properly attributed to a specific user client type
- [2026-11-05] "SPTM hypervisor interface is new attack surface in iOS 26" | UNVERIFIED — plausible | research agent found references but no primary source; needs binary confirmation
- [2026-11-05] "IOGPUDeviceUserClient s_new_resource reads input[0x50] as page_count" | BINARY CONFIRMED | disassembly of `0xfffffff009bf72bc` shows `ldr w27, [x23, 0x50]` with `tbnz w8, 3, ...` guard
- [2026-11-06] "IOGPUDeviceUserClient is opened via IOServiceOpen('IOGPUDevice', type=1)" | BINARY CONFIRMED (high confidence) | `fcn.fffffff009c16634` = IOGPUDevice::newUserClient-like; `cmp x1, 1; b.ne fail`; allocates via `fcn.fffffff009c0b00c`; x3 used as output ptr handler; empirical verification still needed
- [2026-11-06] "Entitlement gate `com.apple.private.iogpu.disable_wired_collector` in IOGPUDevice::newUserClient" | BINARY FOUND, IMPACT UNVERIFIED | `fcn.fffffff009c133bc` checks AMFI for this property; if absent returns 0 → `newUserClient` returns `0xe00002e2`; unknown if ResearchHost entitlements satisfy this
- [2026-11-06] "AGXDeviceUserClient has 55 selectors (0–54)" | **CORRECTED (session-17)** | TABLE_A has 56 entries (0–55); `cmp w1, #55; b.hi` correctly allows sel=55 through; sel=55 fn=`0x9bf4d18` starts with bare `ret` (no BTI C); calling it on arm64e would BTI-fault → kernel panic
- [2026-11-06] "sel=8 gate bypass: gate=0 → BadArgument" | **CORRECTED (session-17)** | gate=0 → `add w8,w8,#22` → `0xe00002d8` (not BadArgument); gate IS 1 on fresh connections (set during init), so this path is not observed empirically
