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
| Number of selectors | 55 (0–54) | empirical |
| Only selector passing with zero-content input | sel=8 | empirical |
| sel=8 with zeroed input (handle=0) | kIOReturnNoResources | empirical |
| sel=8 with nonzero handle at [0x048] | kIOReturnError | empirical |
| All other selectors (0–7, 9–54) | BadArgument regardless of size or content | empirical |
| iOS 26.6.1 sel=9 struct format | CHANGED from iOS 18.3 — BH2025 field positions don't work | empirical |

> **BINARY CORRECTION (session-13):** Prior GROUND_TRUTH entries claiming sel=8 reads `[0x014]` as a page count with overflow check `(u32)(page_count × 0x1000) ≥ 0x800000` are **incorrect**. Binary analysis confirms:
> - AGXDeviceUserClient sel=8 (`0xfffffff009bf32bc`) is an event subscription manager; it reads only IOUserClient internal fields (`uc[0x24]`, `uc[0x28]`), never dereferences the input struct.
> - No `ldr wN, [xM, 0x14]` instruction exists anywhere in the IOGPUFamily binary.
> - No `cmp wN, 0x800, lsl #12` instruction exists in the binary.
> - The page_count field is at **input[0x50]** in `IOGPUDeviceUserClient::s_new_resource` (a **different user client** opened via type=0).
> - The page pool lookup treats page_count as an array **index** (multiplied by 8), not by 0x1000.
> - **Action required:** Re-run on-device probes testing IOGPUDeviceUserClient type=0 to find the actual overflow.

## AGXDeviceUserClient Selector Table (binary, session-13)

Extracted from TABLE_A (file offset 0x562d8). Entry format: fn_VA | si_sz | sc_in | sc_out.

| sel | fn VA | si_sz | sc_in | sc_out | Notes |
|-----|-------|-------|-------|--------|-------|
| 0 | 0xfffffff009bf2bb4 | 0x0 | 0 | 0 | |
| 1 | 0xfffffff009bf2cc4 | 0x0 | 0 | 0 | |
| 2 | 0xfffffff009bf2cf4 | 0x0 | 0 | 0 | |
| 3 | 0xfffffff009bf2dc4 | 0x0 | 0 | 0 | |
| 4 | 0xfffffff009bf2df4 | 0x0 | 0 | 0 | |
| 5 | 0xfffffff009bf2ecc | 0x0 | 0 | 0 | |
| 6 | 0xfffffff009bf2f2c | unlimited | 0 | 0 | si_sz=unlimited, no pre-check |
| 7 | 0xfffffff009bf322c | 0x0 | 1 | 0 | 1 scalar required |
| 8 | 0xfffffff009bf32bc | unlimited | 0 | 0 | EVENT SUBSCRIPTION; reads uc internal state only |
| 9 | 0xfffffff009bf3440 | 0x0 | 1 | 0 | |
| 10 | 0xfffffff009bf3454 | 0x0 | 2 | 0 | |
| 11 | 0xfffffff009bf346c | 0x0 | 2 | 1 | |
| 12 | 0xfffffff009bf348c | 0x0 | 2 | 0 | |
| 13 | 0xfffffff009bf34b4 | 0x0 | 1 | 0 | |
| 14 | 0xfffffff009bf34c8 | 0x0 | 2 | 0 | |
| 15 | 0xfffffff009bf34e8 | 0x0 | 1 | 0 | |
| 16 | 0xfffffff009bf34fc | 0x0 | 0 | 0 | |
| 17 | 0xfffffff009bf350c | 0x0 | 0 | 0 | |
| 18 | 0xfffffff009bf351c | 0x0 | 1 | 0 | |
| 19 | 0xfffffff009bf3530 | 0x0 | 1 | 0 | |
| 20 | 0xfffffff009bf3548 | 0x0 | 1 | 0 | |
| 21 | 0xfffffff009bf4d24 | 0x0 | 0 | 0 | STUB (unsupported) |
| 22 | 0xfffffff009bf356c | 0x0 | 0 | 0 | |
| 23 | 0xfffffff009bf357c | 0x0 | 0 | 1 | |
| 24 | 0xfffffff009bf358c | 0x0 | 2 | 0 | |
| 25 | 0xfffffff009bf3644 | unlimited | 4 | 1 | si_sz=unlimited, 4 scalars |
| 26 | 0xfffffff009bf38d0 | 0xc | 1 | 1 | |
| 27–34, 36–54 | 0xfffffff009bf4d24 | varies | varies | varies | STUB (unsupported) |
| 35 | 0xfffffff009bf3cfc | 0x0 | 2 | 0 | |

**Key sel=6 note:** TABLE_A entry points to `0xfffffff009bf2f2c` which is a BTI entry point inside a larger function (not the prologue). si_sz=unlimited and sc_in=0 means no kernel pre-check — the function performs its own validation. BINARY UNEXPLORED: sel=6 may be the create/resource-allocation selector. Needs disassembly of full containing function.

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
