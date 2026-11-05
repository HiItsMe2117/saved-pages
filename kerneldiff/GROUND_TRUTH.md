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
| sel=8 minimum struct size | 0x58 bytes | empirical |
| sel=8 `[0x004]` valid values | multiples of 0x100 (0x0, 0x100, 0x200…) | empirical |
| sel=8 `[0x014]` field | page count (u32), × 0x1000 for size | empirical |
| sel=8 size check | `if ((u32)(page_count × 0x1000) ≥ 0x800000) → BadArg` | empirical |
| sel=8 overflow bypass | values ≥ 0x100000 wrap past check | empirical |
| sel=8 with handle=0 | kIOReturnNoResources | empirical |
| sel=8 with nonzero handle | kIOReturnError | empirical |
| All other selectors (0–7, 9–54) | BadArgument regardless of size or content | empirical |
| iOS 26.6.1 sel=9 struct format | CHANGED from iOS 18.3 — BH2025 field positions don't work | empirical |

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

1. Does sel=8's page-population loop use raw `[0x014]` (page_count) or computed `(u32)(page_count * 0x1000)` for iteration? **This determines exploitability.**
2. What selector creates a resource handle (output struct contains non-zero handle)?
3. What is the `kalloc_type` tag for the sel=8 allocated object → which zone, what are its neighbors?
4. What is the entry_size in the page-population loop? (determines OOB write granularity)
5. Is SPTM at EL2 or EL3? Is PPL merged into SPTM on A18?
6. Is `hv_vcpu.c` in the kernelcache or a separate firmware blob?
7. What does `sptm_guest_dispatch` validate — can a forged vcpu survive integrity checks?

---

## Maker-Checker Log
> When Claude proposes a primitive or chain step, a checker agent verifies it.
> Format: [date] Claim | Verdict | Reason

- [2026-11-05] "sel=8 page_count overflow bypasses size check" | EMPIRICALLY CONFIRMED | black-box probe showed 0x100001 → NoRes, 0x100800 → BadArg
- [2026-11-05] "SPTM hypervisor interface is new attack surface in iOS 26" | UNVERIFIED — plausible | research agent found references but no primary source; needs binary confirmation
