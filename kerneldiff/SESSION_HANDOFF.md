# Session Handoff — 2026-11-05
## For Mac Claude to continue

---

## Current Status

### Original goal (unchanged)
Full chain: CVE-2026-112689 (AVE2 OOB write) → kernel R/W → SPTM bypass → AMFI bypass → SpringBoard inject → show Mac battery.

### What's blocked and why
**CVE-2026-112689 direct path is sandbox-blocked.**
- `IOServiceOpen("AppleAVE2Driver")` returns `kIOReturnNotPermitted (0xe00002e2)`.
- Entitlement `com.apple.security.exception.iokit-user-client-class` = `["AppleAVE2UserClient"]` IS in the ResearchHost binary (confirmed via SecTaskCopyValueForEntitlement = YES), but AMFI's sandbox enforcement validates against the provisioning profile which doesn't authorize it.
- TrollStore does NOT support iOS 26 — CoreTrust bug it relied on was patched in iOS 17.0.1.
- VideoToolbox path attempted (see DFCD3C88 result in AppGroup/results): frames dropped (flags=0x1 = kVTEncodeInfoFlags_FrameDropped), never reached kernel code.

### Session-9 findings: new surfaces

Reachable from sandboxed ResearchHost (no extra entitlement):
- **AGXAccelerator type=1** → `AGXDeviceUserClient` — 55+ selectors, all accessible, dispatch table in `IOGPUFamily` kext
- **IOSurfaceRoot type=0** — standard heap grooming tool
- **AppleKeyStore type=0 and type=1** — 3 selectors (0, 1, 16) return SUCCESS with zero input but output is all zeros (no info leak)

---

## AGX Partial Struct Map (sel=8, empirical, 0x60 byte input)

```
Offset   Type   Behavior
0x000    u32    Unknown (zeroed ok)
0x004    u32    Type/flags: 0x100 passes input validation; 0x1/0x10/0x1000/0x10000 → BadArgument
0x008    u64    Unknown (zeroed ok)
0x010    u64    Unknown (zeroed ok)
...
0x040    u64    Unknown (zeroed ok)
0x048    u32    Handle/ID: non-zero → kIOReturnError (object lookup fails; needs valid handle)
0x04c    u32    Handle type?: 0x1 → Error, >0x1 → BadArgument
0x050    u64    Unknown (zeroed ok)
0x058    u64    Unknown (zeroed ok)
```

Baseline: zeroed 0x60 bytes → `kIOReturnNoResources (0xe00002be)` — passes all input validation, fails at resource allocation.

**Key takeaway**: sel=8 is a "do-something-with-existing-object" call. The handle at 0x048 must come from a prior create call. All create selectors (0–14 tested) → BadArgument with zero input, need valid struct format.

---

## Mac Tasks

### 1. Extract IOGPUFamily kext from kernelcache
The kernelcache for iPhone17,4 iOS 26.6.1 (23G83) was used in prior sessions (the AVE2 work).
Path was something like `~/kerneldiff_ave2/23G83_iPhone17,4/AssetData/boot/kernelcache.release.iphone17`.

Extract `com.apple.iokit.IOGPUFamily` from the kernelcache (use `ipsw` or `img4lib` to decompile/extract).
The selector dispatch table is in `__DATA_CONST.__const` of this kext.

**What to map**:
- Selector→function mapping for AGXDeviceUserClient type=1 (selectors 0–55)
- Input struct size checks for each selector (find `cmp` instructions after dispatch)
- Specific: what does sel=8 do? What struct does it expect at [0x048]?
- What selector is the "create buffer" / "allocate memory" call?

### 2. Extract IOGPU.framework from dyld shared cache
The userspace wrapper `IOGPU.framework` translates Metal API calls to IOKit struct calls.
Extract from the iOS 26.6.1 dyld shared cache using `dsc_extractor` or `dyld-shared-cache-extractor`.

**What to look for in IOGPU**:
- Functions that call `IOConnectCallStructMethod` for AGXDeviceUserClient
- Struct layouts for each selector (the framework will have them as local variables or struct types)
- Specifically: how does it construct the input for sel=8? What creates the handle at [0x048]?

### 3. Black Hat 2025 "Dead Pixel Detected" — Wang Yu (Cyberserval)
Reference for IOGPUFamily exploitation technique.
PDF: https://i.blackhat.com/BH-USA-25/Presentations/US-25-Wang-Dead-Pixel-Detected-A-Security-Assessment-of-Apples-Graphics-Subsystem-Wednesday.pdf

The `bitmap_mask` integer underflow → OOB write path in IOGPUFamily.
The techniques for converting OOB write to kernel R/W primitive are relevant even if the specific CVE (CVE-2025-24257, iOS 18.4 patch) doesn't apply to iOS 26.6.1.
Key question: is a similar `bitmap_mask` or integer underflow pattern present in the iOS 26.6.1 version?

### 4. Known patched IOGPUFamily CVEs on 26.6.1
- CVE-2026-39868: double-free, patched in 26.5.2 (26.6.1 has patch)
- CVE-2026-65346: memory corruption, patched IN 26.6.1 (26.6.1 has patch)
Both are patched. Need to find bugs open ON 26.6.1.

### 5. Chain architecture (updated for iOS 26 / A18)
```
Need: sandboxed-app-reachable kernel write
    ↓
AGXDeviceUserClient sel=? (need binary to identify)
    ↓ (OOB write into kalloc type-safe zone — same-type grooming via IOSurface)
Kernel R/W primitive
    ↓
SPTM bypass (separate step — kernel R/W alone NOT sufficient on A18)
    reference: alfiecg24/Titan (iOS 16-17 gadget, now patched in iOS 26)
    need new SPTM gadget for iOS 26.6.1
    ↓
AMFI bypass → arbitrary entitlements
    ↓
SpringBoard injection → Mac battery in status bar
```

---

## Files

| File | Contents |
|---|---|
| `kerneldiff/KEXT_26.6.1.md` | AVE2 binary analysis, CVE-2026-112689 root cause |
| `kerneldiff/KEXT_26.7.2.md` | 26.7.2 diff, all 5 patched CVEs |
| `kerneldiff/AVE2_ANALYSIS.md` | Chain architecture, CalcBufSizeOf map |
| `kerneldiff/IOKIT_SURFACE_MAP.md` | Reachable IOKit surfaces + selector probes |
| `kerneldiff/ave2_poc.py` | CVE-2026-112689 PoC (blocked by sandbox) |
| AppGroup/.../results/DFCD3C88-*.json | VideoToolbox PoC result (frames dropped) |

---

## Notes for Mac Claude

The user's device is iPhone 16 Plus (iPhone17,4), iOS 26.6.1 (23G83). A18 chip.
ResearchHost is a custom iOS app with elevated developer entitlements (`get-task-allow`, `kernel.increased-memory-limit`, `kernel.extended-virtual-addressing`).
ResearchHost runs Python scripts via `offload_python` (async) or `run_native_python` (sync).
AppGroup UUID: `92767569-346F-4ECE-B7F6-8107C7A21B5B`.
Crash logs: `AppGroup/Library/rh-wal/crashes.jsonl`.

**Start with**: extracting IOGPUFamily from kernelcache, mapping the selector table.
