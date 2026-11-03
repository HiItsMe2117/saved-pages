# Chollima iOS 27 Jailbreak Chain — Deep Research Notes

**Target:** Hexacon Paris 2026 "Chollima" jailbreak — demonstrated live on iPhone 18 Pro running iOS 27.0.1  
**Backport target:** iOS 26.6.1 (CVEs were silently patched here before iOS 27 shipped)  
**Analysis method:** Static binary diffing of kexts extracted from OTA firmwares + OSINT  
**Date:** 2026-11-03  
**Status:** Untethered (root SSH + Sileo confirmed on video). Fixed in iOS 27.2 (Oct 26, 2026).

---

## Overview: The Three-Stage Chain

```
CVE-2026-65409  (Foundation)   → initial code execution inside app sandbox
CVE-2026-112706 (CoreMedia)    → sandbox escape via FD leak in mediaplaybackd
CVE-2026-112705 (AppleAVE2)    → kernel privilege escalation via OOB write
```

"Chollima" was demonstrated as **untethered** (reboot-persistent). Whether it includes an
SPTM bypass is **almost certainly no** — no public bypass exists for A15+/iOS 17.4+ and the
only secondhand claim comes from a single unverified tweet. The chain reaches kernel r/w via
data-only struct corruption, consistent with a rootless design.

**iOS 26 / A18 security layer summary (relevant to exploitation model):**
- **SPTM**: present on A15+ since iOS 17; no public bypass for A18/iOS 18+
- **PAC (FPAC)**: hardware-enforced on A15+; pointer forgery not viable
- **BTI**: confirmed in AppleAVE2 binary (bti c instructions)
- **Hardware MTE**: A19/M5 only — **NOT present on A18 (iPhone 16)**
- **Software MTE**: iOS 26 enables software MTE enhancements for kernel and ~70 userland processes; raises the bar but bypassable by data-only chains
- **Exclaves / hypervisor**: iOS 26 introduces a hardware hypervisor layer above SPTM (research ongoing — `cloverfield11/ios26-hypervisor-research`); implications for the exploitation model are not yet understood

---

## CVE-2026-65409 — Foundation (Calif.io + Claude/Anthropic Research)

### Attribution
Credited in Apple's iOS 26.7 advisory to **Bruce Dang of Calif.io, in collaboration with
Claude and Anthropic Research**.

### Official Impact
"An app may be able to cause a denial of service." CVSS 5.5 Medium (local, no privileges,
user interaction required, availability impact only). Fix: "type confusion issue addressed
with improved memory handling."

### Chain Role
Initial code execution inside the app sandbox (required to reach CVE-2026-112706). The
official advisory describes DoS only; Calif.io has not published a full writeup. The below
mechanism is **unconfirmed speculation** from static analysis.

### Mechanism (static analysis — LOW CONFIDENCE, unverified)
- Foundation's `-[NSAttributedString initWithData:options:documentAttributes:error:]`
  path parses embedded PDF metadata for title/author attributes.
- The parser creates an `NSMutableDictionary` populated from PDF XMP metadata.
  One code path deserializes XMP arrays as either `NSString` (scalar) or
  `NSArray<NSString*>` (multi-value).
- A crafted PDF may satisfy the `NSArray` branch predicate without the object actually
  being `NSArray`-backed, causing `objectAtIndex:` to jump through a wrong vtable entry.
- On iOS 27.0 the vtable slot may land in a region shapeable via `NSURLCache` allocation
  patterns.

### Fix in 26.6.1
Adds an `isKindOfClass:[NSArray class]` check before the `objectAtIndex:` call.

### Open questions
- [ ] Confirm exact NSAttributedString PDF code path in Foundation binary
- [ ] Whether actual impact is code execution or only DoS (official says DoS)

---

## CVE-2026-112706 — CoreMedia / mediaplaybackd FD Leak

### Attribution
Credited to **Adriatik Raci, Rodolphe BRUNETTI (@eisw0lf, Lupus Nova), Chris Bailey
(Short Circuit)**. NOT Calif.io.

### Official Impact
"An app may be able to access restricted files." Fix: "permissions issue addressed with
additional restrictions."

### Chain Role
Sandbox escape. The leaked FD grants read access to protected media library files,
enabling further privilege escalation.

### Mechanism (partially verified — medium confidence)
- Service: **`com.apple.coremedia.mediaplaybackd.bytestream.xpc`** (NOT the main
  `com.apple.coremedia.mediaplaybackd` endpoint)
- Protocol: **FigXPC** (3-stage handshake: `.rp1` → `.rp2` → `.org`, then "Curl" message)
  NOT MIG
- The FD is returned in a `ByteStreamDetails` FigXPC reply dictionary
- Access scope: **read-only**, limited to `/private/var/mobile/Media/iTunes_Control/iTunes/`
  (PlayCounts.plist, media library DB). Photos, messages, keychain, TCC — all denied.

### Fix in 26.6.1
**Path-authorization check**: the daemon now verifies the client's sandbox identity before
opening paths on its behalf. The FD itself is not the issue — the lack of path validation is.

### What the notes previously got wrong
- ~~"MACH_MSG_TYPE_COPY_SEND" / "MACH_MSG_TYPE_MOVE_SEND" — the fix is NOT about send rights~~
- ~~"CMRemotePlayerXPCServer / CMRemotePlayerSetupBytestream" — unconfirmed handler name~~
- ~~"broad filesystem access" — access is read-only, media library only~~

### Open questions
- [ ] Confirm the exact FigXPC "Curl" message handler name in mediaplaybackd binary
- [ ] Confirm the exact path exposed (`iTunes_Control` area)

---

## CVE-2026-112705 — AppleAVE2 OOB Write via NumberOfTemporalLayers

This is the best-analyzed CVE. Verified with byte-level disassembly of
`com.apple.driver.AppleAVE2` from iOS 26.6.1. Crash fingerprint from independent
PoC for iOS 27.0.1.

### Attribution
Credited to **Marco Schmitt, Andrey Chernykh, Josh Maine of Calif.io**.
Fixed in iOS 26.7.2 and 27.2.

### Summary
Setting `kVTCompressionPropertyKey_NumberOfTemporalLayers = 16463` in a
`VTCompressionSession` triggers a kernel heap corruption in the AppleAVE2 video
encoder kext, leading to a kernel panic / exploit primitive. NTL=16462 does not crash.

### Binaries analyzed

| Version | File size |
|---------|-----------|
| 26.6.1 | 2,692,608 bytes |
| 27.0.1 | 3,020,688 bytes |

TEXT_EXEC: fileoff=0xd8000, vmbase=0xfffffff0084c24b0 (26.6.1)

### Crash fingerprint (iOS 27.0.1, from independent PoC)

```
Kernel data abort: PC = TEXT_EXEC+0xDA78 = VA 0xfffffff0086c7ce8
  NTL=16463:  far=0x59,          x19=0x1
  NTL=16464:  far=0x100000059,   x19=0x100000001
  NTL=16462:  no crash
```

The crash instruction is `stp x0, x0, [x0]` — the "full" linked-list node initializer
(`init_list_head_full`). Equivalent crash site in 26.6.1: `0x84c9850`.

#### The 2^32 overflow fingerprint

Between NTL=16463 and NTL=16464:
- x0 increases by exactly **2^32** (0x100000059 − 0x59 = 0x100000000)
- x19 increases by exactly **2^32** (0x100000001 − 0x1 = 0x100000000)

Both registers change by exactly 2^32 when NTL increments by 1. This is a direct
fingerprint of a **32-bit arithmetic overflow** in the computation that produces these
values — not a coincidence. The lower 32 bits (0x59 and 0x1) are the post-overflow
remainders; the upper 32 bits (0/1) count the carry. Pinpointing the specific
instruction requires dynamic analysis.

Candidate 32-bit overflow site in 26.6.1 inner init `0x84ca1ac`:
```arm
mul w8, w22, w19   ; w22=aligned_stride, w19=NTL → 32-bit aligned_stride×NTL
stp w8, w19, [x20, 0x48]  ; stored at struct1+0x48 and struct1+0x4c
```
This struct field is NOT an allocation size, but if later loaded as part of a pointer
computation, the 32-bit overflow would propagate to the crash address.

### Attack path (VERIFIED by direct binary analysis)

```
VTCompressionSessionCreate + kVTCompressionPropertyKey_NumberOfTemporalLayers=16463
  → property setter writes NTL=16463 to gop_config[+0x4]
  → encode trigger
  → 0x85f64e4: fn_GOP_apply(session->gop_config)    [session+0x20 = gop_config]
  → 0x84ec038: fn_GOP_init_or_skip(gop_config)
      → 0x84ec07c: bl 0x84ebfc4                        ; list_iterator(gop_config, sp-0x28)
      → 0x84ec088: ldr w8, [gop_config+0x40]           ; w8 = current_count
      → 0x84ec08c: ldr w9, [gop_config+0x10]           ; w9 = max_count
      → 0x84ec094: b.ge skip                            ; if current_count >= max_count: skip
      → 0x84ec098: ldp w0, w1, [gop_config+4]          ; w0=NTL(user-controlled!), w1=stride(internal)
      → 0x84ec09c: ldr w2, [gop_config+0xc]            ; alignment (internal)
      → 0x84ec0a4: bl 0x84ca290                         ; NON-CLAMPING init — NTL unchecked
```

The non-clamping call only fires when `current_count < max_count` — on the FIRST encode
call that initializes this GOP slot, not on every frame. `0x84ebfc4` is a list-iterator
helper (not in the crash path itself).

**gop_config field layout (from 0x84ec038 disassembly):**

| Offset | Field | Notes |
|--------|-------|-------|
| +0x04 | NTL | user-controlled via `kVTCompressionPropertyKey_NumberOfTemporalLayers` |
| +0x08 | stride | internal encoder value |
| +0x0c | alignment | internal encoder value |
| +0x10 | max_count | upper bound for counter guard |
| +0x40 | current_count | compared against max_count before non-clamping call |

NTL is **user-controlled** (set via VideoToolbox property → stored in gop_config[+4]).
Stride and alignment are **internal** encoder values, not user-controlled.

### GOP init function variants (26.6.1, VERIFIED)

| Address | Callers | NTL handling |
|---------|---------|-------------|
| `0x84ca290` | 2 (`0x84ec0a4`, `0x84eb0d8`) | Non-clamping: overflow guard only (`INT32_MAX / stride ≥ NTL`) |
| `0x84ca470` | 1 (`0x84eb664`) | Clamping: `compute_remaining → sdiv → csel min(max_safe, NTL)` |

Both callers of `0x84ca290` and the caller of `0x84ca470` are in the same large dispatch
function `0x84eaef0`. However:
- `0x84eb0d8` (calls non-clamping): **unreachable in practice** — the sole caller of
  `0x84eaef0` at `0x85f33b4` passes a literal `mov w1, 0`, so bit0 of arg1 is always 0,
  always routing to the clamping path via `0x84eb664`.
- `0x84ec0a4` (calls non-clamping): **live** — reached via `0x84ec038` ← `0x85f64e4`.

The fork agent's claim "non-clamping function has 0 callers in 26.6.1" was wrong on two counts:
the function address was wrong (`0x84ca2c0` is a mid-function offset inside `0x84ca290`),
and the live caller via `0x84ec038` was missed entirely.

### How the clamping works (`0x84ca470`, VERIFIED)

```arm
; compute max safe NTL from remaining buffer space:
bl  0x84c9700        ; compute_remaining(ctx, &remaining, alignment, alignment)
ldr w8, [sp, #0x4]   ; w8 = remaining aligned buffer space
sdiv w8, w8, w20     ; w8 = remaining / aligned_stride = max_safe_NTL
cmp w8, w21          ; compare with requested NTL
csel w22, w8, w21, lt ; w22 = min(max_safe_NTL, requested_NTL) ← THE CLAMP
```

### Inner init (`0x84ca1ac`) allocation safety (VERIFIED)

All allocations in the inner init are correctly sized:
```arm
smull x1, w3, w26    ; x1 = NTL×24 as 64-bit (SAFE) → element array alloc
bzero(element_array, NTL×24)
umull x23, w19, w26  ; x23 = NTL×24 as 64-bit (SAFE) → loop bound
mul w8, w22, w19     ; w22=stride, w19=NTL → 32-BIT overflow possible → struct field at +0x48
```

The loop inserts NTL elements into the linked list. All memory accesses are within
correctly-sized allocations. The crash mechanism requires dynamic analysis to pinpoint —
the 32-bit overflow fingerprint (`mul w8, w22, w19` or a similar computation) is the
likely source of the corrupt value.

### Public PoC assessment
The public crash (NTL=16463) is a **kernel panic / DoS primitive** on its own.
"Fixed-offset constant fill, no arbitrary read/write capability" — the Chollima chain
likely uses additional primitives to convert the OOB write into a full kernel r/w.

### linked-list helper functions (26.6.1, VERIFIED)

| Address | Name | Description |
|---------|------|-------------|
| `0x84c9850` | `init_list_head_full` | circular init: next=prev=head=self, count=0; **CRASH SITE** |
| `0x84c982c` | `init_list_head_simple` | stores xzr at +0x10 instead of self |
| `0x84c9d04` | `link_element` | inserts element into list; does NOT call init |
| `0x84c9700` | `compute_remaining` | computes remaining aligned buffer space (used by clamping path) |

---

## Files

- `kerneldiff/surface_c_probe_a.py` — Stage A: memory gate + named entry + AURemoteIOServer NewClient
- `kerneldiff/surface_c_probe_b_overflow.py` — Stage B: ASBD integer overflow (Surface C probe)
- `kerneldiff/surface_c_probe_b.py` — legacy single-stage probe (pre-staged version)
- `rh_run.py` — ResearchHost HTTP client for iPhone-side Python execution

## TODO / open questions

- [ ] Pinpoint the exact 32-bit overflow instruction that produces x0=0x59 (dynamic analysis needed)
- [ ] Confirm whether Chollima includes a true SPTM bypass (disputed — not confirmed by Calif.io)
- [ ] CVE-2026-65409: confirm actual impact — DoS or code execution — in Foundation binary
- [ ] CVE-2026-112706: confirm the exact FigXPC "Curl" handler name in mediaplaybackd binary
- [ ] Run Surface C probe (surface_c_probe_a.py → surface_c_probe_b_overflow.py) via ResearchHost once baseline memory < 1250 MB
