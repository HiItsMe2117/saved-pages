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
(`init_list_head_full`). The equivalent in 26.6.1 is `FUN_0x84c9850`, but that function has
a NULL guard and a larger struct layout — 26.6.1 **does not crash** at NTL=16463 (confirmed
by live device test, 2026-11-03).

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

### Ghidra decompilation — confirmed struct1 layout (VERIFIED 2026-11-03)

Java 25 required for Ghidra 12.2 (min=25, `application.java.min=25`). Temurin 25.0.5
installed at `/tmp/temurin25/jdk-25.0.5+8/Contents/Home`. Decompilation ran clean.

#### GOP buffer struct1 field map (from `FUN_fffffff0084ca1ac` pseudocode)

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| +0x00–0x17 | 8×3=24 | list linkage (next/prev?) | zeroed |
| +0x18 | 8 | self_ptr | set in `FUN_fffffff0084ca290` post-call |
| +0x20 | 8 | element_array_ptr (lVar6) | set post-call |
| +0x28 | 8 | raw_buffer_ptr (lVar7) | set post-call |
| +0x30 | 4 | struct_size = 0xa8 | set post-call |
| +0x34 | 4 | NTL × 24 (element array bytes) | set post-call (32-bit) |
| +0x38 | 4 | buffer_size = iVar4 | set post-call (32-bit) |
| +0x40 | 8 | aligned_buffer_ptr | `param_1[8] = param_3` |
| +0x48 | 4 | aligned_stride × NTL (32-bit) | `*(uint*)(param_1+9) = param_5*param_4` |
| +0x4c | 4 | NTL | `*(uint*)(param_1+0x4c) = param_4` |
| +0x50 | 4 | aligned_stride | `*(int*)(param_1+10) = param_5` |
| +0x58 | 8 | element_array_ptr (lVar6 again) | `param_1[0xb] = param_2` |
| +0x60 | ~24 | list_head_A | initialized by `init_list_head_full` |
| +0x80 | ~24 | list_head_B | initialized by `init_list_head_full` |
| +0xa4 | 4 | remaining_count (= NTL initially) | decremented by FUN_fffffff0084ca770 |

#### The `mul w8, w22, w19` overflow: PROTECTED by overflow guard (CORRECTED)

The 32-bit write at struct1+0x48 (`aligned_stride × NTL mod 2^32`) is **guarded**
in `FUN_fffffff0084ca290` (the non-clamping init):
```c
iVar3 = 0x7fffffff / (int)uVar2;   // = INT32_MAX / aligned_stride
if (iVar3 <= iVar9) return 0xfffffc09;  // REJECTS if NTL ≥ INT32_MAX/aligned_stride
```

This guard ensures `aligned_stride × NTL < INT32_MAX < 2^32` — **no 32-bit overflow
is possible for any inputs that pass the guard**. For NTL=16463 and typical frame
strides (1920–7680 bytes), the guard passes and the product does NOT overflow.

**Consequence:** The "write-any-32-bit-value via aligned_stride × NTL" theory from the
gap analysis is INCORRECT for the crash at NTL=16463. The actual corruption mechanism
requires dynamic analysis — the 2^32 overflow fingerprint in x0/x19 comes from a
DIFFERENT 32-bit computation, not from struct1+0x48. Possibly from `FUN_fffffff0084ca770`
pointer arithmetic or a function that reads struct1 fields later in the pipeline.

#### FUN_fffffff0084ca770 — GOP buffer frame dequeue (VERIFIED)

```c
lVar3 = FUN_fffffff0084c9c24(param_1 + 0x60);  // dequeue element from list_head_A
FUN_fffffff0084c9930(param_1 + 0x60);           // list update
FUN_fffffff0084c9d04(param_1 + 0x80, lVar3);   // link element to list_head_B
iVar1 = *(int *)(param_1 + 0x50);               // iVar1 = aligned_stride
*param_2 = *(long *)(param_1 + 0x40) +          // output_ptr = buffer_base +
    (long)((int)((ulong)(lVar3 - *(long *)(param_1 + 0x58)) >> 3) * iVar1 * -0x55555555);
// The `* -0x55555555` is the compiler's multiply-by-(1/3 mod 2^32) trick:
// (byte_offset_of_element / 8 / 3 = element_index) → element_index × aligned_stride
*(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + -1;  // decrement remaining_count
```

This function is called right after GOP init in `fn_GOP_init_or_skip`. It reads
aligned_stride from struct1+0x50 — **not +0x48** — for the pointer arithmetic.
The computed offset `element_index × aligned_stride` is also a 32-bit multiply;
the same overflow guard prevents it from overflowing for the same reason.

### Dynamic analysis — 26.6.1 device test (2026-11-03)

**Key findings from live device testing via offload_python (iPhone 16+, iOS 26.6.1):**

1. **H.264 rejects NTL property entirely** — `VTSessionSetProperty` returns `-12900` for any
   NTL value on an H.264 session. The crash is **HEVC (`hvc1`)-specific**.

2. **HEVC on 26.6.1 does NOT crash at NTL=16463** — property set succeeds (status=0x0),
   `VTCompressionSessionEncodeFrame` returns 0x0 with `info=0x1` (async queued), no panic.
   Tested NTL values 16462, 16463, 16464, 32767, 65535 — all accepted without crashing.

3. **CVE-2026-112705 is a 27.x-only bug** — confirmed by Ghidra diff:

   | Feature | 26.6.1 `FUN_0x84c9850` | 27.0.1 crash site |
   |---------|------------------------|-------------------|
   | NULL guard | `if (param_1 != 0)` before write | absent — writes unconditionally |
   | list_head size | 4 fields: next, prev, ptr, count (0x1c bytes) | 3 fields: next, prev, count (0x18 bytes) |
   | GOP struct layout | larger struct → different offsets | smaller → NTL=16463 lands at 0x59 |

   Apple restructured the GOP/list-head code between 26.6.1 and 27.0.1, removing the
   NULL guard and shrinking the list_head struct, introducing the vulnerability.

4. **Practical implication**: a 26.6.1 device cannot be reached via CVE-2026-112705.
   The `vt_crash_reproducer.py` script (HEVC, NTL=16463) is valid for 27.x targets;
   on 26.6.1 it confirms the VideoToolbox pipeline is reachable but exits cleanly.

### Public PoC assessment
The public crash (NTL=16463) is a **kernel panic / DoS primitive** on 27.x only.
The crash at `init_list_head_full` with x0=0x59 requires dynamic analysis on a 27.x device
to pinpoint — static analysis rules out the struct1+0x48 overflow guard path for typical
frame strides, and 26.6.1 is protected by the NULL guard in the list_head initializer.

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
