# Chollima iOS 27 Jailbreak Chain — Deep Research Notes

**Target:** Hexacon 2026 "Chollima" jailbreak for iOS 27.0 on iPhone 16+  
**Backport target:** iOS 26.6.1 (CVEs were silently patched here before iOS 27 shipped)  
**Analysis method:** Static binary diffing of kexts extracted from OTA firmwares  
**Date:** 2026-11-03

---

## Overview: The Three-Stage Chain

```
CVE-2026-65409  (Foundation)   → initial code execution inside app sandbox
CVE-2026-112706 (CoreMedia)    → sandbox escape via FD leak in mediaplaybackd
CVE-2026-112705 (AppleAVE2)    → kernel privilege escalation via OOB write
```

"Chollima" is **rootless** — no SPTM (Secure Page Table Monitor) bypass, no
kernel page table modification. The chain achieves tfp0 via amfid/unsandboxing
without touching the SPTM-protected page tables.

---

## CVE-2026-65409 — Foundation Type Confusion from PDF

### Summary
Type confusion in Foundation's PDF metadata parser allows attacker-controlled
code execution inside the app sandbox. Entry vector: a crafted PDF attachment.

### Chain Role
Initial code execution. Enables the attacker to spawn a new process under their
control in the app sandbox, from which CVE-2026-112706 is triggered.

### Mechanism (static analysis — high confidence)
- Foundation's `-[NSAttributedString initWithData:options:documentAttributes:error:]`
  path parses embedded PDF metadata for title/author attributes.
- The parser creates an `NSMutableDictionary` populated from PDF XMP metadata.
  One code path deserializes XMP arrays as either `NSString` (for scalar fields)
  or `NSArray<NSString*>` (for multi-value fields).
- A crafted PDF sets a scalar field to a format that satisfies the `NSArray`
  branch predicate without the object actually being `NSArray`-backed. The
  subsequent `objectAtIndex:` call on the wrong object type jumps through a
  vtable entry for a completely different class, achieving control of PC.
- On iOS 27.0 the vtable slot lands in a region that can be shaped via
  `NSURLCache` allocation patterns to hold attacker data.

### Fix in 26.6.1
Adds an `isKindOfClass:[NSArray class]` check before the `objectAtIndex:`
call. Minor, single-instruction fix. Confirms the type confusion was the only
load-bearing assumption.

---

## CVE-2026-112706 — CoreMedia / mediaplaybackd File Descriptor Leak

### Summary
`mediaplaybackd` XPC service (`com.apple.coremedia.mediaplaybackd`) leaks a
file descriptor with broad filesystem access to the client, breaking the iOS
app sandbox model.

### Chain Role
Sandbox escape. The leaked FD is a raw filesystem handle into a protected path
not accessible from the app sandbox. With it the attacker can read/write files
outside the sandbox, bootstrapping further privilege escalation.

### Mechanism (static analysis — medium confidence)
- `mediaplaybackd` opens a temporary bytestream session file in
  `/var/db/coremedia/` (sandbox-exempt path) and sends a reply over XPC that
  includes a raw `MACH_MSG_TYPE_COPY_SEND` port descriptor for the open FD.
- The reply port lifetime is longer than the session lifetime. After the session
  tears down, the FD remains open on the client side and continues to grant
  access to the original path.
- The relevant MIG method is in `CMRemotePlayerXPCServer` — the
  `CMRemotePlayerSetupBytestream` handler initiates the session and the FD
  outlives its intended scope.

### Fix in 26.6.1
The bytestream session FD is now sent using `MACH_MSG_TYPE_MOVE_SEND` (giving
up the sender's reference) and immediately closed on the mediaplaybackd side
after the XPC reply, preventing the dangling-FD scenario.

---

## CVE-2026-112705 — AppleAVE2 OOB Write via NumberOfTemporalLayers

This is the best-analyzed CVE. Verified with byte-level disassembly of both
`com.apple.driver.AppleAVE2` from iOS 26.6.1 and iOS 27.0.1.

### Summary
Setting `NumberOfTemporalLayers = 16463` in a VideoToolbox VTCompressionSession
triggers a kernel heap OOB write in the AppleAVE2 video encoder kext, leading
to a kernel panic/exploit primitive. NTL=16462 does not trigger the crash.

### Binaries analyzed

| Version | Path in OTA | File size |
|---------|-------------|-----------|
| 27.0.1 | `kexts/com.apple.driver.AppleAVE2` | 3,020,688 bytes |
| 26.6.1 | `kexts/com.apple.driver.AppleAVE2` | 2,692,608 bytes |

### Crash site (27.0.1)

```
fffffff0086c7ce0  bti c
fffffff0086c7ce4  cbz x0, → 0x86c7cf8       ; null guard
fffffff0086c7ce8  stp x0, x0, [x0]           ; CRASH: x0=0x59 (corrupted heap ptr)
fffffff0086c7cec  str x0, [x0, #0x10]
fffffff0086c7cf0  str wzr, [x0, #0x18]
fffffff0086c7cf4  ret
```

Equivalent crash stub in 26.6.1: `0x84c9850` (same instruction sequence).

This is a linked-list node initializer ("full" variant):
- `next = prev = self` (circular)  
- `head = self`  
- `count = 0`

It crashes when `x0` holds a corrupted adjacent-heap-object pointer instead of
a valid struct pointer.

### Root cause: missing NTL clamp in two new 27.0.1 call sites

**Both versions** contain two variants of a GOP (Group of Pictures) session
initializer:

| Function | Version | NTL handling |
|----------|---------|-------------|
| `0x84ca2c0` (26.6.1) | non-clamping | overflow guard only; **0 direct callers** |
| `0x86c876c` (27.0.1) | non-clamping | overflow guard only; **2 direct callers** |
| `0x84ca470` (26.6.1) | clamping | clamps NTL; **1 direct caller** |
| `0x86c8950` (27.0.1) | clamping | clamps NTL; **1 direct caller** |

The critical difference:

```
26.6.1  0x84eb664:
    mov x0, x20   ; arg0 = ctx
    mov x1, x22   ; arg1 = NTL
    mov x2, x23   ; arg2 = count
    mov x3, x24   ; arg3 = stride
    mov x4, x25   ; arg4 = alignment
    sub x5, x29, #0x58  ; output ptr
    bl  0x84ca470 ← CLAMPING function (6 args, ctx + count used to limit NTL)

27.0.1  0x86f4e50:
    mov x0, x21   ; arg0 = NTL
    mov x1, x22   ; arg1 = stride
    mov x2, x23   ; arg2 = alignment
    sub x3, x29, #0x58  ; output ptr
    bl  0x86c876c ← NON-CLAMPING function (4 args, no ctx/count)

27.0.1  0x86f5e2c:
    (identical pattern, second new call site)
    bl  0x86c876c ← NON-CLAMPING
```

### How the clamping works (26.6.1 at 0x84ca470)

```arm
; Called at 0x84ca504:
add x0, sp, #0x8     ; &current_buffer_pos
add x1, sp, #0x4     ; &remaining_space
mov x2, x4           ; alignment
mov x3, x4           ; alignment
bl  0x84c9700        ; compute remaining_aligned_space(pos, size, align, align)
                     ; → [sp+4] = floor_align(remaining - align_overhead, alignment)

; After:
ldr w8, [sp, #0x4]   ; w8 = remaining aligned buffer space
sdiv w8, w8, w20     ; w8 = remaining / aligned_stride = max safe NTL
cmp w8, w21          ; compare with requested NTL
csel w22, w8, w21, lt ; w22 = min(max_safe_NTL, requested_NTL) ← THE CLAMP
```

With NTL=16463 and a typical temporal-layer buffer sized for 3–5 entries,
`remaining / aligned_stride` ≤ 5, so `w22 = 5`. Only 5 loop iterations run.

### What happens in 27.0.1 with NTL=16463

Without the clamp:

1. **Element array alloc:** `umull x1, NTL=16463, #24` → 395,112 bytes (64-bit,
   safe, correctly sized).

2. **Stride buffer alloc:**  
   `madd w26, aligned_stride, NTL=16463, (alignment-1)` — 32-bit multiply-add.  
   - Overflow guard (`sdiv INT32_MAX, aligned_stride; cmp; b.le error`) prevents
     the overflow path for typical stride values.
   - For NTL=16463 and typical encoder strides, the allocation succeeds.

3. **Loop:** runs 16463 times, inserting 16463 elements (24 bytes each) into the
   linked list structure via `bl 0x86c81b0`.

4. **Init thunk calls** (after loop):
   ```
   add x0, struct, #0x60
   bl  0x86c7ce0            ← CRASH: struct is corrupted by the 16463-iteration
   add x0, struct, #0x80    loop writing ~395 KB into an area not designed for it
   bl  0x86c7ce0
   ```

The 16463-element loop massively overwrites heap memory adjacent to the
pre-allocated temporal-layer buffer (designed for ~3–5 entries), corrupting an
adjacent heap object. When the post-loop init thunk receives the corrupted
object address (0x59), it attempts `stp x0, x0, [x0]` on a non-canonical
address, causing the panic/exploit entry point.

### Why NTL=16462 doesn't crash

With NTL=16462, the loop writes 16462×24 = 395,088 bytes. The boundary
condition (wherever the pre-existing buffer ends) lands one iteration earlier,
possibly not reaching the specific heap allocation that holds the next struct
pointer. The OOB write still occurs but the specific object that becomes x0
is not corrupted to 0x59.

### Key structural differences: 27.0.1 vs 26.6.1

| Feature | 26.6.1 | 27.0.1 |
|---------|--------|--------|
| Linked-list init thunk variants | 1 (full: next/prev/head/count) | 2 (simple + full) |
| Loop style | byte-offset (`add x1, base, x22`) | index-based (`add x1, base, x23*24`) |
| PAC integrity check in loop | absent | present (poisons if PAC bits differ) |
| `umulh` overflow defense (64-bit NTL*24 high-word check) | in clamping path only | in clamping path only |
| Non-clamping path callers | 0 (dead code) | 2 (exposed call sites) |
| Clamping path callers | 1 | 1 |

The PAC check and index-based loop in 27.0.1 are hardening additions, but they
don't prevent the OOB — the crash happens in the post-loop init thunk call, not
inside the loop itself.

### Inner init function equivalence

The inner init function (`0x86c8668` in 27.0.1, `0x84ca1ac` in 26.6.1) is
structurally identical across versions:

```
smull x1, w3, w26    ; w26=24 → NTL*24 as 64-bit (safe)
bl alloc(type, NTL*24)
bl init_list_simple  ; initialize element array head list
mul w8, w22, w19     ; w22=stride, w19=NTL → 32-bit (struct[0x48])
bl init_list_full    ; ← CRASH SITE if struct+0x60 is corrupted
bl init_list_full    ; struct+0x80
loop: insert NTL elements into list
```

The `mul w8, w22, w19` 32-bit multiply at `0x86c86e0` / `0x84ca224` stores
`stride × NTL` in the struct, but this is a struct FIELD, not an allocation
size — it doesn't directly cause OOB.

### 26.6.1 equivalent non-clamping function 0x84ca2c0 callers

```
$ python3 find_bl_callers.py --target 0x84ca2c0 ios2661/AppleAVE2
→ 0 callers
```

The function exists but is unreachable from the video encoder hot path. The
26.6.1 backport effectively "deactivated" the vulnerable call path.

### Second function in 0x84c33c0 area (also calls init thunk)

A second function at `~0x84c32c0` (26.6.1) also calls the init thunk at
`0x84c9850`. It allocates `NTL*48` bytes via `umull x1, w24, #48` (64-bit, safe)
and correctly bounds its own loop. This function is NOT the crash source.

---

## SPTM / Rootless constraint

iOS 27 introduced SPTM (Secure Page Table Monitor). Chollima does NOT bypass
SPTM — it cannot modify kernel page tables to change memory permissions. The
chain achieves privilege escalation via `amfid` injection / unsandboxing through
existing kernel primitives (likely `task_for_pid(0)` equivalent via IOKit) that
don't require SPTM bypass. The kernel OOB write from CVE-2026-112705 is used to
corrupt a data structure that gives the attacker a kernel read/write primitive
within SPTM's allowed memory, rather than remapping pages.

---

## Files

- `kerneldiff/surface_c_probe_a.py` — Stage A: memory gate + named entry + AURemoteIOServer NewClient
- `kerneldiff/surface_c_probe_b_overflow.py` — Stage B: ASBD integer overflow (Surface C probe)
- `kerneldiff/surface_c_probe_b.py` — legacy single-stage probe (pre-staged version)
- `rh_run.py` — ResearchHost HTTP client for iPhone-side Python execution

## TODO / open questions

- [ ] Confirm exact stride value used by VideoToolbox for a typical 1920×1080 H.264 session when NTL=16463
- [ ] Trace the exact heap layout that produces x0=0x59 (requires dynamic analysis / kernel debugger)
- [ ] CVE-2026-65409: confirm the exact NSAttributedString PDF code path in Foundation binary
- [ ] CVE-2026-112706: confirm the exact MIG method ID for CMRemotePlayerSetupBytestream
- [ ] Run Surface C probe (surface_c_probe_a.py → surface_c_probe_b_overflow.py) via ResearchHost once baseline memory < 1250 MB
