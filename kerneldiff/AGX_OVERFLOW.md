# AGX sel=8 Integer Overflow — Page-Count Size Check Bypass
Date: 2026-11-05

## Summary

`AGXDeviceUserClient` selector 8 contains an integer overflow in its allocation
size check. The `[0x014]` field (page count, u32) is multiplied by `0x1000`
(page size) in a **32-bit computation**. The check validates the wrapped result,
not the original value, allowing an attacker to pass a huge page count that
appears to be a small allocation.

## Confirmed Behavior (black-box, iOS 26.6.1 / A18)

| page_count  | (page_count × 0x1000) & 0xffffffff | Result  | Notes                      |
|-------------|-------------------------------------|---------|----------------------------|
| 0x0007ff    | 0x007ff000                          | NoRes   | Legitimate max (2047 pages ~8MB) |
| 0x000800    | 0x00800000                          | BadArg  | Exceeds limit — rejected   |
| 0x0fffff    | 0xfffff000                          | BadArg  | Rejected                   |
| **0x100000**| **0x00000000** (overflow)           | **NoRes** | **Bypasses check!**      |
| **0x100001**| **0x00001000** (overflow)           | **NoRes** | **Looks like 1 page!**   |
| **0x100010**| **0x00010000** (overflow)           | **NoRes** | **Looks like 16 pages**  |
| 0x1007ff    | 0x007ff000                          | NoRes   | Looks like 2047 pages      |
| 0x100800    | 0x00800000                          | BadArg  | Wrapped value still caught |

## Struct Layout (sel=8, minimum 0x58 bytes)

```
[0x000]  u32  unknown (0 ok)
[0x004]  u32  type/format — must be multiple of 0x100 (0x0, 0x100, 0x200, 0x300… all pass)
[0x008]  u64  unknown
[0x014]  u32  PAGE COUNT — overflow field (see above)
[0x018]  u64  unknown
...
[0x048]  u32  resource handle — 0 → NoRes; non-zero → kIOReturnError (handle lookup fail)
[0x04c]  u32  handle type
[0x050]  u32  unknown
[0x054]  u32  unknown
```

Struct terminates at byte 0x57 (88 bytes minimum).

## Exploitation Path (requires Mac binary analysis to complete)

### Current blocker
`[0x048]` handle must be a valid resource handle from a "create" selector.
All create selectors (0–54, except 8) are content-gated (return BadArgument
regardless of struct size). Their exact field requirements need IOGPUFamily
kext binary analysis.

### Chain once handle is obtained

```
1. Open IOSurface heap spray
   - Create N×4KB IOSurface objects to fill target kalloc zone
   - Leave gap for the victim allocation

2. sel=8 with page_count=0x100001, valid handle
   - Kernel size check: (0x100001 × 0x1000) & u32 = 0x1000 → passes
   - Kernel allocates 4KB buffer for the resource
   - Resource metadata records page_count=0x100001 (or uses it for iteration)

3. Trigger resource population / page mapping
   - Driver iterates page_count=0x100001 entries
   - Writes 0x100001 × (entry_size) bytes into the 4KB buffer
   - OOB write of ~GBs into adjacent IOSurface control struct

4. IOSurface corruption → type confusion → kernel R/W primitive
   - Corrupt IOSurface's size field → OOBR/W of arbitrary kernel data

5. SPTM bypass → AMFI bypass → SpringBoard injection
```

### Alternative: smaller controlled OOB

For a tighter, more controlled primitive, use:
- page_count = 0x100001 → allocates 0x1000 bytes, appears to have 1 extra page
- Write exactly 0x1001 × entry_size bytes → 1 page OOB (single-page overflow)
- More predictable heap overlap

## Key Unknowns (for Mac binary analysis)

1. **What selector creates a resource handle?** (look for selectors that return handles in output struct)
2. **How does the driver use `[0x014]` after the size check?** Does it use the original u32 field or the computed wrapped size for subsequent operations?
3. **What is `entry_size` in the page-population loop?** (determines actual OOB write size)
4. **Is there a secondary size check using the original field value?** (would close the bypass)

## Files

- `agx_minsize_sweep.json` — full 55-selector minimum-size sweep (stdout from offload job)
- `IOKIT_SURFACE_MAP.md` — reachable IOKit surfaces
- `SESSION_HANDOFF.md` — full Mac task list
