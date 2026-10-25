# sanitize_integer Dispatch Bypass Analysis — iOS 26.6.1 SPTM

*Generated 2026-10-25 | iOS 26.6.1 sptm_26.6.1.bin*

---

## Summary

The `sanitize_integer` mechanism in 26.6.1 SPTM uses a **2-step AND+CMP pattern**
to validate raw integer values from XNU before they are used as dispatch table
indices. The basic table_id sanitizer is structurally sound, but three investigation
targets were identified:

1. **Endpoint 15 reachability gap**: The bounds check at `0xdd47c` uses
   `CMP w21, #0xf; B.CS` (unsigned ≥ 15 = violation), which blocks endpoint 15.
   Tables declaring 16 endpoints can never call ep15 through this path.

2. **Entry address mask truncation**: `AND x10, x8, #0x0000000ffffffff0`
   at `0xdd5d8` clears bits above bit 35. Physical addresses above 68 GB are
   silently truncated before range comparison.

3. **Domain-3 (SK) dispatch path**: Caller domain 3 takes a reduced-validation
   fast path. Not reachable from XNU (domain is hardware-enforced) but worth
   confirming during SK bootstrap window.

---

## Binary Layout

| Segment | vmaddr | fileoff |
|---|---|---|
| __TEXT | 0xfffffff027004000 | 0x0 |
| __DATA_CONST | 0xfffffff027018000 | 0x14000 |
| __LATE_CONST | 0xfffffff027020000 | 0x1c000 |
| __TEXT_EXEC | 0xfffffff027094000 | 0x90000 |

**Key dispatch offsets:**

| Item | File offset | vmaddr |
|---|---|---|
| Dispatch handler prologue | 0xdcfdc | 0xfffffff0270e3fdc |
| Main handler start | 0xdd000 | 0xfffffff0270e4000 |
| table_id AND+CMP sanitizer | 0xdd014–0xdd01c | 0xfffffff0270e4014 |
| table_id re-mask for indexing | 0xdd040 | 0xfffffff0270e4040 |
| Entry addr range check (loop) | 0xdd0dc–0xdd0e0 | 0xfffffff0270e40dc |
| Entry addr range check (high) | 0xdd108–0xdd110 | 0xfffffff0270e4108 |
| Domain-3 (SK) fast path | 0xdd114 | 0xfffffff0270e4114 |
| VIOLATION path (table_id OOB) | 0xdd140 | 0xfffffff0270e4140 |
| Endpoint ID check | 0xdd47c–0xdd480 | 0xfffffff0270e447c |
| Entry addr mask (36-bit) | 0xdd5d8 | 0xfffffff0270e45d8 |

---

## sanitize_integer: How It Works in 26.6.1

No `sanitize_integer()` function call exists. The `UNSAFE_VALUE` annotation in
the source string `sanitize_integer(dispatch_entry_addr_U.UNSAFE_VALUE)` is a
Clang source marker. The actual sanitizer is **inline code** at each call site.

### Table ID sanitizer

```asm
; Entry: x0 = raw table_id from XNU (x16[63:32] after GENTER)
0xdd014:  AND w9, w0, #0xFF        ; step 1: mask to 8 bits
0xdd018:  CMP w9, #0x10            ; step 2: bounds check (16 = max tables)
0xdd01c:  B.CS → 0xdd140           ; if w9 >= 16: VIOLATION + panic
; Falls through: w9 ∈ [0, 15]

0xdd040:  AND x8, x0, #0xFF        ; re-mask for array indexing (x8 = table index)
```

The first AND truncates to 8 bits. The CMP limits to 0–15. All downstream
indexing uses x8 (already masked), never raw x0. **No bypass found for table_id.**

### Entry address sanitizer — Layer 1: domain check

```asm
0xdd06c:  CMP w9, #0x2             ; caller state must be ≥ 2
0xdd07c:  CMP w22, #0x3            ; caller domain
0xdd080:  B.EQ → 0xdd114           ; domain == 3: SK fast path (reduced validation)
0xdd084:  CMP w22, #0x5
0xdd088:  B.CS → 0xdd1cc           ; domain >= 5: VIOLATION
```

Domains 0–4 reach full validation. Domain 3 is SK and bypasses some checks.
`w22` comes from a hardware system register (MRS instruction at 0xdd004–0xdd010)
— not forgeable from XNU GL1 level.

### Entry address sanitizer — Layer 2: range bounds

```asm
0xdd0c0:  LDR x0, [x26, #0x0]     ; load registered dispatch function pointer
0xdd0c4:  MOV x1, x21             ; endpoint arg
0xdd0c8:  BL → (validator)        ; call dispatch_table_lookup
0xdd0dc:  CMP x25, x8             ; compare count against table size
0xdd0e0:  B.CC → 0xdd0c0          ; loop: if count < size, continue
0xdd108:  CMP x8, x19             ; compare entry_addr against base
0xdd110:  B.CS → 0xdd288          ; if entry_addr >= base: out of bounds
```

Entry addresses must be within a registered dispatch table's code range.
The range [x19, x25) is loaded from SPTM's own dispatch table registry —
SPTM-controlled, not XNU-writable.

### Entry address sanitizer — Layer 3: alignment + high-bit mask

```asm
0xdd5d8:  AND x10, x8, #0x0000000ffffffff0   ; mask: keep bits [35:4] only
0xdd5c4:  CMP x21, x9                         ; compare masked value
0xdd5c8:  B.CS → 0xdd5f4                      ; out of range: violation
```

Mask value: `0x0000000ffffffff0`
- Clears low 4 bits (enforces 16-byte alignment)
- Clears bits [63:36] (caps physical address at 68 GB)

---

## Gap 1: Endpoint 15 Blocked

```asm
0xdd47c:  CMP w21, #0xf            ; endpoint_id vs 15
0xdd480:  B.CS → 0xdd69c           ; if endpoint_id >= 15: VIOLATION
; Valid range: endpoint_id ∈ [0, 14]
```

This check rejects endpoint IDs ≥ 15, permitting only 0–14 (15 values).

**Conflict**: The GENTER stub map (REPORT_GENTER_MAP.md) shows 16 stubs for the
NVMe table (0xe): endpoints 0–15. Stubs for ep14 and ep15 both exist in the
kernelcache at vmaddr `0xfffffff00b3fffa0` (ep14) and `0xfffffff00b3fffe0` (ep15).

If this CMP check applies to NVMe table calls, ep15 can never be invoked via the
standard GENTER path. Two possible interpretations:

a) **Intentional gate**: ep15 exists in the stub table as a placeholder but is
   intentionally blocked. The SPTM-side handler may not exist.

b) **Missing path**: The validation check uses `< 15` when it should use `< 16`,
   leaving ep15 callable only if there's an alternate dispatch path that skips
   this check (e.g., the domain-3 SK path at 0xdd114).

**Investigation**: Identify whether this CMP at 0xdd47c applies to ALL tables or
only specific ones. Check if ep15 of table 0xe has a SPTM-side handler.

---

## Gap 2: Entry Address 36-bit Mask Truncation

The mask `0x0000000ffffffff0` at `0xdd5d8` clips bits above bit 35.

**A18 physical memory layout:**
- DRAM base: physical `0x800000000` (32 GB)
- With 8 GB RAM: extends to `0xA00000000` (40 GB) — bits 35:33 set
- iPhone 16 Plus (8 GB): max PA ≈ `0xA00000000`

For a physical address like `0x900000040`:
- Bit 35 = 1 (set, since 0x900000040 > 0x800000000)
- After mask `& 0x0000000ffffffff0` = `0x000000000ffffffff0 & 0x900000040`

Wait — `0x0000000ffffffff0` keeps bits [35:4]:
```
0x900000040 & 0x0000000ffffffff0 = 0x000000000ffffffff0 & 0x900000040
```
Actually: `0x0000000ffffffff0` in hex:
- bit 35 = 1 ✓ (kept by mask)
- bit 36 = 0 (cleared by mask)

So addresses at 0x800000000–0xFFFFFFFFF0 ARE within the 36-bit range and pass
the mask intact. The truncation only affects addresses ≥ 0x1000000000 (64 GB).

**Revised assessment**: On iPhone 16 Plus with 8 GB RAM, all physical addresses
(max ~40 GB) are well within the 36-bit mask window. This gap is **NOT exploitable
on the target device** unless additional MMIO or memory-mapped regions extend
above 64 GB physical. Lower priority.

---

## Gap 3: Domain 3 Fast Path (SK)

The branch at `0xdd080: B.EQ → 0xdd114` (domain == 3 = SK) goes to a short path
that does NOT go through all of the endpoint/entry validation above. The path at
0xdd114 looks like an accelerated accept path:

```asm
0xdd114:  STP x19,x20,[x23,#0x0]  ; store dispatch result
0xdd118:  LDP x29,x30,[x31,#0xa0] ; epilogue
0xdd11c:  LDP x20,x19,[...]
0xdd120:  LDP x22,x21,[...]
          ...
0xdd130:  RET (ERET-style: .word 0xd65f0fff)
```

This is the SK fast path — SK (which runs at a higher security level than XNU)
is granted dispatch without XNU's validation checks. The domain value is
hardware-controlled (system register `EL2_DOM` equivalent) and cannot be spoofed.

**HOWEVER**: During the SPTM bootstrap window (before SK calls
`SK_TO_SPTM_ENDPOINTID_REGISTER_DISPATCH_TABLE`), this fast path may be
active with an uninitialized SK dispatch table. Any TOCTOU between "fast path
active" and "table registered" could allow a domain-3 dispatch to an empty
or partially-initialized handler.

---

## Comparison: 26.6.1 vs 27.0.1

| Check | 26.6.1 | 27.0.1 |
|---|---|---|
| Dispatch format | `(table_id, entry_addr)` as integers | Named `(DISPATCH_TABLE_ID, ENDPOINTID)` pairs |
| Sanitizer type | AND mask + CMP bounds (inline) | Hard enum comparison + VIOLATION_ILLEGAL_DISPATCH_CMD |
| Endpoint 15 | Blocked by CMP at 0xdd47c | Named endpoint, fully enumerated |
| Entry addr mask | 36-bit truncation | N/A — not used in named dispatch |
| SK fast path | Present (domain 3) | Likely present but different |

The 27.0.1 named dispatch eliminates the integer surface entirely. The 26.6.1
integer dispatch remains open on the target device.

---

## Key Strings

| String | File offset |
|---|---|
| `sanitize_integer(dispatch_entry_addr_U.UNSAFE_VALUE)` | 0xf07a |
| `sanitize_integer(dispatch_table_id_U.UNSAFE_VALUE)` | 0xf1b7 |
| `validate_sptm_dispatch_table_id` | 0xfa51 |
| `validate_dispatch_entry_addr` | 0xfab9 |
| `validate_dispatch_endpoint_id` | 0xfae1 |
| `validate_dispatch_target` | 0xf64a |
| `DISPATCH_ID_SPTM_CORE` | 0xfb02 |
| `dispatch_state_machine` | 0xeecc |
| `dispatch_table_lookup` | 0xedef |

---

## Next Steps (Priority Order)

1. **Confirm ep15 status for table 0xe (NVMe)**: Search `sptm_26.6.1.bin` for a
   handler at the ep15 slot. If no handler exists but the stub does, this is a
   dead stub that panics — low risk. If a handler exists and lacks its own
   validation, it's a gate-bypass.

2. **Trace x21 source at 0xdd47c**: Determine whether w21 is the raw endpoint_id
   from x16[31:0] or a pre-sanitized copy. If raw, check whether `CMP w21, 0xf`
   is the ONLY guard (no prior AND mask), making it a potential type confusion.

3. **SK bootstrap TOCTOU**: Map the time between SPTM loading and SK calling
   `REGISTER_DISPATCH_TABLE`. Verify whether the domain-3 fast path is gated on
   the table being registered.
