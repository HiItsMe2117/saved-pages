# SPTM Research Notes — Targeting Guide for iOS 26.6.1 → 27.0.1 Diff

*Compiled 2026-10-25 from arXiv 2510.09272, sigreturn.com, alfiecg.uk, Titan/Dopamine sources, Apple security advisories, and GitHub RE repos.*

---

## 1. What Is SPTM?

**Secure Page Table Monitor** — Apple's replacement for PPL (Page Protection Layer), introduced on A15/M2 and later. Both protect page tables from kernel-level compromise, but they work very differently.

### PPL (A11–A14 / base M1)
- Ran *inside* the kernel's address space in special `__PPLTEXT` / `__PPLDATA` segments
- Entry via a trampoline (`__PPLTRAMP`) that flips SPRR/APRR permission registers
- Single entry point, dispatched through `ppl_handler_table`
- Still trusted the kernel address space; just made page-table pages read-only to normal EL1 code

### SPTM (A15/M2+, iOS 17+)
- Runs as a **completely separate signed binary** (`sptm.t8140.release.im4p`, ~1.2 MB)
- Lives in **Guarded Level 2 (GL2)** via Apple's proprietary GXF (Guarded Execution Feature)
- The kernel (XNU) has **no direct access** to page tables — it must ask SPTM to map/retype
- Started before XNU; passes startup args via `SPTMArgs` structure
- SPTM is the **sole authority** over memory frame types and page-table writes

---

## 2. GXF — The Hardware Primitive

GXF adds *lateral* guarded levels (GL0, GL1, GL2) beside the normal ARM exception levels:

```
GL2  ← SPTM        (highest privilege, owns page tables)
GL1  ← Secure Kernel (seL4 microkernel, hosts Exclaves)
GL0  ← TXM         (Trusted Execution Monitor, owns code signing)
─────────────────────────────────────────────────────
EL2  ← XNU kernel  (Apple runs XNU at EL2, not EL1)
EL1  ← (unused/legacy)
EL0  ← Userspace
```

**Key instructions (no mnemonic in Apple's otool — appears as `.long`):**
- `GENTER` — opcode `0x00201420` (little-endian bytes: `20 14 20 00`) — enter a guarded level
- `GEXIT`  — opcode `0x00201400` (little-endian bytes: `00 14 20 00`) — exit a guarded level

**SPRR** (Shadow Permission Remap Registers): Page-table AP/UXN/PXN bits are now a 4-bit *index* into per-level SPRR registers. GL2 gets read-write to page-table index values; EL2 only gets read access. This is how SPTM exclusively owns page-table writes.

**Key system registers:**
- `GXF_ENTRY_ELx` — entry vector on GENTER
- `GXF_PABENTRY_ELx` — abort vector
- `SPRR_PPERM_EL1`, `SPRR_CONFIG_EL1` — permission configuration
- Guarded levels have own copies of: `TPIDR`, `VBAR`, `ESR`, `ELR`

---

## 3. SPTM Entry Points — Known Function Signatures

These come from the arXiv paper (2510.09272) and sigreturn.com analysis, cross-referenced with XNU source paths:

### Core SPTM functions
```c
// Map a page — the ONLY way to write a PTE
sptm_return_t sptm_map_page(
    pmap_paddr_t ttep,      // physical addr of root translation table
    vm_address_t va,         // virtual address to map
    pt_entry_t new_pte       // the PTE value XNU computed
);

// Change a frame's type — gated by allowed transition table
void sptm_retype(
    pmap_paddr_t physical_address,
    sptm_frame_type_t previous_type,   // must match recorded type
    sptm_frame_type_t new_type,
    sptm_retype_params_t retype_params
);

// Query a frame's type (callable from Secure Kernel)
sptm_frame_type_t sptm_get_frame_type(pmap_paddr_t physical_address);

// DART (I/O MMU) operations
sptm_t8110_dart_map_table(...)
sptm_t8110_dart_unmap_table(...)

// Registration
sptm_register_dispatch_table(...)
```

### XNU call path to sptm_map_page
```
pmap_enter_options()
  └─ pmap_enter_pte()
       └─ sptm_map_page()   [via GENTER_main_gate]
```
Source: `osfmk/arm64/sptm/pmap/pmap.c`

### XNU → SPTM gate (GENTER_main_gate)
- XNU calls SPTM via `GENTER_main_gate` (~77 direct call sites in macOS 26.4.1 kernel)
- Selector in `x16`: bits 48–55 = domain, bits 32–39 = dispatch table index
- Args loaded from a struct pointed to by `x1` into `x0`–`x7`
- Returns via `retab` (arm64e pointer authentication)
- XNU wraps every monitor entry with `recount_enter_secure()` / `recount_leave_secure()`

---

## 4. Frame Types

SPTM tracks a type for every physical frame. Allowed operations depend on type.

### XNU-mappable types (kernel can map these)
| Type | Meaning |
|------|---------|
| `SPTM_UNTYPED` | Unallocated |
| `XNU_DEFAULT` | Normal kernel/userspace data |
| `XNU_USER_EXEC` | Executable userspace page |
| `XNU_USER_JIT` | JIT-compiled code |
| `XNU_PAGE_TABLE` | Page table page |
| `XNU_PROTECTED_IO` | Protected I/O mapping |
| `XNU_COMMPAGE_RO` | Commpage (read-only to user) |
| `XNU_ROZONE` | Read-only zone |
| `XNU_TAG_STORAGE` | MTE tag storage (A19+, iOS 26+) |
| `SPTM_XNU_CODE` | XNU code pages |

### Secure Kernel types
`SK_DEFAULT`, `SK_SHARED_RO`, `SK_SHARED_RW`, `SK_IO`

### Table types XNU can insert PTEs into
`SPTM_KERNEL_ROOT_TABLE`, `SPTM_PAGE_TABLE`, `XNU_PAGE_TABLE`

### Domains
`SPTM_DOMAIN`, `XNU_DOMAIN`, `TXM_DOMAIN`, `SK_DOMAIN`, `XNU_HIB_DOMAIN`

**Retyping rule:** A global table indexed by current type has a bitmask of allowed destination types. Cross-domain retyping is restricted to a small allowed set.

---

## 5. TXM (Trusted Execution Monitor) — Brief

Runs in GL0. Owns code signing, entitlements, trust caches, provisioning profiles.

**Call path from XNU:**
```
txm_kernel_call_internal()  [bsd/kern/code_signing/txm.c]
  └─ txm_genter()
       └─ GENTER (x16 upper 32 bits = 0x00020000)
```

**~40 selectors** — names begin `kTXMKernelSelector`:
- `kTXMKernelSelectorRegisterCodeSignature`
- `kTXMKernelSelectorEnterLockdownMode`
- … (6 more in `bsd/kern/kern_trustcache.c`)

**iOS 27 change:** `pmap_cs` and page-execute enforcement **moved from kernel `__PPLTEXT` to TXM**. `__PPLTEXT` is **absent** from iOS 27 kernelcache. Strings like `"page enforcement failed"` now live in TXM, not kernel.

---

## 6. mach_make_memory_entry_64 and SPTM

### The Trigon bug (CVE-2023-32434, patched iOS 16.5.1)
- Integer overflow in `mach_make_memory_entry_internal` (called by `mach_make_memory_entry_64`)
- Overflow check: `if ((offset + *size + parent_entry->data_offset) > parent_entry->size)`
- Both `size` (crafted as `0xFFFFFFFFFFFFC000`) and `offset` are user-supplied → wrap
- Produces a memory entry spanning ~18,000 PB, bypassing bounds checks in `mach_vm_map`
- Used `PurpleGfxMem` / `IOSurface` to map kernel physical memory into userspace
- Built arbitrary physical read/write from there

### SPTM's relationship to this class of bug
- SPTM does **not** directly protect `mach_make_memory_entry_64` — the overflow is in Mach VM logic above the pmap layer
- However, SPTM's frame typing prevents a successful exploit from *doing* certain things with a bad mapping:
  - Can't retype an `XNU_PAGE_TABLE` frame to `XNU_DEFAULT` without going through allowed transitions
  - A page quarantined as a page table can't be freely mapped into userspace
- The `pmap_tte_remove` UAF repo (Indegosblade) notes SPTM quarantines freed pages, blocking exploitation even if you get the primitive

### What to look for in our diff
Search near `mach_make_memory_entry_64` string occurrences for changes to:
- `mach_make_memory_entry_internal` bounds checks
- `vm_map_enter` / `vm_map_enter_mem_object` validation
- `named_entry->size` comparisons
- The `internal` flag checks around `vm_page_insert_internal`

---

## 7. Concrete Grep Targets for Our Kernel Binary

### Byte pattern (GENTER instruction)
```python
GENTER = b'\x20\x14\x20\x00'
GEXIT  = b'\x00\x14\x20\x00'
```
Count occurrences in `__TEXT_EXEC` to measure how many SPTM call sites exist. 
Expect ~150 in iOS 26 kernelcache; iOS 27 may add or remove some.

### String patterns to scan
```python
strings_to_find = [
    # SPTM core
    "sptm_map_page",
    "sptm_retype",
    "sptm_get_frame_type",
    "sptm_register_dispatch_table",
    "sptm_uat_",              # UAT (Unified Address Translation) ops
    "SPTMArgs",
    "sptm.t",                 # firmware name references
    
    # Frame types  
    "XNU_DEFAULT",
    "XNU_PAGE_TABLE",
    "XNU_USER_EXEC",
    "XNU_USER_JIT",
    "XNU_TAG_STORAGE",        # MTE tag storage — new in iOS 26
    "SPTM_UNTYPED",
    
    # Domains
    "XNU_DOMAIN",
    "TXM_DOMAIN",
    "SPTM_DOMAIN",
    
    # GXF / gate infrastructure
    "GENTER_main_gate",
    "genter_setup",
    "gxf_setup_early",
    "gxf_setup_late",
    "recount_enter_secure",
    "recount_leave_secure",
    
    # TXM (code signing moved in iOS 27)
    "txm_kernel_call",
    "txm_genter",
    "kTXMKernelSelector",
    "page enforcement failed",  # moved from kernel to TXM in iOS 27
    
    # PPL remnants (should shrink/disappear in iOS 27)
    "__PPLTEXT",
    "ppl_handler_table",
    "pmap_cs_",               # pmap code-signing — moved to TXM in iOS 27
    "unsupported on non-PPL",
    
    # pmap core
    "pmap_enter_options",
    "pmap_enter_pte",
    "pmap_lockdown",
    
    # mach_make_memory_entry
    "mach_make_memory_entry_64",
    "mach_make_memory_entry_internal",
    "named_entry",
    
    # Memory tagging (MTE, A19/iOS 26+)
    "XNU_TAG_STORAGE",
    "EMTE",
    "kalloc_type",
    
    # iOS 27 SPTM changes (from iOS27.0.1 research)
    "uat_sync_outer_tlb",
    "VIOLATION_T8110_DART",
    "uat_dekker",
    "Failed to verify TLBI",
    "wrprot",                 # REMOVED in iOS 27.2b3 SPTM
]
```

### Segment markers
```python
# PPL-era kernel has these; SPTM-era should have __DATA_SPTM instead
ppl_segments   = ["__PPLTEXT", "__PPLDATA", "__PPLDATA_CONST"]
sptm_segments  = ["__DATA_SPTM", "__TEXT_BOOT_EXEC"]
```
If `__PPLTEXT` is present → PPL-based kernel.
If `__DATA_SPTM` is present → SPTM-based kernel.
In iOS 27, `__PPLTEXT` expected to be fully absent (confirmed by scion PR #3).

---

## 8. What Changed iOS 26.6.1 → iOS 27

### Confirmed (from scion/dylanneve1 PR #3 and iOS security advisory)
- **`pmap_cs` / page-execute enforcement moved from kernel to TXM** — `__PPLTEXT` gone from 27 kernelcache
- **21 kernel CVEs fixed** in iOS 27, including:
  - Race conditions (CVE-2026-84507, CVE-2026-84630, CVE-2026-65402)
  - Use-after-free (CVE-2026-84521, CVE-2026-43686)
  - OOB writes (CVE-2026-28968, CVE-2026-84566)
  - Type confusion (CVE-2026-84602)
  - Privilege escalation (CVE-2026-43689 — malicious app gains root)
  - Sandboxed app → kernel code execution (CVE-2026-84607)
- **SPTM binary itself**: 27.0.1 and 27.2b1 are byte-identical; 27.2b3 added 21 new strings around UAT/GMMU TLBI race hardening
- **TXM binary**: research vs release builds differ by ~4.4 KB (mostly diagnostic strings); ~419 B in `__text`

### What to target in the diff
1. **`__PPLTEXT` segment presence/absence** — the clearest architectural signal
2. **`pmap_cs_*` functions** — should move out of kernel into TXM
3. **`kTXMKernelSelector`** — count/type of new selectors added
4. **GENTER instruction count** — how many new call sites in iOS 27 kernel
5. **The 21 patched CVEs** — look for changed bounds checks, lock orderings, UAF fixes near known subsystems (NFS, vm_map, IPC)
6. **`page enforcement failed` string** — present in 26.6.1 kernel? Should move to TXM binary in iOS 27
7. **MTE / tag storage** — any changes around `XNU_TAG_STORAGE` frame type

---

## 9. Known Bypasses / Vulnerabilities (for context)

| Tool/CVE | Versions | Method |
|----------|----------|--------|
| **Titan** (alfiecg24) | iOS 16.1 – 17.3.1 | AGX coprocessor ROP → modify TTBR0/TTBR1 in AGX hibernate context → self-referencing PTE → full PPL+SPTM defeat |
| **silentIO** | iOS 18.6.2 | RTKit ERET loader gadget (patched iOS 18.1b4 with PAC on AGX thread state) |
| **CVE-2023-32434** (Trigon) | iOS 7 – 16.5 | Integer overflow in `mach_make_memory_entry_internal` → 18 PB mapping → arbitrary phys r/w |
| **pmap_tte_remove** (Indegosblade) | Through iOS 26.6b1 | uint16 refcount overflow in pt_desc → physical UAF; SPTM quarantine mitigates but doesn't fix |

---

## 10. Key Source Files (XNU open-source paths)
```
osfmk/arm64/sptm/pmap/pmap.c          ← pmap_enter_options → sptm_map_page call
osfmk/arm64/sptm/sptm.h               ← SPTMArgs struct definition
osfmk/arm64/sptm/sptm_common.h        ← domain definitions (XNU_DOMAIN etc)
bsd/kern/code_signing/txm.c           ← txm_kernel_call_internal, selectors
bsd/kern/code_signing/ppl.c           ← PPL shim (legacy, replaced by txm.c on A15+)
bsd/kern/kern_trustcache.c            ← 6 extra TXM selectors
bsd/sys/code_signing_internal.h       ← CODE_SIGNING_MONITOR unified API
osfmk/arm/pmap/pmap.c                 ← ppl_handler_table (PPL dispatch)
osfmk/arm/pmap/pmap_ppl_interface.c   ← PPL interface helpers
```

---

## 11. References
- **Primary**: Steffin & Classen, *Modern iOS Security Features: A Deep Dive into SPTM, TXM, and Exclaves*, arXiv 2510.09272 (2025) — https://arxiv.org/abs/2510.09272
- sigreturn.com — SPTM, TXM and PPL: Apple kernel monitors, memory tagging
- alfiecg.uk — Trigon writeup (CVE-2023-32434) — https://alfiecg.uk/2025/03/01/Trigon.html
- alfiecg24/Titan — SPTM bypass source — https://github.com/alfiecg24/Titan
- dylanneve1/scion PR #3 — iOS 27 TXM patch notes — https://github.com/dylanneve1/scion/pull/3
- IvanIVGrozny/iOS27.0.1-SPTM-Research — 27.2 SPTM binary diff — https://github.com/IvanIVGrozny/iOS27.0.1-SPTM-Research
- Apple iOS 27 security advisory — https://support.apple.com/en-us/149034
- Indegosblade/pmap-tte-remove — pmap UAF + SPTM quarantine note — https://github.com/Indegosblade/pmap-tte-remove
- Asahi Linux progress report (GXF/SPRR/SPTM) — https://asahilinux.org/2026/08/progress-report-7-2/
- Apple Platform Security Guide (Aug 2026) — https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf
