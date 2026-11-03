# Research Gap Analysis — iOS 26/27 Chollima Chain
**Date:** 2026-11-03  
**Status:** Living document — update as gaps close

---

## 1. iOS 26 / A18 lens vs iOS 18 / A16 lens

### What changed that matters for exploitation

| Feature | iOS 18 / A16 | iOS 26 / A18 |
|---------|-------------|-------------|
| SPTM | Not present (A16) | Present, strongly enforced (A18) |
| MTE | Not present (A16) | Present — async tag-fault on OOB loads |
| PAC | Present (FPAC on A15+) | Present, enforced |
| BTI | Present | Present (confirmed in AppleAVE2 binary) |
| Kernel heap isolation | zone-based | zone-based + kalloc_type segregation |

**SPTM impact on exploit model:**
- iOS 18 / pre-SPTM: OOB write → corrupt pointer → forge kernel pointer → write to page table → escalate
- iOS 26 / SPTM: OOB write → must corrupt data structure within SPTM-permitted memory → build primitive via data-only path
- Page table writes, PPL region writes: blocked at hardware level. No public bypass for A15+/iOS 17.4+. Chollima almost certainly rootless.
- Known SPTM bypass research (Rocket, Titan) only covers A14–A17, iOS 16–17.3.1 — NOT applicable to our target.

**MTE — CRITICAL CORRECTION:**
- **Hardware MTE is A19/M5 only. Our target (iPhone 16+, A18) does NOT have hardware MTE.**
- iOS 26 does add software MTE enhancements for the kernel and ~70 userland processes — raises the bar but data-only chains bypass it
- The AVE2 crash (x0=0x59) is a DATA ABORT on a WRITE (`stp x0,x0,[x0]`) — consistent with no MTE on A18 stopping it earlier

**Exclaves / hypervisor layer (new — iOS 26 only):**
- iOS 26 introduces a hardware hypervisor layer sitting above SPTM (`cloverfield11/ios26-hypervisor-research`)
- This layer is entirely undocumented publicly and its effect on data-only exploitation is unknown
- TXM shift (iOS 26→27): some kernel security checks moved to TXM between versions (see `dylanneve1/scion`)
- **Gap:** We don't know if Exclaves intercepts any of the operations in the Chollima chain

**FPAC / PAC impact:**
- x0=0x59 is NOT a valid PAC-signed pointer — crash confirms the corruption produces a raw, non-authenticated pointer
- Correct exploit approach: corrupt a NON-POINTER field (integer, size, index) so you never need to forge a PAC
- This is the "data-only" approach: corrupt struct fields that influence memory layout/access, not function pointers

**Conclusion:** Our binary analysis is appropriate for iOS 26 — we correctly identified data structure corruption, not code pointer hijack. The SPTM + no-hardware-MTE + PAC constraint means the Chollima chain likely corrupts something like a `struct ipc_port` field or `task_t` reference to build kernel r/w without touching page tables. The Exclaves layer is the one unknown we haven't accounted for.

---

## 2. What we haven't analyzed about the crash primitive

### The x0=0x59 value — what does it tell us?

The 32-bit overflow fingerprint (NTL=16463: x0=0x59, NTL=16464: x0=0x100000059) tells us:
- x0 is the result of a 32-bit computation involving NTL that wraps at 2^32
- The result 0x59 = 89 decimal is then used as a kernel pointer to init_list_head

**What we need to know (NOT yet analyzed):**
- What SPECIFIC struct/field adjacent to the GOP allocation gets overwritten with 0x59?
- What is the heap layout between the element_array/struct1 allocations and the adjacent object?
- In a working exploit, what field WOULD you overwrite (i.e., what useful corruption can this OOB produce)?
- Does Chollima use this as a TYPE CONFUSION primitive (corrupt an object's isa pointer or type tag)?

**Gap:** We need to trace what allocation sits adjacent to the GOP element_array in the kernel heap for a typical 1920×1080 H.264 session. This requires dynamic analysis (kernel debugger) or heap grooming analysis.

---

## 3. Prior jailbreak / kernel primitive research we haven't done

### What we've looked at
- The Chollima chain specifically (Hexacon 2026)
- Official CVE advisories

### What we haven't reviewed
- **Checkra1n / unc0ver / Dopamine / Fugu15 / palera1n** primitive techniques — how they converted OOB writes to kernel r/w before SPTM
- **Project Zero iOS kernel research** (Ian Beer et al.) — deep technical writeups on IOKit, Mach port, IPC exploitation
- **ziVA (Zimperium 2017)** — Adam Donenfeld found 7 AppleAVE2Driver vulns chained on iOS ≤10.3.1, all via MIG `SetSessionSettings` (method 7). Same driver module. **We have not checked whether this MIG interface still exists in 26.6.1 with new exploitable conditions.**
- **CVE-2019-8795** — missing bounds check in `AppleAVE2Driver::SetSessionSettings` (MIG method index 7), patched iOS 13.2. Is method 7 in 26.6.1? Is it the same handler?
- **SPTM internals research** — any public analysis of what SPTM protects and what it doesn't
- **Post-SPTM iOS 17/18 kernel exploit techniques** — specifically: CVE-2025-43520 (DarkSword, iOS 18) used socket/inpcb struct corruption for data-only kernel r/w with no SPTM bypass; this is the closest template to our situation

**Gap:** We're missing the "what primitives have worked on iOS 17/18 post-SPTM A17" baseline. Before looking for new paths, we should catalog what's been demonstrated to work in that regime.

---

## 4. Tools we have vs tools we should be using

### Currently using
| Tool | Use | Gap |
|------|-----|-----|
| radare2 (r2) | Disassembly | No decompilation; manual only |
| Ghidra 12.2 + PyGhidra | Decompilation | **OPERATIONAL** (2026-11-03). Java 25 required. Confirmed struct1 layout, closed the mul-overflow theory, found the overflow guard. |
| ResearchHost | iPhone Python execution | Probes written but NOT YET RUN |
| rh_run.py | ResearchHost client | Working |
| Manual BL scan (Python) | Caller analysis | Works but tedious |
| Web search | OSINT | Covered |

### Not using but should consider
| Tool | What it provides | Why we need it |
|------|-----------------|----------------|
| **Ghidra — gop_config setup** | Decompile session init to trace gop_config[+8] (stride) | Need to confirm if stride is user-controlled via frame dimensions (determines if NTL+stride write-any-value is feasible) |
| **r2 analysis mode** (`aaa`) | Automatic xrefs, function boundaries | We're using raw `-q` mode; `aaa` then `axt addr` gives all callers automatically |
| **Binary diff (diffware/BinDiff)** | 26.6.1 vs 27.0.1 delta | We did manual diff; automated diff would show ALL changed functions, not just the ones we guessed |
| **ipsw** CLI tool | Firmware extraction/analysis | Clean kext extraction, version comparison |
| **frida** (if available) | Dynamic instrumentation on-device | Would let us trace the actual GOP alloc path live, confirm heap layout |
| **otool** | Mach-O header/symbol analysis | Quick symbol table dump would show any exported names |
| **strings** | String-based function identification | Finding debug strings near vulnerable functions |

**Biggest gap:** We're not using r2's analysis mode for automatic cross-reference discovery. Every caller scan we ran was a manual Python script. `r2 -q -c "aaa; axt 0xfffffff0084ca290"` would have given us all callers in seconds.

---

## 5. Analysis of the known attack surface vs novel surfaces

### What we've covered
- AppleAVE2 `kVTCompressionPropertyKey_NumberOfTemporalLayers` overflow (CVE-2026-112705) — deep
- CoreMedia mediaplaybackd FigXPC FD leak (CVE-2026-112706) — surface-level; PoC repos exist, not examined
- Foundation PDF type confusion (CVE-2026-65409) — unconfirmed mechanism
- Surface C probe: AURemoteIOServer ASBD overflow (CVE-2026-113912) — probe written, not run

### On "DoS only" assessments — don't stop at the first wall

The IOGPUFamily OOB (CVE-2025-24257) was declared unexploitable on DEFAULT heap layout.
That doesn't close the question for AVE2. Creative angles to pursue BEFORE accepting DoS:

**1. The `mul w8, w22, w19` overflow — CORRECTED by Ghidra analysis (2026-11-03)**  
Ghidra decompilation confirmed the 32-bit write at struct1+0x48 is PROTECTED:
```c
iVar3 = 0x7fffffff / aligned_stride;
if (iVar3 <= NTL) return error;  // REJECTS NTL ≥ INT32_MAX/stride
```
This guard ensures `aligned_stride × NTL < INT32_MAX` — NO OVERFLOW POSSIBLE for any
inputs that pass the guard. The "write-any-32-bit-value via `mul`" theory is wrong for
NTL=16463 crash values. The actual crash mechanism is from something else (dynamic analysis
required). **Retract creative angle #1 and #2 as stated — the guard closes them.**

**REVISED exploitation model:**  
The 2^32 fingerprint in x0/x19 must come from a DIFFERENT 32-bit computation downstream.
Candidates: (a) some caller of `FUN_fffffff0084ca770` does 32-bit arithmetic on the struct
fields; (b) the NTL=16463 value triggers some other unchecked path; (c) the 30MB buffer
allocation side-effects cause heap corruption in adjacent regions (kalloc_large territory).
None of these has been traced statically — dynamic analysis is the next required step.

**2. Counter guard `current_count < max_count` is still a timing/ordering surface.**  
The non-clamping call fires only on the FIRST GOP slot allocation (current_count < max_count).
Multiple concurrent sessions can race to shape heap layout at allocation time. This is
independent of the mul overflow and remains valid for heap grooming.

**3. The main buffer size IS user-tunable (via NTL).**  
The main buffer `iVar4 = (alignment-1) + aligned_stride × NTL` bytes (~30MB for NTL=16463,
1920-byte stride). Large kernel allocations land in kalloc_large. The SIZE being tunable
via NTL means you can aim the allocation at specific heap regions. Confirmed from Ghidra.

**4. NTL controls timing of first-init via the counter guard.**  
Setting NTL very high (up to the overflow guard limit = INT32_MAX/stride ≈ 1M for stride=2048)
maximizes the buffer size. This could be used to pressure/groom the kernel heap.

**Rule:** "No adjacent pointers in this zone" means "find a way to put the right adjacent
object there." Always look for grooming angles before accepting unexploitable.

### CVE-2026-112706 PoC repos (not yet examined)
Public PoC code exists: `MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak` and `794pn2s6fh-hub/cve-112706`.
- "FigXPC memory-origin handshake completes with status 0 for unprivileged client" — unauthenticated handshake step is the leverage point
- "Fix was incomplete in iOS 27.0 — auxiliary opcodes still affected on iOS 26.5" — may still be usable on our target

### Novel surfaces not yet explored
- **AppleAVE2 MIG/IOKit interface (high priority)**: ziVA (2017) and CVE-2019-8795 both hit `AppleAVE2Driver::SetSessionSettings` (MIG method 7) directly. We've only analyzed the VideoToolbox→gop_config path. The raw IOKit dispatch table is a parallel entry surface we haven't touched.
- **DART / frame dimension trigger**: 32768×16384 dimensions → DART PTE-invalid write fault — completely different bug in AVE pipeline, unexplored. May be a lower-bar surface.
- **Other VTCompressionSession properties**: Are there other numeric properties flowing into unchecked 32-bit arithmetic in AppleAVE2 or AppleANE?
- **Other FigXPC services**: Are there other `*.bytestream.xpc` services with the same unauthenticated handshake pattern?
- **Heap zone analysis for AVE2 OOB**: CVE-2025-24257 (IOGPUFamily OOB) was assessed unexploitable because "data heap contains no pointers." Need to verify AVE2's kalloc zone contains pointer fields, otherwise our OOB is DoS-only by design.
- **Kernel extensions new in iOS 26**: Kexts with no iOS 18 equivalent = highest-probability novel surfaces. Not inventoried.

---

## 6. Notes/reference management gaps

### Current state
- `RESEARCH_NOTES_CVE_CHAIN.md` — main analysis, now updated with verified findings
- `GAP_ANALYSIS.md` — this file
- Probe scripts: `surface_c_probe_a.py`, `surface_c_probe_b_overflow.py`, `surface_c_probe_b.py`
- `rh_run.py` — ResearchHost client

### Missing
- **Tool inventory doc**: what tools are on Mac, what's on iPhone, what versions
- **Binary inventory doc**: what firmware OTAs we have, what kexts have been extracted
- **Attack surface registry**: structured list of potential surfaces, their status (unexplored/partial/confirmed)
- **Prior art bibliography**: links to Project Zero posts, Hexacon talks, PAC/SPTM research papers
- **Session notes from the Surface C probe work**: the probe is ready but we haven't documented the ASBD overflow math or the expected reply layout changes in the notes

---

## 7. Priority actions to close the gaps

**High:**
1. Run the Surface C probe (surface_c_probe_a → surface_c_probe_b_overflow) when memory < 1250 MB
2. Determine actual NTL=16463 crash mechanism — use Ghidra to decompile callers of `FUN_fffffff0084ca770` and any function that reads struct1+0x48/+0x4c; requires dynamic analysis ultimately
3. Use Ghidra to trace gop_config[+8] stride write path — determine if stride is user-controlled via frame width
4. Read CVE-2026-112706 PoC repos (`MchinaMd57764/CVE-2026-112706-CoreMedia-fd-leak`, `794pn2s6fh-hub/cve-112706`) — code exists, we haven't looked
5. Check AppleAVE2 MIG dispatch table in 26.6.1 — prior bugs (ziVA, CVE-2019-8795) hit method 7; is it still present?
6. Verify AVE2 kalloc zones contain pointer fields — prerequisite for knowing if OOB is exploitable vs DoS-only

**Medium:**
7. Study DarkSword (CVE-2025-43520, iOS 18) data-only primitive technique — closest public template to our situation
8. Analyze the DART / 32768×16384 dimension trigger — separate AVE bug, may be lower-bar surface
9. Document Exclaves/hypervisor layer implications for iOS 26 exploitation — `cloverfield11/ios26-hypervisor-research`
10. Switch to r2 `aaa` + `axt` for all future caller scans

**Low:**
11. Confirm Foundation CVE-2026-65409 mechanism in binary (DoS vs code execution)
12. Survey other VTCompressionSession properties for similar integer-overflow patterns
13. Survey other FigXPC services for unauthenticated handshake pattern
14. Build formal attack surface registry and binary/tool inventory docs

**DONE:**
- ~~Set up Ghidra on Mac~~ ✓ Ghidra 12.2 + Java 25 (Temurin 25.0.5) + PyGhidra 3.0, 2026-11-03
- ~~Decompile key AVE2 functions~~ ✓ struct1 layout confirmed from FUN_fffffff0084ca1ac pseudocode
- ~~Verify mul overflow theory~~ ✓ CLOSED: overflow guard (`INT32_MAX/stride > NTL`) prevents it
