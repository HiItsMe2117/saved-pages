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
- Page table writes, PPL region writes: blocked at hardware level. No bypass confirmed for A18.
- The Chollima chain is "untethered" but SPTM bypass is disputed. If rootless: must achieve persistence via data-only means.

**MTE impact:**
- Hardware-enforced heap tag checking (16-byte granules, 4-bit tags)
- Tags are checked on LOAD (async mode): the OOB WRITE may succeed but a subsequent READ of the corrupted granule with the wrong tag will fault
- This affects HOW you land the corruption — you need to hit a granule with a compatible or zero tag
- The AppleAVE2 crash (x0=0x59) is a DATA ABORT on a WRITE (stp x0,x0,[x0]) — this suggests the corruption reached the init_list_head stage before MTE caught a load
- OR: the OOB write targets a region not protected by MTE (kalloc_type allocations may have tag=0 for some types)

**FPAC / PAC impact:**
- x0=0x59 is NOT a valid PAC-signed pointer — this crash confirms the exploit corrupts a value to 0x59 which is then used as a raw pointer
- In a working exploit you would NOT forge a PAC pointer — instead you'd corrupt a NON-POINTER field (integer, size, index) and use it to build a read/write primitive without ever needing to control PC
- This is the "data-only" approach: corrupt struct fields that influence memory layout/access, not function pointers

**Conclusion:** Our binary analysis IS mostly appropriate for iOS 26 — we correctly identified a data structure corruption (linked list head pointer to 0x59) rather than a code pointer. The SPTM constraint means the Chollima chain likely uses the OOB to corrupt something like a `struct ipc_port` field, a `task_t` pointer, or similar kernel objects that let you escalate without modifying page tables.

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
- **Prior audio/video kext exploits** — whether AppleAVE or similar kexts have been exploited before, what primitives they gave
- **SPTM internals research** — any public analysis of what SPTM protects and what it doesn't
- **Post-SPTM iOS 17/18 kernel exploit techniques** — how exploits adapted after SPTM was introduced on A17 Pro (iPhone 15 Pro)

**Gap:** We're missing the "what primitives have worked on iOS 17/18 post-SPTM A17" baseline. Before looking for new paths, we should catalog what's been demonstrated to work in that regime.

---

## 4. Tools we have vs tools we should be using

### Currently using
| Tool | Use | Gap |
|------|-----|-----|
| radare2 (r2) | Disassembly | No decompilation; manual only |
| ResearchHost | iPhone Python execution | Probes written but NOT YET RUN |
| rh_run.py | ResearchHost client | Working |
| Manual BL scan (Python) | Caller analysis | Works but tedious |
| Web search | OSINT | Covered |

### Not using but should consider
| Tool | What it provides | Why we need it |
|------|-----------------|----------------|
| **Ghidra + GhidraARM64** | Decompilation of ARM64 | Function semantics, struct recovery, type inference — would have found the gop_config struct layout instantly |
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
- CoreMedia mediaplaybackd FigXPC FD leak (CVE-2026-112706) — surface-level
- Foundation PDF type confusion (CVE-2026-65409) — unconfirmed mechanism
- Surface C probe: AURemoteIOServer ASBD overflow (CVE-2026-113912) — probe written, not run

### Novel surfaces not yet explored
- **Other VTCompressionSession properties**: Are there other numeric properties that flow into unchecked 32-bit arithmetic in AppleAVE2 or AppleANE?
- **Other audio kexts**: AppleAudioKext, AppleSEPManager — do they have similar MIG/XPC-level integer surfaces?
- **IOKit surfaces**: The classic iOS exploit surface. We haven't surveyed IOKit drivers for integer overflows or type confusions specific to A18.
- **Other FigXPC services**: If CVE-2026-112706 is in `mediaplaybackd.bytestream.xpc`, are there other `*.bytestream.xpc` or FigXPC-based services with similar patterns?
- **NVMe / DART surfaces**: The second trigger found (32768×16384 dimensions → DART PTE-invalid write) suggests a DIFFERENT bug in the AVE pipeline. This is unexplored.
- **Kernel extensions added/changed in iOS 26**: What new kexts shipped with iOS 26 that have no iOS 18 equivalent? These are highest-probability for novel surfaces.

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
2. Switch to r2 analysis mode (`aaa`) + `axt` for all future caller scans
3. Identify what iOS 17/18 post-SPTM exploit primitives have been publicly documented

**Medium:**
4. Set up Ghidra analysis of AppleAVE2 on Mac for function-level decompilation
5. Analyze the DART / 32768×16768 dimension trigger — may be a separate, easier-to-exploit surface
6. Survey other VTCompressionSession properties for similar integer-overflow patterns

**Low:**
7. Confirm Foundation CVE-2026-65409 mechanism in binary (DoS vs code execution)
8. Analyze FigXPC protocol surface more broadly (other services)
9. Build formal attack surface registry doc
