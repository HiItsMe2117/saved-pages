# AppleAVE2 — iOS 26.7.2 (23H128, build iPhone17,4)

**Binary**: com.apple.driver.AppleAVE2  
**Source version**: TBD (expect 905.40.x — same base as 26.6.1 with security patches only)  
**OTA**: `~/kerneldiff_ave2/iOS26.7.2_OTAs/iPhone17,4_23H128_KEY_[...].aea` (8.7 GB)  
**Kernelcache**: `~/kerneldiff_ave2/26_7_2/` (extracting)  
**Kext path (Mac)**: TBD after extraction

---

## Status: PENDING EXTRACTION

The 26.7.2 OTA downloaded. Kernelcache extraction in progress (ipsw ota extract --kernel).  
Once extracted: `ipsw kernel extract <kc> "com.apple.driver.AppleAVE2" --output <dir>`

---

## Blackwing Progressive Audit Context

**CVE-2026-64747** (iOS 26.6 — ALREADY PATCHED on target 26.6.1):
- Researcher: Franco Belman, Blackwing Intelligence
- Fix: "better size validation" — same component, same researcher
- 26.6.1 kext already has this fix; 26.5 kext does NOT

**CVE-2026-112689** (iOS 26.7.2 — **OPEN on target 26.6.1**):
- Researcher: Franco Belman, Blackwing Intelligence (follow-up audit)
- Fix: "improved input validation" — adjacent/same code path as 64747
- The 26.6 fix plugged parameter A; 112689's fix plugged parameter B in the same function

**Pattern**: Two separate parameters in the same size calculation function, each unvalidated, found in sequential audits by the same researcher.

---

## CVE Patches in iOS 26.7.2 — AVEVideoEncoder (5 total, all OPEN on 26.6.1)

| CVE               | Researcher                                      | Type       | Impact                                   | Fix description                 |
|-------------------|-------------------------------------------------|------------|------------------------------------------|---------------------------------|
| CVE-2026-112705   | Marco Schmitt, Andrey Chernykh, Josh Maine (Calif.io) | OOB write | System termination only            | Improved bounds checking        |
| CVE-2026-112689   | Franco Belman (Blackwing Intelligence)          | OOB write  | **Terminate OR corrupt kernel memory**   | Improved input validation       |
| CVE-2026-112470   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112468   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112469   | Hcamael + 章鱼哥@aipy                            | OOB write  | **Terminate OR corrupt kernel memory**   | Improved bounds checking        |
| CVE-2026-112466   | Hcamael + 章鱼哥@aipy                            | **OOB read** | **Terminate OR read kernel memory**    | Improved input validation       |

**Key insight — Hcamael had a full chain:**
- CVE-2026-112466 (OOB read) = **KASLR bypass** / kernel memory leak
- CVE-2026-112470/468/469 (OOB write) = **kernel memory corruption**
- Read first → get kernel addresses → then write to known targets
- 4 CVEs from one team = same component, likely same code path, 4 distinct buffer types

**CVE-2026-112705 (Calif.io):**
- "System termination only" — no kernel corruption impact in Apple's notes
- Likely hits a buffer that's not on the kernel heap (or write lands in non-critical memory)
- Lower priority for exploit chain

---

## CalcBufSizeOf Functions (expected same 17 names as 26.6.1)

TBD — populate after extracting kext and running `strings | grep CalcBufSizeOf`

---

## Diff vs 26.6.1

TBD — key questions:
1. Which CalcBufSizeOf function bodies changed? (confirms which is the patched one)
2. Were any `mul` instructions changed to `smull`? (arithmetic fix)
3. Were any new `cmp` / `b.gt` checks added before multiplications? (input validation fix)
4. Were any new `cmp` / `csel` added in write-side loops? (bounds check fix)

---

## Notes

- This is the MINIMAL diff target: only security patches, no new encoder features
- 26.7.2 kext should have identical function names/structure to 26.6.1 (same codebase)
- Use `cmp` on function bytes to find changed functions: `cmp` command or Python byte diff
- The 27.0.1 kext is a MAJOR rewrite (905.50?) — not useful for isolating CVE patches
