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

## Expected CVE Patches (iOS 26.7.2)

| CVE               | Researcher            | Description                    | Likely fix                       |
|-------------------|-----------------------|--------------------------------|----------------------------------|
| CVE-2026-112689   | Blackwing Intelligence| "improved input validation"    | Add bounds check on input param before allocation |
| CVE-2026-112470   | Hcamael + 章鱼哥       | "improved bounds checking"     | Fix write index bounds in encode loop |
| CVE-2026-112468   | Hcamael + 章鱼哥       | "improved bounds checking"     | Fix write index bounds (different buffer) |
| CVE-2026-112469   | Hcamael + 章鱼哥       | "improved bounds checking"     | Fix write index bounds (different buffer) |

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
