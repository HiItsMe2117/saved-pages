# Kernel Diff Project State

## Goal
Diff kernelcaches between iOS 26.6.1 and iOS 26.1 for iPhone 16 Plus (iPhone17,4).
Context: Trigon jailbreak study — tracking what Apple patched between these versions,
especially around `mach_make_memory_entry_64` and SPTM/PPL hardening.

## Target Device
- **iPhone 16 Plus** = `iPhone17,4`

## IPSW URLs

### iOS 26.6.1 (build 23G83)
```
https://updates.cdn-apple.com/2026SummerFCS/fullrestores/140-75160/D83A8969-3179-4D59-9F72-37FFC825CD9A/iPhone17,4_26.6.1_23G83_Restore.ipsw
```

### iOS 26.1 (build 23B85)
```
https://updates.cdn-apple.com/2025FallFCS/fullrestores/089-12124/FD18BC86-63E5-4FE1-AD33-D4B62995ECF2/iPhone17,4_26.1_23B85_Restore.ipsw
```

## Pipeline

```
fetch_kc.py <ipsw_url> <name>.im4p     # range-request kernelcache out of IPSW
unwrap_im4p.py <name>.im4p <name>.macho # strip IM4P, decompress LZFSE
# then diff the two Mach-O files
```

Save output files somewhere persistent (NOT the scratchpad — it dies with the session).
Suggest: `/root/code/saved-pages/kerneldiff/` or `/root/`.

## Status
- [x] IPSW URLs confirmed
- [x] fetch_kc.py written (with ZIP64 support — both local_off and cd_offset are ZIP64)
- [x] unwrap_im4p.py written
- [x] Downloaded 26.6.1 kernelcache → `kerneldiff/kc_26.6.1.im4p` (22,077,586 bytes)
- [x] Downloaded 26.1 kernelcache  → `kerneldiff/kc_26.1.im4p`   (21,995,219 bytes)
- [x] IM4P unwrapped both — LZFSE payloads saved:
      `kerneldiff/kc_26.6.1.macho.lzfse` (22,077,202 bytes, magic bvx2)
      `kerneldiff/kc_26.1.macho.lzfse`   (21,994,838 bytes, magic bvx2)
- [x] Decompress LZFSE → raw Mach-O
      `kerneldiff/kc_26.6.1.macho` — Mach-O 64-bit arm64e, filetype=12
      `kerneldiff/kc_26.1.macho`   — Mach-O 64-bit arm64e, filetype=12
- [x] Symbol extraction approach: production kernel stripped (nsyms=0)
      Symbols identified via string scanning + MIG name-table scan
- [x] Full diff analysis complete → REPORT.md

## Key Findings Summary
- **26.6.1 has 304 kexts** (+2: AppleThunderboltUSBType2 adapters); 26.1 has 302
- **300/302 kexts changed**, 0 unchanged — entire kernel was recompiled
- **__TEXT_EXEC shrank -1.96MB** in 26.6.1
- **mach_make_memory_entry_64** MIG index shifted by 1 (from `!O_` to `!N_` in LINKEDIT)
- **SPTM strings +19**: `sptm`/`sptm_` references grew significantly
- **PPL being removed**: `unsupported on non-PPL systems` strings gone in 26.6.1
- **Sandbox kext**: most changed kext by byte count (1.75MB diff), shrank 50KB
- **corecrypto** and **AppleImage4** both changed — crypto/boot path updates
- **Build root**: 26.6.1 uses `iPhoneOS26.6.Internal.sdk`, 26.1 uses `iPhoneOS26.1.Internal.sdk`
- File-position diff not meaningful (code shifted due to 1.96MB size change)

## Kernel Build Strings (from IM4P description field)
- 26.6.1: `KernelManagement_host-487.100.11`
- 26.1:   `KernelManagement_host-487.0.4`

## Files on disk (NOT in git — too large; re-run scripts to regenerate)
- `kerneldiff/kc_26.6.1.im4p`        — raw IM4P from IPSW range-request
- `kerneldiff/kc_26.1.im4p`           — raw IM4P from IPSW range-request
- `kerneldiff/kc_26.6.1.macho.lzfse` — LZFSE payload extracted from IM4P
- `kerneldiff/kc_26.1.macho.lzfse`   — LZFSE payload extracted from IM4P

## Notes
- IPSW ZIP is ZIP64: both the central-directory offset AND per-file local_offset
  are 0xFFFFFFFF sentinels — must parse ZIP64 extra fields (tag 0x0001) to get
  real values. fetch_kc.py handles this now.
- Kernelcache is deflate-compressed (method=8) in the ZIP, then LZFSE-compressed
  inside the IM4P. Two layers of compression.
- `apk add lzfse` works on this machine (Alpine Linux). Already installed.
- lzfse must be called with file args (`-i file -o file`), not stdin pipe.
  unwrap_im4p.py now uses a temp file approach.
- Once decompressed, diff with `jtool2 -d` or `nm` + text diff on symbol lists.

## To resume in a new session
1. `cd ~/code/saved-pages`
2. `git pull`
3. Read this file
4. If .lzfse files still exist on disk: get lzfse working then decompress
5. If they don't: re-run fetch_kc.py + unwrap_im4p.py (fast, ~2 min each)
