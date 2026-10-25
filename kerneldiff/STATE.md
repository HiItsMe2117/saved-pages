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

## iOS 27.0.1 (build 24A446) — ADDED
```
https://updates.cdn-apple.com/2026FallFCS/ff004e4f-0c2c-489a-b3c2-42b07bb962bc/iPhone17,4_27.0.1_24A446_Restore.ipsw
```
- Downloaded → `kerneldiff/kc_27.0.1.im4p` (23.4MB) → `kerneldiff/kc_27.0.1.macho` (74.4MB)
- KernelManagement_host-**514.2.2** (jumped from 487 → 514)
- 26.6.1 vs 27.0.1 SPTM-targeted diff IN PROGRESS → `kerneldiff/REPORT_27.md`
  Checkpoints 1-4 written; steps 5-7 still running in background agent

## Key 26.6.1 → 27.0.1 Findings So Far
- **GENTER (+23)**: 150 → 173 SPTM call sites in __TEXT_EXEC
- **__DATA_SPTM +64KB**, **__TEXT_EXEC +3.6MB**, **__PRELINK_TEXT +1.4MB**
- **__PPLTEXT**: already gone in BOTH versions (removed before 26.6.1)
- **New SPTM fn**: `sptm_page_is_sk_shared_realtime` — Secure Kernel realtime page sharing
- **New**: SPTM now manages ASIDs directly (`insufficient number of ASIDs supplied by SPTM`)
- **Image4**: 12 new "attempted to get X without PPL context" strings in 27.0.1
- **libsptm_init** path restructured (string removed)
- **mach_make_memory_entry_64**: "Unsanitary input" validation string removed; MIG index `!N_`→`!f_`

## Version Ladder — COMPLETE (kernel IDs collapsed the ladder)
- 26.6.2 (23G90): KernelManagement_host-**487.100.11** — SAME as 26.6.1 (no kernel change)
- 27.0   (24A437): KernelManagement_host-**514.2.2**   — SAME as 27.0.1 (no kernel change)
- Ladder collapses to ONE diff: 26.6.1 → 27.0 ≡ REPORT_27.md (already done)

## SPTM / TXM Binaries (bonus discovery from 27.0 IPSW listing)
- `Firmware/sptm.t8140.release.im4p` — the actual SPTM binary (~1.2MB, GL2 execution)
- `Firmware/txm.iphoneos.release.im4p` — TXM (Trust Monitor) binary
- Can be extracted with fetch_kc.py targeting those filenames
- "page enforcement failed" and SPTM enforcement logic lives in sptm.t8140

## SPTM Binary Analysis — COMPLETE
Commit: 6a85b0a → REPORT_SPTM.md (267 lines)
String files: sptm_26.6.1_strings.txt, sptm_27.0.1_strings.txt
Google Doc: https://docs.google.com/document/d/1Gp4FXADaiA2W-AAym7uPtVjr19T_lRjbJoG2RycuyZE/edit

Key SPTM findings:
- Dispatch redesigned: raw integers → named (table_id, endpoint_id) pairs
- 0 → 36 ENDPOINTIDs, 2 → 21 DISPATCH_TABLE IDs
- EXEC_MODE_SK_DEFAULT NEW — SK now a first-class SPTM caller
- 3 new SK_TO_SPTM endpoints: RETYPE, PHYS_TO_TYPE, REGISTER_DISPATCH_TABLE
- GPU SAPT revocation gaps closed (AGX technique blocked)
- Only 1 VIOLATION removed (restructure, not relaxation)

## GENTER Map — COMPLETE (REPORT_GENTER_MAP.md)
Key findings:
- ALL 173 GENTER calls go through a centralized stub dispatch array in __TEXT_EXEC
- Each stub encodes (table_id << 32) | endpoint_id in x16
- 27.0.1 stubs are larger (64 vs 44 bytes): new ADRP+LDRB+CBNZ "SPTM ready" guard per stub
- Dispatch table 0xe is entirely NEW with 16 endpoints (0..15) — entirely new XNU→SPTM surface
- Table 9 endpoint 0 (0x900000000) is new — the core pmap/retype table gained endpoint 0
- 4 old endpoints removed (tables 7, 9, 10)

## Next Steps — Exploit Surface Research
Priority order:
1. Identify dispatch table 0xe subsystem: which kext calls these 16 new stubs (NVMe/CPUTRACE/HIB)
2. Trace callers of 0x900000000 (table 9, ep 0 — new core retype/mapping call)
3. Extract SK binary (sk.*.im4p) → map 3 SK_TO_SPTM_ENDPOINTID GENTER calls
4. Investigate SPTM_HIB_ENDPOINTID_IOFILTER_PROTECTED_WRITE hibernation write path
5. Study mach_make_memory_entry "Unsanitary input" string removal (Trigon-adjacent)

## Files on disk (NOT in git)
- sptm_26.6.1.bin (1.09MB) — SPTM binary iOS 26.6.1
- sptm_27.0.1.bin (1.14MB) — SPTM binary iOS 27.0.1
- sptm_26.6.1.im4p, sptm_27.0.1.im4p — raw IM4P containers

## Files on disk — VERSION LADDER (NOT in git)
- kc_26.6.2.macho (72.6MB) — same kernel as 26.6.1
- kc_27.0.macho   (78.0MB) — same kernel as 27.0.1

## To resume in a new session
1. `cd ~/code/saved-pages && git pull`
2. Read STATE.md, REPORT.md, SPTM_RESEARCH.md, REPORT_27.md
3. Kernelcaches on disk (NOT in git — regenerate if missing, ~2 min each):
   - kc_26.1.macho, kc_26.6.1.macho, kc_27.0.1.macho
4. Tools: `apk add lzfse` (already installed), pip available, numpy available
5. If REPORT_27.md incomplete: check if background agent still running, else re-run analyse.py
