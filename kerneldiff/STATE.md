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
- [x] fetch_kc.py written
- [x] unwrap_im4p.py written
- [ ] Download 26.6.1 kernelcache
- [ ] Download 26.1 kernelcache
- [ ] Unwrap both
- [ ] Diff / analyse

## Notes
- No `lzfse` binary or Python binding available yet. `unwrap_im4p.py` will save
  the compressed payload as `<name>.macho.lzfse` and print instructions.
- Try `apt-get install lzfse` first. If unavailable, see compile instructions
  in unwrap_im4p.py comments.
- IPSW ZIP central directory is at the end of the file — range requests work fine.
- Kernelcache in modern IPSWs is usually stored uncompressed (method 0) in the ZIP,
  so we get raw IM4P bytes from the range request.
