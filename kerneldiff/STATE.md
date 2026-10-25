# Kernel Diff Project State

---
## INVESTIGATION LOG (quick reference — newest first)

| Date | Path | Tool/File | Finding | Report |
|---|---|---|---|---|
| 2026-10-25 | q_tail user-space exposure | kc_27.0.1.macho | NOT user-space reachable; entirely kernel-internal; all 3 gaps need kernel exec first | REPORT_QTAIL_USERSPACE.md |
| 2026-10-25 | nvme-sptm EDT property | kc_26.6.1 + kc_27.0.1 | Set by iBoot; present in both versions; nvme-sppl downgrade: devices w/sppl only bypass all SPTM NVMe guards | REPORT_NVME_SPTM_EDT.md |
| 2026-10-25 | sanitize_integer dispatch bypass | sptm_26.6.1.bin | IN PROGRESS — what does sanitize_integer do; can it be bypassed? | REPORT_SANITIZE_INT.md |
| 2026-10-25 | vm_sanitize correction behavior | kc_26.6.1.macho | IN PROGRESS — soft-landing present on 26.6.1; correction behavior exploitable? | REPORT_VMSANITIZE_26.md |
| 2026-10-25 | STRATEGIC PIVOT | — | Target is 26.6.1. Diffs show what 27.0.1 fixed = open on target. Not chasing Trigon. | — |
| 2026-10-25 | nvme_instance writability | kc_27.0.1.macho + sptm_27.0.1.bin | NOT XNU-writable; linear flag in SPTM-private memory set at boot; q_tail walk-off now top target | REPORT_NVME_INSTANCE.md |
| 2026-10-25 | SET_SQ_ENTRY bounds | sptm_27.0.1.bin | 3 gaps: linear-mode PA bypass, q_tail walk-off, unchecked payload | REPORT_NVME_SQENTRY.md |
| 2026-10-25 | NVMe eps 10–15 guards | sptm_27.0.1.bin | Not unguarded; VIOLATION_NVME_ILLEGAL_CALL + allowed_functions bitmask in __DATA | REPORT_NVME_UNGUARDED.md |
| 2026-10-25 | SK binary location | IPSW 27.0.1 | SK sealed inside SPTM image; not standalone; bootstrapped by SPTM+0x9f90c GENTER | REPORT_SK_BINARY.md |
| 2026-10-25 | mach_make_memory_entry | kc_26.6.1 vs kc_27.0.1 | vm_sanitize_telemetry.c entirely removed; 30+ VM APIs lost soft-landing correction layer | REPORT_MME_SANITIZE.md |
| 2026-10-25 | Table 9 ep 0 callers | kc_27.0.1.macho | New XNU retype entry; arm64e PAC indirect; absent in 26.6.1; parallel to SK_TO_SPTM_RETYPE | REPORT_RETYPE_EP0.md |
| 2026-10-25 | Table 0xe subsystem | kc_27.0.1.macho | SPTM_NVME; caller=com.apple.iokit.IONVMeFamily; PAC fn-ptr + preemption wrapper 0xab4bf78 | REPORT_TABLE0E.md |
| 2026-10-25 | GENTER stub mapping | kc_26.6.1 + kc_27.0.1 | 150→173 stubs; table 0xe NEW (16 eps); universal CBNZ guard added; +28 dispatch IDs | REPORT_GENTER_MAP.md |
| 2026-10-25 | SPTM binary diff | sptm_26.6.1.bin + sptm_27.0.1.bin | Dispatch redesign; SK exec mode; 3 GPU SAPT gaps closed; IOMMU registry new | REPORT_SPTM.md |
| 2026-10-25 | 26.6.1 vs 27.0.1 kernel | kc_26.6.1 + kc_27.0.1 | +23 GENTER; __TEXT_EXEC +3.6MB; SPTM fn additions; mach_make_memory_entry MIG shift | REPORT_27.md |
| 2026-10-25 | 26.1 vs 26.6.1 kernel | kc_26.1 + kc_26.6.1 | 300/302 kexts changed; __TEXT_EXEC -1.96MB; SPTM strings +19; PPL strings gone | REPORT.md |

---
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

## Exploit Surface Research — COMPLETE (5 reports committed)

### Table 0xe = SPTM_NVME (REPORT_TABLE0E.md)
- Caller: com.apple.iokit.IONVMeFamily (exclusive, 34× string density vs next)
- Call path: PAC-signed function pointer + disable_preemption wrapper at 0xab4bf78
- NVMe was already in SPTM 26.6.1 (8 handlers); table-0xe is migration to named dispatch
- Eps 10–15 blocked by allowed_functions bitmask (VIOLATION_NVME_ILLEGAL_CALL); bitmask in __DATA

### Table 9 Endpoint 0 (REPORT_RETYPE_EP0.md)
- Stub at 0xfffffff00b400594; confirmed absent in 26.6.1
- No direct BL callers — arm64e PAC-signed indirect dispatch
- Likely SPTM_XNU_RETYPE entry; parallel to new SK_TO_SPTM_ENDPOINTID_RETYPE (same release)
- Retype is the crown jewel: type confusion between kernel/RO/user/GPU/secure memory

### SET_SQ_ENTRY Bounds Gaps (REPORT_NVME_SQENTRY.md) ← HIGH VALUE
THREE gaps found:
1. LINEAR MODE BYPASS (0x0b86c4): CBZ skips entire PA range check when nvme-linear-sq set in nvme_instance
   → IF nvme_instance is XNU-writable, DMA reaches arbitrary physical memory
2. q_tail WALK-OFF: qtail_state[q_tail] accessed with no CMP before array index (LDRB w8, [x24, #0xc08])
   → out-of-range q_tail reads arbitrary SPTM memory as state byte
3. SQ entry content unchecked: command payload (opcode, PRP, CDW10-15) not inspected by SPTM
KEY UNKNOWN: is nvme_instance in XNU-writable memory during IONVMeFamily operation?

### mach_make_memory_entry "Unsanitary input" (REPORT_MME_SANITIZE.md)
- Entire vm_sanitize_telemetry.c subsystem removed from 27.0.1 (covered 30+ VM APIs)
- Soft-landing layer that logged bad inputs, clamped/corrected, continued → now GONE
- Hard @%s:%d panic assertions in vm_memory_entry.c still present
- Gap: whatever soft corrections did that hard assertions don't cover → unhandled in 27.0.1
- Mirrors SPTM's simultaneous removal of sanitize_integer(UNSAFE_VALUE)

### SK Binary (REPORT_SK_BINARY.md)
- SK is NOT a standalone IPSW file — it lives sealed inside SPTM's image
- SPTM bootstraps SK via MSR writes (entry point, stack) + GENTER at SPTM+0x9f90c
- ExclaveCore bundle uses GENTER for L4 hypercalls (different calling convention, not SPTM)
- TXM has GEXIT (not GENTER) — TXM is called by SPTM, doesn't originate calls
- SK→SPTM calls must be found within sptm_27.0.1.bin by reversing bootstrap sequence

## NVMe Attack Chain — CRYSTALLIZED (post-kernel-exec only)
All three SET_SQ_ENTRY gaps require kernel code execution as precondition. Call chain:
  NVMeCoastGuardSetTCBEntry(tcb_queue_entry*, AppleNVMeRequest*)
    → pmap_iommu_ioctl(NVME_PPL_IOCTL_SET_SQ_ENTRY)
      → GENTER table=0xe ep=8
Both args are kernel-owned structs. All 4 IONVMeFamily user clients (Sanitize, UpdateUC,
FWNamespaceUC, EANUC) are firmware management only — none touch submission queues.

Chain to GL2 DMA primitive (needs kernel exec first):
  1. Kernel exec → vtable control → EnableLinearSQ() → linear mode active in nvme_instance
  2. Linear mode → SET_SQ_ENTRY skips PA range check → DMA to arbitrary physical memory at GL2
  3. Separately: q_tail walk-off → read arbitrary SPTM GL2 memory as 1-byte state value

nvme-sppl downgrade: devices with nvme-sppl but NOT nvme-sptm route through pre-SPTM NVMe path.
All VIOLATION_NVME_* guards and table-0xe enforcement inactive on such devices.

## Next Steps — Priority
1. Find kernel code execution primitive (needed to reach NVMe GL2 chain above)
   Candidates: vm_sanitize gap (REPORT_MME_SANITIZE), retype ep-0 (REPORT_RETYPE_EP0),
   hibernation write (SPTM_HIB_ENDPOINTID_IOFILTER_PROTECTED_WRITE)
2. nvme-sppl downgrade path — which devices/configs have sppl but not sptm?
   Any lab device with modified EDT could test the unguarded NVMe path
3. Reverse SPTM bootstrap (0x9f904-0x9f90c MSR writes) → find SK entry in SPTM image
4. Investigate SPTM_HIB_ENDPOINTID_IOFILTER_PROTECTED_WRITE (hibernation write path)

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
