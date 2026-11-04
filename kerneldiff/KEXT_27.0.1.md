# AppleAVE2 — iOS 27.0.1 (24A446, build iPhone17,4)

**Binary**: com.apple.driver.AppleAVE2  
**Source version**: TBD (expect 905.50+ — MAJOR version bump vs 26.6.1)  
**OTA**: `~/kerneldiff_ave2/iOS27.0.1_OTAs/iPhone17,4_24A446_KEY_[...].aea` (9.1 GB)  
**Kernelcache**: `~/kerneldiff_ave2/27_0_1/24A446__iPhone17,4/AssetData/boot/kernelcache.release.iphone17`  
**Kext path (Mac)**: `~/kerneldiff_ave2/27_0_1/kexts/com.apple.driver.AppleAVE2`

---

## Segment Map (27.0.1)

| Section                     | File off   | VA                       | Size       |
|-----------------------------|------------|--------------------------|------------|
| `__TEXT.__const`            | 0x770      | 0xfffffff00729d100       | ~300 KB    |
| `__TEXT_EXEC.__text`        | 0xf4000    | 0xfffffff0086ba270       | ~1.9 MB    |

**Note**: Much larger than 26.6.1 (new encoder features added). KC_BASE for 27.0.1 differs.

---

## CalcBufSizeOf Functions — 22 total (up from 17)

**Changes vs 26.6.1:**

| In 26.6.1              | In 27.0.1               | Notes                                          |
|------------------------|-------------------------|------------------------------------------------|
| LFSRef                 | LFSOutput               | Renamed — loop filter ref → output             |
| LFSResult              | (removed?)              | Merged into LFSOutput or dropped               |
| LRSResult              | LRSOutput               | Renamed                                        |
| Recon                  | (removed)               | Split into DPB + other                         |
| StaticAreaQPModInfo    | (removed)               | Dropped or renamed                             |
| *(new)*                | DPB                     | **Explicit DPB calc — confirms "centralized overflow-safe wrapper"** |
| *(new)*                | ColoFwDataInfo          | Colocated forward data info                    |
| *(new)*                | LRB                     | Low-resolution buffer                          |
| *(new)*                | STFSrcNeighborInfo      | Spatial transform filter neighbor              |
| *(new)*                | SrcNeighborAboveFltPixel| New neighbor type                              |
| *(new)*                | SrcNeighborLeftInfo     | New neighbor type                              |
| *(new)*                | SrcNeighborLeftPixel    | New neighbor type                              |
| *(new)*                | EntropyCodingHeader     | New entropy buffer type                        |

**Full 27.0.1 CalcBufSizeOf list:**
```
AVE_CalcBufSizeOfMBInputCtrl
AVE_CalcBufSizeOfCodedData
AVE_CalcBufSizeOfMBStats
AVE_CalcBufSizeOfStaticAreaCBP0Cntr
AVE_CalcBufSizeOfColoFwDataInfo        ← NEW
AVE_CalcBufSizeOfDPB                   ← NEW (was inside Recon)
AVE_CalcBufSizeOfColocated
AVE_CalcBufSizeOfLRB                   ← NEW
AVE_CalcBufSizeOfHSCOutput
AVE_CalcBufSizeOfLFSOutput             ← RENAMED from LFSRef
AVE_CalcBufSizeOfLRSOutput             ← RENAMED from LRSResult
AVE_CalcBufSizeOfSrcNeighborInfo
AVE_CalcBufSizeOfSTFSrcNeighborInfo    ← NEW
AVE_CalcBufSizeOfSrcNeighborPixel
AVE_CalcBufSizeOfSrcNeighborData
AVE_CalcBufSizeOfSrcNeighborFwData
AVE_CalcBufSizeOfSrcNeighborAboveFltPixel ← NEW
AVE_CalcBufSizeOfSrcNeighborLeftInfo   ← NEW
AVE_CalcBufSizeOfSrcNeighborLeftPixel  ← NEW
AVE_CalcBufSizeOfEntropyCoding
AVE_CalcBufSizeOfEntropyCodingHeader   ← NEW
AVE_CalcBufSizeOfMCTFOutput
```

---

## Key Observations

1. **DPB is now explicit** — the centralized overflow-safe DPB wrapper mentioned in patch notes is confirmed as a new CalcBufSizeOfDPB function. In 26.6.1 DPB arithmetic was embedded inside CalcBufSizeOfRecon.

2. **LFSRef renamed to LFSOutput** — the loop filter reference buffer architecture was rearchitected. The 32-bit overflow in LFSRef (at 0x84eee68 in 26.6.1) may have been fixed in this rename.

3. **5 new SrcNeighbor types** — indicates new encoder modes (STF, left-pixel neighbors, filtered-above-pixel neighbors). Not security-related.

4. **27.0.1 is a MAJOR rewrite** — not a suitable diff target for isolating CVE patches. The 26.7.2 diff is the correct one.

---

## Notes

- This kext is NOT the target version for CVE analysis (26.7.2 is)
- The major architectural differences make function-level comparison with 26.6.1 impractical
- Use only to verify that the same function changed in both 26.7.2 and 27.0.1
