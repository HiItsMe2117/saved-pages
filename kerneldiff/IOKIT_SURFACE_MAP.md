# IOKit Surface Map — ResearchHost (iOS 26.6.1 sandboxed)
Date: 2026-11-05

## Reachable Surfaces (no entitlement needed)

| Service         | Type | Result        | Selectors |
|-----------------|------|---------------|-----------|
| AGXAccelerator  | 1    | OPEN          | 0–54 all exist (BadArgument), sel=8 NoResources |
| IOSurfaceRoot   | 0    | OPEN          | 0–31 all exist (BadArgument) |
| AppleKeyStore   | 0    | OPEN          | 0,1,16 SUCCESS; 2–63 mixed |
| AppleKeyStore   | 1    | OPEN          | Identical to type=0 |

## Sandbox-Blocked Surfaces

AppleAVE2Driver, IOHIDDevice, IOPMrootDomain, AppleSMC, IOUSBDevice,
IOUSBInterface, AppleMobileFileIntegrity, AppleCredentialManager

## AGXAccelerator (type=1) — Selector Map

Connection type=1 → AGXDeviceUserClient (GPU kernel driver).

- sel 0–54: BadArgument (all exist, need valid struct input)
- sel 8:    kIOReturnNoResources (0xe00002be) — went past input validation
- sel 55+:  Unsupported (selector table ends around 55)

**Notes:**
- No sandbox gating on any selector — fully accessible from container
- Huge attack surface: 55 selectors all reachable
- Need to identify struct formats from AGX kext binary
- sel=8 is highest priority: passed input validation, hit resource allocation

## AppleKeyStore — Selector Map

Both type=0 and type=1 respond identically.

| Sel | Result                        | Notes |
|-----|-------------------------------|-------|
| 0   | SUCCESS                       | Returns with zeroed 0x100 input |
| 1   | SUCCESS                       | Returns with zeroed 0x100 input |
| 16  | SUCCESS                       | Returns with zeroed 0x100 input |
| 2–4 | BadArgument                   | Need valid input |
| 5   | kIOReturnNotPrivileged (c1)   | Kext-level check |
| 6–7 | BadArgument                   | Need valid input |
| 8   | SANDBOX                       | Sandbox-gated (even on open connection) |
| 9–15| BadArgument                   | Need valid input |
| 17  | 0xe00002f0                    | Unknown error |
| 18  | BadArgument                   |  |
| 19  | SANDBOX                       | Sandbox-gated |
| 20–22 | kIOReturnNotPrivileged (c1) |  |
| 23–31 | BadArgument                |  |
| 32  | SANDBOX                       | Sandbox-gated |
| 33–39 | kIOReturnNotPrivileged (c1) |  |
| 40  | BadArgument                   |  |
| 41  | kIOReturnNotPrivileged (c1)   |  |
| 42–50 | BadArgument                |  |
| 51  | kIOReturnNotPrivileged (c1)   |  |
| 52–55 | BadArgument                |  |
| 56–63 | BadArgument                |  |

**Notes:**
- `kIOReturnNotPrivileged (0xe00002c1)` = kext-level check, NOT sandbox
- sel 0,1,16 succeed with zeroed input — worth probing what they return
- sel 8,19,32 sandbox-gated WITHIN the open connection (unusual — per-selector sandbox rules)

## IOSurfaceRoot — Selector Map

- sel 0–31: All exist (BadArgument on zeroed input)
- Use: heap spray/grooming tool (create/destroy surfaces at specific kalloc sizes)

## Not Found / Not Accessible

AGXDevice, AppleNVMe, AppleH11ANEInterface, AppleNeuralEngine,
AppleISP, AppleSEP, IOHIDSystem, IOFramebuffer, IO80211Controller,
CoreCapture, IOAudioDevice

## Next Steps

1. Probe AGX sel=8 with varying struct sizes to find valid input format
2. Read output of AppleKeyStore sel=0, 1, 16 (look for kernel addresses / info leak)
3. Find AGX kext binary to map selector→function
4. XPC sniff: mediaserverd interface when VideoToolbox is active
5. Use IOSurfaceRoot as heap grooming primitive once kernel write established
