#!/usr/bin/env python3
"""
probe_sel55_btifault.py — Test AGXDeviceUserClient sel=55.

Background (session-17):
  TABLE_A has 56 entries (0–55), not 55.
  Bounds check: `cmp w1, #55; b.hi` — sel=55 passes.
  sel=55 fn=0xfffffff009bf4d18 starts with bare `ret` (no BTI C landing pad).
  On arm64e (iOS), calling via BRAA to a non-BTI address → BTI fault → kernel panic.

  If sel=55 returns normally (no panic), one of:
  a) The IOKit dispatch helper calls via a trampoline that skips BTI checking
  b) BTI is not enforced for this kext on this device
  c) The fn ptr is somehow redirected via PAC

  Expected results:
  - BadArgument: IOKit pre-check blocked (sc_in=0, si_sz=0 → no pre-check expected)
  - NoResources or other non-fatal: fn was actually called, returned immediately (ret path)
  - Kernel panic: BTI fault on arm64e as expected
  - Any result other than BadArgument: confirms sel=55 is reachable

  Also testing sel=22 (so_sz=unlimited, sc_in=0, si_sz=0 — no pre-check, unexplored).
"""

def run():
    try:
        import iokit
    except ImportError:
        print("[!] iokit module not available")
        return

    SERVICE = "AGXAccelerator"
    TYPE = 1  # AGXDeviceUserClient

    print(f"[*] Opening {SERVICE} type={TYPE}")
    try:
        conn = iokit.IOServiceOpen(SERVICE, TYPE)
        print(f"  conn={conn:#x}")
    except Exception as e:
        print(f"  FAILED: {e}")
        return

    # --- sel=55 ---
    print("\n[*] sel=55 (fn=0x9bf4d18 → bare `ret`, no BTI C)")
    print("    Expected: BTI panic on arm64e, or NoResources if fn was called")

    # sc_in=0, si_sz=0, sc_out=0 → no scalars, no struct needed
    try:
        ret, out = iokit.IOConnectCallMethod(conn, 55, [], None)
        print(f"  sel=55 no-args:    ret={ret:#010x}  out_scalars={out}")
    except Exception as e:
        print(f"  sel=55 no-args:    error: {e}")

    # Try with 0-byte struct too (redundant with no struct, but explicit)
    try:
        ret, out = iokit.IOConnectCallStructMethod(conn, 55, b"")
        print(f"  sel=55 empty struct: ret={ret:#010x}")
    except Exception as e:
        print(f"  sel=55 empty struct: error: {e}")

    # Try with a small struct just in case the dispatch helper reads it
    try:
        ret, out = iokit.IOConnectCallStructMethod(conn, 55, bytes(0x10))
        print(f"  sel=55 0x10-zeroed: ret={ret:#010x}")
    except Exception as e:
        print(f"  sel=55 0x10-zeroed: error: {e}")

    # --- sel=22 (unexplored: so_sz=unlimited, sc_in=0, si_sz=0) ---
    print("\n[*] sel=22 (fn=0x9bf356c, so_sz=unlimited, unexplored)")
    try:
        ret, out = iokit.IOConnectCallMethod(conn, 22, [], None)
        print(f"  sel=22 no-args:    ret={ret:#010x}  out_scalars={out}")
    except Exception as e:
        print(f"  sel=22 no-args:    error: {e}")

    try:
        ret, out = iokit.IOConnectCallStructMethod(conn, 22, bytes(0x100))
        print(f"  sel=22 0x100 struct: ret={ret:#010x}  out_len={len(out)}")
    except Exception as e:
        print(f"  sel=22 0x100 struct: error: {e}")

    # --- Verify gate is open (sel=8 should return NoResources) ---
    print("\n[*] Gate sanity check: sel=8 should return NoResources")
    try:
        ret, _ = iokit.IOConnectCallStructMethod(conn, 8, bytes(0x10))
        print(f"  sel=8: ret={ret:#010x}  {'OK (NoResources = gate open)' if ret == 0xe00002cb else 'unexpected'}")
    except Exception as e:
        print(f"  sel=8: error: {e}")

    print("\n[*] Done")

run()
