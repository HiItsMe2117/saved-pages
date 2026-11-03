#!/usr/bin/env python3
"""
rh_run.py — ResearchHost client
Usage:
  rh ping              check connection, print device info
  rh state             show persisted _rh_state dict
  rh reset             reset Python capture (clear stdout/stderr buffers)
  rh <file.py>         run a probe file, print output cleanly
  rh <file.py> -v      also show raw JSON
  rh -h HOST <cmd>     override host (default: RH_HOST env or 10.0.0.2)

State threading: probes can persist values across calls via builtins._rh_state.
  Store:  import builtins; _rh_state(nc_hndl=0x1234)
  Read:   from rh_state import nc_hndl  (auto-injected preamble)
"""

import sys, os, json, socket, time

HOST = os.environ.get("RH_HOST", "10.0.0.18")  # Mac as iproxy relay → iPhone:8765
PORT = 8765
TIMEOUT = 15

# ── helpers ────────────────────────────────────────────────────────────────

def http(method, path, body=b""):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))
        req = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {HOST}:{PORT}\r\n"
               f"Content-Length: {len(body)}\r\n"
               f"Connection: close\r\n\r\n").encode() + body
        s.sendall(req)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    finally:
        s.close()
    # split headers / body
    sep = resp.find(b"\r\n\r\n")
    return json.loads(resp[sep+4:]) if sep != -1 else {}

def color(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def print_result(data, verbose=False):
    if verbose:
        print(color("2", json.dumps(data, indent=2)))
        print()
    out = data.get("out", "")
    err = data.get("err", "")
    if out.strip():
        print(out, end="" if out.endswith("\n") else "\n")
    if err.strip():
        for line in err.splitlines():
            print(color("33", f"ERR  {line}"))

# ── state helpers injected into every probe ───────────────────────────────

STATE_PREAMBLE = """
import builtins as _bi
if not hasattr(_bi, '_rh_state'):
    _bi._rh_state = {}
_rh_state = _bi._rh_state

def _rh_store(**kw):
    _bi._rh_state.update(kw)
    for k, v in kw.items():
        print(f"[rh] stored {k}={v!r}")
"""

# ── commands ───────────────────────────────────────────────────────────────

def cmd_ping():
    try:
        d = http("GET", "/ping")
        print(color("32", "CONNECTED"))
        print(f"  model : {d.get('model','?')}")
        print(f"  ios   : {d.get('ios','?')}")
        print(f"  ips   : {', '.join(d.get('ips', []))}")
    except Exception as e:
        print(color("31", f"FAILED: {e}"))
        sys.exit(1)

def cmd_state():
    code = "import builtins, json\nprint(json.dumps(getattr(builtins,'_rh_state',{}), default=repr))"
    d = http("POST", "/run", (STATE_PREAMBLE + code).encode())
    raw = d.get("out", "{}").strip()
    try:
        state = json.loads(raw)
        if not state:
            print("(empty)")
        for k, v in state.items():
            print(f"  {k} = {v!r}")
    except Exception:
        print(raw)

def cmd_reset():
    code = ("import sys, builtins\n"
            "class _Cap:\n"
            "    def __init__(self): self._b=[]\n"
            "    def write(self,s): self._b.append(str(s))\n"
            "    def flush(self): pass\n"
            "    def getvalue(self):\n"
            "        v=''.join(self._b); self._b=[]; return v\n"
            "sys.stdout=_Cap()\nsys.stderr=_Cap()\n"
            "print('Python capture reset')\n")
    d = http("POST", "/run", code.encode())
    print_result(d)

def cmd_run(path, verbose=False):
    try:
        with open(path) as f:
            src = f.read()
    except FileNotFoundError:
        print(color("31", f"file not found: {path}"))
        sys.exit(1)

    payload = (STATE_PREAMBLE + src).encode()
    t0 = time.time()
    try:
        d = http("POST", "/run", payload)
    except socket.timeout:
        print(color("31", "TIMEOUT — probe hung or server died"))
        sys.exit(1)
    except ConnectionRefusedError:
        print(color("31", f"Connection refused — is ResearchHost running on {HOST}:{PORT}?"))
        sys.exit(1)

    elapsed = time.time() - t0
    label = os.path.basename(path)
    print(color("2", f"── {label}  ({elapsed:.1f}s) ──────────────────"))
    print_result(d, verbose)

# ── main ───────────────────────────────────────────────────────────────────

def main():
    global HOST
    args = sys.argv[1:]

    # -h HOST override
    if "-h" in args:
        i = args.index("-h")
        HOST = args[i+1]
        args = args[:i] + args[i+2:]

    if not args or args[0] in ("--help", "help"):
        print(__doc__)
        sys.exit(0)

    cmd = args[0]
    verbose = "-v" in args

    if cmd == "ping":
        cmd_ping()
    elif cmd == "state":
        cmd_state()
    elif cmd == "reset":
        cmd_reset()
    elif os.path.exists(cmd) or cmd.endswith(".py"):
        cmd_run(cmd, verbose)
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
