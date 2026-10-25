#!/usr/bin/env python3
"""
Unwrap an IM4P container to extract the raw decompressed Mach-O kernel.
Usage: python3 unwrap_im4p.py <input.im4p> <output.macho>

LZFSE decompression requires one of:
  - apt-get install lzfse        (provides /usr/bin/lzfse)
  - pip install lzfse            (Python binding)
If neither is available the compressed payload is saved as <output>.lzfse
with instructions to decompress manually.
"""

import sys
import os
import struct
import subprocess

MACHO_MAGIC = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe'}

def asn1_length(data, i):
    b = data[i]; i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7f
    return int.from_bytes(data[i:i+n], 'big'), i + n

def asn1_string(data, i):
    i += 1  # skip tag
    l, i = asn1_length(data, i)
    return data[i:i+l], i + l

def extract_im4p(data):
    i = 0
    assert data[i] == 0x30, f"Expected SEQUENCE at 0, got {data[i]:#04x}"
    i += 1
    _, i = asn1_length(data, i)

    magic, i = asn1_string(data, i)
    assert magic == b'IM4P', f"Expected IM4P, got {magic}"

    kc_type, i = asn1_string(data, i)
    print(f"[*] Type:        {kc_type.decode()}")

    desc, i = asn1_string(data, i)
    print(f"[*] Description: {desc.decode(errors='replace')}")

    assert data[i] == 0x04, f"Expected OCTET STRING at {i}, got {data[i]:#04x}"
    i += 1
    payload_len, i = asn1_length(data, i)
    return data[i:i+payload_len]

def decompress_lzfse(payload, out_path):
    magic4 = payload[:4]

    if magic4 in MACHO_MAGIC:
        print("[*] Payload is already Mach-O, writing directly")
        with open(out_path, 'wb') as f:
            f.write(payload)
        return True

    if magic4 == b'bvx-':
        # LZFSE "uncompressed" — 8-byte header then raw data
        print("[*] bvx- (LZFSE passthrough)")
        with open(out_path, 'wb') as f:
            f.write(payload[8:])
        return True

    print(f"[*] Payload magic: {magic4.hex()} — needs LZFSE decompression")

    # Try system lzfse binary
    for candidate in ('/usr/bin/lzfse', '/usr/local/bin/lzfse'):
        if os.path.exists(candidate):
            r = subprocess.run([candidate, '-decode', '-i', '-', '-o', out_path],
                               input=payload, capture_output=True)
            if r.returncode == 0:
                print(f"[+] Decompressed via {candidate}")
                return True

    # Try Python binding
    try:
        import lzfse
        with open(out_path, 'wb') as f:
            f.write(lzfse.decompress(payload))
        print("[+] Decompressed via Python lzfse module")
        return True
    except ImportError:
        pass

    # Fallback: save compressed payload
    lzfse_path = out_path + '.lzfse'
    with open(lzfse_path, 'wb') as f:
        f.write(payload)
    print(f"[!] No LZFSE decompressor available.")
    print(f"[!] Compressed payload saved to: {lzfse_path}")
    print(f"[!] To decompress, run one of:")
    print(f"[!]   apt-get install lzfse && lzfse -decode -i {lzfse_path} -o {out_path}")
    print(f"[!]   pip install lzfse && python3 -c \"import lzfse,sys; open(sys.argv[2],'wb').write(lzfse.decompress(open(sys.argv[1],'rb').read()))\" {lzfse_path} {out_path}")
    return False

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.im4p> <output.macho>")
        sys.exit(1)

    in_path, out_path = sys.argv[1], sys.argv[2]

    with open(in_path, 'rb') as f:
        data = f.read()

    print(f"[*] Read {len(data):,} bytes, magic: {data[:4].hex()}")

    if data[:4] in MACHO_MAGIC:
        print("[*] Already a Mach-O, copying directly")
        with open(out_path, 'wb') as f:
            f.write(data)
    elif data[0] == 0x30:
        payload = extract_im4p(data)
        print(f"[+] Payload: {len(payload):,} bytes, magic: {payload[:4].hex()}")
        decompress_lzfse(payload, out_path)
    else:
        print(f"[!] Unrecognised format: {data[:16].hex()}")
        sys.exit(1)

    if os.path.exists(out_path):
        sz = os.path.getsize(out_path)
        magic = open(out_path, 'rb').read(4)
        print(f"[+] Output: {out_path} ({sz:,} bytes, magic: {magic.hex()})")

if __name__ == '__main__':
    main()
