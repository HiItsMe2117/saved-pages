#!/usr/bin/env python3
"""
Extract kernelcache from iOS IPSW via range requests — no full download needed.
Usage: python3 fetch_kc.py <ipsw_url> <output.im4p>
"""

import sys
import struct
import subprocess

def curl_range(url, start, end):
    r = subprocess.run(
        ['curl', '-s', '-L', '--range', f'{start}-{end}', url],
        capture_output=True
    )
    if r.returncode != 0:
        raise RuntimeError(f"curl failed: {r.stderr.decode()}")
    return r.stdout

def get_content_length(url):
    r = subprocess.run(['curl', '-sI', '-L', url], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.lower().startswith('content-length:'):
            return int(line.split(':', 1)[1].strip())
    raise RuntimeError("Could not get Content-Length")

def find_eocd(data):
    idx = data.rfind(b'PK\x05\x06')
    if idx == -1:
        # Check for ZIP64 EOCD
        idx = data.rfind(b'PK\x06\x06')
        if idx == -1:
            raise ValueError("EOCD not found in tail")
    return idx

def parse_eocd(data, idx):
    sig = struct.unpack_from('<I', data, idx)[0]
    if sig == 0x06054b50:  # standard EOCD
        _, disk, cd_disk, entries_disk, entries, cd_size, cd_offset, comment_len = \
            struct.unpack_from('<IHHHHIIH', data, idx)
        return cd_size, cd_offset, entries
    elif sig == 0x06064b50:  # ZIP64 EOCD
        # ZIP64: sizes are 8-byte
        (_, record_size, version_made, version_needed, disk, cd_disk,
         entries_disk, entries, cd_size, cd_offset) = \
            struct.unpack_from('<IQHHIIQQQQ', data, idx)
        return cd_size, cd_offset, entries
    raise ValueError(f"Unknown EOCD signature: {sig:#010x}")

def parse_central_directory(data):
    entries = []
    i = 0
    while i + 46 <= len(data):
        sig = struct.unpack_from('<I', data, i)[0]
        if sig != 0x02014b50:
            break
        (_, version_made, version_needed, flags, compression,
         mod_time, mod_date, crc32, compressed_size, uncompressed_size,
         filename_len, extra_len, comment_len, disk_start,
         int_attrs, ext_attrs, local_offset) = struct.unpack_from('<IHHHHHHIIIHHHHHII', data, i)
        i += 46
        name = data[i:i+filename_len].decode('utf-8', errors='replace')
        i += filename_len + extra_len + comment_len
        entries.append({
            'name': name,
            'compression': compression,
            'compressed_size': compressed_size,
            'uncompressed_size': uncompressed_size,
            'local_offset': local_offset,
        })
    return entries

def get_data_offset(url, local_offset):
    header = curl_range(url, local_offset, local_offset + 29)
    _, _, _, _, _, _, _, _, _, filename_len, extra_len = \
        struct.unpack_from('<IHHHHHIIIHH', header)
    return local_offset + 30 + filename_len + extra_len

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ipsw_url> <output.im4p>")
        sys.exit(1)

    url, out = sys.argv[1], sys.argv[2]

    print(f"[*] Getting IPSW size...")
    size = get_content_length(url)
    print(f"[*] IPSW: {size:,} bytes ({size/1024**3:.2f} GB)")

    tail_size = min(131072, size)
    tail_start = size - tail_size
    print(f"[*] Fetching last {tail_size//1024}KB for EOCD...")
    tail = curl_range(url, tail_start, size - 1)

    eocd_idx = find_eocd(tail)
    cd_size, cd_offset, num_entries = parse_eocd(tail, eocd_idx)
    print(f"[*] Central dir: offset={cd_offset:,}  size={cd_size:,}  entries={num_entries}")

    print(f"[*] Fetching central directory ({cd_size//1024}KB)...")
    cd_data = curl_range(url, cd_offset, cd_offset + cd_size - 1)

    entries = parse_central_directory(cd_data)

    kc = next((e for e in entries if 'kernelcache' in e['name'].lower()), None)
    if not kc:
        print("[-] No kernelcache found. Files in IPSW:")
        for e in entries[:30]:
            print(f"    {e['name']}")
        sys.exit(1)

    print(f"[+] Found: {kc['name']}")
    print(f"    method={kc['compression']}  size={kc['compressed_size']:,} bytes")

    data_offset = get_data_offset(url, kc['local_offset'])
    print(f"[*] Downloading kernelcache ({kc['compressed_size']//1024//1024} MB)...")
    payload = curl_range(url, data_offset, data_offset + kc['compressed_size'] - 1)

    if kc['compression'] == 8:
        import zlib
        print("[*] Inflating (deflate)...")
        payload = zlib.decompress(payload, -15)
    elif kc['compression'] != 0:
        print(f"[!] Unknown compression method {kc['compression']}, saving raw")

    with open(out, 'wb') as f:
        f.write(payload)

    print(f"[+] Saved {len(payload):,} bytes → {out}")
    print(f"[*] Magic: {payload[:4].hex()}  ({payload[:4]})")

if __name__ == '__main__':
    main()
