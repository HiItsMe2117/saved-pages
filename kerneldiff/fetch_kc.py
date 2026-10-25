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
        raise ValueError("EOCD not found in tail")
    return idx

def parse_eocd(data, idx, url):
    """Parse EOCD; if ZIP64 sentinel detected, fetch and parse ZIP64 EOCD."""
    _, disk, cd_disk, entries_disk, entries, cd_size, cd_offset, comment_len = \
        struct.unpack_from('<IHHHHIIH', data, idx)

    if cd_offset != 0xFFFFFFFF:
        return cd_size, cd_offset, entries

    # ZIP64: find locator (PK\x06\x07) immediately before the EOCD
    loc_sig = b'PK\x06\x07'
    loc_idx = data.rfind(loc_sig, 0, idx)
    if loc_idx == -1:
        raise ValueError("ZIP64 EOCD locator not found")

    # Locator: sig(4) + disk(4) + zip64_eocd_offset(8) + total_disks(4)
    _, loc_disk, z64_eocd_offset, total_disks = struct.unpack_from('<IIQI', data, loc_idx)
    print(f"[*] ZIP64 EOCD at file offset {z64_eocd_offset:,}")

    # Fetch 56 bytes of ZIP64 EOCD record
    z64_raw = curl_range(url, z64_eocd_offset, z64_eocd_offset + 55)
    # sig(4)+record_size(8)+ver_made(2)+ver_needed(2)+disk(4)+cd_disk(4)+
    # entries_disk(8)+entries(8)+cd_size(8)+cd_offset(8)
    (sig, record_size, ver_made, ver_needed, z64_disk, z64_cd_disk,
     z64_entries_disk, z64_entries, z64_cd_size, z64_cd_offset) = \
        struct.unpack_from('<IQHHIIQQQQ', z64_raw)
    assert sig == 0x06064b50, f"Bad ZIP64 EOCD sig: {sig:#010x}"
    return z64_cd_size, z64_cd_offset, z64_entries

def parse_zip64_extra(extra, csz, usz, local_offset):
    """Parse ZIP64 extended information from extra field, filling in 0xFFFF... sentinel values."""
    j = 0
    while j + 4 <= len(extra):
        tag, sz = struct.unpack_from('<HH', extra, j); j += 4
        field = extra[j:j+sz]; j += sz
        if tag != 0x0001:
            continue
        k = 0
        if usz == 0xFFFFFFFF and k + 8 <= len(field):
            usz = struct.unpack_from('<Q', field, k)[0]; k += 8
        if csz == 0xFFFFFFFF and k + 8 <= len(field):
            csz = struct.unpack_from('<Q', field, k)[0]; k += 8
        if local_offset == 0xFFFFFFFF and k + 8 <= len(field):
            local_offset = struct.unpack_from('<Q', field, k)[0]; k += 8
    return csz, usz, local_offset

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
        extra = data[i+filename_len:i+filename_len+extra_len]
        i += filename_len + extra_len + comment_len
        # Resolve ZIP64 sentinels
        compressed_size, uncompressed_size, local_offset = \
            parse_zip64_extra(extra, compressed_size, uncompressed_size, local_offset)
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
    cd_size, cd_offset, num_entries = parse_eocd(tail, eocd_idx, url)
    print(f"[*] Central dir: offset={cd_offset:,}  size={cd_size:,}  entries={num_entries}")

    print(f"[*] Fetching central directory ({cd_size//1024}KB)...")
    cd_data = curl_range(url, cd_offset, cd_offset + cd_size - 1)

    entries = parse_central_directory(cd_data)

    print(f"[*] Files in IPSW ({len(entries)} total):")
    for e in entries:
        print(f"    {e['name']}")

    kc = next((e for e in entries if 'kernelcache' in e['name'].lower()), None)
    if not kc:
        print("[-] No kernelcache entry found in the above list")
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
