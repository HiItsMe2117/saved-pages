#!/usr/bin/env python3
"""
Extract symbol lists from an iOS MH_FILESET kernelcache (Mach-O filetype=12).
Walks LC_FILESET_ENTRY load commands, parses each embedded image's symtab.

Usage:
    python3 extract_symbols.py <kernelcache.macho> <output.txt>
"""

import sys
import struct
import os

# Mach-O constants
MH_MAGIC_64     = 0xFEEDFACF
MH_CIGAM_64     = 0xCFFAEDFE  # byte-swapped
LC_SYMTAB       = 0x2
LC_FILESET_ENTRY = 0x80000035

# nlist_64 type masks
N_STAB  = 0xe0
N_TYPE  = 0x0e
N_EXT   = 0x01
N_UNDF  = 0x00
N_ABS   = 0x02
N_SECT  = 0x0e
N_INDR  = 0x0a

def read_mach_header(data, off):
    magic = struct.unpack_from('<I', data, off)[0]
    if magic == MH_MAGIC_64:
        swap = False
    elif magic == MH_CIGAM_64:
        swap = True
    else:
        return None
    fmt = '>IIIIIIII' if swap else '<IIIIIIII'
    magic, cpu, subcpu, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from(fmt, data, off)
    return {'off': off, 'cpu': cpu, 'ftype': ftype, 'ncmds': ncmds,
            'sizeofcmds': sizeofcmds, 'swap': swap}

def iter_load_commands(data, hdr):
    fmt_prefix = '>' if hdr['swap'] else '<'
    off = hdr['off'] + 32  # sizeof mach_header_64
    for _ in range(hdr['ncmds']):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(fmt_prefix + 'II', data, off)
        yield cmd, cmdsize, off
        off += cmdsize

def parse_symtab(data, hdr, symoff, nsyms, stroff):
    """Extract (addr, name) from a nlist_64 symbol table."""
    fmt = '>' if hdr['swap'] else '<'
    symbols = []
    for i in range(nsyms):
        entry_off = symoff + i * 16
        if entry_off + 16 > len(data):
            break
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(fmt + 'IBBHQ', data, entry_off)

        # Skip stabs and undefined symbols
        if n_type & N_STAB:
            continue
        t = n_type & N_TYPE
        if t == N_UNDF or t == N_INDR:
            continue

        # Read name from string table
        name_start = stroff + n_strx
        name_end = data.index(b'\x00', name_start) if b'\x00' in data[name_start:name_start+512] else name_start
        name = data[name_start:name_end].decode('utf-8', errors='replace')

        if name:
            symbols.append((n_value, name))
    return symbols

def extract_from_image(data, off, image_name):
    """Extract symbols from a single Mach-O image at offset `off`."""
    hdr = read_mach_header(data, off)
    if not hdr:
        return []

    symbols = []
    fmt = '>' if hdr['swap'] else '<'

    for cmd, cmdsize, lc_off in iter_load_commands(data, hdr):
        if cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from(fmt + 'IIII', data, lc_off + 8)
            # Offsets in LC_SYMTAB are relative to the start of the FILE (not the image)
            # For embedded fileset images, they're relative to the embedded image start
            abs_symoff = off + symoff
            abs_stroff = off + stroff
            syms = parse_symtab(data, hdr, abs_symoff, nsyms, abs_stroff)
            for addr, name in syms:
                symbols.append((addr, name, image_name))
    return symbols

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <kernelcache.macho> <output.txt>")
        sys.exit(1)

    kc_path, out_path = sys.argv[1], sys.argv[2]

    print(f"[*] Reading {kc_path}...")
    with open(kc_path, 'rb') as f:
        data = f.read()
    print(f"[*] {len(data):,} bytes loaded")

    hdr = read_mach_header(data, 0)
    if not hdr:
        print("[-] Not a valid Mach-O"); sys.exit(1)
    print(f"[*] Mach-O filetype={hdr['ftype']}, ncmds={hdr['ncmds']}")

    fmt = '>' if hdr['swap'] else '<'
    all_symbols = []

    if hdr['ftype'] == 12:  # MH_FILESET
        print("[*] MH_FILESET detected — walking LC_FILESET_ENTRY commands...")
        entries = []
        for cmd, cmdsize, lc_off in iter_load_commands(data, hdr):
            if cmd == LC_FILESET_ENTRY:
                vmaddr, fileoff, name_off_in_lc, _ = struct.unpack_from(fmt + 'QQII', data, lc_off + 8)
                name_abs = lc_off + name_off_in_lc
                name_end = data.index(b'\x00', name_abs)
                name = data[name_abs:name_end].decode('utf-8', errors='replace')
                entries.append((name, fileoff))

        print(f"[*] Found {len(entries)} fileset entries")
        for name, fileoff in entries:
            short = name.split('/')[-1]
            syms = extract_from_image(data, fileoff, short)
            print(f"    {short}: {len(syms)} symbols")
            all_symbols.extend(syms)
    else:
        # Single image
        syms = extract_from_image(data, 0, os.path.basename(kc_path))
        all_symbols.extend(syms)

    print(f"[*] Total: {len(all_symbols)} symbols")

    # Sort by address
    all_symbols.sort(key=lambda x: x[0])

    with open(out_path, 'w') as f:
        for addr, name, image in all_symbols:
            f.write(f"{addr:016x} {name}\t[{image}]\n")

    print(f"[+] Written to {out_path}")

if __name__ == '__main__':
    main()
