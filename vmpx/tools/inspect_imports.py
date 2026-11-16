#!/usr/bin/env python3
"""inspect_imports.py - dump PE import descriptors from a file or identity dump.

Usage: python tools/inspect_imports.py <pe-or-dump> [--identity]
For an identity-layout dump every RVA is also a file offset.
"""
import struct
import sys


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def cstr(b, o, cap=256):
    if o < 0 or o >= len(b):
        return None
    end = b.find(b'\0', o, min(len(b), o + cap))
    if end < 0:
        return None
    return b[o:end].decode('latin-1', 'replace')


def parse(path, identity):
    b = open(path, 'rb').read()
    lfanew = u32(b, 0x3C)
    nt = lfanew
    if u32(b, nt) != 0x4550:
        raise SystemExit('not PE')
    fh = nt + 4
    nsec = u16(b, fh + 2)
    optsz = u16(b, fh + 16)
    opt = fh + 20
    magic = u16(b, opt)
    pe64 = magic == 0x20B
    dd = opt + (112 if pe64 else 96)
    imp_rva = u32(b, dd + 8)
    imp_size = u32(b, dd + 12)
    sec = opt + optsz
    secs = []
    for i in range(nsec):
        s = sec + i * 40
        name = b[s:s + 8].rstrip(b'\0').decode('latin-1', 'replace')
        vsize, va, rawsz, rawpt = u32(b, s + 8), u32(b, s + 12), u32(b, s + 16), u32(b, s + 20)
        secs.append((name, va, vsize, rawpt, rawsz))

    def rva_off(rva):
        if identity:
            return rva
        for name, va, vsize, rawpt, rawsz in secs:
            span = max(vsize, rawsz)
            if va <= rva < va + span:
                return rawpt + rva - va
        return None

    print(f'file={path} size={len(b)} sections={nsec} pe64={pe64}')
    print(f'import_rva=0x{imp_rva:X} import_size=0x{imp_size:X}')
    off = rva_off(imp_rva)
    if off is None:
        raise SystemExit('import dir unmapped')
    step = 8 if pe64 else 4
    ordflag = 1 << 63 if pe64 else 1 << 31
    total = 0
    for d in range(min(imp_size // 20 if imp_size else 4096, 512)):
        do = off + d * 20
        if do + 20 > len(b):
            break
        oft, ts, fc, name_rva, ft = struct.unpack_from('<IIIII', b, do)
        if not (oft or name_rva or ft):
            break
        nm = cstr(b, rva_off(name_rva)) if name_rva else None
        if nm is None:
            print(f'[{d:02}] <bad name rva=0x{name_rva:X}> oft=0x{oft:X} ft=0x{ft:X}')
            continue
        trva = oft or ft
        toff = rva_off(trva) if trva else None
        items = []
        if toff is not None:
            for i in range(100000):
                p = toff + i * step
                if p + step > len(b):
                    break
                v = struct.unpack_from('<Q' if pe64 else '<I', b, p)[0]
                if not v:
                    break
                if v & ordflag:
                    items.append(f'#{v & 0xFFFF}')
                else:
                    no = rva_off(v & 0x7FFFFFFFFFFFFFFF)
                    fn = cstr(b, no + 2) if no is not None else None
                    items.append(fn if fn else f'<0x{v:X}>')
        total += len(items)
        print(f'[{d:02}] {nm:20} oft=0x{oft:08X} ft=0x{ft:08X} n={len(items)}')
        if len(sys.argv) > 3 and sys.argv[3] == '-v':
            for x in items[:40]:
                print('      ', x)
    print(f'total functions={total}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    parse(sys.argv[1], '--identity' in sys.argv or sys.argv[1].endswith('.bin'))
