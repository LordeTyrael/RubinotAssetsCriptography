import struct, sys

def decode_index(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'RTC\0', 'bad magic'
    ver, count = struct.unpack_from('<II', d, 4)
    ioff, isize = struct.unpack_from('<QQ', d, 0x10)
    assert ver == 3 and isize == 32 * count and ioff + isize == len(d), \
        f'{path}: count={count} isize={isize} ioff={ioff} filesize={len(d)}'
    idx = bytearray(d[ioff:ioff+isize])
    key = count ^ 0x52544321
    for n in range(0, isize, 4):
        v = struct.unpack_from('<I', idx, n)[0] ^ key
        struct.pack_into('<I', idx, n, v)
        key = (key * 0x41c64e6d + 0x3039) & 0xFFFFFFFF
    return d, count, ioff, bytes(idx)

def main():
    for i in range(1, 6):
        path = f'assetsdecrypted/data/dat-{i:02d}.rtc'
        d, count, ioff, idx = decode_index(path)
        print(f'== dat-{i:02d}: count={count} index@0x{ioff:x} data zone 0x20..0x{ioff:x} ({ioff-0x20} bytes)')
        # show first entries as 4x u64
        for e in range(min(3, count)):
            vals = struct.unpack_from('<QQQQ', idx, e*32)
            print(f'   [{e}] ' + ' '.join(f'{v:016x}' for v in vals))

if __name__ == '__main__':
    main()
