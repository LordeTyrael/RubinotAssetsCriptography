"""Extract all RTC v3 archives to PNG files.

Parser: RTC\0 v3 | Index at EOF (off=0x10, entry_size=32)

Index: LCG-XOR | seed = count ^ 0x52544321 | key = key * 0x41c64e6d + 0x3039

Entry (32B): struct { u64 id, offset; u32 size, _dup, dims; } (dims: h<<16 | w)

Blob: seed = (w<<16 | h) ^ 0x52544321 | key = (rotr(seed,25) ^ size) * 0x5bd1e995 ^ (k >> 15)
"""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rtcindex import decode_index
from rtcblob import lcg_xor, blob_seed

OUT = 'assetsdecrypted/rtc/'

def main():
    os.makedirs(OUT, exist_ok=True)
    for i in range(1, 6):
        path = f'assetsdecrypted/data/dat-{i:02d}.rtc'
        d, count, ioff, idx = decode_index(path)
        outdir = os.path.join(OUT, f'dat-{i:02d}')
        os.makedirs(outdir, exist_ok=True)
        bad = 0
        for e in range(count):
            entry = idx[e*32:(e+1)*32]
            idv, off, szdup, prm = struct.unpack('<QQQQ', entry)
            sz = szdup & 0xFFFFFFFF
            w, h = prm & 0xFFFF, (prm >> 16) & 0xFFFF
            blob = d[off:off+sz]
            pt = lcg_xor(blob, blob_seed((w << 16) | h, sz))
            if pt[:8] != b'\x89PNG\r\n\x1a\n':
                bad += 1
                if bad <= 3:
                    print(f'  dat-{i:02d}[{e}] NOT PNG: {pt[:16].hex()}')
            name = f'{e:05d}_{idv:016x}.png'
            open(os.path.join(outdir, name), 'wb').write(pt)
        print(f'dat-{i:02d}: {count} entries extracted, {bad} non-PNG')

if __name__ == '__main__':
    main()
