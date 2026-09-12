"""
Decode RTC blobs. Index entries: (id u64, off u64, size u64 dup, params u64).

"""
import struct, sys
sys.path.insert(0, '.')
from rtc_index import decode_index

M32 = 0xFFFFFFFF

def lcg_xor(buf, k):
    out = bytearray(buf)
    for n in range(0, len(out) & ~3, 4):
        v = struct.unpack_from('<I', out, n)[0] ^ k
        struct.pack_into('<I', out, n, v)
        k = (k * 0x41c64e6d + 0x3039) & M32
    for n in range(len(out) & ~3, len(out)):
        out[n] ^= (k >> ((n & 3) << 3)) & 0xFF
    return bytes(out)

def blob_seed(base, size):
    k = base ^ 0x52544321
    k = (((k >> 25) | (k << 7)) & M32 ^ size) * 0x5bd1e995 & M32
    k = (k >> 15 ^ k) & M32
    return k

def decode_blob(entry, d):
    idv, off, sz, prm = struct.unpack_from('<QQQQ', entry)
    blob = d[off:off+sz]
    return blob, idv, off, sz, prm

def looks(b):
    if b[:1] == b'\x5d' or b[:2] in (b'\x78\x9c', b'\x78\xda', b'BM') or b[:4] in (b'RTC\0', b'\x89PNG'): return True
    pr = sum(1 for x in b[:64] if 32 <= x < 127)
    return pr > 48

def main():
    for i in (5, 4):
        d, count, ioff, idx = decode_index(f'assetsdecrypted/data/dat-{i:02d}.rtc')
        print(f'== dat-{i:02d}')
        for e in range(2):
            entry = idx[e*32:(e+1)*32]
            blob, idv, off, sz, prm = decode_blob(entry, d)
            u32s = struct.unpack('<8I', entry)
            for wi, w in enumerate(u32s):
                pt = lcg_xor(blob[:256], blob_seed(w, sz & M32))
                if looks(pt):
                    print(f'  [{e}] u32[{wi}]={w:#010x}: {pt[:24].hex()}')
            else:
                pass
        print('   (only hits shown)')

if __name__ == '__main__':
    main()
