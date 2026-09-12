"""
Decode RubinOT minimap tiles (minimap-*.bmp.lzma) to BMP files.

"""
import glob, lzma, os, sys

FILT = [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 25, 'lc': 3, 'lp': 0, 'pb': 2}]
SRC = 'RubinOT 2.0/bin/things/rubini/assets/'
DST = 'assetsdecrypted/minimap_bmp/'

def decode(path):
    d = open(path, 'rb').read()
    assert d[0x20] == 0x5d, 'unexpected props byte'
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=FILT)
    return dec.decompress(d[0x2d:])

def main():
    os.makedirs(DST, exist_ok=True)
    files = sorted(glob.glob(SRC + 'minimap-*.bmp.lzma'))
    ok = 0
    for f in files:
        bmp = decode(f)
        assert bmp[:2] == b'BM', f'no BMP magic: {f}'
        name = os.path.basename(f).replace('.bmp.lzma', '.bmp')
        open(DST + name, 'wb').write(bmp)
        ok += 1
    print(f'{ok}/{len(files)} tiles decoded -> {DST}')

if __name__ == '__main__':
    main()
