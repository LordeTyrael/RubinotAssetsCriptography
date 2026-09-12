import os sys, zlib
from Crypto.Cipher import AES

KEY = bytes.fromhex('f85bc1fca8e29aa19c26b70622b98dd700a89ea8eadd14ea55516fa6b487ced2')
SRC = 'RubinOT 2.0/bin/things/rubini/'
DST = 'decrypted'
NAMES = (['Rubinot.dat', 'Rubinot.otfi'] +
         [f'Rubinot{i}.spr' for i in range(1, 14)])

def decrypt(path):
    d = open(path, 'rb').read()
    iv, ct = d[:16], d[16:]
    if len(ct) % 16:
        raise ValueError('ciphertext not 16-byte aligned')
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return zlib.decompress(pt)

def main():
    os.makedirs(DST, exist_ok=True)
    for name in NAMES:
        src = SRC + name
        if not os.path.exists(src):
            print(f'-- {name}: MISSING, skipped')
            continue
        out = decrypt(src)
        dst = DST + name
        open(dst, 'wb').write(out)
        print(f'OK {name}: {os.path.getsize(src):>10} -> {len(out):>10}  head {out[:8].hex()}')

if __name__ == '__main__':
    main()
