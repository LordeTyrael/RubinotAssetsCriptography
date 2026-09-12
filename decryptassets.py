import os
import sys
import zipfile
import zlib

from Crypto.Cipher import AES

KEY = bytes.fromhex("f85bc1fca8e29aa19c26b70622b98dd700a89ea8eadd14ea55516fa6b487ced2")
RTC = RubinOT 2.0\bin\assets.rtc"
OUT = "decrypted"


def decrypt_entry(raw):
    iv, ct = raw[:16], raw[16:]
    if len(ct) == 0:
        return raw
    if len(ct) % 16:
        return raw  # not encrypted (e.g. .json, .ttf entries)
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    try:
        return zlib.decompress(pt)
    except zlib.error:
        return pt  # not zlib-wrapped (rare)


def main():
    zf = zipfile.ZipFile(RTC)
    infos = [i for i in zf.infolist() if not i.is_dir()]
    total, done, failed = len(infos), 0, []
    for i in infos:
        try:
            data = decrypt_entry(zf.read(i.filename))
            dst = os.path.join(OUT, i.filename.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
            done += 1
            if done % 100 == 0:
                print(f"{done}/{total} ...", flush=True)
        except Exception as e:
            failed.append((i.filename, str(e)))
            print(f"FAIL {i.filename}: {e}", flush=True)
    print(f"done: {done}/{total}, failed: {len(failed)}")
    if failed:
        for n, e in failed:
            print(f"  {n}: {e}")


if __name__ == "__main__":
    main()
