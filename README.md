# RubinOT — Asset & Cryptography Documentation

RubinOT is a heavily customized Brazilian OpenTibia server (OTClient fork, DirectX
build, Tauri/Rust launcher, EMAC kernel anti-cheat). This document covers **only the
containers and cryptography** — how every shipped file is packed, obfuscated or
encrypted, and how to undo it. Sprite/ObjectBuilder conversion will be a separate repo.

All figures below were measured against the 10/08/2026 client.

---

## 1. The Assets

| File / folder | Size | Entries | Content |
|---|---|---|---|
| `bin/assets.rtc` | 227 MB | 1,197 files (+179 dirs) | The whole game: UI, scripts, styles, fonts, shaders, sounds |
| `bin/things/rubini/Rubinot1..13.spr` | ~1.0 GB | 1,241,459 sprite slots | Sprite pixel archives (extended `.spr`) |
| `bin/things/rubini/Rubinot.dat` | 9.7 MB | 1 | Object definitions (appearances protobuf) |
| `bin/things/rubini/Rubinot.otfi` | 229 B | 1 | Format descriptor (plain text, unencrypted) |
| `bin/things/rubini/assets/minimap-*.bmp.lzma` | — | 242 | Automap tiles |
| `assets.rtc → data/dat-01..05.rtc` | 204 MB | 2,846 images | Splash art, automap fog sheets, UI icons |
| `bin/x64/upd2.bin` | 21 MB | 3,182 | Edge/WebView2 resource bundle (not game content) |
| `bin/x64/emac.bin` | 82 B | 1 | Anti-cheat reporting endpoint |
| `bin/x64/aleksandr.bin`, `worterbuch.bin` | 156 B / 23.8 KB | 1 each | Anti-cheat detection wordlists — **still encrypted** |

### `assets.rtc` contents by extension

| Ext | Count | Ext | Count |
|---|---|---|---|
| `.png` | 342 | `.ttf` | 15 |
| `.lua` | 290 | `.json` | 15 |
| `.otui` | 254 | `.ogg` | 12 |
| `.otfont` | 106 | `.rtc` | 5 |
| `.otmod` | 105 | `.otml` | 3 |
| `.frag` | 48 | `.otcm` | 2 |

---

## 2. What Is Encrypted — and What Isn't

| Object | Layer | Algorithm | Key known |
|---|---|---|---|
| `assets.rtc` entries | Container + cipher | Stored ZIP → AES-256-CBC → zlib | yes |
| `Rubinot*.spr` / `.dat` / `.otfi` | Cipher | Same AES-256-CBC, whole file | yes |
| `dat-01..05.rtc` | Obfuscation only | LCG keystream XOR (no cipher) | n/a |
| minimap `.bmp.lzma` | Compression only | Raw LZMA1 | n/a |
| `upd2.bin` | Container only | none | n/a |
| `emac.bin` | Toy cipher | single-byte XOR `0xa1` | yes |
| `aleksandr.bin` / `worterbuch.bin` | Cipher | custom CAST-256-family CBC | no |
| `EMCL*` scan logs | Cipher | same CAST-256 family, session-keyed | no |
| `Tibia*.spr` / `.dat` (stale) | Cipher | unknown key (pre-rebrand originals) | no |

There is **no per-file key derivation** anywhere. RubinOT uses exactly one global
32-byte AES key for every asset; only the IV changes (per file, random, stored
inline). That is why recovering the key once unlocked the entire game.

---

## 3. `assets.rtc` — The Main Asset Bundle

**Chain:** plain **stored ZIP** (`compress_type == 0`) → per entry: `IV ‖ AES-256-CBC ‖ zlib`.

```
entry bytes (as stored in the ZIP):
  +0x00  IV           16 bytes, random per file
  +0x10  ciphertext   AES-256-CBC, PKCS#7 padded
                      plaintext = zlib( original file )
```

**Key (global, 32 bytes):**

```
f85bc1fca8e29aa19c26b70622b98dd700a89ea8eadd14ea55516fa6b487ced2
```

```python
from Crypto.Cipher import AES
import zlib

KEY = bytes.fromhex("f85bc1fca8e29aa19c26b70622b98dd700a89ea8eadd14ea55516fa6b487ced2")

def decrypt_entry(raw):
    iv, ct = raw[:16], raw[16:]
    if len(ct) == 0 or len(ct) % 16:
        return raw                                  # stored in the clear
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    try:
        return zlib.decompress(pt)                  # normal path
    except zlib.error:
        return pt                                   # rare: not zlib-wrapped
```

A handful of entries (some `.json`, `.ttf`) are stored unencrypted; the decryptor
detects them because the payload after the 16-byte prefix is not 16-byte aligned.

**How the key was recovered.** The decrypt path in `bin/x64/rubinot_dx.exe`
(`FUN_140cc1140` → `FUN_14591cc97`) is protected with **Oreans Code Virtualizer** —
it is VM bytecode, invisible to any decompiler. The key was lifted by emulating that
region in Unicorn and hooking the moment it calls OpenSSL:
`EVP_CipherInit_ex(ctx, EVP_aes_256_cbc, NULL, key, iv)` @ `0x141bfa0f0`, with the
`EVP_CIPHER` struct @ `0x14284f3d0` (nid `0x1ab` = 427, key_len 0x20, iv_len 0x10).
The IV is simply the 16-byte header read from the file.

---

## 4. `things/` — Sprites and Object Definitions

`Rubinot1..13.spr`, `Rubinot.dat` and `Rubinot.otfi` use **the same scheme as an
`assets.rtc` entry**, applied to the whole file: 16-byte IV prefix, AES-256-CBC with
the global key, plaintext zlib-wrapped.

```python
iv, ct = data[:16], data[16:]
pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
pt = pt[:-pt[-1]]
plain = zlib.decompress(pt)
```

### Decrypted `.spr` container (OTClient extended)

```
+0x00  u32 signature 0x59E48E02
+0x04  u32 sprite count
+0x08  u32 address[count]      -- file offset of each sprite's payload
...    per sprite: RLE-compressed 32x32 RGBA pixels
```

Sprite counts as shipped: `Rubinot1` = 100,001; `Rubinot2..11` = 100,000 each;
`Rubinot12` = `Rubinot13` = 70,729 (12 and 13 are byte-identical — 13 is a stray
duplicate; the `.otfi` says 12 files).

**Address table is 1-based on sprite id:** the payload for sprite *id* is at
`8 + 4*(id-1)`. Ids 1 and 2 are null (`address[0] == address[1] == 0`). Reading slot
`id` instead of `id-1` shifts every render by one sprite.

### `Rubinot.dat`

Appearances protobuf, 9.7 MB, starts `10 4a 00 00 4d 02 01 00 …` (header item count
66,125 = max id; ids run 100..66,224).

### `Rubinot.otfi` (plain text, unencrypted)

```
DatSpr
  extended: true
  transparency: true
  frame-durations: true
  frame-groups: true
  bounding-box: true
  metadata-file: Rubinot.dat
  sprites-file: Rubinot.spr
  sprite-size: 32
  sprite-count: 12
  sprite-data-size: 4096
```

### `Tibia*.spr` / `Tibia*.dat`

Same directory, **different key** — they do not decrypt with the global key. They are
stale pre-rebrand originals (Jan-2026), unreferenced by the current `.otfi`. Nothing
in them that `Rubinot*` does not already have.

---

## 5. `dat-01..05.rtc` — RTC Archives (Obfuscation, Not Crypto)

These are the 5 `.rtc` entries inside `assets.rtc` (204 MB total). **No cipher is
involved** — blobs are scrambled with an LCG keystream XOR, and the seed is derived
from data the archive itself carries (image dimensions + size), so no key material is
needed.

### Container

```
+0x00  'RTC\0'
+0x04  u32 version = 3
+0x08  u32 count
+0x0C  u32 0
+0x10  u64 index_offset          -- index sits AT EOF
+0x18  u64 index_size = 32*count
+0x20  data zone                 -- file[0x20 : index_offset]
```

### Index decode

```python
key = count ^ 0x52544321                 # "!CTR"
for each u32 v in index:
    v ^= key
    key = (key * 0x41C64E6D + 0x3039) & 0xFFFFFFFF   # MSVC LCG
```

**Entry (32 bytes):** `u64 id | u64 offset | u32 size | u32 size (dup) | u32 dims`
where `dims = (h << 16) | w`.

### Blob decode

```python
def blob_seed(base, size):                # base = (w << 16) | h  (u16-swapped dims)
    k = base ^ 0x52544321
    k = ((((k >> 25) | (k << 7)) & 0xFFFFFFFF) ^ size) * 0x5BD1E995 & 0xFFFFFFFF
    return (k >> 15 ^ k) & 0xFFFFFFFF

# then the same LCG-XOR loop over the blob, with that k as the starting key
```

Tail bytes (length not a multiple of 4) are XORed with the key bytes directly.

### Contents

100% images: `dat-01..03` = 23 large splash/artwork PNGs (up to 5504×3072),
`dat-04` = 885 × 522×522 RGBA automap fog/mask sheets, `dat-05` = 1,938 small RGBA
UI icons/frames (9×9 … 66×44). One BMP. No sprites, no map data.

---

## 6. Minimap Tiles — `minimap-<32|64>-<x>-<y>-<n>-<64hex>.bmp.lzma`

**No encryption.** A 45-byte custom header plus a raw LZMA1 stream.

```
+0x00  24 zero bytes               reserved key/IV slot — unused
+0x18  70 0a fa 80 + 3 varying bytes   unknown (checksum?)
+0x20  u8  props = 0x5d             lc=3 lp=0 pb=2
+0x21  u32 dict_size = 0x02000000   (32 MB)
+0x25  u64 stream length            = filesize - 45
+0x2d  raw LZMA1 stream
```

```python
import lzma
FILT = [{'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 25, 'lc': 3, 'lp': 0, 'pb': 2}]
bmp = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=FILT).decompress(data[0x2D:])
```

Decodes to a 512×512 (or 256×256 for the `-64-` series) 32bpp BMP with a
BITMAPV4HEADER and BGRA masks. 242/242 tiles verified.

> Gotcha: `lzma.FORMAT_ALONE` fails — the u64 at `0x25` is the **compressed stream
> length**, not the uncompressed size. Use `FORMAT_RAW` starting at `0x2d`.

---

## 7. `upd2.bin` — Not Game Content, Not Encrypted

21 MB, never encrypted. Plain container:

```
+0x00  u32 5
+0x04  u32 1
+0x08  u16 count = 3182
+0x0A  u16 0x4b
+0x0C  index: count × (u16 id, u32 offset)
       then payloads: gzip (1598), raw (1291), PNG (274)
```

Contents are a **Microsoft Edge / WebView2 resource bundle**: `edge://` HTML/CSS/JS,
Chromium `edge://resources`, Edge Collections JSON, MS Store extension reputation DB,
274 UI PNGs. Zero game references, zero key material. Safe to drop from any asset
share.

---

## 8. EMAC Anti-Cheat Blobs

EMAC (EMAC LAB LTDA) is the kernel anti-cheat: user-mode `bin/x64/emac-client64.dll`
scans and reports, kernel driver `EMAC-Driver-GL-TB-x64.sys` (service `EMACDRVGLTB`)
guards the process. All binaries are Code-Virtualizer protected and validly signed.

### 8.1 `emac.bin`

Single-byte XOR `0xa1`:

```python
plain = bytes(b ^ 0xA1 for b in data)
# {"endpoint": "wss://tibia-ws.emac.ac/exilium/", "name": "rubinot-exilium"}
```

### 8.2 `aleksandr.bin` / `worterbuch.bin`

Cipher fully mapped, raw 16-byte key still missing. These are the only encrypted
RubinOT files left. They hold anti-cheat detection wordlists (cheat-tool
process/window/driver signatures) — no game or asset value.

**Container.** CBC over the whole file, with the tail **zero-padded to 16 and then
truncated back to the real filesize** — that is why the sizes are not 16-multiples
(`156 = 9×16 + 12`, `23777 = 1486×16 + 1`). To decrypt: zero-pad to a 16-multiple,
CBC-decrypt, truncate.

The shared 8-byte prefix `a3 77 01 f0 dd 49 d1 81` is **plaintext magic, not
ciphertext** (a 16-byte block cipher cannot produce two files sharing exactly 8
ciphertext prefix bytes). The CBC payload therefore starts at file offset 8.

Two versions of `worterbuch.bin` exist: `bin/` = 23,178 B (old) and `bin/x64/` =
23,777 B (live). They share only the 8-byte magic — C1 diverges from byte 8, i.e. a
per-version IV or a versioned plaintext header.

**Cipher.** A custom **CAST-256-family 16-byte block cipher in CBC mode**. Not stock
CAST-5 — the S-boxes are a whitened/custom set.

| Piece | Address (`emac-client64.dll`) |
|---|---|
| Custom S-box tables (4×256 u32) | `0x1806D3C80` |
| Key schedule (rcx = 16-byte key, rdx = 0x88-byte ctx) | `0x18046D2A0` |
| Block encrypt (rcx=in, rdx=out, r8=ctx) | `0x18046C480` |
| Block decrypt | `0x18046B660` |
| CBC decrypt wrapper (+ iv ptr, blk fn) | `0x180465250` |
| CBC encrypt wrapper | `0x180465450` |
| Direction / mode dispatchers | `0x18046DE50` / `0x18046DE80` |

The key schedule uses the golden-ratio family constants `0x61C88647`, `0x3C6EF373`,
`0x78DDE6E6`, `0xF1BBCDCC` and emits a 34×u32 context (whitening pair + 32 subkeys).

**The same cipher exists unobfuscated inside `rubinot_dx.exe`** — custom tables at
RVA `0x28F4640`, key schedule at VA `0x141D1E840`. But no constant key sits at any
call site: keys arrive as arguments from the generic crypto API layer.

**What has been ruled out** (all negative): ~8,300 derived key candidates
(md5/sha1/sha256 slices of every plausible string, S-box sums, asset-key halves,
update-manifest hashes, UUID, startup seed); ~117 M unaligned byte-window sweeps
across `emac-client64.dll`, `rubinot_dx.exe`, `RubinOT.exe`, the kernel driver,
`emac-core.dll`, `upd2.bin`, and a post-`DllMain` memory snapshot; `movabs`
immediate pairs; stack strings; pointer immediates. The raw key is **not contiguous
plain bytes anywhere on disk** and is not trivially derived.

Launcher logs prove the blobs are downloaded pre-encrypted from the update server
(`aleksandr.bin.new`, `worterbuch.bin.new`), so the key **must** be client-side —
most likely folded into Oreans VM bytecode constants, or derived from server/session
state at runtime.


### 8.3 `EMCL*` scan logs

`bin/x64/logs/emac-client64-<date>.log`: `EMCL` + 4 random bytes + high-entropy body.
1065 B = 8 + 66×16 + 1 → the same zero-pad-and-truncate container shape, separate
(session-keyed) key. Would be a free oracle for any candidate key.

---

## 9. Key & Constant Reference

| Name | Value | Used by |
|---|---|---|
| AES-256 asset key | `f85bc1fc a8e29aa1 9c26b706 22b98dd7 00a89ea8 eadd14ea 55516fa6 b487ced2` | `assets.rtc`, `things/*` |
| AES IV | first 16 bytes of each payload | same |
| RTC magic | `'RTC\0'`, version 3 | `dat-01..05.rtc` |
| RTC index seed | `count ^ 0x52544321` | index + blob |
| RTC LCG | `k = k*0x41C64E6D + 0x3039` | index + blob |
| RTC blob mixer | `rotr(k,25) ^ size`, `* 0x5BD1E995`, `k ^= k>>15` | blob |
| SPR signature | `0x59E48E02` | `Rubinot*.spr` |
| upd2 header | `05 00 00 00 01 00 00 00`, count 3182, `0x4b` | `upd2.bin` |
| emac.bin XOR | `0xa1` | `emac.bin` |
| Blob magic (plaintext) | `a3 77 01 f0 dd 49 d1 81` | aleksandr / worterbuch |
| CAST-256-family key | **UNKNOWN** | aleksandr / worterbuch / EMCL logs |

---

## 10. Tools

| Script | Purpose |
|---|---|
| `decryptassets.py` | Bulk-decrypt `assets.rtc` → `assets_decrypted/` |
| `decrypthings.py` | Decrypt `Rubinot*.spr` / `.dat` / `.otfi` |
| `rtcindex.py`, `rtc_blob.py`, `extractrtc.py` | Decode + extract `dat-01..05.rtc` |
| `decodeminimap.py` | Decode all minimap `.bmp.lzma` → BMP |

---

## 11. Format Quirks

- **`.lua` decrypts to LuaJIT 2.1 bytecode**, not source. Header
  `1b 4c 4a 02 0a` — version `0x02` (LuaJIT 2.1), flags `0x0A` = `F_STRIP|F_FR2`
  (debug info stripped, so decompiled locals come out as `var_N_M`). Use
  `luajit-decompiler-v2.exe` for readable code; 4 files resist it (decompiler bug,
  not a format difference).
- **`.png` / `.otui` / `.otml` / `.ogg`** come out directly usable after decryption.
- **A few `.json` / `.ttf` entries are stored in the clear** — no IV, no ciphertext.
- **`Rubinot12.spr` ≡ `Rubinot13.spr`** (byte-identical, md5 `0b72f3e5…`). Only 12
  are real; 13 is a stray duplicate.
- **Sprite ids are 1-based** against the `.spr` address table (slot `k` = id `k+1`).
- The whole `data/dat-*.rtc` set is **images only** — no sprites, no map data. The
  world map is not shipped; on-disk minimap tiles are downloaded/cached content.
