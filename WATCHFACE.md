# SiFli `.watch` dial format

Reverse-engineering notes on the `.watch` watch-face container used by IDO / VeryFit watches built on SiFli
(思澈) SoCs, and on the image resources inside it.

> **Status: work in progress.** Everything here was checked against four real files
> (`wf_w62.watch`, 9 files; `wf_f82.watch`, 50 files; `wf_w124.watch`, 25 files; `wf_w98.watch`, 51 files) plus vendor source files. Each claim is tagged:
>
> | Tag | Meaning |
> |---|---|
> | **VERIFIED** | Checked in code against the sample files (checksums matched, round trip identical, or output rendered correctly). |
> | **SOURCE** | Taken from vendor source (`ido_app_custom_dial_make.c`, the OpenEZIP tool, `bf0_hal_ezip.c`), consistent with the samples. |
> | **OBSERVED** | Seen in the samples, but meaning or generality not established. |
> | **UNKNOWN** | Not determined. Do not guess. |

Reference implementation: [`extract_sifli_dial.py`](extract_sifli_dial.py) — unpack, repack and decode.

---

## 1. Overview

A `.watch` file is a flat archive of the files a watch needs to install one watch face:

```
.watch
├── /dynamic_app/watchface/installer/<name>.dsc        descriptor (see §4)
├── /dynamic_app/watchface/installer/<name>.so         face logic, compiled ARM ELF (see §5)
├── /dynamic_app/watchface/installer/<name>_res.so     resource module, compiled ARM ELF
└── /dynamic_app/watchface/<name>/ezip/*.bin           images, including the thumbnail <name>_tn.bin
```

`<name>` is e.g. `wf_w62` or `wf_f82`. Every file is stored under its absolute **device path**. **VERIFIED** on both samples.

Pipeline context (**SOURCE**, from the designer's JavaScript): the designer exports a project zip containing
`iwf.json`, `font.json` and source images; the C source for the face is generated server-side from `iwf.json`; the
images are converted to the ezip format and the face is compiled to ELF inside the SiFli SCons build. A pure-Python
tool can therefore read and repack `.watch` files, but cannot produce the compiled `.so` modules.

---

## 2. Container layout

All integers are **little-endian**. **VERIFIED** (every header and per-file checksum matched on both samples; unpack →
repack reproduced `wf_w62.watch` byte for byte). Layout is **SOURCE**: `ido_app_custom_dial_make.c`.

```
offset                      size   content
0x00                        32     head_t
0x20                        N      name table (N = name_size): NUL-terminated device paths
0x20 + N                    16*C   file table (C = file_count): C × file_head_t
0x20 + N + 16*C             ...    file data, concatenated, no padding
```

### 2.1 `head_t` (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | u32 | `magic` | `0xA1B2C8D9`, i.e. bytes `D9 C8 B2 A1` |
| 0x04 | u16 | `size` | Header size; `32` in both samples. Name table starts at this offset. |
| 0x06 | u16 | `project_no` | `13` in both samples. Meaning **UNKNOWN**. |
| 0x08 | u16 | `file_count` | 9 (`wf_w62`), 50 (`wf_f82`) |
| 0x0A | u16 | `checksum` | CRC-16 (§2.3) over everything after the header: `file[size : size + data_size]` |
| 0x0C | u32 | `data_size` | Bytes after the header (= file length − 32) |
| 0x10 | u32 | `name_size` | Length of the name table: 505 (`wf_w62`), 3227 (`wf_f82`) |
| 0x14 | 12 | `reserve` | All zero in both samples. Preserved verbatim when repacking. |

Example, `wf_w62.watch`:
`d9 c8 b2 a1 | 20 00 | 0d 00 | 09 00 | c8 ba | 85 de 01 00 | f9 01 00 00 | 00…`

### 2.2 `file_head_t` (16 bytes, one per file)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | u32 | `name_off` | Offset of the file's path, relative to the end of `head_t` (i.e. from `size`) |
| 0x04 | u32 | `file_size` | Bytes of file data |
| 0x08 | u16 | `crc16` | CRC-16 (§2.3) of the file data |
| 0x0A | u16 | `reserve` | 0 in both samples. Preserved when repacking. |
| 0x0C | u32 | `offset` | **Stored value = (offset of the data within the data area) + 32** |

Resolving a file:

```
name       = NUL-terminated string at  size + name_off
data_start = offset + name_size + 16 * file_count          # = 32 + name_size + 16*C + data_offset
data       = file[data_start : data_start + file_size]
```

Files are stored back to back; in both samples the last file ends exactly at the end of the `.watch`.
The index order is: `.dsc`, `.so`, `_res.so`, thumbnail `_tn.bin`, then the remaining images in name order.
(**OBSERVED**; order is not required by the parser logic seen.)

### 2.3 Checksum: CRC-16/MODBUS

Polynomial `0xA001` (reflected `0x8005`), initial value `0xFFFF`, no final XOR. This is the table-driven `CRC16`
(`CRC16Hi`/`CRC16Lo`) in the vendor C code. **VERIFIED**: matches the header checksum and all per-file checksums on both
samples.

```python
def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc
```

### 2.4 Minimal reader

```python
import struct

def read_watch(d):
    magic, size, proj, cnt, ck, dsz, nsz = struct.unpack_from('<IHHHHII', d, 0)
    assert magic == 0xA1B2C8D9 and crc16(d[size:size + dsz]) == ck
    for i in range(cnt):
        no, fs, c, res, off = struct.unpack_from('<IIHHI', d, size + nsz + 16 * i)
        name = d[size + no:d.index(b'\0', size + no)].decode()
        start = off + nsz + 16 * cnt
        data = d[start:start + fs]
        assert crc16(data) == c
        yield name, data
```

---

## 3. File inventory and naming

Both samples have the same shape (**OBSERVED**):

| Sample | Files | `.dsc` | `.so` | images |
|---|---|---|---|---|
| `wf_w62.watch` | 9 | 1 | 2 | 6 (`_tn` + 5) |
| `wf_f82.watch` | 50 | 1 | 2 | 47 (`_tn` + 46) |

Image file names follow `wf_<face>_<widget>_<content>_<font>_<index>.bin`, mirroring the designer's export names
(**SOURCE**: `ProtocolUtilSiChe.js`). Examples:

| File | Widget / role |
|---|---|
| `wf_w62_picture_dialBg.bin`, `wf_f82_picture_dialBg_0.bin` | Background picture |
| `wf_w62_time_1_dialPointer_1..3.bin` | Hour / minute / second hands |
| `wf_f82_time_0_dialClock_0..10.bin` | Digit images for a digital clock |
| `wf_w62_week_0_dialDate.bin` | Weekday labels (7 frames in one file) |
| `wf_f82_week_2_dialDate_0..6.bin` | Weekday labels (one file per day) |
| `wf_f82_date_1_dialDate_0..10.bin`, `wf_f82_temprature_3_dialData_0..12.bin` | Digit/symbol images (11 and 13 files) |
| `<name>_tn.bin` | Thumbnail shown in the watch-face picker |

Hands are stored uncompressed (§6.2); the designer places them in a separate `no_ezip` folder (**SOURCE**).
How multi-frame widgets are split differs between the two samples (one 7-frame file vs. seven files).
Why is **UNKNOWN**.

---

## 4. The `.dsc` descriptor

Small (68 bytes in both samples), a list of `type, length, NUL-terminated string` entries followed by a trailer.
Hex dump of `wf_w62.dsc`:

```
06 07 'wf_w62\0'   0a 07 'wf_w62\0'   08 0a 'wf_w62.so\0'
09 0e 'wf_w62_tn.bin\0'   07 0e 'wf_w62_res.so\0'   00 00   30 f7 e4 6a
```

- Entry = 1-byte type, 1-byte length (string length + 1, includes the NUL), then the string. **VERIFIED** (parses both samples).
- Types seen: `0x06` and `0x0A` carry the face name (meaning of each **UNKNOWN**), `0x08` the face module, `0x09` the
  thumbnail, `0x07` the resource module. The role names are inferred from the strings; the code values are **OBSERVED**.
- After the entries: `00 00`, then a 4-byte value (`30 f7 e4 6a` / `c6 62 de 24` / `2d 1b 7f 7f` on `wf_w62` / `wf_f82` /
  `wf_w98`). **VERIFIED** (3 faces): it is the CRC-32 described in §5.1 over all preceding bytes of the file.
- The `.dsc` is therefore fully specified: all five strings follow from the face name. Why types `0x06` and `0x0A` both
  carry the face name is still **UNKNOWN**.

---

## 5. The `.so` modules

`<name>.so` and `<name>_res.so` are 32-bit ARM ELF shared objects (**OBSERVED**, both samples):

| Property | Value |
|---|---|
| Class / type | `ELFCLASS32`, `ET_DYN` (3) |
| Machine | `EM_ARM` (40) |
| `e_flags` | `0x05000400` (EABI version 5, hard-float flag) |
| Sizes | `wf_w62.so` 4632 B, `wf_f82.so` 10248 B, `*_res.so` 2472 B (both) |

The face module imports LVGL (v7-style) functions such as `lv_img_create` and `lv_img_set_angle`, and its source is
generated from the designer's layout (**SOURCE**: the generated `wf_sifliTest.c`; clock-hand angles use tenths of a degree,
with the hand rotated about a per-hand pivot).

### 5.1 Trailing CRC-32 — VERIFIED

Every `.so`, `_res.so` and `.dsc` ends in a 4-byte little-endian value. It is a **CRC-32 with polynomial `0x04C11DB7`,
initial value `0xFFFFFFFF`, no bit reflection and no final XOR** (CRC-32/MPEG-2) over all bytes of the file except these
last 4. Verified on all six files of `wf_f82` and `wf_w98` (`.dsc`, `.so`, `_res.so`), and on `wf_w62`'s `.dsc` from its recorded bytes.
```python
def crc32_mpeg2(data, c=0xFFFFFFFF):
    for b in data:
        c ^= b << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    return c
```
It was found because the two `_res.so` files differ only in the face name and this trailer, which makes the XOR of the
two trailers equal the CRC of the XOR of the files for any CRC.

### 5.2 `<name>_res.so` is the language pack — OBSERVED

`wf_f82_res.so` and `wf_w98_res.so` are the same 2472 bytes except for the 3 bytes of the face name (offset 1344) and the CRC.
They export tables such as `en_us_lang`, `zh_cn_lang`, `de_DE_lang`, `lv_i18n_lang_pack` plus `*_lang_translation`, i.e.
the compiled `resource/lang/multi_language_table.xlsx`. It does **not** hold image data. How the `.xlsx` becomes
this ELF is **UNKNOWN**.

### 5.3 `<name>.so` structure — OBSERVED (wf_f82, wf_w98)

- RT-Thread-style dynamic module. Exports: `module_init`, `module_cleanup`, `wf_<name>_register` (+ `_stack`).
- Imports firmware symbols (resolved on the watch), e.g. `lv_img_create`, `lv_img_set_src`, `lv_img_set_angle`,
  `lv_img_set_pivot`, `lv_task_create`, `dlmodule_*`, `app_clock_register`, `service_get_current_time`, `rt_malloc`;
  the set varies with the widgets used (`wf_f82`: weather/temperature; `wf_w98`: battery percentage, 3-circle activity data).
- Sections `.text` (Thumb code, 0xd2c bytes in `wf_f82`), `.rodata`, `.data.rel.ro`, `.dynamic`, `.got`, `.data`, `.bss`.
- Image references are absolute device paths in `.rodata`, e.g. `/dynamic_app/watchface/wf_f82/ezip/wf_f82_picture_dialBg_0.bin`.
- `.comment`: `GCC: (GNU MCU Eclipse ARM Embedded GCC, 64-bit) 8.2.1 20181213`; target Armv8-M mainline (`Tag_CPU_arch`
  v8-M.mainline), FPv5-D16, hard-float, Thumb, "Aggressive Size" optimisation.
- The `.c` that produces it includes firmware headers (`app_module.h`, `lvgl.h`, `service_comm.h`, `rtdef.h`,
  `app_clock_comm.h`, `mod_installer.h`, `app_activity_info.h`, `app_unit.h`, `app_dial_data.h`); none are available.

---

## 6. Image `.bin` files

### 6.1 Resource header (first 4 bytes, little-endian u32, LVGL-style bitfield)

| Bits | Field |
|---|---|
| 0–4 | `format` |
| 10–20 | `width` |
| 21–31 | `height` |

**VERIFIED**: yields the correct size for every decoded image. Other bits are **UNKNOWN**.

| `format` | Meaning | Status |
|---|---|---|
| 5 | Raw RGB565 + alpha, uncompressed (§6.2) | VERIFIED |
| 1 | ezip frame, RGB565, no alpha (§6.3) | VERIFIED |
| 2 | ezip frame, RGB565 + alpha (§6.3) | VERIFIED |
| 0x1F (31) | Multi-frame container of ezip frames (§6.4) | VERIFIED (`wf_w62` only) |

### 6.2 Raw images (`format` 5)

After the 4-byte header: `width × height` pixels, 3 bytes each: RGB565 (u16 LE) then alpha (u8, straight alpha),
row-major. Then a 4-byte trailer (**UNKNOWN**). **VERIFIED**: file size is exactly `4 + w·h·3` + 4. Used for
clock hands (`wf_w62`: 26×88, 26×106, 26×106; `wf_f82`: 34×220 ×3).

RGB565 → 8-bit: `r = (c>>11 & 31)·255//31`, `g = (c>>5 & 63)·255//63`, `b = (c & 31)·255//31`.

### 6.3 ezip frame (`format` 1 or 2)

The compression is performed in hardware by the SiFli EZIP block on the watch (**SOURCE**: `bf0_hal_ezip.c` only configures
that block; it contains no bitstream). The layout below was worked out against the **OpenEZIP** decoder and checked on real
files. File offsets, starting from the 4-byte resource header:

| File offset | Size | Endian | Field |
|---|---|---|---|
| 0 | 4 | LE | Resource header (§6.1) |
| 4 | 4 | BE | `size`: length of the stream below, **including** the Adler-32 |
| 8 | 1 | | `ctrl` (see below) |
| 9 | 1 | | `depth`: bits per pixel of the decoded data (16, 24 or 8) |
| 10 | 1 | | `block_rows`: rows per block (32 in all samples) |
| 11 | 1 | | flags (0 in all samples) |
| 12 | 2+2 | BE | width, height (repeat the resource header) |
| 16 | 1 | | low nibble = filter mode: `1` = no row filters, otherwise PNG-style filters present (0 in all samples) |
| 17–19 | 3 | | `00 00 00` for RGB565 variants; byte 17 = palette count − 1 in the palette variant (§6.6) |
| 20 | 2 | BE | `rows` (see below) |
| 22 | 2 | BE | `nblk`: number of blocks |
| 24 | 4·`nblk` | BE | Block table (§6.3.1) |
| 24 + 4·`nblk` | … | | Compressed data |
| 4 + `size` − 4 | 4 | BE | **Adler-32** of the *decoded* (still filtered) data |

The file can be longer than `4 + size` by a few bytes (4–7 observed on `wf_f82`; purpose **UNKNOWN**, possibly padding).

**`ctrl`**: `0x4C` for 24-bit (format 2) images, `0x48` for 16-bit (format 1) images, `0x43` for 8-bit palette images
(**OBSERVED** correlation). The high nibble selects the entropy coder: `>2` and `!=5` → shared Huffman (§6.3.2, seen: 4);
otherwise per-block raw DEFLATE (from OpenEZIP, **UNTESTED**: no sample uses it).

**`rows`** equals `min(height, 32)` in every sample (26 for the 60×26 weekday frames, 20 for the 12×20 digits,
32 for the larger images), i.e. the number of rows per block. **OBSERVED.** OpenEZIP's shared-Huffman path uses this value
as the block size for the filter reset in §6.3.3, and so does `extract_sifli_dial.py`; the `block_rows` byte at offset 10 is
32 in all samples and is not used by that path.

#### 6.3.1 Block table

`nblk` big-endian u32 values, `ceil(height / block_rows)` blocks (1 for 60×26, 10 for 172×320, 12 for 360×360).
For the shared-Huffman coder the table is **not needed to decode**; the whole block stream is decoded sequentially.
What the entries contain is **UNKNOWN** (they may be block offsets; OpenEZIP masks the first one with `0x00FFFFFF`
in its per-block-DEFLATE path, reason unknown).

#### 6.3.2 Shared-Huffman stream (`ctrl >> 4 == 4`) — VERIFIED

A DEFLATE-style bit stream (bits LSB-first) with one Huffman table shared by all blocks:

1. **Table header**, with *no* leading BFINAL/BTYPE bits: `HLIT` (5 bits, +257), `HDIST` (5 bits, +1), `HCLEN` (4 bits, +4).
2. Code-length code lengths: `HCLEN` × 3 bits, in the standard order `16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15`.
3. Literal/length and distance code lengths, decoded with symbols 0–15 (length), 16 (repeat previous 3–6),
   17 (zeros 3–10), 18 (zeros 11–138), exactly as in DEFLATE. Canonical Huffman code assignment as in DEFLATE.
4. **Align to the next 4-byte boundary.**
5. Then one or more **blocks**, each: `BFINAL` (1 bit), `BTYPE` (2 bits): `0` = stored, `1` or `2` = compressed with the
   shared tables from step 3 (no per-block tables). Stored blocks: 16-bit length, then skip 4 bytes (LEN and NLEN),
   then raw bytes. Compressed blocks use standard DEFLATE length/distance symbols and extra bits; symbol 256 ends the block.
6. **Align to a 4-byte boundary after every block**; stop after the block with `BFINAL = 1`.

Decoded size equals `height × (width × bytes_per_pixel + 1)`, where the `+1` is the filter-type byte per row.
`bytes_per_pixel = depth / 8`. The Adler-32 of that buffer must match the trailer: **it did for every RGB565 / RGB565+alpha
frame decoded from both samples** (23 ezip image files, including both backgrounds and both thumbnails; the 6 raw
hand images have no checksum).

#### 6.3.3 PNG-style row filters

Each row is preceded by a filter-type byte (0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth), exactly as in PNG with
`bpp` = bytes per pixel. **The "previous row" is treated as all zero at the first row of each block** (row index
`y % rows == 0`, `rows` from file offset 20), so blocks are independently decodable.

#### 6.3.4 Pixel formats after unfiltering

| `format` | `depth` | Bytes/pixel | Pixel |
|---|---|---|---|
| 1 | 16 | 2 | RGB565, little-endian |
| 2 | 24 | 3 | RGB565 little-endian, then alpha byte (straight alpha) |

Newer variants seen on `wf_w124` (all `format` 1, `depth` 8 in the header, same shared-Huffman stream and filters,
**VERIFIED**: Adler-32 matches on all 22 images, colours checked against the thumbnail):

| `ctrl` (byte 8) | Bytes/pixel | Pixel |
|---|---|---|
| `0x42` | 3 | **B, G, R** (thumbnail, background) |
| `0x46` | 4 | **B, G, R, A** (clock digits; checked on white glyphs only) |

`depth == 8` in byte 9 therefore does not identify a palette image; use `ctrl == 0x43`.

### 6.4 Multi-frame container (`format` 0x1F) — VERIFIED on `wf_w62` only

| File offset | Size | Endian | Field |
|---|---|---|---|
| 0 | 4 | LE | Resource header (`format` = 0x1F, width, height of one frame) |
| 4 | 4 | LE | Frame count `n` |
| 8 | 4 | LE | Second count/limit (**UNKNOWN** meaning) |
| 0x10 | 4·`n` | LE | Offsets `o[i]`, measured from file offset 4 |
| `o[i] + 4` | 4 | LE | Frame size `s[i]` |
| `o[i] + 8` | `s[i]` | | A complete ezip frame (§6.3), with its own 4-byte resource header |

`wf_w62_picture_dialBg.bin` is a container with one frame (172×320, format 1); `wf_w62_week_0_dialDate.bin` has 7 frames
(60×26, format 2, SUN..SAT). `wf_f82` has no `0x1F` files; its images are single frames (§6.3).

### 6.5 Thumbnail

`<name>_tn.bin` is a normal single ezip frame (`wf_w62`: 136×252, `wf_f82`: 270×270). **VERIFIED**.

### 6.6 8-bit palette variant (`ctrl` 0x43) — index map decodable, colours UNRESOLVED

On `wf_f82`, 24 of 47 images (clock digits, weekday labels, some date/temperature digits) use `ctrl` 0x43.

- **VERIFIED** (24/24 on `wf_f82`, Adler-32 OK; also `wf_w98` has none): byte 17 = entry count − 1. The colour table has
  4 bytes per entry, starting at file offset 24. The shared-Huffman stream starts at
  `24 + 4·count + 4·(blocks − 1)` where `blocks = ceil(h / f[10])`. The one extra word per additional block looks like the
  next block's offset. The decoded stream is `h·(w+1)` bytes: a filtered 1-byte-per-pixel index map.
- The index map is clearly an image (glyphs "1", "7", "TUE" are recognisable). Indices are numbered in first-appearance order.
- Table bytes are in **B, G, R, x** order: opaque glyph pixels give (37,59,81) vs (32,60,82) in an RGB565 sibling.
- Entries such as `80 80 80 02`, `55 55 55 03`, `40 40 40 04` obey colour × x ≈ 256, i.e. an un-premultiplied value of 1,
  so `x` may be real alpha.
- **UNRESOLVED:** applying entry *i* to index *i* gives a background that is about 56 % opaque and a glyph interior that is
  about 13 % opaque, which contradicts the thumbnail (navy digits, transparent background). Table order, the unused last
  entry and the alpha rule are **UNKNOWN**. Tried: raster, column, reversed, serpentine and tile first-appearance orders; a
  smoothness search (degenerate). `extract_sifli_dial.py --palette` therefore writes the index map, the raw table and an
  **UNVERIFIED** preview only.
- What would settle it: a source PNG plus the `.bin` made from it by SiFli's GraphicsTool.

---

## 7. Open questions

1. Meaning of `project_no` (13 in the first two samples) and of the header `reserve` bytes.
2. The trailing 4 bytes of raw (`format` 5) images, and the 4–7 extra bytes after some ezip frames (probably padding to 4).
3. Why `.dsc` types `0x06` and `0x0A` both hold the face name.
4. Block-table entries (§6.3.1), the `rows` field (§6.3), and the unused bits of the resource header.
5. The 8-bit palette variant: colour/alpha rule (§6.6).
6. The standard raw-DEFLATE ezip stream and per-block raw DEFLATE stream (both in OpenEZIP; no sample available).
7. Whether other devices use other `project_no` values or `format` codes.
8. Building a valid `.watch` from scratch. Solved or cheap: container (§2), `.dsc` and all CRC trailers (§4, §5.1).
   Still open: compiling the face `.so` (toolchain and firmware headers needed, §5.3), producing `_res.so` from the `.xlsx` (§5.2),
   and an ezip encoder (block table, mode selection).

## 8. Sources

- `ido_app_custom_dial_make.c`: vendor packer for the container (`head_t`, `file_head_t`, CRC-16).
- OpenEZIP (SiFli ezip decoder tool, `ezip_decoder.py` / `sifli_header.py`): ezip stream layouts and shared-Huffman decoder.
- `bf0_hal_ezip.c`: SiFli EZIP hardware driver (decode modes EZIP / GZIP / LZ4, error flags); no bitstream.
- Designer JS (`WatchService.js`, `ProtocolUtilSiChe.js`): export zip layout, image naming, `ezip` / `no_ezip` split.
- `wf_sifliTest.c`: example generated LVGL face source (hand pivots and angle formulas).
- Sample faces: `wf_w62.watch`, `wf_f82.watch`, `wf_w124.watch`, `wf_w98.watch`; export projects `wf_sifliTest.zip` (two versions).
