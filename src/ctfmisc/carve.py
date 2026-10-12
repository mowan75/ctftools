"""文件雕复（binwalk 精简版）：从任意数据中切出内嵌文件。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO

from . import filetypes

SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff\xe0", "jpg"),
    (b"\xff\xd8\xff\xe1", "jpg"),
    (b"\xff\xd8\xff\xdb", "jpg"),
    (b"GIF89a", "gif"),
    (b"GIF87a", "gif"),
    (b"BM", "bmp"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b\x08", "gz"),
    (b"BZh9", "bz2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"%PDF-", "pdf"),
    (b"RIFF", "riff"),
    (b"OggS", "ogg"),
    (b"fLaC", "flac"),
    (b"ID3", "mp3"),
    (b"SQLite format 3\x00", "sqlite"),
]


@dataclass
class Carved:
    offset: int
    ext: str
    size: int
    data: bytes
    desc: str


IMAGE_EXTS = {"png", "jpg", "gif", "bmp", "webp", "tif"}


def validate(ext: str, chunk: bytes) -> bool:
    """严格校验魔数命中是否真的是该格式（避免 'BM' 这类 2 字节魔数的误报）。"""
    if len(chunk) < 16:
        return False
    try:
        if ext in IMAGE_EXTS:
            from PIL import Image
            with Image.open(BytesIO(chunk)) as img:
                w, h = img.size
                if not (0 < w <= 100000 and 0 < h <= 100000):
                    return False
                img.format  # 触发头部解析
            return True
        if ext == "zip":
            if len(chunk) < 30 or chunk[:4] != b"PK\x03\x04":
                return False
            ver, flags, method = int.from_bytes(chunk[4:6], "little"), int.from_bytes(chunk[6:8], "little"), \
                int.from_bytes(chunk[8:10], "little")
            nlen, elen = int.from_bytes(chunk[26:28], "little"), int.from_bytes(chunk[28:30], "little")
            if ver > 63 or method not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98, 99):
                return False
            if not (0 < nlen <= 512) or elen > 4096 or 30 + nlen + elen > len(chunk):
                return False
            name = chunk[30:30 + nlen]
            return sum(1 for b in name if 32 <= b < 127 or b in (0x5C,)) / nlen > 0.8
        if ext == "gz":
            return len(chunk) > 18 and chunk[2] == 8 and (chunk[3] & 0xE0) == 0
        if ext == "bz2":
            return len(chunk) > 14 and chunk[3:4].isdigit()
        if ext == "xz":
            return len(chunk) > 24 and chunk[6:8] in (b"\x00\x04", b"\x00\x00")
        if ext == "7z":
            return len(chunk) > 32 and chunk[6:8] == b"\x00\x04"
        if ext == "rar":
            return len(chunk) > 20 and chunk[5] in (0x00, 0x01)
        if ext == "pdf":
            return len(chunk) > 32 and b"%%EOF" in chunk[-2048:] or b"obj" in chunk[:2048]
        if ext == "riff":
            declared = int.from_bytes(chunk[4:8], "little")
            return 8 <= declared <= max(len(chunk) + 4096, 8)
        if ext == "ogg":
            return len(chunk) > 27 and chunk[4] == 0
        if ext == "flac":
            return len(chunk) > 42 and chunk[4:8][:1] == b"\x00"
        if ext == "mp3":
            b = chunk[6:10]
            size = (b[0] & 0x7F) << 21 | (b[1] & 0x7F) << 14 | (b[2] & 0x7F) << 7 | (b[3] & 0x7F)
            return all(x < 0x80 for x in b) and 0 < size < len(chunk) + 4096
        if ext == "sqlite":
            return len(chunk) > 100 and chunk[16:18] in (b"\x04\x00", b"\x02\x00", b"\x01\x01")
    except Exception:
        return False
    return True


def carve(data: bytes, min_size: int = 64, max_items: int = 12,
          limit_each: int = 8 * 1024 * 1024) -> list[Carved]:
    """按魔数扫描内嵌文件，并按格式结束标记裁剪长度。"""
    hits: list[Carved] = []
    seen: set[int] = set()
    for sig, ext in SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            start = idx + 1
            if idx == 0 or idx in seen:
                continue
            end = find_end(data, idx, ext)
            if end - idx < min_size:
                continue
            seen.add(idx)
            chunk = data[idx:min(end, idx + limit_each)]
            if not validate(ext, chunk):
                continue
            info = filetypes.identify(chunk)
            hits.append(Carved(idx, ext, len(chunk), chunk, info.desc))
            if len(hits) >= max_items:
                return sorted(hits, key=lambda h: h.offset)
    return sorted(hits, key=lambda h: h.offset)


def find_end(data: bytes, start: int, ext: str) -> int:
    if ext == "png":
        i = data.find(b"IEND", start)
        return i + 8 if i > 0 else len(data)
    if ext == "jpg":
        i = data.find(b"\xff\xd9", start)
        return i + 2 if i > 0 else len(data)
    if ext == "gif":
        i = data.find(b"\x3b", start)
        return i + 1 if i > 0 else len(data)
    if ext == "zip":
        i = data.find(b"PK\x05\x06", start)
        if i > 0 and len(data) >= i + 22:
            clen = int.from_bytes(data[i + 20:i + 22], "little")
            return i + 22 + clen
        return len(data)
    if ext == "pdf":
        i = data.find(b"%%EOF", start)
        return i + 5 if i > 0 else len(data)
    return len(data)


def find_all_offsets(data: bytes) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for sig, ext in SIGNATURES:
        for m in re.finditer(re.escape(sig), data):
            out.append((m.start(), ext))
    return sorted(out)
