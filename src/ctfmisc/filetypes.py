"""文件类型识别、文本形态判断与主数据区边界定位。"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass
class TypeInfo:
    ext: str
    desc: str
    mime: str = ""
    offset: int = 0
    confident: bool = True


_SIGS: list[tuple[bytes, int, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", 0, "png", "PNG 图片"),
    (b"\xff\xd8\xff", 0, "jpg", "JPEG 图片"),
    (b"GIF87a", 0, "gif", "GIF 图片"),
    (b"GIF89a", 0, "gif", "GIF 图片"),
    (b"BM", 0, "bmp", "BMP 位图"),
    (b"II*\x00", 0, "tif", "TIFF 图片"),
    (b"MM\x00*", 0, "tif", "TIFF 图片"),
    (b"RIFF", 0, "riff", "RIFF 容器"),
    (b"\x00\x00\x01\x00", 0, "ico", "ICO 图标"),
    (b"%PDF", 0, "pdf", "PDF 文档"),
    (b"PK\x03\x04", 0, "zip", "ZIP 压缩包"),
    (b"PK\x05\x06", 0, "zip", "ZIP 空压缩包"),
    (b"PK\x07\x08", 0, "zip", "ZIP 分卷/流式"),
    (b"\x1f\x8b", 0, "gz", "GZIP 压缩流"),
    (b"BZh", 0, "bz2", "BZIP2 压缩流"),
    (b"\xfd7zXZ\x00", 0, "xz", "XZ 压缩流"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip 压缩包"),
    (b"Rar!\x1a\x07\x00", 0, "rar", "RAR 压缩包"),
    (b"Rar!\x1a\x07\x01\x00", 0, "rar5", "RAR5 压缩包"),
    (b"\x7fELF", 0, "elf", "Linux 可执行文件"),
    (b"MZ", 0, "exe", "Windows 可执行文件"),
    (b"SQLite format 3\x00", 0, "sqlite", "SQLite 数据库"),
    (b"fLaC", 0, "flac", "FLAC 音频"),
    (b"OggS", 0, "ogg", "OGG 媒体"),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap", "PCAP 流量包"),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap", "PCAP 流量包（大端）"),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng", "PCAPNG 流量包"),
    (b"ID3", 0, "mp3", "MP3 音频（含 ID3 标签）"),
    (b"\xff\xfb", 0, "mp3", "MP3 音频"),
    (b"\xff\xf3", 0, "mp3", "MP3 音频"),
    (b"-->\x00", 0, "ttf", "TrueType 字体"),
    (b"{\\rtf", 0, "rtf", "RTF 文档"),
    (b"<?xml", 0, "xml", "XML 文档"),
    (b"\x1a\x45\xdf\xa3", 0, "mkv", "Matroska/WebM"),
    (b"gimp xcf", 0, "xcf", "GIMP 工程文件"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", 0, "7z", "7-Zip 压缩包"),
]


def identify(data: bytes, name: str = "") -> TypeInfo:
    for sig, off, ext, desc in _SIGS:
        if data[off:off + len(sig)] == sig:
            info = TypeInfo(ext, desc, offset=off)
            if ext == "riff" and len(data) >= 12:
                sub = data[8:12]
                if sub == b"WAVE":
                    return TypeInfo("wav", "WAV 音频")
                if sub == b"WEBP":
                    return TypeInfo("webp", "WebP 图片")
                if sub == b"AVI ":
                    return TypeInfo("avi", "AVI 视频")
            return info
    if len(data) > 262 and data[257:262] == b"ustar":
        return TypeInfo("tar", "TAR 归档")
    if data[:4] == b"II\x2a\x00" or data[:4] == b"MM\x00\x2a":
        return TypeInfo("tif", "TIFF 图片")
    low = data[:512].lstrip()
    if low[:5].lower() == b"<!doc" or low[:5].lower() == b"<html":
        return TypeInfo("html", "HTML 页面")
    if data[:2] in (b"\x1f\x9d",) or data[:3] == b"\x1f\x8b\x08":
        return TypeInfo("z", "compress/Z 压缩流")
    kind = text_kind(data[:4096])
    if kind:
        return TypeInfo(_KIND_EXT.get(kind, "txt"), f"文本（{kind}）", confident=False)
    return TypeInfo("bin", "未知二进制", confident=False)


_KIND_EXT = {
    "base64": "b64", "hex": "hex", "binary": "bin8", "text": "txt",
    "morse": "morse", "json": "json", "xml": "xml", "source": "txt",
    "octal": "oct", "decimal": "dec",
}


def text_kind(data: bytes) -> str:
    if not data:
        return ""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = data.decode("gbk")
        except UnicodeDecodeError:
            printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
            return "text" if printable / len(data) > 0.9 else ""
    s = s.strip()
    if not s:
        return ""
    if re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", s) and len(s.replace("\n", "")) % 4 in (0, 2, 3):
        core = re.sub(r"\s", "", s)
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", core) and len(core) >= 16:
            return "base64"
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F\s]{4,}", s) and len(re.sub(r"\s", "", s)) % 2 == 0:
        letters = set(re.sub(r"\s", "", s).lower()) - set("0123456789")
        if letters:
            return "hex"
    if re.fullmatch(r"[01\s]{8,}", s):
        return "binary"
    if re.fullmatch(r"[.\-\s/|]{6,}", s) and ("." in s or "-" in s):
        return "morse"
    if re.fullmatch(r"[0-7\s]{6,}", s):
        return "octal"
    if re.fullmatch(r"\d[\d\s]{5,}", s):
        return "decimal"
    st = s.lstrip()
    if st[:1] in "{[(" and st[:1] in "{[":
        return "json"
    if st[:1] == "<":
        return "xml"
    if re.search(r"(?m)^\s*(?:import |from |#include|def |class |function )", s):
        return "source"
    if sum(1 for c in s if c.isprintable() or c in "\r\n\t") / max(len(s), 1) > 0.95:
        return "text"
    return ""


_ENDS: dict[str, bytes] = {
    "png": b"IEND",
    "jpg": b"\xff\xd9",
    "gif": b"\x3b",
}


def main_data_end(data: bytes, ext: str) -> int:
    """返回主文件数据的结束偏移（之后的内容为附加数据）。"""
    if ext == "png":
        idx = data.rfind(b"IEND")
        return idx + 8 if idx >= 0 else len(data)
    if ext in ("jpg", "jpeg"):
        idx = data.rfind(b"\xff\xd9")
        return idx + 2 if idx >= 0 else len(data)
    if ext == "gif":
        idx = data.rfind(b"\x3b")
        return idx + 1 if idx >= 0 else len(data)
    if ext == "zip":
        idx = data.rfind(b"PK\x05\x06")
        if idx >= 0 and len(data) >= idx + 22:
            comment_len = int.from_bytes(data[idx + 20:idx + 22], "little")
            return idx + 22 + comment_len
        return len(data)
    return len(data)


def trailing_data(data: bytes, ext: str) -> bytes:
    end = main_data_end(data, ext)
    return data[end:]
