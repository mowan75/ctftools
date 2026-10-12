"""压缩包处理：伪加密修复、口令爆破、注释/文件名、嵌套解包。"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import tarfile
import zipfile
from dataclasses import dataclass

COMMON_PASSWORDS = [
    "", "123456", "12345678", "123456789", "password", "admin", "root", "flag", "ctf",
    "1234", "12345", "0000", "1111", "111111", "666666", "888888", "abc123", "qwerty",
    "letmein", "welcome", "iloveyou", "666", "888", "999999", "520520", "1314520",
    "qwer1234", "a123456", "123123", "11111111", "password1", "p@ssw0rd", "Passw0rd",
    "1", "12", "123", "123123123", "abc", "abcabc", "aaa", "test", "guest", "user",
    "administrator", "toor", "hack", "hacker", "ctf123", "flag123", "misc", "stego",
    "zxc123", "asd123", "123qwe", "qweasd", "zxcvbnm", "asdfgh", "987654321",
    "159357", "741852963", "147258369", "woaini", "woaini1314", "5201314",
]


@dataclass
class Entry:
    name: str
    size: int
    compressed: int
    encrypted: bool
    crc: int
    comment: bytes = b""


def decode_zip_name(info: zipfile.ZipInfo) -> str:
    """还原被错误解码的文件名（GBK/UTF-8 混用是常见考点）。"""
    name = info.filename
    if info.flag_bits & 0x800:
        return name
    try:
        raw = name.encode("cp437")
    except UnicodeEncodeError:
        return name
    for enc in ("utf-8", "gbk", "big5"):
        try:
            cand = raw.decode(enc)
            if cand:
                return cand
        except UnicodeDecodeError:
            continue
    return name


def zip_entries(data: bytes) -> tuple[list[Entry], bytes]:
    entries: list[Entry] = []
    comment = b""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            comment = zf.comment
            for info in zf.infolist():
                entries.append(Entry(
                    name=decode_zip_name(info),
                    size=info.file_size,
                    compressed=info.compress_size,
                    encrypted=bool(info.flag_bits & 1),
                    crc=info.CRC,
                    comment=info.comment,
                ))
    except Exception:
        pass
    return entries, comment


def pseudo_encrypted(data: bytes) -> bool:
    """判断是否为“伪加密”：标志位声称加密，但数据其实可正常解压。"""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.flag_bits & 1:
                    try:
                        zf.read(info.filename)
                        return True
                    except Exception:
                        return False
    except Exception:
        return False
    return False


def fix_pseudo_encryption(data: bytes) -> bytes:
    """清除本地头 / 中央目录中的加密标志位，返回修复后的数据。"""
    buf = bytearray(data)
    for m in re.finditer(b"PK\x03\x04", bytes(buf)):
        off = m.start() + 6
        if off + 2 <= len(buf):
            flag = int.from_bytes(buf[off:off + 2], "little") & ~0x1
            buf[off:off + 2] = flag.to_bytes(2, "little")
    for m in re.finditer(b"PK\x01\x02", bytes(buf)):
        off = m.start() + 8
        if off + 2 <= len(buf):
            flag = int.from_bytes(buf[off:off + 2], "little") & ~0x1
            buf[off:off + 2] = flag.to_bytes(2, "little")
    return bytes(buf)


def extract_zip(data: bytes, password: bytes | None = None, max_total: int = 40 * 1024 * 1024,
                max_files: int = 200) -> tuple[dict[str, bytes], str]:
    """解压 zip，返回 ({文件名: 内容}, 备注)。"""
    out: dict[str, bytes] = {}
    note = ""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()][:max_files]
            total = 0
            bad = 0
            for info in infos:
                if total > max_total:
                    break
                try:
                    chunk = zf.read(info.filename, pwd=password)
                except Exception:
                    bad += 1
                    continue
                total += len(chunk)
                out[decode_zip_name(info)] = chunk
            if bad:
                note = f"{bad} 个文件解压失败（可能已加密）"
    except Exception as exc:
        note = f"zip 解析异常: {exc}"
    return out, note


def crack_password(data: bytes, extra: list[str] | None = None, digits: int = 0,
                   limit: int = 200000) -> str | None:
    """用内置字典 + 可选纯数字空间爆破 zip 口令。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return None
    target = None
    for info in zf.infolist():
        if not info.is_dir():
            target = info
            break
    if target is None:
        return None

    candidates: list[str] = []
    candidates.extend(extra or [])
    candidates.extend(COMMON_PASSWORDS)
    if digits:
        for i in range(10 ** digits):
            candidates.append(str(i).zfill(digits))

    for pw in candidates[:limit]:
        try:
            with zf.open(target.filename, pwd=pw.encode("utf-8", "ignore")):
                return pw
        except Exception:
            continue
    return None


def name_passwords(data: bytes, outer_name: str = "", inner_names: list[str] | None = None) -> list[str]:
    """题目常用套路：密码就是压缩包自己的文件名 / 里面条目的文件名（去扩展名）。

    返回按可能性排序的口令候选。
    """
    cands: list[str] = []

    def add(value: str) -> None:
        value = (value or "").strip()
        for v in {value, value.rsplit(".", 1)[0] if "." in value else value}:
            if v and v not in cands:
                cands.append(v)

    add(outer_name)
    entries, _comment = zip_entries(data)
    for e in entries:
        add(e.name.rsplit("/", 1)[-1])
    for n in inner_names or []:
        add(n.rsplit("/", 1)[-1])
    # 附带的 hash 风格名（去掉扩展名后常直接当密码）
    for c in list(cands):
        if re.fullmatch(r"[0-9a-f]{16,64}", c.lower()):
            add(c)
    return cands


def crack_with_names(data: bytes, outer_name: str = "") -> str | None:
    """先用"文件名当密码"的套路试，再退回字典。"""
    pw = crack_password(data, extra=name_passwords(data, outer_name), limit=4000)
    if pw is not None:
        return pw
    return crack_password(data, digits=4)


def is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def extract_any(data: bytes, name: str = "") -> tuple[dict[str, bytes], str]:
    """按类型解压 gzip / bzip2 / xz / tar / zip / 7z。"""
    low = name.lower()
    out: dict[str, bytes] = {}
    note = ""
    try:
        if data[:2] == b"\x1f\x8b":
            raw = gzip.decompress(data)
            return {re.sub(r"\.(gz|tgz)$", "", name) or "解压结果": raw}, "gzip 解压"
        if data[:3] == b"BZh":
            return {name or "解压结果": bz2.decompress(data)}, "bzip2 解压"
        if data[:6] == b"\xfd7zXZ\x00":
            return {name or "解压结果": lzma.decompress(data)}, "xz 解压"
        if data[:4] == b"7z\xbc\xaf\x27\x1c":
            try:
                import py7zr
                with py7zr.SevenZipFile(io.BytesIO(data)) as zf:
                    for fn, bio in zf.readall().items():
                        out[fn] = bio.read()
                return out, "7z 解压"
            except Exception as exc:
                return {}, f"7z 解压失败: {exc}"
        if is_tar(data) or low.endswith((".tar", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.size < 20 * 1024 * 1024:
                        fh = tf.extractfile(member)
                        if fh:
                            out[member.name] = fh.read()
            return out, "tar 解包"
        if data[:2] == b"PK":
            return extract_zip(data)
    except Exception as exc:
        note = str(exc)
    return out, note


def interesting_names(names: list[str]) -> list[str]:
    """挑出可疑文件名（含 flag / 密码 / 提示等字样）。"""
    pat = re.compile(r"(flag|key|pass|hint|secret|密码|提示|readme)", re.I)
    return [n for n in names if pat.search(n)]


def crc_bruteforce(data: bytes, max_bytes: int = 2, limit: int = 1_500_000,
                   on_progress=None) -> tuple[bytes | None, str]:
    """ZIP 短内容 CRC 爆破：已知条目 CRC32 时反推 1~2 字节/数字/短单词内容。"""
    import itertools
    import zlib as _zlib
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        info = next((i for i in zf.infolist() if not i.is_dir()), None)
    except Exception:
        return None, "不是合法 ZIP"
    if info is None:
        return None, "ZIP 里没有文件"
    target = info.CRC
    tried = 0

    def hit(chunk: bytes) -> bool:
        return _zlib.crc32(chunk) & 0xFFFFFFFF == target

    # 纯数字
    for n in range(10 ** 6):
        tried += 1
        if hit(str(n).encode()):
            return str(n).encode(), f"命中：内容为十进制数字 {n}"
        if tried > limit:
            break
    # 1~2 字节全排列
    for length in range(1, max_bytes + 1):
        for combo in itertools.product(range(256), repeat=length):
            tried += 1
            if tried > limit:
                break
            if hit(bytes(combo)):
                return bytes(combo), f"命中：内容为 {bytes(combo)!r}"
    # 常见短单词
    for word in ("flag", "ctf", "test", "admin", "root", "pass", "key", "1", "0", "true", "false"):
        tried += 1
        if hit(word.encode()):
            return word.encode(), f"命中：内容为 {word!r}"
    return None, f"未爆破出内容（已尝试 {tried} 次；CRC 爆破只适用于内容很短的条目）"
