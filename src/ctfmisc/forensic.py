"""取证类隐写：文件时间戳编码、文件名提示（base64/键盘错位）、AD1/镜像线索。"""

from __future__ import annotations

import base64
import os
import re
from collections import Counter


def timestamps_binary(paths: list[str], early_mask: int | None = None) -> list[tuple[str, str]]:
    """同目录一大批文件、大小相同但修改时间只有两种 → 时间戳编码了二进制数据。

    按文件名里的序号排序，把两种 mtime 分别当作 0/1，拼成字节再解成文本。
    """
    entries = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        m = re.search(r"(\d+)", os.path.basename(p))
        idx = int(m.group(1)) if m else len(entries)
        entries.append((idx, os.path.basename(p), st.st_mtime, st.st_size))
    if len(entries) < 16:
        return []
    entries.sort(key=lambda t: t[0])
    times = [t[2] for t in entries]
    uniq = sorted(set(times))
    results: list[tuple[str, str]] = []
    if len(uniq) <= 4:
        # 只有两三种时间：直接映射
        for order in (uniq, list(reversed(uniq))):
            bits = []
            mapping = {v: (0 if i == 0 else 1) for i, v in enumerate(order)}
            for t in times:
                bits.append(mapping.get(t, 0))
            results.append(_bits_report("时间戳编码", bits))
    else:
        # 时间分成明显两簇（例如 2024 / 2025）：按中位数切分
        mid = (min(times) + max(times)) / 2
        bits = [0 if t < mid else 1 for t in times]
        results.append(_bits_report("时间戳编码（按中位数二分）", bits))
        bits2 = [1 if t < mid else 0 for t in times]
        results.append(_bits_report("时间戳编码（反向）", bits2))
    return [r for r in results if r[1]]


def _bits_report(tag: str, bits: list[int]) -> tuple[str, str]:
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        data.append(val)
    txt = "".join(chr(b) if 32 <= b < 127 else "·" for b in data)
    printable = sum(1 for b in data if 32 <= b < 127) / max(len(data), 1)
    if printable < 0.85:
        return tag, ""
    return tag, f"{len(bits)} 个文件 → {len(data)} 字节：{txt[:200]}"


def filename_hints(name: str) -> list[tuple[str, str]]:
    """文件名里常藏提示：base64 / hex / 反转 / “key/密码”关键字。"""
    out: list[tuple[str, str]] = []
    base = os.path.basename(name)
    stem = base.rsplit(".", 1)[0]
    for token in re.findall(r"[A-Za-z0-9+/=]{8,}", stem):
        padded = token + "=" * (-len(token) % 4)
        for label, fn in (("base64", lambda t: base64.b64decode(t)),
                          ("base32", lambda t: base64.b32decode(t.upper() + "=" * (-len(t) % 8))),
                          ("hex", lambda t: bytes.fromhex(t))):
            try:
                raw = fn(padded if label != "hex" else token)
            except Exception:
                continue
            if label == "hex" and not re.fullmatch(r"[0-9a-fA-F]+", token):
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if text.isprintable() and len(text) >= 3:
                out.append((f"文件名里的 {label} 片段", f"{token} → {text}"))
                break
    if re.search(r"(key|pass|密码|hint|shift|flag)", stem, re.I):
        out.append(("文件名含提示词", stem))
    return out


_PLAIN = "1234567890-=[];',./`\\"
_SHIFT = "!@#$%^&*()_+{}:\"<>?~|"
_SHIFT_TABLE = str.maketrans({p: s for p, s in zip(_PLAIN, _SHIFT)})


def keyboard_shift_variants(text: str) -> list[str]:
    """键盘错位/Shift 变换：12345678 → !@#$%^&* 这类（题目里常直接当密码）。"""
    out = [text.translate(_SHIFT_TABLE)]
    # 大小写翻转（Shift 状态相反）
    out.append(text.swapcase())
    return [o for o in dict.fromkeys(out) if o != text]


def ad1_hint(data: bytes) -> str:
    """AD1（FTK Imager 逻辑镜像）识别与线索。"""
    if data[:16] == b"ADSEGMENTEDFILE":
        return ("这是 FTK Imager 的 AD1 逻辑镜像（ADSEGMENTEDFILE）。"
                "里面是分段的文件数据（含 zlib 压缩块），本工具可直接做 strings/雕复；"
                "完整解析建议用 FTK Imager / AccessData FTK（题目给密码时）。")
    if data[:4] in (b"\x00\x00\x00\x00",) and len(data) > 8 * 1024 * 1024:
        return "大体积未知格式，可能是磁盘/内存镜像"
    return ""
