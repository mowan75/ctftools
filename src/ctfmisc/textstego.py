"""文本类隐写：SNOW 空格、零宽字符、Base64 填充位、敲击码、Emoji 编码。"""

from __future__ import annotations

import base64
import re


# --------------------------------------------------------------------------- #
# SNOW（行尾空格/Tab 隐写）
# --------------------------------------------------------------------------- #
def snow_extract(text: str) -> list[tuple[str, str]]:
    """提取行尾的空格/Tab 序列，按 SNOW 规则还原数据。

    SNOW 把数据编码成行尾的 空格/Tab：空格=0、Tab=1，每 8 位一个字节（高位在前）。
    """
    results: list[tuple[str, str]] = []
    lines = text.split("\n")
    bits_space_tab: list[int] = []
    bits_tab_space: list[int] = []
    for line in lines:
        m = re.search(r"[ \t]+$", line)
        if not m:
            continue
        tail = m.group(0)
        if "\t" in tail:
            for ch in tail:
                bits_space_tab.append(0 if ch == " " else 1)
                bits_tab_space.append(1 if ch == " " else 0)
    for tag, bits in (("SNOW（空格=0 Tab=1）", bits_space_tab), ("SNOW（空格=1 Tab=0）", bits_tab_space)):
        data = _bits_to_bytes(bits)
        if len(data) >= 3:
            text_out = "".join(chr(b) if 32 <= b < 127 else "·" for b in data[:200])
            results.append((tag, f"{len(data)} 字节：{text_out}"))
    return results


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        val = 0
        for b in bits[i:i + 8]:
            val = (val << 1) | b
        out.append(val)
    return bytes(out)


# --------------------------------------------------------------------------- #
# 零宽字符隐写
# --------------------------------------------------------------------------- #
ZW_CHARS = {
    "\u200b": 0,   # zero width space
    "\u200c": 1,   # zero width non-joiner
    "\u200d": 2,   # zero width joiner
    "\u2060": 3,   # word joiner
    "\ufeff": 4,   # BOM
}


def zero_width_extract(text: str) -> list[tuple[str, str]]:
    """零宽字符隐写：不可见字符承载数据，二进制/Bacon/摩斯/四进制多种编码都试一遍。"""
    seq = [c for c in text if c in ZW_CHARS]
    if len(seq) < 8:
        return []
    results: list[tuple[str, str]] = []
    vals = [ZW_CHARS[c] for c in seq]
    # 二进制（200b/200c 或 200c/200d 两种常见映射）
    for name, zero, one in (("200b=0/200c=1", 0, 1), ("200c=0/200d=1", 1, 2),
                            ("200b=1/200c=0", 1, 0)):
        bits = [1 if v == one else (0 if v == zero else None) for v in vals]
        if any(b is None for b in bits):
            continue
        data = _bits_to_bytes(bits)
        if len(data) >= 3:
            txt = "".join(chr(b) if 32 <= b < 127 else "·" for b in data[:200])
            results.append((f"零宽字符二进制（{name}）", f"{len(data)} 字节：{txt}"))
    # Bacon（每 5 个一组，a/b 两种字符）
    for name, a_val, b_val in (("200b=A 200c=B", 0, 1), ("200c=A 200d=B", 1, 2)):
        bits = [1 if v == b_val else (0 if v == a_val else None) for v in vals]
        if any(b is None for b in bits) or len(bits) < 10:
            continue
        out = []
        for i in range(0, len(bits) - 4, 5):
            group = bits[i:i + 5]
            if all(b is not None for b in group):
                out.append(chr(65 + sum(b << (4 - j) for j, b in enumerate(group))))
        if out:
            results.append((f"培根密码（{name}）", "".join(out)[:200]))
    # 四进制
    if all(v in (0, 1, 2, 3) for v in vals):
        data = bytearray()
        for i in range(0, len(vals) - 3, 4):
            data.append((vals[i] << 6) | (vals[i + 1] << 4) | (vals[i + 2] << 2) | vals[i + 3])
        if data:
            txt = "".join(chr(b) if 32 <= b < 127 else "·" for b in data[:200])
            results.append(("零宽字符四进制", f"{len(data)} 字节：{txt}"))
    # 摩斯（200c=点 200d=划 200b=分隔）
    morse = ""
    for v in vals:
        morse += {0: " ", 1: ".", 2: "-"}.get(v, "")
    if "." in morse or "-" in morse:
        from . import codec
        dec = codec.dec_morse(morse)
        if dec:
            results.append(("零宽字符摩斯", dec[:200]))
    return results


# --------------------------------------------------------------------------- #
# Base64 填充位隐写
# --------------------------------------------------------------------------- #
def base64_stego(text: str) -> list[tuple[str, str]]:
    """Base64 隐写：编码时末尾字节的多余位没有清零，可以藏 2~6 bit/组。"""
    core = re.sub(r"\s", "", text)
    if len(core) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=]+", core):
        return []
    groups = [core[i:i + 4] for i in range(0, len(core) - 3, 4)]
    bits: list[int] = []
    for g in groups:
        pad = g.count("=")
        if pad == 0:
            continue
        keep = {1: 2, 2: 4}[pad]      # 1 个 = 时保留 2 bit，2 个 = 时保留 4 bit
        idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = g[3 - pad]
        if last not in idx:
            continue
        val = idx.index(last)
        # 取被丢弃的低 keep 位
        for k in range(keep - 1, -1, -1):
            bits.append((val >> k) & 1)
    if len(bits) < 8:
        return []
    data = _bits_to_bytes(bits)
    txt = "".join(chr(b) if 32 <= b < 127 else "·" for b in data)
    return [("Base64 填充位隐写", f"{len(data)} 字节：{txt[:300]}")]


# --------------------------------------------------------------------------- #
# 敲击码 / Emoji
# --------------------------------------------------------------------------- #
def tap_code_decode(text: str) -> str | None:
    """敲击码（Tap code）：两个 1-5 的数字表示一个字母，常写成 . 或 数字。"""
    nums = re.findall(r"[1-5]", text)
    if len(nums) < 4 or len(nums) % 2:
        # 尝试点号形式
        groups = re.findall(r"([.\s]{1,10})", text)
        return None
    if not re.fullmatch(r"[\s1-5,;|/.]+", text.strip()):
        return None
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    out = []
    for i in range(0, len(nums), 2):
        r, c = int(nums[i]) - 1, int(nums[i + 1]) - 1
        out.append(square[r * 5 + c])
    return "".join(out)


EMOJI_MAP = {
    "😀": "A", "😃": "B", "😄": "C", "😁": "D", "😆": "E", "😅": "F", "😂": "G",
    "🤣": "H", "😊": "I", "😇": "J", "🙂": "K", "🙃": "L", "😉": "M", "😌": "N",
    "😍": "O", "🥰": "P", "😘": "Q", "😗": "R", "😙": "S", "😚": "T", "😋": "U",
    "😛": "V", "😝": "W", "😜": "X", "🤪": "Y", "🤨": "Z",
}


def emoji_decode(text: str) -> str | None:
    """emoji-aes / emoji 编码：把 emoji 映射回字母。"""
    out = [EMOJI_MAP[c] for c in text if c in EMOJI_MAP]
    if len(out) < 4:
        return None
    return "".join(out)
