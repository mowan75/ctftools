"""编码 / 古典密码 解码器集合，以及多层递归自动解码（CyberChef 式魔法）。"""

from __future__ import annotations

import base64
import binascii
import gzip
import html
import io
import itertools
import re
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import filetypes
from .flags import find_flags

Transform = Callable[[str], "bytes | str | None"]


@dataclass
class T:
    name: str
    fn: Transform
    group: str = "编码"
    spec: bool = False   # True = 猜测型（结果必然存在，需要高分才继续深入）


@dataclass
class DecodeResult:
    chain: list[str]
    value: str
    raw: bytes
    score: float
    flags: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return " → ".join(self.chain)


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
PRINTABLE = set(range(32, 127))


def to_text(data: bytes | str) -> str:
    if isinstance(data, str):
        return data
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "ignore")


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for c in s if ord(c) in PRINTABLE or c in "\r\n\t" or "\u4e00" <= c <= "\u9fff")
    return good / len(s)


_CIPHERISH = re.compile(r"^[A-Za-z0-9+/=\s]{12,}$|^[0-9a-fA-F\s]{12,}$|^[01\s]{12,}$")


def text_score(s: str) -> float:
    """给解码结果打分：越像“有意义的内容”越高。"""
    if not s:
        return -100.0
    s = s.strip()
    if len(s) < 2:
        return -100.0
    flags = find_flags(s)
    score = printable_ratio(s) * 30.0
    if flags:
        score += 120.0 + max(f.score for f in flags) / 4
    zh = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    if zh:
        score += min(zh, 60) * 1.2
    letters = sum(c.isalpha() for c in s)
    spaces = s.count(" ")
    if letters and spaces and 3 <= spaces <= len(s) / 2:
        score += 12.0
    common = ("flag", "the", "ctf", "key", "congrat", "success", "welcome", "this", "your", "is")
    low = s.lower()
    score += sum(6 for w in common if w in low)
    if _CIPHERISH.match(s):
        score -= 18.0
    if len(set(s)) <= 3 and len(s) > 8:
        score -= 25.0
    if "\ufffd" in s:
        score -= 40.0
    score -= min(len(s), 400) * 0.02
    return score


# --------------------------------------------------------------------------- #
# 编码类
# --------------------------------------------------------------------------- #
def _b64_variant(s: str, altchars=None, url: bool = False) -> bytes | None:
    core = re.sub(r"\s", "", s)
    if url:
        core = core.replace("-", "+").replace("_", "/")
    core = core.rstrip("=")
    if len(core) < 4:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+", core):
        return None
    pad = "=" * (-len(core) % 4)
    try:
        return base64.b64decode(core + pad, validate=False)
    except (binascii.Error, ValueError):
        return None


def dec_b64(s: str):
    out = _b64_variant(s)
    if out is None:
        return None
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        return out
    return out if printable_ratio(text) < 0.85 else text


def dec_b64_url(s: str):
    if "-" not in s and "_" not in s:
        return None
    return _b64_variant(s, url=True)


def dec_b32(s: str):
    core = re.sub(r"\s", "", s).upper()
    core = core.rstrip("=")
    if len(core) < 8 or not re.fullmatch(r"[A-Z2-7]+", core):
        return None
    pad = "=" * (-len(core) % 8)
    try:
        return base64.b32decode(core + pad)
    except (binascii.Error, ValueError):
        return None


def dec_b32hex(s: str):
    core = re.sub(r"\s", "", s).upper().rstrip("=")
    if len(core) < 8 or not re.fullmatch(r"[0-9A-V]+", core):
        return None
    pad = "=" * (-len(core) % 8)
    try:
        return base64.b32hexdecode(core + pad)
    except (binascii.Error, ValueError):
        return None


def _hex_clean(s: str) -> str | None:
    core = re.sub(r"0x", "", s, flags=re.I)
    core = re.sub(r"[^0-9a-fA-F]", "", core)
    if len(core) < 4 or len(core) % 2:
        return None
    return core


def dec_hex(s: str):
    core = _hex_clean(s)
    if not core:
        return None
    if not re.search(r"[a-fA-F]", s):
        return None
    try:
        return bytes.fromhex(core)
    except ValueError:
        return None


def dec_hexdump(s: str):
    """把 xxd / hexdump 输出还原为字节。"""
    if not re.search(r"^[0-9a-f]{4,8}[: ]", s, re.M):
        return None
    out = bytearray()
    ok = False
    for line in s.splitlines():
        m = re.match(r"^[0-9a-fA-F]{4,8}[: ]\s+(.*)$", line)
        if not m:
            continue
        body = m.group(1).split("|")[0]
        for tok in body.split():
            if re.fullmatch(r"[0-9a-fA-F]{2,8}", tok) and len(tok) % 2 == 0:
                try:
                    out.extend(bytes.fromhex(tok))
                    ok = True
                except ValueError:
                    pass
    return bytes(out) if ok and out else None


def dec_a85(s: str):
    core = s.strip()
    if "<~" in core:
        core = core[core.index("<~") + 2:]
    core = core.replace("~>", "").strip()
    if not re.fullmatch(r"[!-u\s]+", core):
        return None
    try:
        return base64.a85decode(core, adobe=False)
    except (ValueError, binascii.Error):
        return None


def dec_b85(s: str):
    core = re.sub(r"\s", "", s)
    if not re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~.]+", core):
        return None
    try:
        return base64.b85decode(core)
    except (ValueError, binascii.Error):
        return None


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")


def _baseX(s: str, alphabet: str) -> bytes:
    num = 0
    for ch in s:
        num = num * len(alphabet) + alphabet.index(ch)
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip(alphabet[0]))
    return b"\x00" * pad + out


def dec_b58(s: str):
    core = re.sub(r"\s", "", s)
    if len(core) < 5 or any(c not in _B58 for c in core):
        return None
    try:
        return _baseX(core, _B58)
    except ValueError:
        return None


def _b91_decode(s: str) -> bytes | None:
    if any(c not in _B91 for c in s):
        return None
    table = {c: i for i, c in enumerate(_B91)}
    v, b, n, out = -1, 0, 0, bytearray()
    for ch in s:
        if ch not in table:
            return None
        c = table[ch]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while True:
                out.append(b & 255)
                b >>= 8
                n -= 8
                if n <= 7:
                    break
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out) or None


def dec_b91(s: str):
    core = re.sub(r"\s", "", s)
    if len(core) < 6:
        return None
    return _b91_decode(core)


_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def dec_b36(s: str):
    """Base36 解码（整段当一个大整数）。"""
    core = re.sub(r"\s", "", s).lower()
    if len(core) < 6 or any(c not in _B36 for c in core):
        return None
    try:
        num = int(core, 36)
    except ValueError:
        return None
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return raw or None


def dec_b62(s: str):
    """Base62 解码（0-9A-Za-z 字母表）。"""
    core = re.sub(r"\s", "", s)
    if len(core) < 6 or any(c not in _B62 for c in core):
        return None
    try:
        num = 0
        for c in core:
            num = num * 62 + _B62.index(c)
    except ValueError:
        return None
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(core) - len(core.lstrip("0"))
    return b"\x00" * pad + raw if raw else None


BASE100_TABLE: list[str] = []


def _base100_table() -> list[str]:
    """base100：把字节映射成一串 emoji（256 个）。"""
    global BASE100_TABLE
    if BASE100_TABLE:
        return BASE100_TABLE
    table = []
    # base100 官方表：从 U+1F400 附近开始取 256 个连续码点
    for code in range(0x1F400, 0x1F400 + 256):
        try:
            table.append(chr(code))
        except ValueError:
            break
    BASE100_TABLE = table
    return table


def dec_base100(s: str):
    """Base100 解码（emoji → 字节）。"""
    table = _base100_table()
    chars = [c for c in s if ord(c) > 0x2000]
    if len(chars) < 2:
        return None
    idx = {c: i for i, c in enumerate(table)}
    out = bytearray()
    for c in chars:
        if c in idx:
            out.append(idx[c])
        else:
            # 兼容变体：按码点相对偏移
            v = ord(c) - 0x1F400
            if 0 <= v < 256:
                out.append(v)
            else:
                return None
    return bytes(out) or None


BASE_FAMILY = [
    ("Base64", dec_b64), ("Base64(URL)", dec_b64_url), ("Base32", dec_b32),
    ("Base32hex", dec_b32hex), ("Base16/Hex", dec_hex), ("Base85", dec_b85),
    ("Ascii85", dec_a85), ("Base58", dec_b58), ("Base91", dec_b91),
    ("Base36", dec_b36), ("Base62", dec_b62), ("Base100", dec_base100),
]


def base_family_chain(text: str, max_depth: int = 8) -> list[tuple[list[str], str]]:
    """Base 家族连环解码（“We are Family”那类题）：每轮把所有 Base 都试一遍，看谁有进展。"""
    from .flags import find_flags
    frontier = [([], text.strip())]
    results: list[tuple[list[str], str]] = []
    seen = {text.strip()[:200]}
    for _depth in range(max_depth):
        nxt = []
        for chain, value in frontier:
            for name, fn in BASE_FAMILY:
                try:
                    res = fn(value)
                except Exception:
                    continue
                if res is None:
                    continue
                if isinstance(res, bytes):
                    try:
                        out = res.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                else:
                    out = res
                out = out.strip()
                if not out or out == value or out[:200] in seen:
                    continue
                seen.add(out[:200])
                new_chain = chain + [name]
                nxt.append((new_chain, out))
                if find_flags(out):
                    results.append((new_chain, out))
                if len(out) >= 4 and not out.isprintable():
                    continue
        frontier = nxt[:40]
        if not frontier:
            break
    results.sort(key=lambda kv: (len(kv[0]), -len(kv[1])))
    return results[:10]


def dec_url(s: str):
    if "%" not in s and "+" not in s:
        return None
    if not re.search(r"%[0-9a-fA-F]{2}", s):
        return None
    out = urllib.parse.unquote_plus(s)
    return out if out != s else None


def dec_url2(s: str):
    if s.count("%25") == 0 and s.count("%") < 2:
        return None
    out = urllib.parse.unquote(urllib.parse.unquote(s))
    return out if out != s else None


def dec_html(s: str):
    if not re.search(r"&(#x?[0-9a-fA-F]+|[a-zA-Z]{2,8});", s):
        return None
    out = html.unescape(s)
    return out if out != s else None


def dec_unicode_escape(s: str):
    if not re.search(r"\\u[0-9a-fA-F]{4}", s):
        return None
    try:
        return s.encode().decode("unicode_escape")
    except Exception:
        return None


def dec_percent_u(s: str):
    if "%u" not in s.lower():
        return None
    out = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    return out if out != s else None


def dec_quoted_printable(s: str):
    if not re.search(r"=[0-9A-Fa-f]{2}", s):
        return None
    try:
        from quopri import decodestring
        return decodestring(s.encode("latin-1", "ignore"))
    except Exception:
        return None


def dec_binary(s: str):
    core = re.sub(r"[^01]", "", s)
    if len(core) < 8 or len(core) % 8 or len(core) == len(s):
        return None
    body = core
    try:
        return bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8))
    except ValueError:
        return None


def dec_binary7(s: str):
    core = re.sub(r"[^01]", " ", s)
    toks = [t for t in core.split() if len(t) in (7, 8)]
    if len(toks) < 3:
        return None
    try:
        return bytes(int(t, 2) for t in toks)
    except ValueError:
        return None


def dec_octal(s: str):
    toks = re.findall(r"\b[0-7]{2,4}\b", s)
    if len(toks) < 3 or not re.fullmatch(r"[\s,;|0-7]+", s.strip()):
        return None
    if all(len(t) == 3 for t in toks) and max(int(t, 8) for t in toks) > 255:
        return None
    try:
        return bytes(int(t, 8) & 0xFF for t in toks)
    except ValueError:
        return None


def dec_decimal(s: str):
    if re.fullmatch(r"[\d.\s,;|]+", s.strip()) and re.search(r"\d+\.\d+\.\d+", s):
        toks = [t for t in re.split(r"[.\s,;|]+", s.strip()) if t]
        if all(t.isdigit() and 0 <= int(t) <= 255 for t in toks):
            return bytes(int(t) for t in toks)
    toks = re.findall(r"\b\d{2,3}\b", s)
    if len(toks) < 4 or not re.fullmatch(r"[\d\s,;|]+", s.strip()):
        return None
    vals = [int(t) for t in toks]
    if not all(0 <= v <= 255 for v in vals):
        return None
    if not any(32 <= v < 127 for v in vals):
        return None
    return bytes(vals)


def dec_dna(s: str):
    core = re.sub(r"[^ACGTUacgtu]", "", s).upper().replace("U", "T")
    if len(core) < 8 or len(core) % 4:
        return None
    if len(core) == len(s.strip()):
        return None
    mapping = {"A": "00", "C": "01", "G": "10", "T": "11"}
    bits = "".join(mapping[c] for c in core)
    if len(bits) % 8:
        bits = bits[:len(bits) - len(bits) % 8]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def dec_zlib(s: str):
    try:
        raw = base64.b64decode(re.sub(r"\s", "", s) + "==")
    except Exception:
        return None
    if raw[:2] not in (b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e"):
        return None
    try:
        return zlib.decompress(raw)
    except zlib.error:
        return None


def dec_gzip_b64(s: str):
    try:
        raw = base64.b64decode(re.sub(r"\s", "", s) + "==")
    except Exception:
        return None
    if raw[:2] != b"\x1f\x8b":
        return None
    try:
        return gzip.decompress(raw)
    except OSError:
        return None


_UU_ALPHABET = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"


def dec_uu(s: str):
    lines = [l for l in s.splitlines() if l and not l.startswith(("begin", "end"))]
    if len(lines) < 2:
        return None
    out = bytearray()
    for line in lines:
        if not line or not line[0] in _UU_ALPHABET[1:]:
            continue
        n = (_UU_ALPHABET.find(line[0]) & 0x3F)
        chunk = line[1:]
        if n == 0:
            continue
        data = bytearray()
        for i in range(0, len(chunk), 4):
            grp = chunk[i:i + 4].ljust(4, " ")
            vals = [(_UU_ALPHABET.find(c) & 0x3F) for c in grp]
            x = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
            data.extend(x.to_bytes(3, "big"))
        out.extend(data[:n])
    return bytes(out) if out else None


# --------------------------------------------------------------------------- #
# 古典密码
# --------------------------------------------------------------------------- #
def _letters_only(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z]{4,}", s.strip()))


def rot_n(s: str, n: int):
    def shift(ch):
        if "a" <= ch <= "z":
            return chr((ord(ch) - 97 + n) % 26 + 97)
        if "A" <= ch <= "Z":
            return chr((ord(ch) - 65 + n) % 26 + 65)
        return ch
    return "".join(shift(c) for c in s)


def rot47(s: str):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)


def atbash(s: str):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", "-----": "0", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-....-": "-", "-..-.": "/", ".-..-.": '"', "---...": ":", "-.-.-": ";",
    ".----.": "'", "-.--.": "(", "-.--.-": ")", "..--.-": "_", ".-.-": "+",
    "-...-": "=", ".-.-.": "+", "-.-.--": "!", ".-..-..": '"',
}


def dec_morse(s: str):
    core = s.strip()
    if not re.fullmatch(r"[.\-\s/_|]*", core) or not ("-" in core or "." in core):
        return None
    core = core.replace("|", " ").replace("/", " / ").replace("_", "-")
    words = re.split(r"\s{2,}|/", core.strip())
    out_words = []
    for w in words:
        letters = []
        for tok in w.split():
            letters.append(_MORSE.get(tok, "?"))
        out_words.append("".join(letters))
    out = " ".join(out_words)
    if "?" in out or not out.strip():
        return None
    return out


def dec_bacon(s: str):
    core = re.sub(r"[^A-Za-z01]", "", s).upper()
    if len(core) < 10 or len(core) % 5:
        return None
    if len(core) == len(s.strip()) and not re.fullmatch(r"[01]+", core):
        return None
    table = {}
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 24 字母版（I/J, U/V 合并）
    alpha26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for i in range(32):
        pat = format(i, "05b").replace("0", "A").replace("1", "B")
        table[pat] = alpha26[i]
    out = []
    for i in range(0, len(core), 5):
        chunk = core[i:i + 5]
        if set(chunk) <= {"A", "B"}:
            out.append(table.get(chunk, "?"))
        else:
            bit = "".join("B" if c in "BCDEFGHIJKLMNOPQRSTUVWXYZ" else "A" for c in chunk)
            out.append(table.get(bit, "?"))
    txt = "".join(out)
    return txt if "?" not in txt and txt.isalpha() else None


def dec_a1z26(s: str):
    toks = re.split(r"[^0-9]+", s.strip())
    toks = [t for t in toks if t]
    if len(toks) < 3 or not all(1 <= int(t) <= 26 for t in toks):
        return None
    if not re.fullmatch(r"[\d\s\-.,|]+", s.strip()):
        return None
    return "".join(chr(64 + int(t)) for t in toks)


def dec_polybius(s: str):
    digits = re.sub(r"[^1-5]", "", s)
    if len(digits) < 6 or len(digits) % 2:
        return None
    if not re.fullmatch(r"[\s1-5,;|/]+", s.strip()):
        return None
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    out = []
    for i in range(0, len(digits), 2):
        r, c = int(digits[i]) - 1, int(digits[i + 1]) - 1
        out.append(square[r * 5 + c])
    return "".join(out)


_VIG_KEYS = ["flag", "ctf", "key", "keys", "cipher", "secret", "password", "abcd",
             "abc", "love", "misc", "hello", "pass", "admin", "buuctf", "hint"]


def _vigenere_dec(s: str, key: str):
    out = []
    ki = 0
    for ch in s:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            k = ord(key[ki % len(key)].lower()) - 97
            out.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def dec_vigenere_knownkeys(s: str) -> str | None:
    if len(s) < 8:
        return None
    results = [_vigenere_dec(s, k) for k in _VIG_KEYS]
    best = max(results, key=text_score)
    return best if text_score(best) > 20 else None


def dec_rail_fence(s: str) -> str | None:
    if len(s) < 10 or not re.fullmatch(r"[A-Za-z0-9_{}\-!?.,]+", s.strip()):
        return None
    best, best_score = None, -1e9
    for rails in range(2, 9):
        try:
            out = _rail_dec(s, rails)
        except Exception:
            continue
        sc = text_score(out)
        if sc > best_score:
            best, best_score = out, sc
    return best if best_score > 25 else None


def _rail_dec(cipher: str, rails: int) -> str:
    n = len(cipher)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows = [[] for _ in range(rails)]
    idx = 0
    for i in range(n):
        rows[pattern[i % len(pattern)]].append(i)
    out = [""] * n
    pos = 0
    for r in range(rails):
        for i in rows[r]:
            out[i] = cipher[pos]
            pos += 1
    return "".join(out)


def dec_affine_brute(s: str) -> str | None:
    if not _letters_only(s) or len(s) < 6:
        return None
    best, best_score = None, -1e9
    for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        inv = pow(a, -1, 26)
        for b in range(26):
            out = []
            for ch in s:
                if ch.isalpha():
                    low = ch.islower()
                    x = ord(ch.lower()) - 97
                    y = (inv * (x - b)) % 26
                    out.append(chr(y + (97 if low else 65)))
                else:
                    out.append(ch)
            cand = "".join(out)
            sc = text_score(cand)
            if sc > best_score:
                best, best_score = cand, sc
    return best if best_score > 25 else None


def dec_columnar_brute(s: str) -> str | None:
    core = s.strip()
    if len(core) < 12 or len(core) > 400 or not re.fullmatch(r"[A-Za-z]+", core):
        return None
    best, best_score = None, -1e9
    for width in range(2, 7):
        if len(core) % width:
            continue
        for perm in itertools.permutations(range(width)):
            try:
                out = _columnar_dec(core, width, perm)
            except Exception:
                continue
            sc = text_score(out)
            if sc > best_score:
                best, best_score = out, sc
    return best if best_score > 30 else None


def _columnar_dec(cipher: str, width: int, perm: tuple[int, ...]) -> str:
    n = len(cipher)
    rows = n // width
    cols = {}
    pos = 0
    for j in perm:
        cols[j] = cipher[pos:pos + rows]
        pos += rows
    return "".join(cols[j][i] for i in range(rows) for j in range(width))


def dec_qwerty_shift(s: str) -> str | None:
    if not s.strip():
        return None
    keyboard = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"
    shifted = "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./`"
    table = str.maketrans(keyboard + keyboard.upper(), shifted + shifted.upper())
    out = s.translate(table)
    return out if out != s else None


def dec_reverse(s: str):
    out = s[::-1]
    return out if out != s else None


# --------------------------------------------------------------------------- #
# 注册表
# --------------------------------------------------------------------------- #
TRANSFORMS: list[T] = [
    T("Base64 解码", dec_b64, "编码"),
    T("Base64(URL) 解码", dec_b64_url, "编码"),
    T("Base32 解码", dec_b32, "编码"),
    T("Base32hex 解码", dec_b32hex, "编码"),
    T("Hex 解码", dec_hex, "编码"),
    T("Hexdump 还原", dec_hexdump, "编码"),
    T("Base85 解码", dec_b85, "编码"),
    T("Ascii85 解码", dec_a85, "编码"),
    T("Base58 解码", dec_b58, "编码"),
    T("Base91 解码", dec_b91, "编码"),
    T("URL 解码", dec_url, "编码"),
    T("URL 二次解码", dec_url2, "编码"),
    T("HTML 实体解码", dec_html, "编码"),
    T("Unicode 转义解码", dec_unicode_escape, "编码"),
    T("%uXXXX 解码", dec_percent_u, "编码"),
    T("Quoted-Printable 解码", dec_quoted_printable, "编码"),
    T("二进制(8bit)转字节", dec_binary, "编码"),
    T("二进制(7bit)转字节", dec_binary7, "编码"),
    T("八进制转字节", dec_octal, "编码"),
    T("十进制/点分十进制转字节", dec_decimal, "编码"),
    T("DNA 编码解码", dec_dna, "编码"),
    T("Base64→zlib 解压", dec_zlib, "编码"),
    T("Base64→gzip 解压", dec_gzip_b64, "编码"),
    T("UUencode 解码", dec_uu, "编码"),
    T("ROT13 (凯撒 13)", lambda s: rot_n(s, 13), "古典密码", True),
    T("ROT47", rot47, "古典密码", True),
    T("凯撒暴力枚举", lambda s: _best_caesar(s), "古典密码", True),
    T("Atbash 反转字母表", atbash, "古典密码", True),
    T("摩斯电码解码", dec_morse, "古典密码"),
    T("培根密码解码", dec_bacon, "古典密码"),
    T("A1Z26 解码", dec_a1z26, "古典密码"),
    T("Polybius 方阵解码", dec_polybius, "古典密码"),
    T("维吉尼亚(常见密钥)", dec_vigenere_knownkeys, "古典密码", True),
    T("栅栏密码暴力", dec_rail_fence, "古典密码", True),
    T("仿射密码暴力", dec_affine_brute, "古典密码", True),
    T("列置换暴力", dec_columnar_brute, "古典密码", True),
    T("键盘错位还原", dec_qwerty_shift, "古典密码", True),
    T("字符串反转", dec_reverse, "杂项", True),
]


def _best_caesar(s: str) -> str | None:
    if len(s) < 6 or not re.search(r"[A-Za-z]{4,}", s):
        return None
    cands = [rot_n(s, i) for i in range(1, 26)]
    best = max(cands, key=text_score)
    return best if text_score(best) > 20 else None


def transform_names() -> list[str]:
    return [t.name for t in TRANSFORMS]


def is_speculative(name: str) -> bool:
    for t in TRANSFORMS:
        if t.name == name:
            return t.spec
    return False


def apply_named(name: str, text: str) -> bytes | str | None:
    for t in TRANSFORMS:
        if t.name == name:
            return t.fn(text)
    return None


def manual_decode(text: str) -> list[tuple[str, str, float]]:
    """对所有解码器跑一遍，返回 (名称, 结果, 分数) 列表。"""
    out = []
    for t in TRANSFORMS:
        try:
            res = t.fn(text)
        except Exception:
            res = None
        if res is None:
            continue
        if isinstance(res, bytes):
            if len(res) > 4000:
                continue
            s = to_text(res)
        else:
            s = res
        if not s or s.strip() == text.strip():
            continue
        out.append((t.name, s, text_score(s)))
    out.sort(key=lambda x: -x[2])
    return out


def auto_decode(chain: list[str], value: str, text: str, *,
                max_depth: int = 6, beam: int = 10, deadline: float | None = None,
                results: list[DecodeResult] | None = None) -> list[DecodeResult]:
    """Beam search 多层自动解码，返回按分数排序的结果链。"""
    if results is None:
        results = []
    if deadline is None:
        deadline = time.time() + 25
    frontier = [(chain, value, text_score(value))]
    visited = {value.strip()[:400]}
    for _depth in range(max_depth):
        if time.time() > deadline:
            break
        nxt: list[tuple[list[str], str, float]] = []
        for ch, val, sc in frontier:
            for t in TRANSFORMS:
                if time.time() > deadline:
                    break
                try:
                    res = t.fn(val)
                except Exception:
                    continue
                if res is None:
                    continue
                if isinstance(res, bytes):
                    if len(res) > 20000:
                        continue
                    info = filetypes.identify(res)
                    if info.confident and info.ext not in ("txt", "bin"):
                        results.append(DecodeResult(ch + [t.name], f"[识别为 {info.desc}，{len(res)} 字节]",
                                                    res, 200.0, []))
                        continue
                    s = to_text(res)
                else:
                    s = res
                s = s.strip()
                if not s or s == val.strip() or s[:400] in visited:
                    continue
                visited.add(s[:400])
                sc2 = text_score(s)
                nxt.append((ch + [t.name], s, sc2))
                fl = [h.value for h in find_flags(s)[:3]]
                if fl:
                    results.append(DecodeResult(ch + [t.name], s[:2000], s.encode("utf-8", "ignore"), sc2, fl))
        if not nxt:
            break
        nxt.sort(key=lambda x: -x[2])
        frontier = nxt[:beam]
        for ch, val, sc in frontier:
            if sc > 35:
                results.append(DecodeResult(ch, val[:2000], val.encode("utf-8", "ignore"), sc,
                                            [h.value for h in find_flags(val)[:3]]))
    results.sort(key=lambda r: (-r.score, len(r.chain)))
    return results[:40]


def best_caesar_variants(s: str) -> list[tuple[int, str]]:
    return [(i, rot_n(s, i)) for i in range(26)]


def decode_image_bytes_to_text(data: bytes) -> str:
    """把字节尽力转成可读文本（用于预览）。"""
    return to_text(data)


def b64encode_text(text: str) -> str:
    return base64.b64encode(text.encode("utf-8", "ignore")).decode()


def hexdump(data: bytes, width: int = 16) -> str:
    out = io.StringIO()
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.write(f"{off:08x}  {hexs}  |{asci}|\n")
    return out.getvalue()
