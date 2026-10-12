"""扩展密码学：XOR 爆破、维吉尼亚/替换密码自动破解、古典密码、AES/DES、JWT、RSA 攻击。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import math
import re
import string
from collections import Counter

# --------------------------------------------------------------------------- #
# 英文评分（用于自动破解的“择优”）
# --------------------------------------------------------------------------- #
EN_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23, "g": 2.02,
    "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75,
    "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06, "u": 2.76,
    "v": 0.98, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07, " ": 18.0,
}
COMMON_WORDS = ("the", "and", "that", "have", "for", "not", "with", "you", "this", "but",
                "his", "from", "they", "flag", "ctf", "key", "are", "was", "all", "one")


def english_score(text: str) -> float:
    """越高越像英文/有意义文本。"""
    if not text:
        return -1e9
    total = 0.0
    for ch in text:
        lc = ch.lower()
        if lc in _LOG_FREQ:
            total += _LOG_FREQ[lc]
        elif ch in _SYMBOLS:
            total += -3.2
        elif ch == "\n":
            total += -1.0
        elif ch == "\t":
            total += -2.0
        elif ch == "\r":
            total += -4.5
        elif 32 <= ord(ch) < 127:
            total += -3.9
        else:
            total += -6.5
    score = total / len(text) * 10
    low = text.lower()
    for w in COMMON_WORDS:
        score += low.count(w) * 1.5
    if len(text) >= 20:
        spaces = text.count(" ") / len(text)
        if spaces < 0.02:
            score -= 14          # 英文句子一定有空格，编码/密文没有
        elif 0.05 <= spaces <= 0.25:
            score += 8
    return score


_LOG_FREQ = {c: math.log(f / 100.0) for c, f in EN_FREQ.items()}
_SYMBOLS = set("{}_!@#$%^&*()-+=[]:;,.?/|0123456789")


def looks_textful(data: bytes) -> bool:
    if not data:
        return False
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data) > 0.85


# --------------------------------------------------------------------------- #
# XOR
# --------------------------------------------------------------------------- #
def xor_single_byte(data: bytes, topn: int = 8) -> list[tuple[int, float, bytes]]:
    out = []
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        out.append((key, english_score(dec.decode("latin-1")), dec))
    out.sort(key=lambda x: -x[1])
    return out[:topn]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_repeating(data: bytes, max_keylen: int = 24, topn: int = 5) -> list[tuple[bytes, float, bytes]]:
    """按汉明距离猜密钥长度，再逐列做单字节爆破（经典 repeating-key XOR 破解）。"""
    if len(data) < 8:
        return []

    def col_score(column: bytes, k: int) -> float:
        """逐列评分：只看字符频率对数似然，不做空格/长度惩罚（稀疏列适用）。"""
        total = 0.0
        for b in column:
            c = b ^ k
            if 97 <= c <= 122:
                total += _LOG_FREQ[chr(c)]
            elif 65 <= c <= 90:
                total += _LOG_FREQ[chr(c + 32)] - 0.5
            elif c == 32:
                total += _LOG_FREQ[" "]
            elif 48 <= c <= 57:
                total += -3.0
            elif 32 <= c < 127:
                total += -3.9
            else:
                total += -7.0
        return total / max(len(column), 1)

    best_lens: list[tuple[float, int]] = []
    for klen in range(2, min(max_keylen, len(data) // 4) + 1):
        chunks = [data[i:i + klen] for i in range(0, min(len(data), klen * 8), klen)]
        chunks = [c for c in chunks if len(c) == klen][:8]
        if len(chunks) < 2:
            continue
        dists = [_hamming(chunks[i], chunks[j]) / klen
                 for i in range(len(chunks)) for j in range(i + 1, len(chunks))]
        if dists:
            best_lens.append((sum(dists) / len(dists), klen))
    best_lens.sort()
    results = []
    for _norm, klen in best_lens[:6]:
        key = bytearray()
        for col in range(klen):
            column = data[col::klen]
            best = max(range(256), key=lambda k: col_score(column, k))
            key.append(best)
        key_b = bytes(key)
        dec = bytes(b ^ key_b[i % klen] for i, b in enumerate(data))
        results.append((key_b, english_score(dec.decode("latin-1")), dec))
    results.sort(key=lambda x: -x[1])
    # 去重
    seen, uniq = set(), []
    for key, sc, dec in results:
        if key in seen:
            continue
        seen.add(key)
        uniq.append((key, sc, dec))
    return uniq[:topn]


def xor_fixed_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_guess_key_from_known(data: bytes, known_prefix: bytes = b"flag{") -> bytes | None:
    """已知明文开头（默认 flag{）时直接推出密钥。"""
    if len(data) < len(known_prefix):
        return None
    return bytes(a ^ b for a, b in zip(data[:len(known_prefix)], known_prefix))


def xor_known_plaintext_attack(data: bytes, guesses: tuple[bytes, ...] = (b"flag{", b"ctf{", b"FLAG{")) -> list[tuple[bytes, bytes]]:
    """已知明文攻击：假定明文某处是 flag{ 之类的固定串，反推密钥并验证。

    这是 CTF 里 XOR 题最快的一招（明文里几乎一定有 flag{）。
    """
    import math
    scores = _LOG_FREQ

    def quick(col: bytes, k: int) -> float:
        """轻量评分：只按字符频率对数似然，避免逐列 256 次重算整段文本。"""
        total = 0.0
        for b in col:
            c = b ^ k
            if 97 <= c <= 122:
                total += scores[chr(c)]
            elif 65 <= c <= 90:
                total += scores[chr(c + 32)] - 0.6
            elif c == 32:
                total += scores[" "]
            elif 32 <= c < 127:
                total += -3.9
            else:
                total += -6.5
        return total

    results: list[tuple[bytes, bytes]] = []
    max_klen = max(1, min(40, len(data) // 2))
    for klen in range(1, max_klen + 1):
        col_keys = []
        for col in range(klen):
            column = data[col::klen]
            best_k, best_sc = 0, -1e9
            for k in range(256):
                sc = quick(column, k)
                if sc > best_sc:
                    best_k, best_sc = k, sc
            col_keys.append(best_k)
        for guess in guesses:
            n = len(guess)
            for start in range(0, max(len(data) - n + 1, 0)):
                key: list[int | None] = [None] * klen
                ok = True
                for j, ch in enumerate(guess):
                    pos = (start + j) % klen
                    v = data[start + j] ^ ch
                    if key[pos] is None:
                        key[pos] = v
                    elif key[pos] != v:
                        ok = False
                        break
                if not ok:
                    continue
                filled = bytearray(key[c] if key[c] is not None else col_keys[c] for c in range(klen))
                dec = xor_fixed_key(data, bytes(filled))
                dec_text = dec.decode("latin-1")
                printable = sum(1 for c in dec_text if 32 <= ord(c) < 127 or c in "\r\n\t") / max(len(dec_text), 1)
                sc = english_score(dec_text)
                if (printable > 0.97 and klen <= 3 * len(guess)
                        and (b"flag{" in dec.lower() or (sc > -13 and b"{" in dec))):
                    results.append((bytes(filled), dec))
                    # 明文质量足够好时就可以收工了
                    if b"flag{" in dec.lower() and sc > -13.5:
                        results.sort(key=lambda kv: (len(kv[0]), -english_score(kv[1].decode("latin-1"))))
                        return results[:5]
    seen, uniq = set(), []
    for key, dec in results:
        if key in seen:
            continue
        seen.add(key)
        uniq.append((key, dec))
    uniq.sort(key=lambda kv: (b"flag{" not in kv[1].lower(),
                              len(kv[0]), -english_score(kv[1].decode("latin-1"))))
    return uniq[:5]


def vigenere_known_plaintext_attack(text: str, guesses: tuple[str, ...] = ("flag{", "ctf{", "FLAG{")) -> list[tuple[str, str]]:
    """同上的维吉尼亚版本：假定明文里出现 flag{ 等固定串，反推密钥。"""
    letters = [(i, c.lower()) for i, c in enumerate(text) if c.isalpha()]
    if len(letters) < 6:
        return []
    indices = [i for i, _c in letters]
    flat = "".join(c for _i, c in letters)
    results = []
    for klen in range(1, 25):
        for guess in guesses:
            g = "".join(c for c in guess.lower() if c.isalpha())
            if len(g) < 4:
                continue
            for start in range(0, len(flat) - len(g) + 1):
                key: list[str | None] = [None] * klen
                ok = True
                for j, ch in enumerate(g):
                    pos = (start + j) % klen
                    k = chr((ord(flat[start + j]) - ord(ch)) % 26 + 97)
                    if key[pos] is None:
                        key[pos] = k
                    elif key[pos] != k:
                        ok = False
                        break
                if not ok:
                    continue
                for col in range(klen):
                    if key[col] is None:
                        column = flat[col::klen]
                        best, best_sc = "a", -1e9
                        for s in range(26):
                            shifted = "".join(chr((ord(c) - 97 - s) % 26 + 97) for c in column)
                            sc = english_score(shifted)
                            if sc > best_sc:
                                best, best_sc = chr(s + 97), sc
                        key[col] = best
                key_str = "".join(k or "a" for k in key)
                plain = _vigenere_dec(text, key_str)
                if "{" in plain and english_score(plain) > -20:
                    results.append((key_str, plain))
    seen, uniq = set(), []
    for key, plain in results:
        if key in seen:
            continue
        seen.add(key)
        uniq.append((key, plain))
    uniq.sort(key=lambda kp: -english_score(kp[1]))
    return uniq[:5]


# --------------------------------------------------------------------------- #
# 维吉尼亚
# --------------------------------------------------------------------------- #
def _index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def vigenere_crack(text: str, max_keylen: int = 20) -> list[tuple[str, float, str]]:
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return []
    candidates: list[tuple[str, float, str]] = []
    for klen in range(1, max_keylen + 1):
        ics = []
        for col in range(klen):
            column = "".join(letters[col::klen])
            ics.append(_index_of_coincidence(column))
        avg_ic = sum(ics) / len(ics) if ics else 0
        if klen > 1 and avg_ic < 0.055:
            continue
        key = []
        for col in range(klen):
            column = "".join(letters[col::klen])
            best_shift, best_score = 0, -1e9
            for shift in range(26):
                shifted = "".join(chr((ord(c.lower()) - 97 - shift) % 26 + 97) for c in column)
                sc = english_score(shifted)
                if sc > best_score:
                    best_shift, best_score = shift, sc
            key.append(chr(best_shift + 97))
        key_str = "".join(key)
        plain = _vigenere_dec(text, key_str)
        candidates.append((key_str, english_score(plain), plain))
    # 常见密钥兜底
    for k in ("flag", "ctf", "key", "cipher", "secret", "password", "misc", "hint", "vigenere"):
        plain = _vigenere_dec(text, k)
        candidates.append((k, english_score(plain), plain))
    candidates.sort(key=lambda x: -x[1])
    seen, uniq = set(), []
    for key, sc, plain in candidates:
        if key in seen:
            continue
        seen.add(key)
        uniq.append((key, sc, plain))
    return uniq[:8]


def _vigenere_dec(text: str, key: str) -> str:
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            k = ord(key[ki % len(key)].lower()) - 97
            out.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# 单表替换（频率 + 爬山法）
# --------------------------------------------------------------------------- #
_BIGRAMS = None


def _bigram_table() -> dict[str, float]:
    global _BIGRAMS
    if _BIGRAMS is None:
        # 常用英文双字母组合（近似，够爬山法收敛）
        common = ("th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
                  "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
                  "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
                  "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
                  "om", "ur")
        _BIGRAMS = {bg: 1.0 for bg in common}
    return _BIGRAMS


def substitution_crack(text: str, iterations: int = 4000, restarts: int = 6) -> list[tuple[str, float, str]]:
    """对单表替换密码做爬山法自动求解（需要较长文本）。"""
    import random
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 40:
        return []
    cipher = "".join(letters)
    bigrams = _bigram_table()

    def score(mapping: dict[str, str]) -> float:
        dec = "".join(mapping.get(c, c) for c in cipher)
        sc = english_score(dec) * 0.5
        sc += sum(2.5 for i in range(len(dec) - 1) if dec[i:i + 2] in bigrams)
        for w in COMMON_WORDS:
            sc += dec.count(w) * 8
        return sc

    alpha = string.ascii_lowercase
    results = []
    for _ in range(restarts):
        perm = list(alpha)
        random.shuffle(perm)
        mapping = dict(zip(alpha, perm))
        cur = score(mapping)
        for _ in range(iterations):
            a, b = random.sample(alpha, 2)
            mapping[a], mapping[b] = mapping[b], mapping[a]
            new = score(mapping)
            if new >= cur:
                cur = new
            else:
                mapping[a], mapping[b] = mapping[b], mapping[a]
        plain = "".join(mapping.get(c, c) for c in cipher)
        results.append((plain, cur, "".join(mapping[c] for c in alpha)))
    results.sort(key=lambda x: -x[1])
    return results[:3]


# --------------------------------------------------------------------------- #
# Playfair / Hill / 其它古典
# --------------------------------------------------------------------------- #
def _playfair_square(key: str) -> list[str]:
    seen, out = set(), []
    for ch in re.sub(r"[^a-z]", "", key.lower()).replace("j", "i") + string.ascii_lowercase.replace("j", ""):
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return out


def playfair_decode(text: str, key: str) -> str:
    sq = _playfair_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(sq)}
    pairs = re.sub(r"[^a-z]", "", text.lower().replace("j", "i"))
    if len(pairs) % 2:
        pairs += "x"
    out = []
    for i in range(0, len(pairs), 2):
        a, b = pairs[i], pairs[i + 1]
        if a not in pos or b not in pos:
            continue
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(sq[ra * 5 + (ca - 1) % 5] + sq[rb * 5 + (cb - 1) % 5])
        elif ca == cb:
            out.append(sq[((ra - 1) % 5) * 5 + ca] + sq[((rb - 1) % 5) * 5 + cb])
        else:
            out.append(sq[ra * 5 + cb] + sq[rb * 5 + ca])
    return "".join(out)


_COMMON_KEYS = ["flag", "ctf", "key", "playfair", "password", "secret", "cipher", "monarchy",
                "security", "algorithm", "misc", "hint", "hello", "abc", "test"]


def playfair_crack(text: str) -> list[tuple[str, float, str]]:
    out = []
    for key in _COMMON_KEYS:
        dec = playfair_decode(text, key)
        out.append((key, english_score(dec), dec))
    out.sort(key=lambda x: -x[1])
    return out[:5]


def _mod_inv(a: int, m: int = 26) -> int | None:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def hill_known_plaintext(pairs: list[tuple[str, str]], size: int = 2) -> list[list[int]] | None:
    """已知明文/密文对求解 Hill 密钥矩阵（pairs 为 (明文, 密文) 字母串）。"""
    import numpy as np
    if len(pairs) < size:
        return None
    P = np.array([[ord(c) - 97 for c in pairs[i][0][:size]] for i in range(size)], dtype=object)
    C = np.array([[ord(c) - 97 for c in pairs[i][1][:size]] for i in range(size)], dtype=object)
    det = int(round(np.linalg.det(P.astype(float)))) % 26
    inv = _mod_inv(det)
    if inv is None:
        return None
    # 伴随矩阵法求逆（mod 26）
    import numpy as np2
    adj = np2.round(np.linalg.inv(P.astype(float)) * np.linalg.det(P.astype(float))).astype(int) % 26
    Pinv = (inv * adj) % 26
    K = (Pinv @ C) % 26
    return [[int(v) for v in row] for row in K.tolist()]


def hill_decrypt(text: str, key_matrix: list[list[int]], size: int = 2) -> str:
    nums = [ord(c) - 97 for c in re.sub(r"[^a-z]", "", text.lower())]
    out = []
    for i in range(0, len(nums) - size + 1, size):
        block = nums[i:i + size]
        vals = [sum(key_matrix[r][c] * block[c] for c in range(size)) % 26 for r in range(size)]
        out.extend(chr(v + 97) for v in vals)
    return "".join(out)


# --------------------------------------------------------------------------- #
# 对称加密（AES / DES / 3DES）
# --------------------------------------------------------------------------- #
def symmetric_decrypt(data: bytes, key: bytes, iv: bytes | None = None,
                      algos: tuple[str, ...] = ("AES", "DES", "3DES"),
                      modes: tuple[str, ...] = ("ECB", "CBC")) -> list[tuple[str, bytes]]:
    """用给定 key/iv 试各种算法与模式（常见于“给了密钥的对称加密”题）。"""
    from Crypto.Cipher import AES, DES, DES3
    out: list[tuple[str, bytes]] = []
    mapping = {"AES": AES, "DES": DES, "3DES": DES3}
    for name in algos:
        mod = mapping.get(name)
        if mod is None:
            continue
        needed = {"AES": (16, 24, 32), "DES": (8,), "3DES": (16, 24)}[name]
        k = key
        if len(k) not in needed:
            if name == "AES":
                k = hashlib.md5(key).digest()          # 常见：key 取 md5
            elif name == "DES":
                k = (key + b"\x00" * 8)[:8]
            else:
                k = (key + b"\x00" * 24)[:24]
        for mode_name in modes:
            try:
                if mode_name == "ECB":
                    cipher = mod.new(k, mod.MODE_ECB)
                else:
                    iv_b = iv or b"\x00" * (16 if name == "AES" else 8)
                    iv_b = (iv_b + b"\x00" * 16)[:16 if name == "AES" else 8]
                    cipher = mod.new(k, mod.MODE_CBC, iv_b)
                dec = cipher.decrypt(data)
                # 尝试去 PKCS7 填充
                if dec and 1 <= dec[-1] <= 16 and dec.endswith(bytes([dec[-1]]) * dec[-1]):
                    dec = dec[:-dec[-1]]
                out.append((f"{name}-{mode_name}", dec))
            except Exception:
                continue
    return out


def guess_bytes(value: str) -> bytes:
    """把题目里给的 key/iv 文本转成字节（支持 hex / base64 / 原文）。"""
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) % 2 == 0 and len(value) >= 8:
        return bytes.fromhex(value)
    try:
        if re.fullmatch(r"[A-Za-z0-9+/=]+", value) and len(value) % 4 == 0:
            return base64.b64decode(value)
    except Exception:
        pass
    return value.encode("utf-8", "ignore")


# --------------------------------------------------------------------------- #
# RC4 / TEA / XXTEA（杂项里常给的“自写加密”）
# --------------------------------------------------------------------------- #
def rc4(data: bytes, key: bytes) -> bytes:
    """RC4 加解密（对称，同一个函数）。"""
    S = list(range(256))
    j = 0
    klen = max(len(key), 1)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rc4_variants(data: bytes, key: bytes) -> list[tuple[str, bytes]]:
    """RC4 常见变体：标准、key 可能是 hex/base64、密文可能是 hex/base64。"""
    out = [("RC4 标准", rc4(data, key))]
    for name, enc in (("RC4(丢弃前256字节)", rc4(b"\x00" * 256 + data, key)[256:]),
                      ("RC4(丢弃前768字节)", rc4(b"\x00" * 768 + data, key)[768:])):
        out.append((name, enc))
    return out


def _tea_encrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    delta = 0x9E3779B9
    s = 0
    for _ in range(32):
        s = (s + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
    return v0, v1


def _tea_decrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    delta = 0x9E3779B9
    s = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return v0, v1


def _key_ints(key: bytes) -> list[int]:
    key = (key + b"\x00" * 16)[:16]
    return [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]


def tea_decrypt(data: bytes, key: bytes, rounds_note: str = "标准 TEA / 大端") -> bytes:
    """标准 TEA 解密（8 字节一块，大端）。"""
    k = _key_ints(key)
    out = bytearray()
    for i in range(0, len(data) - 7, 8):
        v0 = int.from_bytes(data[i:i + 4], "big")
        v1 = int.from_bytes(data[i + 4:i + 8], "big")
        a, b = _tea_decrypt_block(v0, v1, k)
        out += a.to_bytes(4, "big") + b.to_bytes(4, "big")
    return bytes(out)


def tea_encrypt(data: bytes, key: bytes) -> bytes:
    k = _key_ints(key)
    data = data + b"\x00" * (-len(data) % 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        v0 = int.from_bytes(data[i:i + 4], "big")
        v1 = int.from_bytes(data[i + 4:i + 8], "big")
        a, b = _tea_encrypt_block(v0, v1, k)
        out += a.to_bytes(4, "big") + b.to_bytes(4, "big")
    return bytes(out)


def xtea_decrypt(data: bytes, key: bytes) -> bytes:
    """XTEA 解密。"""
    delta = 0x9E3779B9
    k = [int.from_bytes(((key + b"\x00" * 16)[:16])[i:i + 4], "big") for i in range(0, 16, 4)]
    out = bytearray()
    for i in range(0, len(data) - 7, 8):
        v0 = int.from_bytes(data[i:i + 4], "big")
        v1 = int.from_bytes(data[i + 4:i + 8], "big")
        s = (delta * 32) & 0xFFFFFFFF
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
            s = (s - delta) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
        out += v0.to_bytes(4, "big") + v1.to_bytes(4, "big")
    return bytes(out)


def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    """XXTEA 解密（32 位小端字，key 变长）。"""
    if len(data) < 8 or len(data) % 4:
        return b""
    v = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
    n = len(v)
    k = [int.from_bytes(((key + b"\x00" * 16)[:16])[i:i + 4], "little") for i in range(0, 16, 4)]
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    total = (rounds * delta) & 0xFFFFFFFF

    def mx(y, z, p, e, s):
        return (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF))) ^ \
               ((s ^ y) + (k[(p & 3) ^ e] ^ z))

    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            y = v[(p - 1) % n]
            z = v[p]
            s = total
            v[p] = (v[p] - mx(y, z, p, e, s)) & 0xFFFFFFFF
        y = v[n - 1]
        z = v[0]
        v[0] = (v[0] - mx(y, z, 0, e, total)) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
    raw = b"".join(x.to_bytes(4, "little") for x in v)
    # 去掉常见 0 填充
    return raw.rstrip(b"\x00")


# --------------------------------------------------------------------------- #
# 复合模数上的椭圆曲线（RSA 模数 + ECC 那类题：用“分母不可逆”分解 n）
# --------------------------------------------------------------------------- #
class _NonInvertible(Exception):
    def __init__(self, den: int):
        super().__init__("denominator not invertible")
        self.den = den


def _ec_add(P, Q, a, n):
    """椭圆曲线点加（模 n，n 可以是合数）。返回 (point, 分母) 供 gcd 用。"""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % n == 0:
        return None
    if P == Q:
        den = (2 * y1) % n
        num = (3 * x1 * x1 + a) % n
    else:
        den = (x2 - x1) % n
        num = (y2 - y1) % n
    try:
        inv = pow(den, -1, n)
    except ValueError:
        raise _NonInvertible(den) from None   # 分母与 n 不互素 → 可以分解 n
    lam = num * inv % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)


def ec_factor_n(n: int, a: int, x: int, y: int, steps: int = 4000,
                extra_points: int = 12) -> int | None:
    """在模 n（合数）的椭圆曲线上累加 k·P，遇到分母不可逆就 gcd 出因子。

    n=p*q 时，P 的阶模 p 与模 q 通常不同，累计过程中必然出现一次
    “分母与 n 不互素”，此时 gcd(分母, n) 就是 p 或 q。
    """
    import random
    points = [(x % n, y % n)]
    rnd = random.Random(0xC7F)
    for _ in range(extra_points):
        # 换几个随机点（不要求在曲线上，照样能触发不可逆分母）
        points.append((rnd.randrange(2, n - 1), rnd.randrange(2, n - 1)))
    for px, py in points:
        P = (px, py)
        Q = None
        for _ in range(max(steps // max(len(points), 1), 200)):
            try:
                Q = _ec_add(Q, P, a, n)
            except _NonInvertible as exc:
                g = math.gcd(exc.den, n)
                if 1 < g < n:
                    return g
                break
            if Q is None:
                break
    return None


def ec_make_point(p: int, q: int, a: int, b: int, seed: int = 0) -> tuple[int, int, int]:
    """按题目的方式在 n=p*q 上构造一个点（用于自测/复现）。"""
    n = p * q
    x = seed or 2
    while True:
        y2 = (x ** 3 + a * x + b) % n
        if pow(y2, (p - 1) // 2, p) == 1 and pow(y2, (q - 1) // 2, q) == 1:
            yp = pow(y2, (p + 1) // 4, p)
            yq = pow(y2, (q + 1) // 4, q)
            _, s, t = _egcd(p, q)
            y = (s * p * yq + t * q * yp) % n
            return n, x, y
        x += 1


def ec_composite_solve(n: int, a: int, b: int, x0: int, y0: int,
                       cipher: list[int], p: int | None = None,
                       q: int | None = None) -> tuple[bytes, int, int] | None:
    """解“RSA 模数上的椭圆曲线”加密：分解 n → 用 CRT 算每轮倍点 → 异或还原明文。

    加密（见 WZBC 2025 Crypto-Curve）：
        G = G + G;  c += [G.x ^ block, G.y ^ block]
    """
    if not (p and q):
        p = ec_factor_n(n, a, x0, y0)
        if not p:
            return None
        q = n // p
    if p * q != n:
        return None

    def double_mod(m: int, P):
        """在模 m 下做倍点（m 是素数，除法一定可逆）。"""
        if P is None:
            return None
        x1, y1 = P
        if y1 % m == 0:
            return None
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, m) % m
        x3 = (lam * lam - 2 * x1) % m
        y3 = (lam * (x1 - x3) - y1) % m
        return (x3, y3)

    Gp = (x0 % p, y0 % p)
    Gq = (x0 % q, y0 % q)
    out = bytearray()
    for i in range(0, len(cipher) - 1, 2):
        Gp = double_mod(p, Gp)
        Gq = double_mod(q, Gq)
        if Gp is None or Gq is None:
            break
        # CRT 合并出 mod n 的坐标
        xp, yp = Gp
        xq, yq = Gq
        qinv = pow(q, -1, p)
        pinv = pow(p, -1, q)
        x = (xp * q * qinv + xq * p * pinv) % n
        y = (yp * q * qinv + yq * p * pinv) % n
        for coord, cval in ((x, cipher[i]), (y, cipher[i + 1])):
            val = coord ^ cval
            size = max(1, (cval.bit_length() + 7) // 8)
            out += val.to_bytes(size, "big").lstrip(b"\x00") or b""
    return bytes(out), p, q
# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def jwt_crack_hs256(token: str, wordlist: list[str]) -> str | None:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    signing_input = (parts[0] + "." + parts[1]).encode()
    try:
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except Exception:
        return None
    for word in wordlist:
        if hmac.new(word.encode(), signing_input, hashlib.sha256).digest() == sig:
            return word
    return None


COMMON_JWT_KEYS = [
    "secret", "password", "123456", "admin", "key", "jwt", "token", "changeme",
    "your-256-bit-secret", "secretkey", "flask", "node", "secret123", "test", "root",
    "flag", "ctf", "jwtsecret", "supersecret", "passw0rd", "12345678", "abcdefg",
]


# --------------------------------------------------------------------------- #
# RSA 攻击
# --------------------------------------------------------------------------- #
def _iroot(x: int, n: int) -> int:
    if x < 0:
        return 0
    if x == 0:
        return 0
    hi = 1 << ((x.bit_length() // n) + 2)
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def int_to_text(m: int) -> str:
    if m <= 0:
        return ""
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def rsa_small_e(n: int, e: int, c: int, maxk: int = 200) -> str | None:
    m = _iroot(c, e)
    if m and pow(m, e) == c:
        return int_to_text(m)
    for k in range(1, maxk):
        m = _iroot(c + k * n, e)
        if m and pow(m, e, n) == c % n:
            return int_to_text(m)
    return None


def rsa_fermat(n: int, limit: int = 2_000_000) -> tuple[int, int] | None:
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def rsa_pollard(n: int, limit: int = 1_000_000) -> int | None:
    if n % 2 == 0:
        return 2
    x = y = 2
    d = 1
    for i in range(1, limit):
        x = (x * x + 1) % n
        y = (y * y + 1) % n
        y = (y * y + 1) % n
        d = math.gcd(abs(x - y), n)
        if 1 < d < n:
            return d
        if d == n:
            return None
    return None


def rsa_wiener(n: int, e: int) -> int | None:
    """Wiener 攻击：私钥 d 很小时可直接恢复。"""
    def cont_frac(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b

    def convergents(cf):
        n0, d0, n1, d1 = 0, 1, 1, 0
        for q in cf:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n1, d1

    for k, d in convergents(cont_frac(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = math.isqrt(disc)
        if t * t == disc and (s + t) % 2 == 0:
            return d
    return None


def rsa_common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> str | None:
    g, a, b = _egcd(e1, e2)
    if g != 1:
        return None
    # m = c1^a * c2^b mod n
    def pow_signed(base: int, exp: int) -> int:
        if exp < 0:
            return pow(_modinv(base, n), -exp, n)
        return pow(base, exp, n)
    try:
        m = (pow_signed(c1, a) * pow_signed(c2, b)) % n
    except Exception:
        return None
    return int_to_text(m)


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def rsa_from_phi(n: int, e: int, c: int, phi: int) -> str | None:
    try:
        d = _modinv(e, phi)
        return int_to_text(pow(c, d, n))
    except Exception:
        return None


def rsa_attack_all(n: int, e: int, c: int, extra: dict | None = None) -> list[tuple[str, str]]:
    """把常见 RSA 弱参数攻击一次跑完。"""
    out: list[tuple[str, str]] = []
    extra = extra or {}
    if isinstance(extra.get("phi"), int):
        r = rsa_from_phi(n, e, c, extra["phi"])
        if r:
            out.append(("已知 phi", r))
    for name, key in (("p", "p"), ("q", "q")):
        if isinstance(extra.get(key), int) and extra.get(key) > 1:
            p = extra["p"]
            q = extra.get("q") or n // p
            if p * q == n:
                r = rsa_from_phi(n, e, c, (p - 1) * (q - 1))
                if r:
                    out.append((f"已知 {key} 因子", r))
                break
    r = rsa_small_e(n, e, c)
    if r:
        out.append(("小指数直接开方", r))
    f = rsa_fermat(n)
    if f and f[0] > 1:
        r = rsa_from_phi(n, e, c, (f[0] - 1) * (f[1] - 1))
        if r:
            out.append(("费马分解（p、q 接近）", r))
    p = rsa_pollard(n)
    if p and 1 < p < n and n % p == 0:
        q = n // p
        r = rsa_from_phi(n, e, c, (p - 1) * (q - 1))
        if r:
            out.append(("Pollard rho 分解", r))
    if extra.get("n2") and extra.get("e2") and extra.get("c2"):
        r = rsa_common_modulus(n, e, c, extra["e2"], extra["c2"])
        if r:
            out.append(("共模攻击", r))
    d = rsa_wiener(n, e)
    if d:
        r = int_to_text(pow(c, d, n))
        if r:
            out.append(("Wiener 攻击（d 过小）", r))
    return out
