"""其他常见 Misc 技法：二维码、脑洞语言、JWT、哈希、RSA 基础攻击。"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import re

from .flags import find_flags


# --------------------------------------------------------------------------- #
# 二维码
# --------------------------------------------------------------------------- #
def qr_decode(data: bytes) -> list[str]:
    """识别图片中的二维码（支持多码、缩放增强、反色）。"""
    results: list[str] = []
    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return results
        detector = cv2.QRCodeDetector()
        variants = [("原图", img)]
        h, w = img.shape[:2]
        if max(h, w) < 1200:
            variants.append(("放大 3x", cv2.resize(img, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC)))
        variants.append(("反色", 255 - img))
        variants.append(("旋转90", cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)))
        variants.append(("旋转180", cv2.rotate(img, cv2.ROTATE_180)))
        variants.append(("旋转270", cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)))
        variants.append(("左右镜像", cv2.flip(img, 1)))
        variants.append(("上下镜像", cv2.flip(img, 0)))
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        variants.append(("二值化", cv2.cvtColor(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
                                              cv2.COLOR_GRAY2BGR)))
        if max(h, w) < 900:
            big = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
            g2 = cv2.cvtColor(big, cv2.COLOR_BGR2GRAY)
            variants.append(("放大+二值化", cv2.cvtColor(
                cv2.threshold(g2, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1], cv2.COLOR_GRAY2BGR)))
        for _label, im in variants:
            try:
                ok, texts, _pts, _ = detector.detectAndDecodeMulti(im)
                if ok:
                    results.extend(t for t in texts if t)
            except Exception:
                pass
            try:
                text, _pts, _ = detector.detectAndDecode(im)
                if text:
                    results.append(text)
            except Exception:
                pass
    except Exception:
        pass
    if not results:
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode as zbar_decode
            img = Image.open(io.BytesIO(data))
            for item in zbar_decode(img):
                try:
                    text = item.data.decode("utf-8")
                except UnicodeDecodeError:
                    text = item.data.decode("latin-1")
                kind = getattr(item, "type", "")
                results.append(text if str(kind).upper().startswith("QR") else f"[{kind}] {text}")
        except Exception:
            pass
    seen, uniq = set(), []
    for r in results:
        if r and r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


def qr_generate(text: str) -> bytes | None:
    try:
        import qrcode
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 脑洞语言
# --------------------------------------------------------------------------- #
def _run_bf(code: str, cells: int = 30000, max_steps: int = 8_000_000, max_out: int = 4096) -> str:
    code = re.sub(r"[^<>,.+\-\[\]]", "", code)
    if not code:
        return ""
    tape = [0] * cells
    ptr = 0
    out: list[str] = []
    stack, pc, steps = [], 0, 0
    jump = {}
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise ValueError("括号不匹配")
            j = stack.pop()
            jump[i], jump[j] = j, i
    while pc < len(code) and steps < max_steps:
        c = code[pc]
        if c == ">":
            ptr += 1
        elif c == "<":
            ptr -= 1
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == ".":
            out.append(chr(tape[ptr]))
            if len(out) >= max_out:
                break
        elif c == ",":
            tape[ptr] = 0
        elif c == "[" and tape[ptr] == 0:
            pc = jump[pc]
        elif c == "]" and tape[ptr] != 0:
            pc = jump[pc]
        ptr = max(0, min(cells - 1, ptr))
        pc += 1
        steps += 1
    return "".join(out)


def brainfuck(code: str) -> str:
    try:
        return _run_bf(code)
    except Exception:
        return ""


def ook(code: str) -> str:
    """Ook! / Ook. 转 Brainfuck 再执行。"""
    tokens = re.findall(r"[Oo][Oo][Kk][.!?]", code)
    if len(tokens) < 8:
        return ""
    mapping = {
        ".?": ">", "?.": "<", "..": "+", "!!": "-", "!.": ".", ".!": ",",
        "!?": "[", "?!": "]",
    }
    bf = []
    for i in range(0, len(tokens) - 1, 2):
        a = tokens[i][3]
        b = tokens[i + 1][3]
        bf.append(mapping.get(a + b, ""))
    return brainfuck("".join(bf))


def whitespace(code: str) -> str:
    """Whitespace 语言解释器（空格 / Tab / 换行）。"""
    src = "".join(ch for ch in code if ch in " \t\n")
    if len(src) < 16:
        return ""
    S, T, L = " ", "\t", "\n"
    n = len(src)

    def decode():
        """把源码解析成 (操作, 参数) 指令流，非法指令处停止。"""
        i = 0
        while i < n:
            c = src[i]
            if c == S:
                sub = src[i + 1:i + 2]
                if sub == S:
                    i += 2
                    start = i
                    i += 1
                    while i < n and src[i] != L:
                        i += 1
                    yield ("push", src[start:i])
                    i += 1
                elif sub == L:
                    t = src[i + 2:i + 3]
                    if t == S:
                        yield ("dup", ""); i += 3
                    elif t == T:
                        i += 3
                        start = i
                        i += 1
                        while i < n and src[i] != L:
                            i += 1
                        yield ("copy", src[start:i]); i += 1
                    elif t == L:
                        yield ("swap", ""); i += 3
                    else:
                        return
                elif sub == T:
                    t = src[i + 2:i + 3]
                    if t == L:
                        yield ("discard", ""); i += 3
                    elif t == S:
                        i += 3
                        start = i
                        i += 1
                        while i < n and src[i] != L:
                            i += 1
                        yield ("slide", src[start:i]); i += 1
                    else:
                        return
                else:
                    return
            elif c == T:
                sub = src[i + 1:i + 2]
                if sub == S:
                    op = src[i + 2:i + 4]
                    table = {S + S: "add", S + T: "sub", S + L: "mul", T + S: "div", T + T: "mod"}
                    if op not in table:
                        return
                    yield (table[op], ""); i += 4
                elif sub == T:
                    t = src[i + 2:i + 3]
                    if t == S:
                        yield ("store", ""); i += 3
                    elif t == T:
                        yield ("retrieve", ""); i += 3
                    else:
                        return
                elif sub == L:
                    op = src[i + 2:i + 4]
                    table = {S + S: "outchar", S + T: "outnum", T + S: "inchar", T + T: "innum"}
                    if op not in table:
                        return
                    yield (table[op], ""); i += 4
                else:
                    return
            elif c == L:
                sub = src[i + 1:i + 2]
                if sub == L:
                    if src[i + 2:i + 3] != L:
                        return
                    yield ("end", ""); i += 3
                elif sub == S:
                    t = src[i + 2:i + 3]
                    if t not in (S, T, L):
                        return
                    i += 3
                    start = i
                    while i < n and src[i] != L:
                        i += 1
                    name = src[start:i]
                    i += 1
                    yield ({S: "label", T: "call", L: "jump"}[t], name)
                elif sub == T:
                    t = src[i + 2:i + 3]
                    if t not in (S, T, L):
                        return
                    i += 3
                    start = i
                    while i < n and src[i] != L:
                        i += 1
                    name = src[start:i]
                    i += 1
                    yield ({S: "jz", T: "jneg", L: "ret"}[t], name)
                else:
                    return
            else:
                return

    def num(enc: str) -> int:
        if not enc:
            return 0
        sign = -1 if enc[0] == T else 1
        bits = "".join("0" if ch == S else "1" for ch in enc[1:])
        return sign * int(bits or "0", 2)

    try:
        program = list(decode())
    except Exception:
        return ""
    if not program:
        return ""

    labels = {arg: idx for idx, (op, arg) in enumerate(program) if op == "label"}
    stack: list[int] = []
    heap: dict[int, int] = {}
    calls: list[int] = []
    out: list[str] = []
    pc, steps = 0, 0
    while pc < len(program) and steps < 3_000_000:
        steps += 1
        op, arg = program[pc]
        pc += 1
        if op == "push":
            stack.append(num(arg))
        elif op == "dup":
            stack.append(stack[-1] if stack else 0)
        elif op == "copy":
            k = num(arg)
            stack.append(stack[-1 - k] if len(stack) > k else 0)
        elif op == "swap":
            if len(stack) >= 2:
                stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == "discard":
            if stack:
                stack.pop()
        elif op == "slide":
            k = num(arg)
            if stack:
                top = stack.pop()
                for _ in range(k):
                    if stack:
                        stack.pop()
                stack.append(top)
        elif op in ("add", "sub", "mul", "div", "mod"):
            b = stack.pop() if stack else 0
            a = stack.pop() if stack else 0
            if op == "add":
                stack.append(a + b)
            elif op == "sub":
                stack.append(a - b)
            elif op == "mul":
                stack.append(a * b)
            elif op == "div":
                stack.append(int(a / b) if b else 0)
            else:
                stack.append(a - int(a / b) * b if b else 0)
        elif op == "store":
            val = stack.pop() if stack else 0
            addr = stack.pop() if stack else 0
            heap[addr] = val
        elif op == "retrieve":
            stack.append(heap.get(stack.pop() if stack else 0, 0))
        elif op == "outchar":
            out.append(chr((stack.pop() if stack else 0) % 0x110000))
        elif op == "outnum":
            out.append(str(stack.pop() if stack else 0))
        elif op == "inchar":
            stack.append(0)
        elif op == "innum":
            stack.append(0)
        elif op == "call":
            calls.append(pc)
            pc = labels.get(arg, pc)
        elif op == "jump":
            pc = labels.get(arg, pc)
        elif op == "jz":
            if (stack.pop() if stack else 0) == 0:
                pc = labels.get(arg, pc)
        elif op == "jneg":
            if (stack.pop() if stack else 0) < 0:
                pc = labels.get(arg, pc)
        elif op == "ret":
            if calls:
                pc = calls.pop()
        elif op == "end":
            break
        if len(out) > 8192:
            break
    return "".join(out)


ESOTERIC = {
    "Brainfuck": brainfuck,
    "Ook!": ook,
}


# --------------------------------------------------------------------------- #
# JWT / 哈希 / RSA
# --------------------------------------------------------------------------- #
def jwt_decode(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    def _d(seg: str):
        seg = seg.replace("-", "+").replace("_", "/")
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.b64decode(seg))
    try:
        return {"header": _d(parts[0]), "payload": _d(parts[1]),
                "signature": parts[2] if len(parts) > 2 else ""}
    except Exception:
        return {}


_HASH_TYPES = [
    (32, "MD5 / NTLM"), (40, "SHA-1"), (56, "SHA-224"), (64, "SHA-256"),
    (96, "SHA-384"), (128, "SHA-512"), (16, "MySQL / DES"), (13, "DES"),
]


def hash_identify(h: str) -> str:
    h = h.strip()
    if re.fullmatch(r"[a-f0-9]{32,128}", h, re.I):
        for ln, name in _HASH_TYPES:
            if len(h) == ln:
                return name
    if re.fullmatch(r"\\$2[aby]?\\$.{56}", h) or re.fullmatch(r"\\$2[aby]\\$.{56}", h):
        return "bcrypt"
    if h.startswith("$1$"):
        return "MD5-crypt"
    if h.startswith("$5$"):
        return "SHA-256-crypt"
    if h.startswith("$6$"):
        return "SHA-512-crypt"
    if re.fullmatch(r"[a-f0-9]{16}", h, re.I):
        return "CRC32 / MySQL4.1"
    return "未知"


_WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "admin", "abc123", "000000", "iloveyou", "666666",
    "888888", "5201314", "woaini", "letmein", "welcome", "monkey", "flag", "ctf",
    "root", "toor", "test", "guest", "hello", "secret", "passw0rd", "p@ssw0rd",
    "1234567890", "112233", "123321", "654321", "zxcvbnm", "asdfgh", "qwer1234",
]


def hash_crack(h: str, extra: list[str] | None = None, digits: int = 4) -> str | None:
    """字典 + 纯数字空间的弱口令爆破。"""
    h = h.strip().lower()
    algo = None
    for name, fn in (("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)):
        digest_len = fn(b"").hexdigest().__len__()
        if len(h) == digest_len:
            algo = fn
            break
    if algo is None:
        return None
    words = list(extra or []) + _WEAK_PASSWORDS
    for w in words:
        if algo(w.encode()).hexdigest() == h:
            return w
    for i in range(min(10 ** digits, 1_000_000)):
        if algo(str(i).encode()).hexdigest() == h:
            return str(i)
    return None


def _iroot(x: int, n: int) -> int:
    if x < 0:
        return 0
    r = int(round(x ** (1.0 / n)))
    for cand in range(max(0, r - 3), r + 4):
        if cand ** n == x:
            return cand
    lo, hi = 0, 1 << ((x.bit_length() // n) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo ** n == x else 0


def rsa_attacks(n: int, e: int, c: int) -> list[tuple[str, str]]:
    """常见 RSA 弱参数攻击：小指数直接开方、费马分解、n 的平方差分解。"""
    out: list[tuple[str, str]] = []
    for k in range(0, 24):
        m = _iroot(c + k * n, e)
        if m and pow(m, e, n) == c % n:
            out.append(("小指数直接开方", _int_to_text(m)))
            break
    a = math.isqrt(n) + 1
    for _ in range(200000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and q > 1 and p * q == n:
                phi = (p - 1) * (q - 1)
                try:
                    d = pow(e, -1, phi)
                    m = pow(c, d, n)
                    out.append(("费马分解成功", _int_to_text(m)))
                except ValueError:
                    out.append(("费马分解成功（无法求逆元）", f"p={p}"))
                break
        a += 1
    return out


def common_factor(n1: int, n2: int) -> int:
    return math.gcd(n1, n2)


def _int_to_text(m: int) -> str:
    if m <= 0:
        return ""
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    return s if s.isprintable() else raw.hex()


def analyze_text(text: str) -> list[tuple[str, str]]:
    """对一段文本做“脑洞”识别，返回 (标题, 结果)。"""
    out: list[tuple[str, str]] = []
    if re.search(r"[+\-<>\[\].,]{10,}", text) and text.count("+") + text.count("[") > 4:
        res = brainfuck(text)
        if res:
            out.append(("Brainfuck 解释", res))
    if re.search(r"[Oo][Oo][Kk][.!?]", text):
        res = ook(text)
        if res:
            out.append(("Ook! 解释", res))
    if re.fullmatch(r"[ \t\n]{20,}", text):
        res = whitespace(text)
        if res:
            out.append(("Whitespace 解释", res))
    if re.fullmatch(r"ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.?[A-Za-z0-9_\-]*", text.strip()):
        data = jwt_decode(text.strip())
        if data:
            out.append(("JWT 解码", json.dumps(data, ensure_ascii=False, indent=1)))
    if re.fullmatch(r"[a-fA-F0-9]{16,128}", text.strip()):
        kind = hash_identify(text.strip())
        out.append(("哈希识别", kind))
        pw = hash_crack(text.strip())
        if pw is not None:
            out.append(("弱口令命中", pw))
    return out
