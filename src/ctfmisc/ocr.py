"""图片文字识别（可选依赖 RapidOCR）：很多杂项题的 flag 就是图里画的一行字。"""

from __future__ import annotations

import io
import re
import threading

_engine = None
_lock = threading.Lock()
_failed = False


def available() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return not _failed
    except Exception:
        return False


def _get_engine():
    global _engine, _failed
    if _engine is not None or _failed:
        return _engine
    with _lock:
        if _engine is None and not _failed:
            try:
                from rapidocr_onnxruntime import RapidOCR
                _engine = RapidOCR()
            except Exception:
                _failed = True
    return _engine


MAX_SIDE = 1600


def _prepare(data: bytes, scale: int = 1) -> bytes:
    """把图片缩放到 OCR 友好的尺寸：大图降采样（速度），小图放大（准确率）。

    原实现直接把 2888x3788 的大图丢给引擎，单次就要几十秒；这里统一限制
    长边不超过 1600，缩放后小字仍然清晰，速度提升一个数量级。
    """
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data)).convert("RGB")
        w, h = im.size
        factor = scale
        if max(w, h) * factor > MAX_SIDE:
            factor = MAX_SIDE / max(w, h)
        if abs(factor - 1.0) > 0.01:
            im = im.resize((max(1, int(w * factor)), max(1, int(h * factor))), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, "PNG")
        return buf.getvalue()
    except Exception:
        return data


def ocr_image(data: bytes, scale: int = 1) -> list[str]:
    """识别图片里的文字；scale>1 会先放大（小字更准），但长边不超过 MAX_SIDE。"""
    engine = _get_engine()
    if engine is None:
        return []
    payload = _prepare(data, scale)
    try:
        res, _ = engine(payload)
    except Exception:
        return []
    out = []
    for item in res or []:
        try:
            text = item[1]
        except Exception:
            continue
        if text and text.strip():
            out.append(text.strip())
    return out


_FIX = str.maketrans({"=": "{", "(": "{", "[": "{", "）": "}", ")": "}", "]": "}", "|": "{"})


def _lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_flag_text(text: str) -> str:
    """修正 OCR 常见误读：多余/缺失花括号、前缀里 I/l、O/0 混淆。"""
    from .flags import KNOWN_PREFIX
    s = text.strip()
    m = re.match(r"([A-Za-z0-9_]{2,20})\{(.+?)\}*$", s)
    if not m:
        return s
    prefix, body = m.group(1), m.group(2)
    body = body.replace("{", "").replace("}", "").strip()
    low = prefix.lower()
    if low not in KNOWN_PREFIX:
        best, best_d = None, 3
        for k in KNOWN_PREFIX:
            if k[:1] != low[:1] or abs(len(k) - len(low)) > 1:
                continue
            d = _lev(low, k)
            if d < best_d:
                best, best_d = k, d
        if best and best_d <= 2:
            prefix = best.upper() if prefix.isupper() else best
    return f"{prefix}{{{body}}}"


def ocr_flags(data: bytes) -> tuple[list[str], list[str]]:
    """OCR 图片并归一化常见误识别，返回 (文本行, flag 候选)。"""
    from .flags import find_flags
    lines: list[str] = []
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as _im:
            small = max(_im.size) <= MAX_SIDE
    except Exception:
        small = True
    # 只有小图才值得放大再跑一遍；大图放大既慢又没收益
    for scale in ((1, 3) if small else (1,)):
        lines += ocr_image(data, scale=scale)
    texts = []
    for line in lines:
        fixed = line.translate(_FIX)
        fixed = re.sub(r"\bctfshow([.\s:])", "ctfshow{", fixed, flags=re.I)
        texts.append(fixed)
    flags: list[str] = []
    for t in texts:
        # OCR 会把 I 认成 l、多打一个花括号；先归一化再打分，阈值也放宽
        flags += [h.value for h in find_flags(normalize_flag_text(t)) if h.score >= 25]
        # 形如 ctfshow{32位hex} 但被 OCR 吃掉了大括号
        m = re.search(r"(ctfshow|flag|ctf)[a-z]?([0-9a-f]{16,64})", t, re.I)
        if m:
            flags.append(f"ctfshow{{{m.group(2)}}}")
    seen, uniq = set(), []
    for f in flags:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return texts, uniq
