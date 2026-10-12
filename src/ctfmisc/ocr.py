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


def ocr_image(data: bytes, scale: int = 1) -> list[str]:
    """识别图片里的文字；scale>1 会先放大（小字更准）。"""
    engine = _get_engine()
    if engine is None:
        return []
    payload = data
    if scale > 1:
        try:
            from PIL import Image
            im = Image.open(io.BytesIO(data))
            im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
            buf = io.BytesIO()
            im.convert("RGB").save(buf, "PNG")
            payload = buf.getvalue()
        except Exception:
            payload = data
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


def ocr_flags(data: bytes) -> tuple[list[str], list[str]]:
    """OCR 图片并归一化常见误识别，返回 (文本行, flag 候选)。"""
    from .flags import find_flags
    lines: list[str] = []
    for scale in (1, 3):
        lines += ocr_image(data, scale=scale)
    texts = []
    for line in lines:
        fixed = line.translate(_FIX)
        fixed = re.sub(r"\bctfshow([.\s:])", "ctfshow{", fixed, flags=re.I)
        texts.append(fixed)
    flags: list[str] = []
    for t in texts:
        flags += [h.value for h in find_flags(t) if h.score >= 40]
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
