"""flag 提取与候选评分。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# 常见 flag 前缀（命中即高分）
KNOWN_PREFIX = {
    "flag", "fl4g", "ctf", "key", "answer", "secret", "dasctf", "nssctf", "hgame",
    "moectf", "buuctf", "buu", "n1ctf", "qwb", "swpuctf", "gactf", "sctf", "xctf",
    "hitctf", "hctf", "actf", "ctfshow", "hdctf", "ezctf", "geek", "geekchallenge",
    "iscc", "ciscn", "d0g3", "de1ctf", "starctf", "0ctf", "wpctf", "deconstest",
    "flag1", "flag2", "flag3", "e", "sctf2023",
}

BRACED = re.compile(r"[A-Za-z0-9_\u4e00-\u9fff]{1,24}\{[^{}\s\r\n]{1,150}\}")
PHRASE = re.compile(
    r"(?:flag|key|answer|token|密码|答案)\s*(?:is|are|:|：|=|是)\s*"
    r"([A-Za-z0-9_\-{}\[\]!@#$%^&*\.+/]{4,96})",
    re.I,
)
HEXTOKEN = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")


@dataclass
class FlagHit:
    value: str
    source: str
    score: float = 0.0
    context: str = ""
    reason: str = ""

    def key(self) -> str:
        return self.value.strip()


def _looks_like_json_or_code(body: str) -> bool:
    if body.startswith('"') and ":" in body:
        return True
    if body.count("\\") > 3:
        return True
    if body.strip() in ("}", "{", "", "%s", "%d"):
        return True
    return False


_SAFE_BODY = re.compile(r"^[A-Za-z0-9_\-\s!@#$%^&*()+={}:;.,?/|~\[\]<>]{2,150}$")


def _plausible(whole: str, prefix: str, body: str) -> bool:
    """过滤随机字节解码出来的伪 flag。"""
    for ch in whole:
        if not (32 <= ord(ch) < 127 or "\u4e00" <= ch <= "\u9fff"):
            return False
    if _looks_like_json_or_code(body):
        return False
    p = prefix.lower()
    known = p in KNOWN_PREFIX or "flag" in p or "ctf" in p or "key" in p
    if known:
        return len(body.strip()) >= 1
    # 未知前缀时要求更严格：前缀至少 2 字符（单字母前缀基本都是解码噪声）
    if len(prefix.strip()) < 2:
        return False
    # 不含空格、无怪异符号、长度够
    if " " in body or not _SAFE_BODY.match(body):
        return False
    return len(body) >= 4


def _prefix_bonus(prefix: str) -> float:
    p = prefix.lower()
    if p in KNOWN_PREFIX:
        return 60.0
    if "flag" in p or "ctf" in p or "key" in p:
        return 40.0
    return 0.0


def find_flags(text: str, source: str = "", extra_patterns: list[str] | None = None) -> list[FlagHit]:
    """在任意文本 / 字节流中寻找 flag 候选。"""
    if not text:
        return []
    hits: list[FlagHit] = []
    seen: set[str] = set()

    def add(value: str, score: float, context: str, reason: str) -> None:
        value = value.strip()
        key = value
        if not value or key in seen:
            return
        seen.add(key)
        hits.append(FlagHit(value=value, source=source, score=score, context=context.strip()[:200], reason=reason))

    for m in BRACED.finditer(text):
        whole = m.group(0)
        prefix, body = whole.split("{", 1)
        body = body[:-1]
        if not _plausible(whole, prefix, body):
            continue
        start = max(0, m.start() - 30)
        ctx = text[start:m.end() + 30].replace("\n", " ")
        add(whole, 30 + _prefix_bonus(prefix) + min(len(body), 40) / 4, ctx, "形如 prefix{...}")

    for m in PHRASE.finditer(text):
        start = max(0, m.start() - 30)
        ctx = text[start:m.end() + 30].replace("\n", " ")
        value = m.group(1).strip().rstrip(".,;")
        # "flag is elsewhere" 这类句式误报：纯小写英文单词不算 flag
        if not ("{" in value or any(c.isdigit() for c in value) or "_" in value
                or "-" in value or len(value) >= 10):
            continue
        add(value, 35 + min(len(value), 40) / 4, ctx, "flag is xxx 句式")

    for pat in extra_patterns or []:
        try:
            rx = re.compile(pat)
        except re.error:
            continue
        for m in rx.finditer(text):
            start = max(0, m.start() - 30)
            ctx = text[start:m.end() + 30].replace("\n", " ")
            add(m.group(0), 55, ctx, f"自定义规则 {pat}")

    for m in HEXTOKEN.finditer(text):
        start = max(0, m.start() - 30)
        ctx = text[start:m.end() + 30].replace("\n", " ")
        add(m.group(0), 12, ctx, "疑似哈希/十六进制令牌")

    hits.sort(key=lambda h: (-h.score, len(h.value)))
    return hits


def merge(hits: list[FlagHit], limit: int = 60) -> list[FlagHit]:
    """合并多来源候选，同值保留最高分。"""
    best: dict[str, FlagHit] = {}
    for h in hits:
        cur = best.get(h.key())
        if cur is None or h.score > cur.score:
            best[h.key()] = h
    out = sorted(best.values(), key=lambda h: (-h.score, len(h.value)))
    return out[:limit]
