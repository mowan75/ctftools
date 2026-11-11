# -*- coding: utf-8 -*-
"""题库元数据：判断待分析路径是否来自内置 corpus，取出题面 / flag 格式 / 提示。

题库目录里每个题目都有 README（题面）和 index.json 元数据。分析时自动识别
“这是题库里的哪道题”，把题面、flag 格式带回结果，并据此给候选加权——这是
题库最有价值的用法：题面里的格式声明可以直接排除大量格式不符的噪声。
"""
from __future__ import annotations

import json
import os

_CACHE: dict[str, dict[str, dict]] = {}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _find_index(path: str) -> tuple[str, str, str]:
    """向上找 index.json，返回 (corpus_dir, index_path, normalized_path)。"""
    cur = os.path.abspath(path)
    if os.path.isfile(cur):
        cur = os.path.dirname(cur)
    norm = _norm(cur)
    while True:
        idx = os.path.join(cur, "index.json")
        if os.path.exists(idx):
            return cur, idx, norm
        parent = os.path.dirname(cur)
        if parent == cur:
            return "", "", norm
        cur = parent


def _load(corpus_dir: str, index_path: str) -> dict[str, dict]:
    key = _norm(corpus_dir)
    if key in _CACHE:
        return _CACHE[key]
    try:
        with open(index_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        _CACHE[key] = {}
        return {}
    by_dir: dict[str, dict] = {}
    for ch in data.get("challenges", []):
        rel = ch.get("dir")
        if rel:
            by_dir[_norm(os.path.join(corpus_dir, rel))] = ch
    _CACHE[key] = by_dir
    return by_dir


def detect(paths: list[str]) -> dict | None:
    """若路径位于某个题库目录内，返回对应题目的元数据。"""
    for p in paths:
        try:
            if not os.path.exists(p):
                continue
        except OSError:
            continue
        corpus_dir, index_path, norm = _find_index(p)
        if not corpus_dir:
            continue
        by_dir = _load(corpus_dir, index_path)
        if not by_dir:
            continue
        cur = norm if os.path.isdir(p) else os.path.dirname(norm)
        base = _norm(corpus_dir)
        while True:
            if cur in by_dir:
                return by_dir[cur]
            parent = os.path.dirname(cur)
            if parent == cur or not parent.startswith(base):
                break
            cur = parent
    return None


def format_prefix(meta: dict | None) -> str:
    """从 known_flag（如 `0ctf{.*}`）取出前缀，用于给候选加权。"""
    if not meta:
        return ""
    fmt = (meta.get("known_flag") or "").strip()
    if "{" in fmt:
        return fmt.split("{", 1)[0].strip().lower()
    return ""


def description(meta: dict | None, limit: int = 900) -> str:
    if not meta:
        return ""
    return ((meta.get("description") or "").strip())[:limit]