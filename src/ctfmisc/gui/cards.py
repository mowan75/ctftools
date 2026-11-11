"""卡片式功能面板：双列卡片网格 + 分类折叠。"""

from __future__ import annotations

import re
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from .theme import (BORDER, BORDER_STRONG, FONT_CARD, FONT_SECTION, FONT_SMALL,
                    FONT_SUBSECTION, FONT_TINY, INK, INK_SOFT, MUTED, PAGE_BG,
                    PRIMARY, PRIMARY_SOFT, SURFACE, accent_for, mix, round_rect)


def _wrap(text: str, font: tkfont.Font, width: int, max_lines: int = 2) -> list[str]:
    """按像素宽度折行：英文按词断、中文按字断，最多 max_lines 行。"""
    if not text:
        return [""]
    tokens = re.findall(r"[A-Za-z0-9_\-./:=+%]+|[\u4e00-\u9fff]|\s+|.", text)
    lines: list[str] = []
    cur = ""
    for tok in tokens:
        if font.measure(cur + tok) <= width:
            cur += tok
            continue
        if tok.isspace():
            if cur:
                lines.append(cur)
                cur = ""
        else:
            if cur:
                lines.append(cur)
            cur = tok
        if len(lines) >= max_lines:
            break
    if len(lines) < max_lines and cur:
        lines.append(cur)
    if len("".join(lines)) < len(text) and lines:
        last = lines[-1]
        while last and font.measure(last + "…") > width:
            last = last[:-1]
        lines[-1] = last + "…"
    return lines[:max_lines]


class Card(tk.Canvas):
    """一张可点击的功能卡片：图标块 + 标题 + 说明 + 徽标。"""

    HEIGHT = 94

    def __init__(self, parent, title: str, subtitle: str, command, badge: str = "",
                 accent: str = PRIMARY, glyph: str = "◆"):
        super().__init__(parent, height=self.HEIGHT, bg=PAGE_BG, highlightthickness=0,
                         cursor="hand2", bd=0)
        self.title = title
        self.subtitle = subtitle
        self.command = command
        self.badge = badge
        self.accent = accent
        self.glyph = glyph
        self._hover = False
        self._cw = 360          # 不能用 _w（tkinter 内部路径名）
        self._title_font = tkfont.Font(family="Microsoft YaHei UI", size=10, weight="bold")
        self._sub_font = tkfont.Font(family="Microsoft YaHei UI", size=9)
        self._badge_font = tkfont.Font(family="Microsoft YaHei UI", size=8)
        self._glyph_font = tkfont.Font(family="Segoe UI Symbol", size=14, weight="bold")
        self._title_lh = max(18, int(self._title_font.metrics("linespace")))
        self._sub_lh = max(14, int(self._sub_font.metrics("linespace")))
        # 高度按字体真实行距推导：高 DPI 下行距会变大，固定像素会把两行文字挤在一起
        self.HEIGHT = int(20 + self._title_lh + 6 + 2 * self._sub_lh + 12)
        self.configure(height=self.HEIGHT)
        self.bind("<Configure>", self._on_configure)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self._draw()

    # ------------------------------------------------------------------ #
    def _on_configure(self, event) -> None:
        if abs(event.width - self._cw) > 2:
            self._cw = event.width
            self._draw()

    def _on_enter(self, _e=None) -> None:
        self._hover = True
        self._draw()

    def _on_leave(self, _e=None) -> None:
        self._hover = False
        self._draw()

    def _on_click(self, _e=None) -> None:
        if callable(self.command):
            self.command()

    # ------------------------------------------------------------------ #
    def _draw(self) -> None:
        self.delete("all")
        w, h = self._cw, self.HEIGHT
        base = mix(self.accent, "#ffffff", 0.10)
        # 阴影 + 卡片主体
        round_rect(self, 3, 5, w - 3, h - 2, 14, fill="#e3e7f1", outline="")
        body = "#ffffff" if not self._hover else mix(self.accent, "#ffffff", 0.05)
        round_rect(self, 2, 2, w - 4, h - 5, 14, fill=body,
                   outline=self.accent if self._hover else BORDER, width=1)

        # 左侧图标块：垂直居中对齐文字区域
        title_cy = 18 + self._title_lh / 2
        sub_top = 18 + self._title_lh + 5
        block_cy = (sub_top + 2 * self._sub_lh + 18) / 2
        tile = max(38, int(self._sub_lh * 2.3))
        tile_top = int(block_cy - tile / 2)
        round_rect(self, 14, tile_top, 14 + tile, tile_top + tile, 11, fill=base, outline="")
        self.create_text(14 + tile / 2, tile_top + tile / 2 - 1, text=self.glyph,
                         fill=self.accent, font=self._glyph_font)

        # 标题独占一行；徽标放右下角，说明按剩余宽度折两行
        text_x = 14 + tile + 12
        badge_w = self._badge_font.measure(self.badge) + 16 if self.badge else 0
        title_limit = max(w - text_x - 26, 120)
        title = self.title
        while title and self._title_font.measure(title) > title_limit:
            title = title[:-1]
        if title != self.title:
            title = title[:-1] + "…"
        self.create_text(text_x, title_cy, text=title, anchor="w",
                         font=self._title_font, fill=INK)
        sub_limit = max(w - text_x - 26 - (badge_w + 8 if self.badge else 0), 100)
        lines = _wrap(self.subtitle, self._sub_font, sub_limit, max_lines=2)
        for i, line in enumerate(lines):
            self.create_text(text_x, sub_top + i * self._sub_lh + self._sub_lh / 2,
                             text=line, anchor="w", font=self._sub_font, fill=MUTED)
        if self.badge:
            bx2 = w - 28
            bx1 = bx2 - badge_w
            by = h - 26
            round_rect(self, bx1, by, bx2, by + 16, 8,
                       fill=mix(self.accent, "#ffffff", 0.14), outline="")
            self.create_text((bx1 + bx2) / 2, by + 8, text=self.badge, fill=self.accent,
                             font=self._badge_font)
        self.create_text(w - 14, 22 + self._title_lh / 2, text="›", anchor="e",
                         font=("Microsoft YaHei UI", 15),
                         fill=self.accent if self._hover else "#cbd5e1")


class CollapsibleSection(tk.Frame):
    """可折叠分组：level=1 大类，level=2 小类。"""

    def __init__(self, parent, title: str, hint: str = "", level: int = 1,
                 expanded: bool = True, accent: str = PRIMARY, glyph: str = ""):
        super().__init__(parent, bg=PAGE_BG)
        self.expanded = expanded
        self.level = level
        self.accent = accent
        head = tk.Frame(self, bg=PAGE_BG, cursor="hand2")
        head.pack(fill="x")
        if level == 1:
            bar = tk.Canvas(head, width=6, height=24, bg=PAGE_BG, highlightthickness=0)
            round_rect(bar, 1, 2, 5, 22, 2, fill=accent, outline="")
            bar.pack(side="left", padx=(2, 8), pady=(12, 2))
            font = FONT_SECTION
            fg = INK
            pad = (12, 2)
        else:
            dot = tk.Canvas(head, width=10, height=10, bg=PAGE_BG, highlightthickness=0)
            dot.create_oval(2, 2, 8, 8, fill=mix(accent, "#ffffff", 0.55), outline="")
            dot.pack(side="left", padx=(22, 6), pady=(9, 2))
            font = FONT_SUBSECTION
            fg = INK_SOFT
            pad = (8, 2)
        self.arrow = tk.Label(head, text="▾" if expanded else "▸", bg=PAGE_BG,
                              fg=accent, font=("Microsoft YaHei UI", 9, "bold"))
        self.arrow.pack(side="left", padx=(4, 4), pady=pad)
        self.title_label = tk.Label(head, text=title, bg=PAGE_BG, fg=fg, font=font)
        self.title_label.pack(side="left", pady=pad)
        if glyph and level == 1:
            tk.Label(head, text=glyph, bg=PAGE_BG, fg=mix(accent, "#ffffff", 0.8),
                     font=("Segoe UI Symbol", 11)).pack(side="left", padx=(8, 0), pady=pad)
        self.hint_label = None
        if hint:
            self.hint_label = tk.Label(head, text=hint, bg=PAGE_BG, fg=MUTED,
                                       font=FONT_SMALL)
            self.hint_label.pack(side="left", padx=(10, 0), pady=(pad[0] + 2, pad[1]))
        self.count_label = tk.Label(head, text="", bg=mix(accent, "#ffffff", 0.12),
                                    fg=accent, font=FONT_TINY, padx=8, pady=1)
        self.count_label.pack(side="right", padx=(0, 12), pady=(pad[0] + 2, pad[1]))
        self.body = tk.Frame(self, bg=PAGE_BG)
        if expanded:
            self.body.pack(fill="x")
        for w in (head, self.arrow, self.title_label, self.hint_label, self.count_label):
            if w is not None:
                w.bind("<Button-1>", lambda _e: self.toggle())

    def toggle(self, expand: bool | None = None) -> None:
        want = (not self.expanded) if expand is None else expand
        if want == self.expanded:
            return
        self.expanded = want
        self.arrow.configure(text="▾" if want else "▸")
        if want:
            self.body.pack(fill="x")
        else:
            self.body.pack_forget()

    def set_count(self, n: int) -> None:
        self.count_label.configure(text=f"{n} 项" if n else "")


class CardList(tk.Frame):
    """可滚动的双列卡片网格，支持搜索过滤。"""

    def __init__(self, parent):
        super().__init__(parent, bg=SURFACE)
        self.canvas = tk.Canvas(self, bg=SURFACE, highlightthickness=0)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.inner = tk.Frame(self.canvas, bg=SURFACE)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>",
                        lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._resize)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.bind_all(seq, self._wheel)
        self._cards: list[tuple[str, Card]] = []
        self._sections: list[tuple[str, CollapsibleSection]] = []
        self._grids: list[tk.Frame] = []

    def _resize(self, event) -> None:
        self.canvas.itemconfigure(self._win, width=event.width)

    def _pointer_inside(self) -> bool:
        try:
            wdg = self.winfo_containing(*self.winfo_pointerxy())
        except Exception:
            return False
        while wdg is not None:
            if wdg is self:
                return True
            try:
                wdg = wdg.master
            except Exception:
                return False
        return False

    def _wheel(self, event) -> None:
        # bind_all 会收到整个窗口的滚轮事件：只有指针在卡片区时才滚动，
        # 否则右侧结果/日志/题目面板滚动时左侧列表会跟着动
        if not self._pointer_inside():
            return None
        try:
            if event.num == 4:
                self.canvas.yview_scroll(-2, "units")
            elif event.num == 5:
                self.canvas.yview_scroll(2, "units")
            else:
                self.canvas.yview_scroll(-1 * (event.delta // 120), "units")
        except Exception:
            pass
        return "break"

    def build(self, sections) -> None:
        """sections: [(大类, 提示, [(小类, 提示, [卡片...]), ...]), ...]"""
        for child in self.inner.winfo_children():
            child.destroy()
        self._cards.clear()
        self._sections.clear()
        self._grids.clear()
        for bi, (big_name, big_hint, subs) in enumerate(sections):
            accent = accent_for(big_name, bi)
            total = sum(len(s[2]) for s in subs)
            big = CollapsibleSection(self.inner, big_name, big_hint, level=1,
                                     expanded=big_name.startswith("★"), accent=accent)
            big.pack(fill="x", padx=8, pady=(10, 2))
            big.set_count(total)
            self._sections.append((big_name, big))
            for sub_name, sub_hint, items in subs:
                sub = CollapsibleSection(big.body, sub_name, sub_hint, level=2,
                                         expanded=True, accent=accent)
                sub.pack(fill="x", padx=10, pady=(4, 0))
                grid = tk.Frame(sub.body, bg=SURFACE)
                grid.pack(fill="x", padx=8, pady=(2, 6))
                grid.columnconfigure(0, weight=1, uniform="card")
                grid.columnconfigure(1, weight=1, uniform="card")
                self._sections.append((f"{big_name}/{sub_name}", sub))
                self._grids.append(grid)
                for i, (title, subtitle, cmd, *rest) in enumerate(items):
                    card = Card(grid, title, subtitle, cmd,
                                badge=(rest[0] if rest else ""), accent=accent,
                                glyph=_glyph_for(f"{big_name} {sub_name} {title}"))
                    card.grid(row=i // 2, column=i % 2, sticky="ew", padx=5, pady=5)
                    self._cards.append((f"{big_name} {sub_name} {title} {subtitle}", card))
        self.inner.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def filter(self, keyword: str) -> None:
        kw = keyword.strip().lower()
        if not kw:
            for i, (_text, card) in enumerate(self._cards):
                card.grid(row=i // 2, column=i % 2, sticky="ew", padx=5, pady=5)
            for _n, sec in self._sections:
                sec.toggle(True)
            return
        visible = [(text, card) for text, card in self._cards if kw in text.lower()]
        for _text, card in self._cards:
            card.grid_remove()
        for i, (_text, card) in enumerate(visible):
            card.grid(row=i // 2, column=i % 2, sticky="ew", padx=5, pady=5)
        for _n, sec in self._sections:
            sec.toggle(True)

    def expand_all(self, expand: bool = True) -> None:
        for _n, sec in self._sections:
            sec.toggle(expand)


_GLYPHS = (
    (("全自动", "一键", "开始"), "⚡"),
    (("手册", "速查"), "✦"),
    (("编码", "Base", "进制"), "⌘"),
    (("图片", "LSB", "PNG", "JPEG", "GIF", "二维码", "猫脸"), "▣"),
    (("音频", "频谱"), "♪"),
    (("压缩包", "ZIP"), "▤"),
    (("流量", "pcap", "USB"), "⇄"),
    (("Web", "站点", "JWT", "SQL", "SSTI"), "◎"),
    (("Crypto", "RSA", "AES", "椭圆"), "⚿"),
    (("逆向", "pyc", "strings", "二进制"), "⚙"),
    (("文档", "PDF", "Office"), "▥"),
    (("题库",), "★"),
)


def _glyph_for(text: str) -> str:
    for keys, glyph in _GLYPHS:
        if any(k.lower() in text.lower() for k in keys):
            return glyph
    return "◆"