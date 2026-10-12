"""卡片式功能面板：仿参考截图的“标题 + 说明”卡片列表。"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

BG = "#f3f4f6"
CARD_BG = "#ffffff"
CARD_HOVER = "#eff6ff"
CARD_BORDER = "#e5e7eb"
CARD_BORDER_HOVER = "#93c5fd"
TITLE_FG = "#111827"
SUB_FG = "#6b7280"
ACCENT = "#2563eb"
SECTION_FG = "#1f2937"


def round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


class Card(tk.Canvas):
    """一张可点击的功能卡片。"""

    HEIGHT = 74

    def __init__(self, parent, title: str, subtitle: str, command, badge: str = ""):
        super().__init__(parent, height=self.HEIGHT, bg=BG, highlightthickness=0, cursor="hand2")
        self.title = title
        self.subtitle = subtitle
        self.command = command
        self.badge = badge
        self._hover = False
        self._cw = 420          # 注意：不能用 _w，那是 tkinter 内部的控件路径名
        self._title_font = tkfont.Font(family="Microsoft YaHei UI", size=11, weight="bold")
        self._sub_font = tkfont.Font(family="Microsoft YaHei UI", size=9)
        self._badge_font = tkfont.Font(family="Microsoft YaHei UI", size=9)
        self.bind("<Configure>", self._on_configure)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self._draw()

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

    def _draw(self) -> None:
        self.delete("all")
        w, h = self._cw, self.HEIGHT
        fill = CARD_HOVER if self._hover else CARD_BG
        outline = CARD_BORDER_HOVER if self._hover else CARD_BORDER
        round_rect(self, 2, 2, w - 3, h - 3, 12, fill=fill, outline=outline, width=1)
        # 左侧色条
        self.create_rectangle(2, 14, 5, h - 14, fill=ACCENT if not self._hover else "#1d4ed8", outline="")
        self.create_text(20, 24, text=self.title, anchor="w", font=self._title_font, fill=TITLE_FG)
        sub = self.subtitle
        limit = max(w - 60, 120)
        if self._sub_font.measure(sub) > limit:
            while sub and self._sub_font.measure(sub + "…") > limit:
                sub = sub[:-1]
            sub += "…"
        self.create_text(20, 50, text=sub, anchor="w", font=self._sub_font, fill=SUB_FG)
        if self.badge:
            self.create_text(w - 18, 24, text=self.badge, anchor="e", font=self._badge_font,
                             fill=ACCENT if self._hover else "#9ca3af")
        self.create_text(w - 18, 50, text="›", anchor="e", font=("Microsoft YaHei UI", 14),
                         fill=ACCENT if self._hover else "#d1d5db")


class CollapsibleSection(tk.Frame):
    """可折叠分组：点击标题（或小箭头）展开/收起。level=1 是大类，level=2 是小类。"""

    def __init__(self, parent, title: str, hint: str = "", level: int = 1, expanded: bool = True):
        super().__init__(parent, bg=BG)
        self.expanded = expanded
        self.level = level
        head = tk.Frame(self, bg=BG, cursor="hand2")
        head.pack(fill="x")
        if level == 1:
            tk.Frame(head, bg=ACCENT, width=5, height=20).pack(side="left", pady=(14, 4), padx=(2, 0))
            font = ("Microsoft YaHei UI", 12, "bold")
            fg = SECTION_FG
            pad_top, pad_bottom = 14, 4
        else:
            tk.Frame(head, bg="#c7d2fe", width=3, height=14).pack(side="left", pady=(10, 3), padx=(18, 0))
            font = ("Microsoft YaHei UI", 10, "bold")
            fg = "#374151"
            pad_top, pad_bottom = 10, 3
        self.arrow = tk.Label(head, text="▾" if expanded else "▸", bg=BG, fg=ACCENT,
                              font=("Microsoft YaHei UI", 11, "bold"))
        self.arrow.pack(side="left", padx=(6, 2), pady=(pad_top, pad_bottom))
        self.title_label = tk.Label(head, text=title, bg=BG, fg=fg, font=font)
        self.title_label.pack(side="left", padx=(2, 0), pady=(pad_top, pad_bottom))
        self.hint_label = None
        if hint:
            self.hint_label = tk.Label(head, text=hint, bg=BG, fg="#9ca3af",
                                       font=("Microsoft YaHei UI", 9))
            self.hint_label.pack(side="left", padx=(10, 0), pady=(pad_top + 2, pad_bottom))
        self.count_label = tk.Label(head, text="", bg=BG, fg="#9ca3af", font=("Microsoft YaHei UI", 9))
        self.count_label.pack(side="right", padx=(0, 14), pady=(pad_top + 2, pad_bottom))
        self.body = tk.Frame(self, bg=BG)
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
    """可滚动的卡片列表，支持搜索过滤。"""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.inner = tk.Frame(self.canvas, bg=BG)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._resize)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.bind_all(seq, self._wheel)
        self._cards: list[tuple[str, Card]] = []
        self._sections: list[tuple[str, SectionHeader]] = []

    def _resize(self, event) -> None:
        self.canvas.itemconfigure(self._win, width=event.width)

    def _wheel(self, event) -> None:
        try:
            if event.num == 4:
                self.canvas.yview_scroll(-2, "units")
            elif event.num == 5:
                self.canvas.yview_scroll(2, "units")
            else:
                self.canvas.yview_scroll(-1 * (event.delta // 120), "units")
        except Exception:
            pass

    def build(self, sections) -> None:
        """sections: [(大类, 提示, [(小类, 提示, [卡片...]), ...]), ...]"""
        for child in self.inner.winfo_children():
            child.destroy()
        self._cards.clear()
        self._sections.clear()
        for big_name, big_hint, subs in sections:
            total = sum(len(s[2]) for s in subs)
            big = CollapsibleSection(self.inner, big_name, big_hint, level=1, expanded=(big_name.startswith("★")))
            big.pack(fill="x", padx=10)
            big.set_count(total)
            self._sections.append((big_name, big))
            for sub_name, sub_hint, items in subs:
                sub = CollapsibleSection(big.body, sub_name, sub_hint, level=2, expanded=True)
                sub.pack(fill="x", padx=6)
                self._sections.append((f"{big_name}/{sub_name}", sub))
                for title, subtitle, cmd, *rest in items:
                    card = Card(sub.body, title, subtitle, cmd, badge=(rest[0] if rest else ""))
                    card.pack(fill="x", padx=12, pady=3)
                    self._cards.append((f"{big_name} {sub_name} {title} {subtitle}", card))
        self.inner.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def filter(self, keyword: str) -> None:
        kw = keyword.strip().lower()
        if not kw:
            for _t, card in self._cards:
                card.pack(fill="x", padx=14, pady=3)
            for _n, sec in self._sections:
                sec.toggle(True)
            return
        for text, card in self._cards:
            if kw in text.lower():
                card.pack(fill="x", padx=14, pady=3)
            else:
                card.pack_forget()
        for _n, sec in self._sections:
            sec.toggle(True)

    def expand_all(self, expand: bool = True) -> None:
        for _n, sec in self._sections:
            sec.toggle(expand)
