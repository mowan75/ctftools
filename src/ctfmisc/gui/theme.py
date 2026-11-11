"""界面主题：配色、字体与绘制辅助。"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

# ---- 基础色板 -------------------------------------------------------------- #
PAGE_BG = "#eef1f7"
SURFACE = "#ffffff"
INK = "#0f172a"
INK_SOFT = "#334155"
MUTED = "#64748b"
FAINT = "#94a3b8"
BORDER = "#e2e6ef"
BORDER_STRONG = "#cbd5e1"

PRIMARY = "#4f46e5"
PRIMARY_DARK = "#4338ca"
PRIMARY_SOFT = "#eef2ff"
SUCCESS = "#0f766e"
SUCCESS_SOFT = "#ecfdf5"
WARN = "#b45309"
DANGER = "#b91c1c"

HEADER_LEFT = "#4338ca"
HEADER_RIGHT = "#7c3aed"
HEADER_SUBTLE = "#c7d2fe"

# ---- 字体 ------------------------------------------------------------------ #
FONT_UI = ("Microsoft YaHei UI", 10)
FONT_SMALL = ("Microsoft YaHei UI", 9)
FONT_TINY = ("Microsoft YaHei UI", 8)
FONT_CARD = ("Microsoft YaHei UI", 10, "bold")
FONT_SECTION = ("Microsoft YaHei UI", 12, "bold")
FONT_SUBSECTION = ("Microsoft YaHei UI", 10, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 15, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_SMALL = ("Consolas", 9)

# ---- 分类强调色 ------------------------------------------------------------ #
_SECTION_ACCENTS = [
    ("速查", "#6d28d9"), ("一键", "#1d4ed8"), ("Misc", "#0f766e"),
    ("Web", "#c2410c"), ("Crypto", "#4338ca"), ("Reverse", "#475569"),
    ("高级", "#0e7490"), ("题库", "#a16207"),
]


def accent_for(name: str, index: int = 0) -> str:
    for key, color in _SECTION_ACCENTS:
        if key in name:
            return color
    palette = ["#6d28d9", "#1d4ed8", "#0f766e", "#c2410c", "#4338ca", "#0e7490", "#be123c"]
    return palette[index % len(palette)]


def mix(color: str, other: str = "#ffffff", ratio: float = 0.12) -> str:
    """把 color 与 other 混合，ratio 是 color 的占比（用于浅色底）。"""
    def rgb(h: str) -> tuple[int, int, int]:
        h = h.lstrip("#")
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r1, g1, b1 = rgb(color)
    r2, g2, b2 = rgb(other)
    r = round(r1 * ratio + r2 * (1 - ratio))
    g = round(g1 * ratio + g2 * (1 - ratio))
    b = round(b1 * ratio + b2 * (1 - ratio))
    return f"#{r:02x}{g:02x}{b:02x}"


def round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


def apply_theme(root: tk.Tk) -> None:
    """统一 ttk 控件风格（clam 主题支持自定义颜色）。"""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(".", font=FONT_UI, background=SURFACE, foreground=INK)
    style.configure("TFrame", background=SURFACE)
    style.configure("Page.TFrame", background=PAGE_BG)
    style.configure("TLabel", background=SURFACE, foreground=INK)
    style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED, font=FONT_SMALL)
    style.configure("TButton", font=FONT_UI, padding=(12, 6), borderwidth=0,
                    background="#f1f3f9", foreground=INK_SOFT, relief="flat")
    style.map("TButton",
              background=[("active", "#e6e9f4"), ("disabled", "#f6f7fb")],
              foreground=[("disabled", FAINT)])
    style.configure("Accent.TButton", background=PRIMARY, foreground="#ffffff",
                    font=("Microsoft YaHei UI", 10, "bold"), padding=(14, 7))
    style.map("Accent.TButton",
              background=[("active", PRIMARY_DARK), ("disabled", "#a5b4fc")])
    style.configure("Soft.TButton", background=PRIMARY_SOFT, foreground=PRIMARY_DARK)
    style.map("Soft.TButton", background=[("active", "#e0e7ff")])
    style.configure("Search.TEntry", fieldbackground=SURFACE, foreground=INK,
                    bordercolor="#c7d2fe", lightcolor="#c7d2fe", darkcolor="#c7d2fe",
                    padding=(10, 6), relief="flat")
    style.configure("TSeparator", background=BORDER)
    style.configure("TNotebook", background=PAGE_BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(14, 7), font=FONT_UI,
                    background="#e6e9f4", foreground=MUTED)
    style.map("TNotebook.Tab", background=[("selected", SURFACE)],
              foreground=[("selected", INK)])
    style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                    foreground=INK, rowheight=26, borderwidth=0)
    style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"),
                    background="#f1f3f9", foreground=MUTED, relief="flat")
    style.map("Treeview", background=[("selected", PRIMARY_SOFT)],
              foreground=[("selected", INK)])
    try:
        root.option_add("*Font", FONT_UI)
        root.option_add("*SelectBackground", "#e0e7ff")
        root.option_add("*SelectForeground", INK)
    except tk.TclError:
        pass


def mono_font(size: int = 10) -> tkfont.Font:
    return tkfont.Font(family="Consolas", size=size)