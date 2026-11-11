"""CTF 杂项解题助手 —— 卡片式桌面主界面（现代浅色主题）。"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import APP_NAME, __version__, report as report_mod
from . import actions, cards, tabs, theme
from .theme import (BORDER, FONT_MONO, FONT_SMALL, FONT_TITLE, HEADER_LEFT,
                    HEADER_RIGHT, INK, MUTED, PAGE_BG, PRIMARY, PRIMARY_SOFT,
                    SUCCESS, SUCCESS_SOFT, SURFACE, WARN, mix, round_rect)

FONT = theme.FONT_UI
FONT_SMALL = theme.FONT_SMALL

HEADER_H = 88


def resource_dir() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
        internal = os.path.join(base, "_internal")
        for cand in (base, internal):
            if os.path.isdir(os.path.join(cand, "corpus")):
                return cand
        return base
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def asset_path(name: str) -> str:
    base = resource_dir()
    for cand in (os.path.join(base, "assets", name), os.path.join(base, "_internal", "assets", name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(base, "assets", name)


def _surface(parent, bg: str = SURFACE) -> tk.Frame:
    return tk.Frame(parent, bg=bg, highlightbackground=BORDER, highlightthickness=1)


class App(tk.Tk):
    def __init__(self) -> None:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # 高 DPI 下字体清晰、坐标一致
        except Exception:
            pass
        super().__init__()
        self.title(f"{APP_NAME}  v{__version__}")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(1360, sw - 60)
        h = min(900, sh - 100)
        self.geometry(f"{w}x{h}+{max(10, (sw - w) // 2)}+{max(10, (sh - h) // 2)}")
        self.minsize(min(1100, sw - 80), min(700, sh - 120))
        self.configure(bg=PAGE_BG)
        try:
            self.iconbitmap(default=asset_path("app.ico"))
        except Exception:
            pass
        self.current_file: str | None = None
        self.cancel_flag = threading.Event()
        self.report = None
        self.last_paths: list[str] = []
        self.last_evidence: list[str] = []
        self.web_url: str = ""
        self.busy = False
        self._tool_refs = []
        self._log_queue: queue.Queue[str] = queue.Queue()
        self.cases: list[report_mod.Case] = []
        self._drain_scheduled = False
        self._view = "result"
        self._total_cards = 0
        theme.apply_theme(self)
        self._header()
        self._statusbar()
        self._body()
        self._bind_drop()
        self.after(300, self._drain_log)
        self.after(900, self._warm_ocr)

    # ------------------------------------------------------------------ #
    # 顶部渐变栏
    # ------------------------------------------------------------------ #
    def _header(self) -> None:
        self.header = tk.Canvas(self, height=HEADER_H, bg=HEADER_LEFT,
                                highlightthickness=0, bd=0)
        self.header.pack(fill="x")
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(self.header, textvariable=self.search_var,
                                      style="Search.TEntry", font=FONT_SMALL)
        self.search_entry.bind("<KeyRelease>", lambda _e: self.card_list.filter(self.search_var.get()))
        self._search_win = self.header.create_window(0, 0, window=self.search_entry,
                                                     anchor="w", width=10, height=28)
        self.header.bind("<Configure>", self._draw_header)
        self._draw_header()

    def _draw_header(self, _event=None) -> None:
        c = self.header
        w = max(c.winfo_width(), 1150)
        c.delete("all")
        steps = max(1, HEADER_H // 2)
        for i in range(steps):
            t = i / max(1, steps - 1)
            color = mix(HEADER_RIGHT, HEADER_LEFT, t)
            c.create_line(0, i * 2, w, i * 2, fill=color, width=2, tags="bg")
            c.create_line(0, i * 2 + 1, w, i * 2 + 1, fill=color, width=1, tags="bg")
        # 装饰圆
        c.create_oval(w - 260, -70, w + 60, 130, outline="", fill=mix(HEADER_RIGHT, "#ffffff", 0.10))
        c.create_oval(w - 470, 40, w - 330, 180, outline="", fill=mix(HEADER_LEFT, "#ffffff", 0.06))
        c.tag_lower("bg")

        # 左侧标识与标题
        round_rect(c, 20, 22, 64, 66, 13, fill="#ffffff", outline="")
        c.create_text(42, 44, text="CTF", fill=PRIMARY, font=("Microsoft YaHei UI", 12, "bold"))
        c.create_text(80, 34, text=APP_NAME, anchor="w", fill="#ffffff", font=FONT_TITLE)
        c.create_text(81, 59, text="Misc · 取证 · 隐写 —— 拖入文件，一键找出 flag",
                      anchor="w", fill="#dbeafe", font=FONT_SMALL)
        round_rect(c, 80 + 176, 33, 80 + 232, 51, 8,
                   fill=mix("#ffffff", HEADER_RIGHT, 0.16), outline="")
        c.create_text(80 + 204, 42, text=f"v{__version__}", fill="#ffffff",
                      font=("Microsoft YaHei UI", 8))

        # 右侧：搜索框 + 两个按钮
        x2 = w - 22
        auto_x2 = x2
        auto_x1 = auto_x2 - 152
        open_x2 = auto_x1 - 10
        open_x1 = open_x2 - 104
        search_x2 = open_x1 - 12
        search_x1 = search_x2 - 236
        round_rect(c, search_x1, 26, search_x2, 62, 10, fill="#ffffff", outline="")
        c.create_text(search_x1 + 14, 44, text="⌕", anchor="w", fill="#94a3b8",
                      font=("Segoe UI Symbol", 13))
        c.create_text(search_x1 + 34, 44, text="搜索功能", anchor="w", fill="#94a3b8",
                      font=FONT_SMALL)
        self._search_win = c.create_window(
            search_x1 + 92, 44, window=self.search_entry, anchor="w",
            width=max(60, search_x2 - search_x1 - 104), height=28)

        round_rect(c, open_x1, 26, open_x2, 62, 10, fill=mix("#ffffff", HEADER_RIGHT, 0.14),
                   outline="#ffffff", width=1)
        c.create_text((open_x1 + open_x2) / 2, 44, text="打开文件", fill="#ffffff",
                      font=FONT_SMALL)
        round_rect(c, auto_x1, 26, auto_x2, 62, 10, fill="#ffffff", outline="")
        c.create_text((auto_x1 + auto_x2) / 2, 44, text="▶ 全自动分析", fill=PRIMARY,
                      font=("Microsoft YaHei UI", 9, "bold"))
        # 用透明矩形承载点击区域
        for x1, x2, tag in ((open_x1, open_x2, "hdr_open"), (auto_x1, auto_x2, "hdr_auto")):
            rid = c.create_rectangle(x1, 26, x2, 62, outline="", fill="", tags=("hdr_hit", tag))
            c.tag_bind(tag, "<Button-1>", lambda _e, f=(self.pick_file_and_set if tag == "hdr_open" else self.run_auto): f())
            c.tag_bind(tag, "<Enter>", lambda _e: c.configure(cursor="hand2"))
            c.tag_bind(tag, "<Leave>", lambda _e: c.configure(cursor=""))
            c.tag_raise(rid)
        c.tag_raise(self._search_win)

    # ------------------------------------------------------------------ #
    def _statusbar(self) -> None:
        bar = tk.Frame(self, bg=SURFACE, height=36, highlightbackground=BORDER,
                       highlightthickness=1)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self.lbl_status = tk.Label(bar, text="就绪", bg=SURFACE, fg="#475569",
                                   font=FONT_SMALL)
        self.lbl_status.pack(side="left", padx=16)
        self.lbl_file = tk.Label(bar, text="未选择文件", bg=PRIMARY_SOFT, fg=PRIMARY,
                                 font=FONT_SMALL, padx=10, pady=2)
        self.lbl_file.pack(side="right", padx=14)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=150)
        self.progress.pack(side="right", padx=(0, 10), pady=6)
        self.lbl_hint = tk.Label(bar, text="拖入题目文件即可开始", bg=SURFACE, fg="#94a3b8",
                                 font=FONT_SMALL)
        self.lbl_hint.pack(side="right", padx=10)

    # ------------------------------------------------------------------ #
    def _body(self) -> None:
        body = tk.Frame(self, bg=PAGE_BG)
        body.pack(fill="both", expand=True, padx=14, pady=(12, 10))
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        left = _surface(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        head = tk.Frame(left, bg=SURFACE)
        head.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(head, text="工具卡片", bg=SURFACE, fg=INK,
                 font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        self.lbl_cards = tk.Label(head, text="", bg=PRIMARY_SOFT, fg=PRIMARY,
                                  font=theme.FONT_TINY, padx=8, pady=1)
        self.lbl_cards.pack(side="left", padx=8)
        tk.Label(head, text="点击卡片即执行；搜索框可按功能过滤", bg=SURFACE, fg=MUTED,
                 font=FONT_SMALL).pack(side="right")
        self.card_list = cards.CardList(left)
        self.card_list.pack(fill="both", expand=True, padx=(6, 4), pady=(0, 8))
        self.card_list.build(actions.build_sections(self))
        self._total_cards = len(self.card_list._cards)
        self.lbl_cards.configure(text=f"{self._total_cards} 项功能")

        right = tk.Frame(body, bg=PAGE_BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        # flag 候选
        flagcard = _surface(right)
        flagcard.grid(row=0, column=0, sticky="ew")
        fh = tk.Frame(flagcard, bg=SURFACE)
        fh.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(fh, text="●", bg=SURFACE, fg=SUCCESS,
                 font=("Microsoft YaHei UI", 9)).pack(side="left")
        tk.Label(fh, text="flag 候选", bg=SURFACE, fg=INK,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(side="left", padx=(6, 6))
        self.lbl_flag_count = tk.Label(fh, text="0", bg=SUCCESS_SOFT, fg=SUCCESS,
                                       font=theme.FONT_TINY, padx=8, pady=1)
        self.lbl_flag_count.pack(side="left")
        self.btn_copy = ttk.Button(fh, text="复制", style="Soft.TButton",
                                   command=self._copy_flag)
        self.btn_copy.pack(side="right")
        self.flags = tk.Listbox(flagcard, font=("Consolas", 11), height=4, bd=0,
                                highlightthickness=0, activestyle="none",
                                exportselection=False, bg="#fbfdff", fg="#065f46",
                                selectbackground="#d1fae5", selectforeground="#064e3b")
        self.flags.pack(fill="x", padx=12, pady=(0, 12))
        self.flags.bind("<Double-Button-1>", self._copy_flag)
        self.flags.bind("<Return>", self._copy_flag)

        # 结果 / 日志
        rescard = _surface(right)
        rescard.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        rh = tk.Frame(rescard, bg=SURFACE)
        rh.pack(fill="x", padx=14, pady=(10, 4))
        self.tab_result = tk.Label(rh, text="结果", bg=PRIMARY_SOFT, fg=PRIMARY,
                                   font=("Microsoft YaHei UI", 9, "bold"), padx=10, pady=3)
        self.tab_result.pack(side="left")
        self.tab_log = tk.Label(rh, text="日志", bg=SURFACE, fg=MUTED,
                                font=FONT_SMALL, padx=10, pady=3)
        self.tab_log.pack(side="left", padx=4)
        self.tab_meta = tk.Label(rh, text="题面", bg=SURFACE, fg=MUTED,
                                 font=FONT_SMALL, padx=10, pady=3)
        self.tab_meta.pack(side="left", padx=4)
        for wdg, name in ((self.tab_result, "result"), (self.tab_log, "log"),
                          (self.tab_meta, "meta")):
            wdg.bind("<Button-1>", lambda _e, n=name: self._switch_view(n))
        self.result_title = tk.Label(rh, text="", bg=SURFACE, fg=MUTED,
                                     font=FONT_SMALL, anchor="e")
        self.result_title.pack(side="right")

        holder = tk.Frame(rescard, bg=SURFACE)
        holder.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        holder.columnconfigure(0, weight=1)
        holder.rowconfigure(0, weight=1)
        self._result_wrap = tk.Frame(holder, bg=SURFACE)
        self._log_wrap = tk.Frame(holder, bg=SURFACE)
        self._meta_wrap = tk.Frame(holder, bg=SURFACE)
        for wrap in (self._result_wrap, self._log_wrap, self._meta_wrap):
            wrap.grid(row=0, column=0, sticky="nsew")

        self.result_text = self._make_text(self._result_wrap)
        self.log_text = self._make_text(self._log_wrap)
        self.meta_text = self._make_text(self._meta_wrap)
        self._meta_ready = False
        self._switch_view("result")

    def _make_text(self, parent) -> tk.Text:
        text = tk.Text(parent, wrap="word", font=FONT_MONO, width=1, bd=0, highlightthickness=0,
                       bg=SURFACE, fg="#1e293b", padx=6, pady=6,
                       spacing1=2, spacing3=3, insertbackground=PRIMARY,
                       selectbackground="#e0e7ff", selectforeground=INK)
        sb = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return text

    def _switch_view(self, name: str) -> None:
        self._view = name
        wraps = {"result": self._result_wrap, "log": self._log_wrap, "meta": self._meta_wrap}
        wraps.get(name, self._result_wrap).lift()
        for wdg, key in ((self.tab_result, "result"), (self.tab_log, "log"),
                         (self.tab_meta, "meta")):
            active = key == name
            wdg.configure(bg=PRIMARY_SOFT if active else SURFACE,
                          fg=PRIMARY if active else MUTED,
                          font=("Microsoft YaHei UI", 9, "bold") if active else FONT_SMALL)

    def show_meta(self, meta: dict | None) -> None:
        """题库题面：赛制 / 题目 / 描述 / flag 格式 / 附件。"""
        self.meta_text.delete("1.0", "end")
        if not meta:
            self.meta_text.insert("end", "当前分析对象不在内置题库中。\n\n"
                                          "把题库里的题目目录拖进来，这里会显示题面与 flag 格式。")
            self._meta_ready = False
            return
        lines = [f"{meta.get('ctf', '')} {meta.get('year', '')} · {meta.get('category', '')}",
                 f"{meta.get('name', '')}", ""]
        desc = (meta.get("description") or "").strip()
        lines.append(desc or "（题面为空）")
        fmt = (meta.get("known_flag") or "").strip()
        if fmt:
            lines += ["", f"flag 格式：{fmt}"]
        files = meta.get("files") or []
        if files:
            lines += ["", "附件："] + [f"  · {f}" for f in files[:20]]
        self.meta_text.insert("end", "\n".join(lines))
        self._meta_ready = True

    def _warm_ocr(self) -> None:
        """后台预加载 OCR 模型，避免第一张图等十几秒。"""
        def job():
            try:
                from .. import ocr
                if ocr.available():
                    ocr._get_engine()
            except Exception:
                pass
        threading.Thread(target=job, daemon=True).start()

    def _bind_drop(self) -> None:
        try:
            import windnd
            windnd.hook_dropfiles(self, func=self._on_drop)
        except Exception:
            pass

    def _on_drop(self, files) -> None:
        paths = []
        for f in files:
            p = f.decode("gbk", "ignore") if isinstance(f, bytes) else str(f)
            if p and os.path.exists(p):
                paths.append(p)
        if not paths:
            return
        self.set_current_file(paths[0])
        self.status_set(f"已接收 {len(paths)} 项，正在自动分析…")
        self.run_pipeline(paths=paths)

    # ------------------------------------------------------------------ #
    # 对外接口（actions.py 使用）
    # ------------------------------------------------------------------ #
    def pick_file(self, prompt: str = "选择文件", types=None) -> str | None:
        path = filedialog.askopenfilename(title=prompt, filetypes=types or [("全部文件", "*.*")])
        return path or None

    def pick_file_and_set(self) -> None:
        path = self.pick_file("选择题目文件")
        if path:
            self.set_current_file(path)
            self.run_pipeline(on_current_file=True)

    def set_current_file(self, path: str) -> None:
        self.current_file = path
        name = os.path.basename(path.rstrip("\\/")) or path
        self.lbl_file.configure(text=name if len(name) <= 28 else name[:26] + "…")

    def status_set(self, text: str) -> None:
        self.lbl_status.configure(text=text)

    def log(self, msg: str) -> None:
        self._log_queue.put(msg)
        if not self._drain_scheduled:
            self._drain_scheduled = True
            self.after(120, self._drain_log)

    def _drain_log(self) -> None:
        self._drain_scheduled = False
        lines = []
        while True:
            try:
                lines.append(self._log_queue.get_nowait())
            except queue.Empty:
                break
        if lines:
            self.log_text.insert("end", "\n".join(lines) + "\n")
            self.log_text.see("end")
        if self.busy:
            self.after(200, self._drain_log)

    def clear_result(self) -> None:
        self.result_text.delete("1.0", "end")
        self.flags.delete(0, "end")
        self.result_title.configure(text="")
        self.lbl_flag_count.configure(text="0")
        try:
            self.show_meta(None)
        except Exception:
            pass

    def show_result(self, title: str, text: str, flags=None, items=None) -> None:
        self.result_title.configure(text=title)
        self._switch_view("result")
        self.result_text.delete("1.0", "end")
        if items:
            for k, v in items:
                self.result_text.insert("end", f"{k}: {v}\n")
            self.result_text.insert("end", "\n")
        self.result_text.insert("end", text)
        self.flags.delete(0, "end")
        seen = set()
        for f in flags or []:
            if f and f not in seen:
                seen.add(f)
                self.flags.insert("end", f"  {f}")
        self.lbl_flag_count.configure(text=str(len(seen)))
        self.status_set(f"{title} 完成" + (f"，命中 {len(seen)} 个 flag 候选" if seen else ""))

    def show_busy(self, busy: bool) -> None:
        self.busy = busy
        if busy:
            self.progress.start(12)
            self.lbl_hint.configure(text="分析中…")
        else:
            self.progress.stop()
            self.lbl_hint.configure(text="拖入题目文件即可开始")

    def worker(self, fn, on_done=None, on_error=None) -> None:
        def target():
            try:
                result = fn()
            except Exception as exc:  # noqa: BLE001
                if on_error:
                    self.after(0, lambda: on_error(exc))
                else:
                    self.after(0, lambda: self.show_result("出错了", str(exc)))
                return
            if on_done:
                self.after(0, lambda: on_done(result))
        threading.Thread(target=target, daemon=True).start()

    def stop(self) -> None:
        self.cancel_flag.set()
        self.status_set("正在停止…")

    def _add_paths(self, paths) -> None:
        """把外部提取结果加入分析队列（高级面板 / 题库使用）。"""
        paths = [p for p in paths if p and os.path.exists(p)]
        if not paths:
            return
        self.set_current_file(paths[0])
        self.run_pipeline(paths=paths)

    def run_auto(self) -> None:
        """顶部 / 高级面板的“开始”：有历史路径就跑历史，否则选文件。"""
        if self.last_paths:
            self.run_pipeline(paths=self.last_paths)
        elif self.current_file:
            self.run_pipeline(on_current_file=True)
        else:
            self.pick_file_and_set()

    # ------------------------------------------------------------------ #
    def run_pipeline(self, paths=None, on_current_file: bool = False) -> None:
        from ..pipeline import Options, Pipeline
        if on_current_file:
            path = self.current_file
            if not path:
                path = self.pick_file("选择题目文件")
                if not path:
                    return
                self.set_current_file(path)
            paths = [path]
        paths = [p for p in (paths or []) if os.path.exists(p)]
        if not paths:
            return
        self.last_paths = paths
        self.clear_result()
        self.cancel_flag.clear()
        self.show_busy(True)
        self.status_set("分析中…")
        self.log(f"===== 开始分析 {len(paths)} 项 =====")

        def job():
            pipe = Pipeline(Options(deep=True, time_budget=600, decode_budget=25),
                            progress=self.log, cancel=self.cancel_flag)
            return pipe.run_paths(paths)

        def done(report):
            self.show_busy(False)
            self.report = report
            meta = getattr(report, "meta", None)
            name = (meta or {}).get("name") or os.path.basename(paths[0].rstrip("\\/")) or paths[0]
            case = report_mod.cases_from_pipeline(report, name=name)
            self.add_case(case)
            self.show_meta(meta)
            if meta:
                self.status_set(f"题库题目：{meta.get('ctf', '')} / {name}")
            if case.flags:
                self.show_result(f"✅ 解出：{name}", report_mod.build_quick_report(case),
                                 flags=case.flags)
            else:
                lines = []
                for f in report.findings:
                    if f.kind in ("warn", "data"):
                        lines.append(f"[{f.kind}] {f.title}   <- {f.source}")
                        if f.detail:
                            lines.append("      " + f.detail[:200].replace("\n", "\n      "))
                lines = lines or ["没有产生实质发现（文件可能只是普通内容）"]
                lines += ["", "提示：展开左侧对应分类用专项卡片手工深挖；"
                              "图片/音频题先看“可视化排查 / 频谱图”。"]
                self.show_result(f"未自动解出：{name}", "\n".join(lines))
                self.status_set("没有自动解出，请按提示用专项卡片继续")
            outdir = getattr(report, "outdir", "") or ""
            if outdir and os.path.isdir(outdir):
                self.result_text.insert("end", f"\n\n生成的文件都在：{outdir}\n")
                self.status_set(f"完成。生成的文件：{outdir}")
                if not getattr(self, "_opened_outdir", False):
                    self._opened_outdir = True
                    try:
                        import subprocess
                        subprocess.Popen(["explorer", outdir])
                    except Exception:
                        pass

        self.worker(job, on_done=done)

    def open_tool(self, key: str) -> None:
        mapping = {"codec": tabs.CodecTab, "image": tabs.ImageTab, "archive": tabs.ArchiveTab,
                   "audio": tabs.AudioTab, "qr": tabs.QrTab, "misc": tabs.MiscTab,
                   "library": tabs.LibraryTab}
        cls = mapping.get(key)
        if cls is None:
            return
        titles = {"codec": "编码 / 密码工具台", "image": "图片工具", "archive": "压缩包工具",
                  "audio": "音频工具", "qr": "二维码工具", "misc": "其他技巧",
                  "library": "内置题库（159 道公开题目）"}
        win = tk.Toplevel(self)
        win.title(titles.get(key, key))
        win.geometry("1120x780" if key != "library" else "1200x800")
        win.configure(bg=PAGE_BG)
        frame = ttk.Frame(win, padding=10)
        frame.pack(fill="both", expand=True)
        tab = cls(self, frame)
        tab.frame.pack(fill="both", expand=True)
        if hasattr(tab, "on_activate"):
            try:
                tab.on_activate()
            except Exception:
                pass
        self._tool_refs.append(tab)

    def open_advanced(self) -> None:
        win = tk.Toplevel(self)
        win.title("高级工具面板 —— 全部专项工具")
        win.geometry("1260x840")
        win.configure(bg=PAGE_BG)
        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        built = {}
        for key, cls, title in (("codec", tabs.CodecTab, "编码 / 密码"),
                                ("image", tabs.ImageTab, "图片隐写"),
                                ("archive", tabs.ArchiveTab, "压缩包"),
                                ("audio", tabs.AudioTab, "音频"),
                                ("qr", tabs.QrTab, "二维码"),
                                ("misc", tabs.MiscTab, "其他技巧"),
                                ("library", tabs.LibraryTab, "题库")):
            tab = cls(self, nb)
            nb.add(tab.frame, text=title)
            built[key] = tab
            self._tool_refs.append(tab)

        def on_change(_e=None):
            cur = nb.nametowidget(nb.select())
            for t in built.values():
                if t.frame is cur and hasattr(t, "on_activate"):
                    try:
                        t.on_activate()
                    except Exception:
                        pass
        nb.bind("<<NotebookTabChanged>>", on_change)

    def add_case(self, case) -> None:
        for i, old in enumerate(self.cases):
            if old.name == case.name and old.category == case.category:
                self.cases[i] = case
                return
        self.cases.append(case)

    def export_writeup(self) -> None:
        if not self.cases:
            messagebox.showinfo("提示", "还没有解题记录。先跑一次「全自动分析」或「Web 一键自动解题」。")
            return
        dialog = tk.Toplevel(self)
        dialog.title("导出解题报告（writeup）")
        dialog.configure(bg=PAGE_BG)
        dialog.transient(self)
        body = ttk.Frame(dialog, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="导出 writeup（格式对齐 CTF 报告模板）",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(0, 10))
        ttk.Label(body, text="战队名称", style="Muted.TLabel").pack(anchor="w")
        team = ttk.Entry(body, width=44)
        team.insert(0, "XXX战队")
        team.pack(fill="x", pady=(0, 8))
        ttk.Label(body, text="排名（可留空）", style="Muted.TLabel").pack(anchor="w")
        ranking = ttk.Entry(body, width=44)
        ranking.pack(fill="x", pady=(0, 12))
        info = tk.Text(body, height=8, width=72, bd=0, highlightthickness=1,
                       highlightbackground=BORDER, bg="#fbfdff", padx=10, pady=8)
        info.insert("1.0", "本报告只保留“解出 flag 的关键步骤”，"
                           "自动忽略没有产生结果的探测过程。\n\n"
                           f"当前已记录 {len(self.cases)} 道题，"
                           f"其中解出 {sum(1 for c in self.cases if c.flags)} 道。")
        info.configure(state="disabled")
        info.pack(fill="both", expand=True)

        def do_export():
            writeup = report_mod.build_writeup(self.cases, team=team.get().strip() or "XXX战队",
                                               ranking=ranking.get().strip())
            path = filedialog.asksaveasfilename(title="保存 writeup", defaultextension=".md",
                                                initialfile="writeup.md",
                                                filetypes=[("Markdown", "*.md"), ("文本", "*.txt")])
            if not path:
                return
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(writeup)
            dialog.destroy()
            self.show_result("解题报告已导出", writeup[:4000])
            messagebox.showinfo("完成", f"writeup 已保存到\n{path}")
        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="导出", style="Accent.TButton", command=do_export).pack(side="right")
        ttk.Button(btns, text="取消", command=dialog.destroy).pack(side="right", padx=8)

    def run_selftest_dialog(self) -> None:
        from ..__main__ import run_selftest
        self.show_busy(True)
        self.status_set("自检中…")

        def job():
            code = run_selftest()
            report = os.path.join(resource_dir(), "自检结果.txt")
            try:
                with open(report, encoding="utf-8") as fh:
                    return code, fh.read()
            except OSError:
                return code, "（自检报告读取失败）"

        def done(res):
            self.show_busy(False)
            code, text = res
            self.show_result("内置自检" + ("（全部通过）" if code == 0 else "（有失败项）"), text)

        self.worker(job, on_done=done)

    def _copy_flag(self, _event=None) -> None:
        sel = self.flags.curselection()
        if sel:
            value = self.flags.get(sel[0]).strip()
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_set(f"已复制：{value}")

    def export_report(self) -> None:
        if not self.report:
            messagebox.showinfo("提示", "还没有分析结果")
            return
        path = filedialog.asksaveasfilename(title="保存分析报告", defaultextension=".md",
                                            initialfile="CTF分析报告.md",
                                            filetypes=[("Markdown", "*.md"), ("文本", "*.txt")])
        if not path:
            return
        lines = [f"# {APP_NAME} 分析报告", "", f"- 分析对象：{len(self.last_paths)} 项",
                 f"- 用时：{self.report.seconds:.1f} 秒", "", "## flag 候选"]
        for hit in self.report.flags:
            lines.append(f"- `{hit.value}`（{hit.source}，置信度 {hit.score:.0f}）")
        lines.append("\n## 分析发现")
        for f in self.report.findings:
            lines.append(f"### [{f.kind}] {f.title}\n- 来源：{f.source}\n\n```\n{f.detail[:1500]}\n```\n")
        lines.append("\n## 处理日志\n```\n" + "\n".join(self.report.log) + "\n```")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        messagebox.showinfo("完成", f"报告已保存到\n{path}")


def main() -> int:
    app = App()
    if len(sys.argv) > 1:
        targets = [p for p in sys.argv[1:] if os.path.exists(p)]
        if targets:
            app.set_current_file(targets[0])
            app.after(500, lambda: app.run_pipeline(paths=targets))
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())