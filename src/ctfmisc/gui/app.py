"""CTF 杂项解题助手 —— 卡片式桌面主界面。"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import APP_NAME, __version__, report as report_mod
from . import actions, cards, tabs

FONT = ("Microsoft YaHei UI", 10)
FONT_SMALL = ("Microsoft YaHei UI", 9)
FONT_MONO = ("Consolas", 10)
PAGE_BG = "#f3f4f6"


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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME}  v{__version__}")
        self.geometry("1280x840")
        self.minsize(1120, 720)
        self.configure(bg=PAGE_BG)
        try:
            self.iconbitmap(default=asset_path("app.ico"))
        except Exception:
            pass
        self.current_file: str | None = None
        self.cancel_flag = threading.Event()
        self.report = None
        self.last_paths: list[str] = []
        self.busy = False
        self._tool_refs = []
        self._log_queue: queue.Queue[str] = queue.Queue()
        self.cases: list[report_mod.Case] = []
        self._drain_scheduled = False
        self._style()
        self._toolbar()
        self._body()
        self._statusbar()
        self._bind_drop()
        self.after(300, self._drain_log)

    # ------------------------------------------------------------------ #
    def _style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
        style.configure(".", font=FONT)
        style.configure("TButton", padding=(10, 5))
        style.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TEntry", padding=4)
        self.option_add("*Font", FONT)

    def _toolbar(self) -> None:
        bar = tk.Frame(self, bg="#ffffff", height=58)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text=APP_NAME, bg="#ffffff", fg="#111827",
                 font=("Microsoft YaHei UI", 13, "bold")).pack(side="left", padx=(16, 4))
        tk.Label(bar, text=f"v{__version__}", bg="#ffffff", fg="#9ca3af",
                 font=FONT_SMALL).pack(side="left", pady=(6, 0))
        ttk.Button(bar, text="打开文件", command=self.pick_file_and_set).pack(side="left", padx=(18, 4))
        ttk.Button(bar, text="▶ 全自动分析", style="Accent.TButton",
                   command=lambda: self.run_pipeline(on_current_file=True)).pack(side="left", padx=4)
        self.btn_stop = ttk.Button(bar, text="■ 停止", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        ttk.Button(bar, text="导出报告", command=self.export_report).pack(side="right", padx=16)
        self.search_var = tk.StringVar()
        entry = ttk.Entry(bar, textvariable=self.search_var, width=22)
        entry.pack(side="right", padx=(4, 10))
        entry.bind("<KeyRelease>", lambda _e: self.card_list.filter(self.search_var.get()))
        tk.Label(bar, text="搜索功能：", bg="#ffffff", fg="#6b7280", font=FONT_SMALL).pack(side="right")
        self.lbl_file = tk.Label(bar, text="当前文件：（把文件拖进来）", bg="#ffffff", fg="#2563eb",
                                 font=FONT_SMALL)
        self.lbl_file.pack(side="right", padx=(10, 20))

    def _body(self) -> None:
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=10, pady=(8, 4))

        left = tk.Frame(pane, bg=PAGE_BG)
        pane.add(left, weight=3)
        tip = tk.Label(left, text="选择下面任意一张卡片开始。多数情况点第一张「全自动分析」就行。",
                       bg=PAGE_BG, fg="#6b7280", font=FONT_SMALL, anchor="w")
        tip.pack(fill="x", padx=14, pady=(6, 0))
        self.card_list = cards.CardList(left)
        self.card_list.pack(fill="both", expand=True)
        self.card_list.build(actions.build_sections(self))

        right = tk.Frame(pane)
        pane.add(right, weight=4)
        flagbox = ttk.LabelFrame(right, text="flag 候选（双击复制）", padding=6)
        flagbox.pack(fill="x")
        self.flags = tk.Listbox(flagbox, font=("Consolas", 11), activestyle="none", height=5,
                                exportselection=False)
        self.flags.pack(side="left", fill="both", expand=True)
        self.flags.bind("<Double-Button-1>", self._copy_flag)
        ttk.Button(flagbox, text="复制", width=6, command=self._copy_flag).pack(side="right", padx=(6, 0), fill="y")

        self.result_box = ttk.LabelFrame(right, text="结果", padding=6)
        self.result_box.pack(fill="both", expand=True, pady=(6, 0))
        self.result_title = ttk.Label(self.result_box, text="", font=("Microsoft YaHei UI", 10, "bold"))
        self.result_title.pack(anchor="w")
        wrap = ttk.Frame(self.result_box)
        wrap.pack(fill="both", expand=True)
        self.result_text = tk.Text(wrap, wrap="word", font=FONT_MONO, undo=True)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=sb.set)
        self.result_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        logbox = ttk.LabelFrame(right, text="日志", padding=6)
        logbox.pack(fill="both", expand=True, pady=(6, 0))
        self.log_text = tk.Text(logbox, height=7, wrap="word", font=FONT_SMALL)
        self.log_text.pack(fill="both", expand=True)

    def _statusbar(self) -> None:
        bar = tk.Frame(self, bg="#ffffff", height=30)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        self.lbl_status = tk.Label(bar, text="就绪", bg="#ffffff", fg="#374151", font=FONT_SMALL)
        self.lbl_status.pack(side="left", padx=14)
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right", padx=14, pady=4)

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
        self.lbl_file.configure(text=f"当前文件：{os.path.basename(path)}")

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

    def show_result(self, title: str, text: str, flags=None, items=None) -> None:
        self.result_title.configure(text=title)
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
                self.flags.insert("end", f)
        self.status_set(f"{title} 完成" + (f"，命中 {len(seen)} 个 flag 候选" if seen else ""))

    def show_busy(self, busy: bool) -> None:
        self.busy = busy
        self.btn_stop.configure(state="normal" if busy else "disabled")
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

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
            name = os.path.basename(paths[0].rstrip("\\/")) or paths[0]
            case = report_mod.cases_from_pipeline(report, name=name)
            self.add_case(case)
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
            import os as _os
            if outdir and _os.path.isdir(outdir):
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
        win.geometry("1080x760" if key != "library" else "1180x780")
        win.configure(bg=PAGE_BG)
        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
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
        win.geometry("1240x820")
        win.configure(bg=PAGE_BG)
        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
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
        """记录一道题的解题结果（供导出 writeup 用）。"""
        for i, old in enumerate(self.cases):
            if old.name == case.name and old.category == case.category:
                self.cases[i] = case
                return
        self.cases.append(case)

    def export_writeup(self) -> None:
        """按 CTF 报告模板导出 writeup（只含解出 flag 的步骤）。"""
        if not self.cases:
            messagebox.showinfo("提示", "还没有解题记录。先跑一次「全自动分析」或「Web 一键自动解题」。")
            return
        dialog = tk.Toplevel(self)
        dialog.title("导出解题报告（writeup）")
        dialog.configure(bg=PAGE_BG)
        dialog.transient(self)
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="导出 writeup（格式对齐 CTF 报告模板）",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(body, text="战队名称").pack(anchor="w")
        team = ttk.Entry(body, width=44)
        team.insert(0, "XXX战队")
        team.pack(fill="x", pady=(0, 6))
        ttk.Label(body, text="排名（可留空）").pack(anchor="w")
        ranking = ttk.Entry(body, width=44)
        ranking.pack(fill="x", pady=(0, 10))
        info = tk.Text(body, height=8, width=72)
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
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="导出", command=do_export).pack(side="right")
        ttk.Button(btns, text="取消", command=dialog.destroy).pack(side="right", padx=6)

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
            self.clipboard_clear()
            self.clipboard_append(self.flags.get(sel[0]))
            self.status_set("已复制到剪贴板")

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
            app.after(400, lambda: app.run_pipeline(paths=targets))
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
