"""各个功能页的具体实现。"""

from __future__ import annotations

import io
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import archive, audio, carve, codec, filetypes, image, misc, pcap
from ..flags import find_flags
from ..pipeline import Item, Options, Pipeline

FONT_SMALL = ("Microsoft YaHei UI", 9)
FONT_MONO = ("Consolas", 10)


def make_text(parent, height=10, mono=True, width=None):
    frame = ttk.Frame(parent)
    text = tk.Text(frame, height=height, wrap="word", undo=True,
                   font=FONT_MONO if mono else FONT_SMALL, width=width)
    sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=sb.set)
    text.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, text


def set_text(widget: tk.Text, content: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)


def copy_to_clipboard(app, value: str) -> None:
    app.clipboard_clear()
    app.clipboard_append(value)
    app.status_set("已复制到剪贴板")


# --------------------------------------------------------------------------- #
class AutoTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self.queue: queue.Queue[str] = queue.Queue()
        self._drain_scheduled = False

        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Label(top, text="把题目文件/文件夹加进左侧列表，然后点“一键自动分析”。"
                            "引擎会依次做：类型识别 → 编码解码 → 隐写提取 → 解包/雕复 → 递归展开 → flag 归集").pack(side="left")
        ttk.Button(top, text="▶ 开始", command=self.app.run_auto).pack(side="right")
        ttk.Button(top, text="清空结果", command=self.clear).pack(side="right", padx=6)

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)

        left = ttk.LabelFrame(pane, text="分析发现", padding=6)
        pane.add(left, weight=3)
        cols = ("kind", "source", "title")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        for col, txt, w in (("kind", "类型", 60), ("source", "来源", 220), ("title", "发现", 320)):
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor="w")
        tsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)
        self.tree.tag_configure("warn", foreground="#b8860b")
        self.tree.tag_configure("data", foreground="#0a6")

        right = ttk.Frame(pane)
        pane.add(right, weight=2)
        flagbox = ttk.LabelFrame(right, text="flag 候选（双击复制）", padding=6)
        flagbox.pack(fill="both", expand=True)
        self.flags = tk.Listbox(flagbox, font=("Consolas", 11), activestyle="none", height=8)
        self.flags.pack(fill="both", expand=True)
        self.flags.bind("<Double-Button-1>", self._copy_flag)
        ttk.Button(flagbox, text="复制选中", command=self._copy_flag).pack(fill="x", pady=3)

        detail = ttk.LabelFrame(right, text="详情", padding=6)
        detail.pack(fill="both", expand=True, pady=(6, 0))
        dframe, self.detail = make_text(detail, height=8, mono=True)
        dframe.pack(fill="both", expand=True)

        logbox = ttk.LabelFrame(self.frame, text="处理日志", padding=6)
        logbox.pack(fill="both", expand=True)
        lframe, self.log = make_text(logbox, height=8, mono=True)
        lframe.pack(fill="both", expand=True)
        self._findings: list = []

    # ------------------------------------------------------------------ #
    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.flags.delete(0, "end")
        set_text(self.detail, "")
        set_text(self.log, "")
        self._findings = []

    def log_line(self, msg: str) -> None:
        self.queue.put(msg)
        if not self._drain_scheduled:
            self._drain_scheduled = True
            self.app.after(120, self._drain)

    def _drain(self) -> None:
        self._drain_scheduled = False
        lines = []
        while True:
            try:
                lines.append(self.queue.get_nowait())
            except queue.Empty:
                break
        if lines:
            self.log.configure(state="normal")
            self.log.insert("end", "\n".join(lines) + "\n")
            self.log.see("end")
            self.app.status_set(lines[-1][:90])

    def start(self, paths: list[str]) -> None:
        self.clear()
        self.app.cancel_flag.clear()
        self.app.show_busy(True)
        options = Options(deep=True, time_budget=300, decode_budget=25)

        def job():
            pipe = Pipeline(options, progress=self.log_line, cancel=self.app.cancel_flag)
            report = pipe.run_paths(list(paths))
            return report

        self.app.worker(job, on_done=self.finish, on_error=self._error)

    def _error(self, exc: Exception) -> None:
        self.app.show_busy(False)
        self.log_line(f"[!] 分析出错：{exc}")
        messagebox.showerror("分析出错", str(exc))

    def finish(self, report) -> None:
        self.app.show_busy(False)
        self.app.report = report
        self._findings = report.findings
        for i, f in enumerate(report.findings):
            tag = "warn" if f.kind == "warn" else ("data" if f.kind == "data" else "")
            self.tree.insert("", "end", iid=str(i), values=(f.kind, f.source, f.title), tags=(tag,))
        for hit in report.flags:
            self.flags.insert("end", f"{hit.value}    [{hit.score:.0f}] {hit.source}")
        if report.flags:
            best = report.flags[0]
            self.app.status_set(f"完成：最可能的 flag 是 {best.value}")
        else:
            self.app.status_set("完成：没有直接命中 flag，请查看“分析发现”里的可疑结果")

    def _show_detail(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        f = self._findings[idx]
        set_text(self.detail, f"{f.title}\n来源：{f.source}\n\n{f.detail}")

    def _copy_flag(self, _event=None) -> None:
        sel = self.flags.curselection()
        if sel:
            value = self.flags.get(sel[0]).split("    [")[0]
            copy_to_clipboard(self.app, value)


# --------------------------------------------------------------------------- #
class CodecTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self._results: list[tuple[str, str, float]] = []

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True)

        left = ttk.LabelFrame(pane, text="输入（可直接粘贴密文 / 拖入 .txt 文件）", padding=6)
        pane.add(left, weight=1)
        lf, self.input = make_text(left, height=18, mono=True)
        lf.pack(fill="both", expand=True)
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=5)
        ttk.Button(btns, text="尝试所有解码", command=self.decode_all).pack(side="left")
        ttk.Button(btns, text="多层自动解码", command=self.decode_deep).pack(side="left", padx=5)
        ttk.Button(btns, text="读入文件", command=self.load_file).pack(side="left")
        ttk.Button(btns, text="清空", command=lambda: set_text(self.input, "")).pack(side="left", padx=5)

        enc = ttk.Frame(left)
        enc.pack(fill="x")
        ttk.Label(enc, text="编码为：").pack(side="left")
        for name, fn in (("Base64", self._to_b64), ("Hex", self._to_hex), ("URL", self._to_url),
                         ("反转", self._to_rev), ("ROT13", self._to_rot13)):
            ttk.Button(enc, text=name, width=8, command=fn).pack(side="left", padx=2)

        right = ttk.LabelFrame(pane, text="解码结果（双击查看/复制全文）", padding=6)
        pane.add(right, weight=2)
        cols = ("method", "value", "score")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", height=10)
        for col, txt, w in (("method", "方法", 150), ("value", "结果", 460), ("score", "评分", 60)):
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor="w")
        tsb = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tsb.pack(side="right", fill="y")
        self.tree.bind("<Double-Button-1>", self._copy_row)
        df, self.detail = make_text(right, height=14, mono=True)
        df.pack(fill="both", expand=True, pady=(6, 0))
        ttk.Label(right, text="提示：结果按“像不像有意义内容”排序；多层链会显示 A → B → C 的完整路径").pack(anchor="w")

    def on_activate(self) -> None:
        pass

    # ------------------------------------------------------------------ #
    def _input_text(self) -> str:
        return self.input.get("1.0", "end").strip()

    def load_file(self) -> None:
        path = filedialog.askopenfilename(title="选择文本文件")
        if not path:
            return
        try:
            data = open(path, "rb").read()
            set_text(self.input, codec.to_text(data))
        except OSError as exc:
            messagebox.showerror("读取失败", str(exc))

    def decode_all(self) -> None:
        text = self._input_text()
        if not text:
            return
        self.tree.delete(*self.tree.get_children())
        self._results = codec.manual_decode(text)
        for i, (name, value, score) in enumerate(self._results):
            self.tree.insert("", "end", iid=str(i), values=(name, value.replace("\n", " ")[:120], f"{score:.0f}"))
        for title, res in misc.analyze_text(text):
            self.tree.insert("", "end", values=(title, res.replace("\n", " ")[:120], "-"))
        hits = find_flags(text)
        if hits:
            self.app.status_set(f"输入中已发现 flag 候选：{hits[0].value}")
            set_text(self.detail, "输入中直接发现：\n" + "\n".join(h.value for h in hits))

    def decode_deep(self) -> None:
        text = self._input_text()
        if not text:
            return
        self.tree.delete(*self.tree.get_children())
        self.app.show_busy(True)
        self.app.status_set("多层爆破解码中…")

        def job():
            return codec.auto_decode([], text, text, max_depth=6, beam=10, deadline=None)

        def done(results):
            self.app.show_busy(False)
            self._results = [(r.path, r.value, r.score) for r in results]
            for i, (path, value, score) in enumerate(self._results):
                mark = "★ " if score >= 100 else ""
                self.tree.insert("", "end", iid=str(i),
                                 values=(mark + path[:150], value.replace("\n", " ")[:110], f"{score:.0f}"))
            self.app.status_set(f"多层解码完成，共 {len(results)} 条结果")
            if results:
                set_text(self.detail, f"路径：{results[0].path}\n\n{results[0].value[:4000]}")

        self.app.worker(job, on_done=done)

    def _copy_row(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        set_text(self.detail, values[1])
        idx = int(sel[0]) if str(sel[0]).isdigit() else -1
        if 0 <= idx < len(self._results):
            set_text(self.detail, self._results[idx][1])

    def _to_b64(self) -> None:
        set_text(self.input, codec.b64encode_text(self._input_text()))

    def _to_hex(self) -> None:
        set_text(self.input, self._input_text().encode("utf-8", "ignore").hex())

    def _to_url(self) -> None:
        import urllib.parse
        set_text(self.input, urllib.parse.quote(self._input_text()))

    def _to_rev(self) -> None:
        set_text(self.input, self._input_text()[::-1])

    def _to_rot13(self) -> None:
        set_text(self.input, codec.rot_n(self._input_text(), 13))


# --------------------------------------------------------------------------- #
class ImageTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self.data: bytes | None = None
        self.path: str = ""
        self.preview_photo = None

        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Button(top, text="打开图片", command=self.open_file).pack(side="left")
        ttk.Label(top, text="   ").pack(side="left")
        ttk.Button(top, text="结构 / 元数据分析", command=self.analyze).pack(side="left")
        ttk.Button(top, text="提取 LSB", command=self.lsb).pack(side="left", padx=5)
        ttk.Button(top, text="生成位平面图", command=self.bitplane).pack(side="left", padx=5)
        ttk.Button(top, text="修复 PNG 高度", command=self.fix_height).pack(side="left", padx=5)
        ttk.Button(top, text="两张图异或/相减", command=self.xor).pack(side="left", padx=5)
        self.lbl_info = ttk.Label(top, text="未打开图片")
        self.lbl_info.pack(side="right")

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)
        left = ttk.LabelFrame(pane, text="预览", padding=6)
        pane.add(left, weight=2)
        self.canvas = tk.Label(left, text="（图片预览区）", background="#f4f4f4")
        self.canvas.pack(fill="both", expand=True)
        right = ttk.LabelFrame(pane, text="分析结果", padding=6)
        pane.add(right, weight=3)
        rf, self.out = make_text(right, height=22, mono=True)
        rf.pack(fill="both", expand=True)
        ttk.Button(right, text="保存分析结果到文件", command=self.save_out).pack(fill="x", pady=4)
        ttk.Button(right, text="把提取到的数据交给自动分析", command=self.send_to_auto).pack(fill="x")
        self.extracted: list[tuple[str, bytes]] = []

    def on_activate(self) -> None:
        pass

    # ------------------------------------------------------------------ #
    def open_file(self) -> None:
        path = filedialog.askopenfilename(title="选择图片",
                                          filetypes=[("图片", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif"),
                                                     ("全部", "*.*")])
        if path:
            self.load(path)

    def load(self, path: str) -> None:
        try:
            self.data = open(path, "rb").read()
        except OSError as exc:
            messagebox.showerror("读取失败", str(exc))
            return
        self.path = path
        self.lbl_info.configure(text=f"{os.path.basename(path)}  {len(self.data)} 字节")
        self.show_preview(self.data)
        self.analyze()

    def show_preview(self, data: bytes) -> None:
        try:
            img = image.open_image(data)
            if img is None:
                return
            img = img.convert("RGB")
            img.thumbnail((520, 520))
            from PIL import ImageTk
            self.preview_photo = ImageTk.PhotoImage(img)
            self.canvas.configure(image=self.preview_photo, text="")
        except Exception:
            pass

    def _write(self, msg: str) -> None:
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def analyze(self) -> None:
        if not self.data:
            return
        set_text(self.out, "")
        self.extracted = []
        from .. import filetypes
        info = filetypes.identify(self.data)
        self._write(f"== 类型：{info.desc}（{len(self.data)} 字节）")
        for f in image.analyze(self.data):
            self._write(f"\n[{f.kind}] {f.title}\n{f.detail[:1200]}")
            if f.data:
                self.extracted.append((f.title, f.data))
        for text in misc.qr_decode(self.data):
            self._write(f"\n[二维码] {text}")
            self.extracted.append(("二维码内容", text.encode()))

    def lsb(self) -> None:
        if not self.data:
            return
        img = image.open_image(self.data)
        if img is None:
            messagebox.showwarning("提示", "无法解析该图片")
            return
        self._write("\n===== LSB 提取结果 =====")
        for label, blob in image.lsb_candidates(img, quick=False):
            if not blob:
                continue
            head = blob[:600]
            printable = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "·" for b in head)
            flag = find_flags(head.decode("latin-1"))
            mark = "★ " if flag else ""
            self._write(f"\n【{mark}{label}】{printable[:400]}")
            if flag:
                self._write("   → flag 命中：" + ", ".join(h.value for h in flag[:3]))
            self.extracted.append((f"LSB {label}", blob))

    def bitplane(self) -> None:
        if not self.data:
            return
        img = image.open_image(self.data)
        if img is None:
            return
        parts = []
        for ch, name in ((0, "R"), (1, "G"), (2, "B")):
            for plane in range(8):
                try:
                    raw = image.lsb_bitplane(img, ch, plane)
                except Exception:
                    continue
                parts.append((f"{name}-bit{plane}", raw))
        if not parts:
            return
        label, blob = parts[0]
        self._write(f"\n已生成位平面数据（共 {len(parts)} 个），把数据当图片分析…")
        self.extracted.extend(parts)
        self.app.status_set("位平面数据已加入提取结果，可点“交给自动分析”")

    def fix_height(self) -> None:
        if not self.data:
            return
        result = image.png_fix_height(self.data)
        if not result:
            self._write("\n高度修复：未发现高度被篡改，或无法修复")
            return
        fixed, h = result
        self._write(f"\n高度修复成功 → {h}")
        self.show_preview(fixed)
        out = filedialog.asksaveasfilename(title="保存修复后的图片", defaultextension=".png",
                                           filetypes=[("PNG", "*.png")])
        if out:
            with open(out, "wb") as fh:
                fh.write(fixed)
            self.app.status_set(f"已保存：{out}")

    def xor(self) -> None:
        if not self.data:
            return
        other = filedialog.askopenfilename(title="选择第二张图片")
        if not other:
            return
        b = open(other, "rb").read()
        result = image.xor_images(self.data, b)
        if not result:
            messagebox.showwarning("提示", "两张图尺寸/格式不兼容")
            return
        self._write("\n异或结果已生成（预览区）")
        self.show_preview(result)
        out = filedialog.asksaveasfilename(title="保存异或结果", defaultextension=".png")
        if out:
            with open(out, "wb") as fh:
                fh.write(result)

    def save_out(self) -> None:
        path = filedialog.asksaveasfilename(title="保存分析结果", defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.out.get("1.0", "end"))
            self.app.status_set(f"已保存：{path}")

    def send_to_auto(self) -> None:
        if not self.extracted:
            messagebox.showinfo("提示", "还没有提取到数据")
            return
        os.makedirs("work", exist_ok=True)
        written = []
        for i, (label, blob) in enumerate(self.extracted[:20]):
            safe = "".join(ch if ch.isalnum() else "_" for ch in label)[:40]
            path = os.path.join("work", f"extract_{i}_{safe}.bin")
            with open(path, "wb") as fh:
                fh.write(blob)
            written.append(path)
        self.app._add_paths(written)
        self.app.status_set(f"已加入 {len(written)} 个提取结果，去“一键自动分析”查看")


# --------------------------------------------------------------------------- #
class ArchiveTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self.data: bytes | None = None
        self.path = ""

        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Button(top, text="打开压缩包", command=self.open_file).pack(side="left")
        ttk.Button(top, text="解压到文件夹", command=self.extract_all).pack(side="left", padx=6)
        ttk.Button(top, text="修复伪加密", command=self.fix_pseudo).pack(side="left", padx=6)
        ttk.Button(top, text="爆破口令（数字 4 位 + 内置字典）", command=self.crack).pack(side="left", padx=6)
        self.lbl = ttk.Label(top, text="未打开压缩包")
        self.lbl.pack(side="right")

        cols = ("name", "size", "enc", "crc")
        self.tree = ttk.Treeview(self.frame, columns=cols, show="headings", height=10)
        for col, txt, w in (("name", "文件名", 420), ("size", "明文大小", 110),
                            ("enc", "加密", 70), ("crc", "CRC32", 110)):
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=6)
        lf, self.out = make_text(self.frame, height=12, mono=True)
        lf.pack(fill="both", expand=True)

    def on_activate(self) -> None:
        pass

    def _say(self, msg: str) -> None:
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def open_file(self) -> None:
        path = filedialog.askopenfilename(title="选择压缩包",
                                          filetypes=[("压缩包", "*.zip *.7z *.rar *.gz *.xz *.bz2 *.tar"),
                                                     ("全部", "*.*")])
        if not path:
            return
        self.path = path
        self.data = open(path, "rb").read()
        self.lbl.configure(text=f"{os.path.basename(path)}  {len(self.data)} 字节")
        set_text(self.out, "")
        self.tree.delete(*self.tree.get_children())
        info = filetypes.identify(self.data)
        if info.ext == "zip":
            entries, comment = archive.zip_entries(self.data)
            for e in entries:
                self.tree.insert("", "end", values=(e.name, e.size, "是" if e.encrypted else "否", hex(e.crc)))
            if comment:
                self._say(f"[注释] {codec.to_text(comment)}")
            suspicious = archive.interesting_names([e.name for e in entries])
            if suspicious:
                self._say("[可疑文件名] " + ", ".join(suspicious))
            if archive.pseudo_encrypted(self.data):
                self._say("[!] 检测到伪加密，点“修复伪加密”即可正常解压")
            for hit in find_flags(codec.to_text(comment) + "\n" + "\n".join(e.name for e in entries)):
                self._say(f"[flag 候选] {hit.value}")
        else:
            self._say(f"类型：{info.desc}；可直接点“解压到文件夹”")

    def extract_all(self) -> None:
        if not self.data:
            return
        outdir = filedialog.askdirectory(title="选择解压目标文件夹")
        if not outdir:
            return
        files, note = archive.extract_any(self.data, os.path.basename(self.path))
        if not files and note:
            self._say(f"[!] {note}")
        count = 0
        for name, blob in files.items():
            target = os.path.join(outdir, os.path.basename(name))
            try:
                with open(target, "wb") as fh:
                    fh.write(blob)
                count += 1
                self._say(f"已写出 {target}  ({len(blob)} 字节)")
            except OSError as exc:
                self._say(f"写出失败 {target}: {exc}")
        self.app.status_set(f"解压完成，共 {count} 个文件")

    def fix_pseudo(self) -> None:
        if not self.data:
            return
        fixed = archive.fix_pseudo_encryption(self.data)
        out = filedialog.asksaveasfilename(title="保存修复后的压缩包", defaultextension=".zip")
        if out:
            with open(out, "wb") as fh:
                fh.write(fixed)
            self._say(f"已保存修复后的压缩包：{out}")
            files, _note = archive.extract_any(fixed, "fixed.zip")
            for name, blob in files.items():
                self._say(f"[修复后可直接解出] {name} ({len(blob)} 字节): {codec.to_text(blob)[:200]}")

    def crack(self) -> None:
        if not self.data:
            return
        self._say("开始爆破口令（内置字典 + 0000-9999）…")
        self.app.show_busy(True)

        def job():
            return archive.crack_password(self.data, digits=4)

        def done(pw):
            self.app.show_busy(False)
            if pw is None:
                self._say("[!] 未命中，可尝试更大字典或明文攻击")
            else:
                self._say(f"[✓] 口令 = {pw!r}")
                files, _note = archive.extract_any(self.data, "x.zip")
                for name, blob in files.items():
                    self._say(f"   {name}: {codec.to_text(blob)[:200]}")

        self.app.worker(job, on_done=done)


# --------------------------------------------------------------------------- #
class AudioTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self.data: bytes | None = None
        self.spec: bytes | None = None
        self.photo = None

        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Button(top, text="打开音频", command=self.open_file).pack(side="left")
        ttk.Button(top, text="音频 LSB 提取", command=self.lsb).pack(side="left", padx=6)
        ttk.Button(top, text="生成频谱图", command=self.spectro).pack(side="left", padx=6)
        ttk.Button(top, text="保存频谱图", command=self.save_spec).pack(side="left", padx=6)
        self.lbl = ttk.Label(top, text="未打开音频")
        self.lbl.pack(side="right")

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)
        left = ttk.LabelFrame(pane, text="频谱图", padding=6)
        pane.add(left, weight=3)
        self.canvas = tk.Label(left, text="（生成频谱图后显示在这里）", background="#f4f4f4")
        self.canvas.pack(fill="both", expand=True)
        right = ttk.LabelFrame(pane, text="结果", padding=6)
        pane.add(right, weight=2)
        rf, self.out = make_text(right, height=20, mono=True)
        rf.pack(fill="both", expand=True)

    def on_activate(self) -> None:
        pass

    def _say(self, msg: str) -> None:
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def open_file(self) -> None:
        path = filedialog.askopenfilename(title="选择音频",
                                          filetypes=[("音频", "*.wav *.mp3 *.ogg *.flac"), ("全部", "*.*")])
        if not path:
            return
        self.data = open(path, "rb").read()
        self.lbl.configure(text=f"{os.path.basename(path)}  {len(self.data)} 字节")
        set_text(self.out, "")
        for f in audio.analyze(self.data):
            self._say(f"[{f.kind}] {f.title}\n{f.detail[:800]}")
            if f.kind == "image" and f.data:
                self.spec = f.data
                self._show_spec(f.data)

    def _show_spec(self, data: bytes) -> None:
        try:
            from PIL import Image, ImageTk
            img = Image.open(io.BytesIO(data))
            img.thumbnail((760, 420))
            self.photo = ImageTk.PhotoImage(img)
            self.canvas.configure(image=self.photo, text="")
        except Exception:
            pass

    def lsb(self) -> None:
        if not self.data:
            return
        for label, blob in audio.wav_lsb_candidates(self.data):
            head = blob[:400]
            printable = "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "·" for b in head)
            flags = find_flags(head.decode("latin-1"))
            self._say(f"\n【{'★ ' if flags else ''}{label}】{printable[:300]}")
            if flags:
                self._say("   → " + ", ".join(h.value for h in flags[:3]))

    def spectro(self) -> None:
        if not self.data:
            return
        spec = audio.spectrogram(self.data)
        if not spec:
            self._say("无法生成频谱图（不是 WAV 或数据太短）")
            return
        self.spec = spec
        self._show_spec(spec)
        self._say("频谱图已生成，若图中藏二维码会自动尝试识别：")
        for text in misc.qr_decode(spec):
            self._say(f"  [二维码] {text}")

    def save_spec(self) -> None:
        if not self.spec:
            messagebox.showinfo("提示", "先生成频谱图")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", initialfile="spectrogram.png")
        if path:
            with open(path, "wb") as fh:
                fh.write(self.spec)
            self.app.status_set(f"已保存：{path}")


# --------------------------------------------------------------------------- #
class QrTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Button(top, text="打开图片识别二维码", command=self.open_file).pack(side="left")
        ttk.Label(top, text="  或输入文本生成二维码：").pack(side="left")
        self.entry = ttk.Entry(top, width=40)
        self.entry.pack(side="left")
        ttk.Button(top, text="生成并保存", command=self.generate).pack(side="left", padx=6)

        lf, self.out = make_text(self.frame, height=18, mono=True)
        lf.pack(fill="both", expand=True, pady=6)
        ttk.Label(self.frame, text="支持多码识别、放大、反色、二值化等增强手段（基于 OpenCV / pyzbar）").pack(anchor="w")

    def on_activate(self) -> None:
        pass

    def open_file(self) -> None:
        path = filedialog.askopenfilename(title="选择含二维码的图片")
        if not path:
            return
        data = open(path, "rb").read()
        results = misc.qr_decode(data)
        if not results:
            self.out.insert("end", "未识别到二维码，可尝试先用图片工具做二值化/放大\n")
            return
        for r in results:
            self.out.insert("end", f"[识别结果] {r}\n")
            flags = find_flags(r)
            if flags:
                self.out.insert("end", "   → flag：" + ", ".join(h.value for h in flags) + "\n")
        self.out.see("end")

    def generate(self) -> None:
        text = self.entry.get().strip()
        if not text:
            return
        data = misc.qr_generate(text)
        if not data:
            messagebox.showerror("失败", "qrcode 库不可用")
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", initialfile="qrcode.png")
        if path:
            with open(path, "wb") as fh:
                fh.write(data)
            self.app.status_set(f"二维码已保存：{path}")


# --------------------------------------------------------------------------- #
class MiscTab:
    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        bar = ttk.Frame(self.frame)
        bar.pack(fill="x")
        for text, cmd in (("脑洞语言解释", self.esolang), ("JWT 解码", self.jwt),
                          ("哈希识别/爆破", self.hash), ("RSA 攻击", self.rsa),
                          ("流量包分析…", self.pcap_file), ("文件雕复…", self.carve_file),
                          ("提取字符串…", self.strings_file), ("十六进制查看…", self.hexview_file)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)
        left = ttk.LabelFrame(pane, text="输入", padding=6)
        pane.add(left, weight=1)
        lf, self.input = make_text(left, height=20, mono=True)
        lf.pack(fill="both", expand=True)
        right = ttk.LabelFrame(pane, text="输出", padding=6)
        pane.add(right, weight=2)
        rf, self.out = make_text(right, height=20, mono=True)
        rf.pack(fill="both", expand=True)

    def on_activate(self) -> None:
        pass

    def _say(self, msg: str = "") -> None:
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def _text(self) -> str:
        return self.input.get("1.0", "end").strip()

    def esolang(self) -> None:
        text = self._text()
        if not text:
            return
        results = misc.analyze_text(text)
        if not results:
            self._say("没有识别出脑洞语言（支持 Brainfuck / Ook! / Whitespace / JWT / 哈希）")
        for title, res in results:
            self._say(f"[{title}]\n{res[:2000]}\n")

    def jwt(self) -> None:
        data = misc.jwt_decode(self._text())
        if not data:
            self._say("不是合法 JWT")
            return
        import json
        self._say(json.dumps(data, ensure_ascii=False, indent=2))

    def hash(self) -> None:
        value = self._text()
        if not value:
            return
        self._say(f"类型：{misc.hash_identify(value)}")
        self.app.show_busy(True)
        self._say("正在用弱口令字典 + 纯数字爆破…")

        def job():
            return misc.hash_crack(value, digits=6)

        def done(pw):
            self.app.show_busy(False)
            self._say(f"明文：{pw!r}" if pw is not None else "未命中（可以试更长的字典）")

        self.app.worker(job, on_done=done)

    def rsa(self) -> None:
        import re
        text = self._text()
        vals = {}
        for key in ("n", "e", "c", "p", "q"):
            m = re.search(rf"{key}\s*=\s*(\d+)", text)
            if m:
                vals[key] = int(m.group(1))
        if {"n", "e", "c"} <= vals.keys():
            results = misc.rsa_attacks(vals["n"], vals["e"], vals["c"])
            if not results:
                self._say("常见攻击（小指数、费马分解）未成功")
            for name, res in results:
                self._say(f"[{name}] {res}")
        elif {"n", "p", "q"} <= vals.keys() and "e" in vals and "c" in vals:
            try:
                phi = (vals["p"] - 1) * (vals["q"] - 1)
                d = pow(vals["e"], -1, phi)
                m = pow(vals["c"], d, vals["n"])
                self._say(f"[直接解密] {misc._int_to_text(m)}")
            except Exception as exc:
                self._say(f"解密失败：{exc}")
        else:
            self._say("请在左侧按 n= / e= / c= 的格式粘贴参数（也支持 p= / q=）")

    def pcap_file(self) -> None:
        path = filedialog.askopenfilename(title="选择流量包",
                                          filetypes=[("流量包", "*.pcap *.pcapng *.cap"), ("全部", "*.*")])
        if not path:
            return
        data = open(path, "rb").read()
        self._say(f"== {os.path.basename(path)}  {len(data)} 字节")
        for f in pcap.analyze(data):
            self._say(f"\n[{f.title}] {f.detail[:1500]}")
            if f.data:
                flags = find_flags(codec.to_text(f.data))
                if flags:
                    self._say("  → flag：" + ", ".join(h.value for h in flags[:3]))
                    out = filedialog.asksaveasfilename(title="保存还原出来的对象", defaultextension=".bin")
                    if out:
                        with open(out, "wb") as fh:
                            fh.write(f.data)

    def carve_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要雕复的文件")
        if not path:
            return
        data = open(path, "rb").read()
        hits = carve.carve(data)
        if not hits:
            self._say("没有发现内嵌文件")
            return
        outdir = filedialog.askdirectory(title="选择保存目录")
        for i, hit in enumerate(hits):
            self._say(f"[{i}] 偏移 {hit.offset}  {hit.desc}  {hit.size} 字节")
            flags = find_flags(codec.to_text(hit.data))
            if flags:
                self._say("     → flag：" + ", ".join(h.value for h in flags[:3]))
            if outdir:
                target = os.path.join(outdir, f"carved_{i}_{hit.offset}.{hit.ext}")
                with open(target, "wb") as fh:
                    fh.write(hit.data)
        if outdir:
            self.app.status_set(f"已导出 {len(hits)} 个内嵌文件到 {outdir}")

    def strings_file(self) -> None:
        path = filedialog.askopenfilename(title="选择文件")
        if not path:
            return
        data = open(path, "rb").read()
        items = pcap.printable_strings(data, 6, 300)
        self._say(f"== 共 {len(items)} 条可打印字符串")
        for s in items:
            flags = find_flags(s)
            self._say(("★ " if flags else "  ") + s[:200])

    def hexview_file(self) -> None:
        path = filedialog.askopenfilename(title="选择文件")
        if not path:
            return
        data = open(path, "rb").read(8192)
        self._say(codec.hexdump(data))


# --------------------------------------------------------------------------- #
class LibraryTab:
    """内置题库：浏览随程序分发的公开 CTF 题目。"""

    def __init__(self, app, parent):
        self.app = app
        self.frame = ttk.Frame(parent, padding=8)
        self.entries: list[dict] = []
        self.loaded = False

        top = ttk.Frame(self.frame)
        top.pack(fill="x")
        ttk.Label(top, text="搜索：").pack(side="left")
        self.search = ttk.Entry(top, width=30)
        self.search.pack(side="left")
        self.search.bind("<Return>", lambda _e: self.refresh())
        ttk.Button(top, text="搜索/刷新", command=self.refresh).pack(side="left", padx=6)
        ttk.Button(top, text="打开题目目录", command=self.open_dir).pack(side="left", padx=6)
        ttk.Button(top, text="加入待分析", command=self.add_to_queue).pack(side="left", padx=6)
        ttk.Button(top, text="重新载入题库", command=lambda: self.load(force=True)).pack(side="left")
        self.lbl = ttk.Label(top, text="")
        self.lbl.pack(side="right")

        pane = ttk.PanedWindow(self.frame, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=6)
        left = ttk.LabelFrame(pane, text="题目列表", padding=6)
        pane.add(left, weight=3)
        cols = ("ctf", "year", "cat", "name")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=20)
        for col, txt, w in (("ctf", "赛事", 120), ("year", "年份", 60),
                            ("cat", "分类", 80), ("name", "题目", 260)):
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w, anchor="w")
        tsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._show)

        right = ttk.Frame(pane)
        pane.add(right, weight=2)
        rf, self.desc = make_text(right, height=16, mono=False)
        rf.pack(fill="both", expand=True)
        self.files = tk.Listbox(right, height=6, font=FONT_MONO)
        self.files.pack(fill="both", expand=True, pady=4)

    # ------------------------------------------------------------------ #
    def corpus_dir(self) -> str:
        from .app import resource_dir
        return os.path.join(resource_dir(), "corpus")

    def load(self, force: bool = False) -> None:
        if self.loaded and not force:
            return
        index = os.path.join(self.corpus_dir(), "index.json")
        if not os.path.exists(index):
            self.lbl.configure(text="未找到题库（corpus/index.json）")
            return
        import json
        with open(index, encoding="utf-8") as fh:
            data = json.load(fh)
        self.entries = data.get("challenges", [])
        self.loaded = True
        total = data.get("total_bytes", 0) / 1024 / 1024
        self.lbl.configure(text=f"共 {len(self.entries)} 题 / {total:.1f} MB（来源：公开 CTF 归档）")
        self.refresh()

    def on_activate(self) -> None:
        self.load()

    def refresh(self) -> None:
        key = self.search.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        count = 0
        for i, e in enumerate(self.entries):
            hay = f"{e.get('ctf','')} {e.get('year','')} {e.get('category','')} {e.get('name','')}".lower()
            if key and key not in hay:
                continue
            self.tree.insert("", "end", iid=str(i),
                             values=(e.get("ctf", ""), e.get("year", ""),
                                     e.get("category", ""), e.get("name", "")))
            count += 1
            if count > 2000:
                break

    def _selected(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.entries[int(sel[0])]

    def _show(self, _event=None) -> None:
        e = self._selected()
        if not e:
            return
        text = f"【{e.get('ctf')} {e.get('year')} / {e.get('category')}】{e.get('name')}\n\n"
        if e.get("known_flag"):
            text += f"题面中出现的 flag 形式：{e['known_flag']}\n\n"
        text += (e.get("description") or "（无题面）")[:4000]
        text += f"\n\n来源：{e.get('source','')}"
        set_text(self.desc, text)
        self.files.delete(0, "end")
        for fn in e.get("files", []):
            self.files.insert("end", f"  {fn}")

    def challenge_dir(self, e: dict) -> str:
        return os.path.join(self.corpus_dir(), *e.get("dir", "").split("/"))

    def open_dir(self) -> None:
        e = self._selected()
        if not e:
            return
        path = self.challenge_dir(e)
        if os.path.isdir(path):
            os.startfile(path)
        else:
            messagebox.showinfo("提示", f"目录不存在：{path}")

    def add_to_queue(self) -> None:
        e = self._selected()
        if not e:
            return
        path = self.challenge_dir(e)
        if not os.path.isdir(path):
            messagebox.showinfo("提示", f"目录不存在：{path}")
            return
        self.app._add_paths([path])
        self.app.status_set(f"已加入题目：{e.get('name')}，去“一键自动分析”")
