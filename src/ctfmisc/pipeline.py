"""一键自动分析流水线：识别 → 分层解析 → 递归展开 → flag 归集。"""

from __future__ import annotations

import io
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import (archive, audio, binary, carve, codec, docs, filetypes, forensic, image, jpegdct,
               misc, ocr, pcap, textstego)
from .flags import FlagHit, find_flags, merge

MAX_READ = 64 * 1024 * 1024
_CIPHER_CHARSET = re.compile(r"^[A-Za-z0-9+/=_\-.\s%|]{8,}$")


def _looks_like_cipher(text: str) -> bool:
    """判断一段文本是否值得做多层自动解码（避免对正常文本大爆破）。"""
    s = text.strip()
    if len(s) < 6:
        return False
    if re.fullmatch(r"[01\s]{8,}", s) or re.fullmatch(r"[0-9\s,.\-]{6,}", s):
        return True
    if re.fullmatch(r"[.\-\s/|_]{6,}", s):
        return True
    if re.fullmatch(r"[A-Za-z]{8,}", s):
        return True
    if _CIPHER_CHARSET.match(s):
        words = re.findall(r"[A-Za-z]{3,}", s)
        # 正常英文句子会有多个常见短词；密文则几乎没有
        if not re.search(r"\b(the|is|are|you|flag|this|and|of|to)\b", s, re.I):
            return True
    return False


@dataclass
class Item:
    label: str
    data: bytes
    depth: int = 0
    origin: str = ""       # 父条目的 label
    step: str = ""         # 人类可读的“这一步做了什么”


@dataclass
class Finding:
    source: str
    title: str
    detail: str = ""
    kind: str = "info"
    data: bytes = b""


@dataclass
class Options:
    deep: bool = True
    max_depth: int = 3
    max_items: int = 160
    time_budget: float = 150.0
    decode_budget: float = 25.0
    zip_digits: int = 4
    extra_patterns: list[str] = field(default_factory=list)
    read_cap: int = MAX_READ


@dataclass
class Report:
    flags: list[FlagHit] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    artifacts: list[tuple[str, bytes]] = field(default_factory=list)
    seconds: float = 0.0
    items: dict[str, Item] = field(default_factory=dict)
    flag_item: dict[str, str] = field(default_factory=dict)
    outdir: str = ""

    def text_flags(self) -> list[str]:
        return [f.value for f in self.flags if f.score >= 50]

    def solve_chains(self, only_found: bool = True) -> list[tuple[str, list[tuple[str, str, str]], list[str]]]:
        """把每个 flag 还原成“从文件到 flag”的步骤链。

        返回 [(根文件名, [(步骤描述, 该步的关键数据/证据), ...], [flag, ...]), ...]
        """
        roots: dict[str, list[str]] = {}
        for value, label in self.flag_item.items():
            root = label
            guard = 0
            while root in self.items and self.items[root].origin and guard < 64:
                root = self.items[root].origin
                guard += 1
            roots.setdefault(root, []).append(value)
        out = []
        for root, values in roots.items():
            if only_found and not values:
                continue
            steps: list[tuple[str, str, str]] = []
            for value in values:
                label = self.flag_item[value]
                chain: list[str] = []
                guard = 0
                while label and guard < 64:
                    chain.append(label)
                    label = self.items[label].origin if label in self.items else ""
                    guard += 1
                for lbl in reversed(chain):
                    item = self.items.get(lbl)
                    if item is None:
                        continue
                    desc = item.step or f"分析 {lbl.split('::')[-1]}"
                    evidence = ""
                    if "::" in lbl:
                        evidence = lbl.split("::")[-1]
                    pair = (desc, evidence, lbl)
                    if pair not in steps:
                        steps.append(pair)
            out.append((root, steps, sorted(set(values))))
        out.sort(key=lambda x: -len(x[2]))
        return out


class Pipeline:
    def __init__(self, options: Options | None = None,
                 progress: Callable[[str], None] | None = None,
                 cancel: threading.Event | None = None):
        self.opt = options or Options()
        self.progress = progress or (lambda msg: None)
        self.cancel = cancel or threading.Event()
        self.report = Report()
        self.deadline = 0.0
        self._seen: set[int] = set()
        self.expected_prefixes: set[str] = set()
        self._items: dict[str, Item] = {}
        self.flag_item: dict[str, str] = {}
        self.outdir: str = ""
        self.root_paths: list[str] = []

    # ------------------------------------------------------------------ #
    def _say(self, msg: str) -> None:
        self.report.log.append(msg)
        self.progress(msg)

    def _add_flags(self, data: bytes, source: str, item_label: str = "") -> None:
        try:
            text = codec.to_text(data)
        except Exception:
            return
        for hit in find_flags(text, source=source, extra_patterns=self.opt.extra_patterns):
            prefix = hit.value.split("{", 1)[0].lower()
            if prefix in self.expected_prefixes:
                hit.score += 60
                hit.reason += "（与题面中出现的格式一致）"
            self.report.flags.append(hit)
            if item_label:
                self.flag_item.setdefault(hit.value, item_label)

    def _scan_expected_prefixes(self, queue: list[Item]) -> None:
        """从题面等文本里提取 “xxx{” 形状的前缀，用于给候选 flag 加权。"""
        pat = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,19})\{")
        for item in queue[:24]:
            if len(item.data) > 200000:
                continue
            try:
                text = item.data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = item.data.decode("gbk")
                except UnicodeDecodeError:
                    continue
            head = text[:400]
            if not head or sum(1 for c in head if c.isprintable()) / len(head) < 0.9:
                continue
            for m in pat.finditer(text):
                self.expected_prefixes.add(m.group(1).lower())
            low = text.lower()
            for m in re.finditer(r"(?:flag\s*(?:format|格式)|格式)\s*[:：]?\s*([a-z0-9_]{2,20})\{", low):
                self.expected_prefixes.add(m.group(1))

    def _finding(self, source: str, title: str, detail: str = "", kind: str = "info", data: bytes = b"") -> None:
        # 发现里带图片数据时，自动落盘并告知路径（用户最常问“生成的图在哪”）
        if data and len(data) > 256 and data[:8] in (b"\x89PNG\r\n\x1a\n",) or (data[:3] == b"\xff\xd8\xff" and len(data) > 256):
            path = self._save_blob(title, data)
            if path:
                detail = (detail + f"\n（图片已保存：{path}）").strip()
        self.report.findings.append(Finding(source, title, detail, kind, data))

    def _artifact_dir(self) -> str:
        if not self.outdir:
            base = self.root_paths[0] if self.root_paths else os.getcwd()
            base = os.path.abspath(base)
            parent = os.path.dirname(base) or os.getcwd()
            name = os.path.basename(base.rstrip("\\/")) or "分析"
            self.outdir = os.path.join(parent, f"{name}_分析结果")
        return self.outdir

    def _save_blob(self, title: str, blob: bytes) -> str:
        import re as _re
        try:
            outdir = self._artifact_dir()
            os.makedirs(outdir, exist_ok=True)
            safe = _re.sub(r'[<>:"/\\|?*\s]+', "_", title)[:60] or "artifact"
            ext = ".jpg" if blob[:3] == b"\xff\xd8\xff" else ".png"
            path = os.path.join(outdir, safe + ext)
            with open(path, "wb") as fh:
                fh.write(blob)
            return path
        except OSError:
            return ""

    def _save_artifacts(self, label: str, candidates, sheet: bytes | None) -> list[str]:
        saved: list[str] = []
        outdir = self._artifact_dir()
        try:
            os.makedirs(outdir, exist_ok=True)
        except OSError:
            return saved
        for w, h, blob in candidates or []:
            try:
                path = os.path.join(outdir, f"候选尺寸_{w}x{h}.png")
                with open(path, "wb") as fh:
                    fh.write(blob)
                saved.append(path)
            except OSError:
                continue
        if sheet:
            try:
                path = os.path.join(outdir, "候选尺寸对照图.png")
                with open(path, "wb") as fh:
                    fh.write(sheet)
                saved.append(path)
            except OSError:
                pass
        if saved:
            self.report.findings.append(Finding(
                label, "生成的文件", "所有候选图已保存到：\n" + "\n".join(saved), "info"))
        return saved

    # ------------------------------------------------------------------ #
    def run_paths(self, paths: list[str]) -> Report:
        self.root_paths = list(paths)
        # 文件名提示（base64/关键字）：很多题的钥匙就在文件名里
        for p in paths:
            for tag, msg in forensic.filename_hints(p):
                self._finding(os.path.basename(p), tag, msg, "info")
                self._add_flags(msg.encode("utf-8", "ignore"), os.path.basename(p))
        # 同目录大量同大小文件 → 时间戳编码
        for p in paths:
            if not os.path.isdir(p):
                continue
            try:
                files = [os.path.join(p, f) for f in sorted(os.listdir(p))]
            except OSError:
                continue
            if len(files) < 16:
                continue
            sizes = {}
            for f in files:
                try:
                    sizes[os.path.getsize(f)] = sizes.get(os.path.getsize(f), 0) + 1
                except OSError:
                    continue
            if sizes and max(sizes.values()) / max(sum(sizes.values()), 1) > 0.5:
                for tag, msg in forensic.timestamps_binary(files):
                    self._finding(os.path.basename(p), tag, msg, "data")
                    self._add_flags(msg.encode("utf-8", "ignore"), f"{os.path.basename(p)} / {tag}")
        queue: list[Item] = []
        for path in paths:
            if os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    for fn in sorted(files):
                        full = os.path.join(root, fn)
                        try:
                            if os.path.getsize(full) <= self.opt.read_cap:
                                with open(full, "rb") as fh:
                                    rel = os.path.relpath(full, start=os.path.dirname(path) or ".")
                                    queue.append(Item(rel, fh.read(), 0, path,
                                                      step=f"打开文件 {rel}"))
                        except OSError:
                            continue
            elif os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                    with open(path, "rb") as fh:
                        data = fh.read(self.opt.read_cap if size > self.opt.read_cap else size)
                    queue.append(Item(os.path.basename(path), data, 0, path,
                                      step=f"打开文件 {os.path.basename(path)}"))
                except OSError as exc:
                    self._say(f"[!] 无法读取 {path}: {exc}")
        return self.run_items(queue)

    def run_items(self, queue: list[Item]) -> Report:
        started = time.time()
        self.deadline = started + self.opt.time_budget
        self._scan_expected_prefixes(queue)
        processed = 0
        pending = list(queue)
        while pending:
            if self.cancel.is_set():
                self._say("[!] 已取消")
                break
            if time.time() > self.deadline:
                self._say("[!] 达到时间上限，提前结束")
                break
            if processed >= self.opt.max_items:
                self._say("[!] 达到处理数量上限，提前结束")
                break
            item = pending.pop(0)
            processed += 1
            if not item.step:
                item.step = f"打开文件 {item.label}"
            key = (hash(item.data[:4096]), len(item.data), item.depth)
            if key in self._seen:
                continue
            self._seen.add(key)
            derived = self._analyze(item)
            for child in derived:
                if child.depth <= self.opt.max_depth and len(pending) < 400:
                    pending.append(child)
            self.report.artifacts.extend((f"{item.label} :: {d.label}", d.data) for d in derived[:12])
        self.report.flags = merge(self.report.flags)
        self.report.items = {label: item for label, item in self._items.items()}
        self.report.flag_item = dict(self.flag_item)
        self.report.outdir = self.outdir
        self.report.seconds = time.time() - started
        if self.outdir and os.path.isdir(self.outdir):
            try:
                files = os.listdir(self.outdir)
            except OSError:
                files = []
            self._say(f"[i] 本次生成的文件（{len(files)} 个）都在：{self.outdir}")
        self._say(f"[✓] 分析结束，用时 {self.report.seconds:.1f} 秒，共处理 {processed} 项，"
                  f"提取 {len(self.report.flags)} 个候选")
        return self.report

    # ------------------------------------------------------------------ #
    def _analyze(self, item: Item) -> list[Item]:
        data = item.data
        self._items[item.label] = item
        prefix = "  " * item.depth
        info = filetypes.identify(data, item.label)
        self._say(f"{prefix}→ {item.label}  [{info.desc} / {len(data)} 字节]")
        derived: list[Item] = []

        self._add_flags(data, item.label, item.label)
        ext_name = os.path.splitext(item.label)[1].lstrip(".").lower()
        _alias = {"jpeg": "jpg", "tif": "tiff", "htm": "html", "pcapng": "pcap"}
        ext_norm = _alias.get(ext_name, ext_name)
        info_norm = _alias.get(info.ext, info.ext)
        if (ext_name and info.confident and info_norm != ext_norm and ext_norm in (
                "png", "jpg", "gif", "bmp", "zip", "gz", "wav", "mp3", "pdf", "pcap")):
            self._finding(item.label, "文件头与扩展名不一致",
                          f"扩展名 .{ext_name}，实际为 {info.desc}", "warn")

        # 文本类
        text = None
        if info.ext in ("txt", "b64", "hex", "bin8", "morse", "json", "xml", "oct", "dec") or not info.confident:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = data.decode("gbk")
                except UnicodeDecodeError:
                    text = None
        if text is not None and len(text.strip()) > 3:
            derived.extend(self._analyze_text(item, text))
            # 文本类隐写：SNOW 空格 / 零宽字符 / Base64 填充位
            for tag, msg in textstego.snow_extract(text):
                self._finding(item.label, tag, msg, "data")
                self._add_flags(msg.encode("utf-8", "ignore"), f"{item.label} / {tag}")
            for tag, msg in textstego.zero_width_extract(text):
                self._finding(item.label, tag, msg, "data")
                self._add_flags(msg.encode("utf-8", "ignore"), f"{item.label} / {tag}")
            for tag, msg in textstego.base64_stego(text):
                self._finding(item.label, tag, msg, "data")
                self._add_flags(msg.encode("utf-8", "ignore"), f"{item.label} / {tag}")
            tap = textstego.tap_code_decode(text)
            if tap:
                self._finding(item.label, "敲击码解码", tap, "data")
                self._add_flags(tap.encode(), f"{item.label} / 敲击码")
            emo = textstego.emoji_decode(text)
            if emo:
                self._finding(item.label, "Emoji 编码解码", emo, "data")
                self._add_flags(emo.encode(), f"{item.label} / Emoji")

        # 图片
        if info.ext in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"):
            for f in image.analyze(data, deep_lsb=True):
                self._finding(item.label, f.title, f.detail, f.kind, f.data)
                if f.data:
                    self._add_flags(f.data, f"{item.label} / {f.title}", f"{item.label}::{f.title}")
                    derived.append(Item(f"{item.label}::{f.title}", f.data, item.depth + 1, item.label,
                                        step=f"图片分析命中：{f.title}"))
            for text_val in misc.qr_decode(data):
                self._say(f"{prefix}  二维码内容: {text_val}")
                self._finding(item.label, "二维码识别", text_val, "data", text_val.encode())
                self._add_flags(text_val.encode(), f"{item.label} / 二维码")
            if info.ext == "png":
                fixed = image.png_fix_height(data)
                if fixed:
                    self._finding(item.label, "PNG 高度被篡改", f"修复后高度为 {fixed[1]}", "data", fixed[0])
                    derived.append(Item(f"{item.label}::修复高度", fixed[0], item.depth + 1, item.label,
                                        step=f"修复被篡改的 PNG 高度（{fixed[1]} 像素）"))
                elif image.png_size_inconsistent(data):
                    # 只有“声明的宽高与像素数据对不上”时才做宽高爆破，避免把正常图片反复递归
                    sheet, notes, sflags = image.png_size_sheet(data, limit=9)
                    if notes or sheet:
                        self._finding(item.label, "PNG 宽高可能被改（枚举所有合法尺寸）",
                                      ("\n".join(notes) if notes else "")
                                      + "\n候选尺寸：" + ", ".join(f"{w}x{h}" for w, h, _b in
                                                                 image.png_bruteforce_size(data, limit=9)),
                                      "warn", sheet)
                        self._save_artifacts(item.label, image.png_bruteforce_size(data, limit=9),
                                             sheet)
                        for fl in sflags:
                            self.report.flags.append(
                                __import__("ctfmisc.flags", fromlist=["FlagHit"]).FlagHit(
                                    fl, f"{item.label} / 宽高爆破", 90.0, "", "宽高爆破命中"))
                            self.flag_item.setdefault(fl, f"{item.label} / 宽高爆破")
                        if sheet:
                            derived.append(Item(f"{item.label}::宽高候选对照图", sheet, item.depth + 1,
                                                item.label, step="枚举 PNG 合法宽高并生成候选对照图"))
            if info.ext == "gif":
                frames = image.gif_frames(data, limit=60)
                if len(frames) > 1:
                    self._finding(item.label, f"GIF 共 {len(frames)} 帧",
                                  "已逐帧拆分，并对每帧做隐写检查（可用「GIF 帧提取」卡片导出）")
                    for idx, blob in frames[:24]:
                        derived.append(Item(f"{item.label}::帧{idx}", blob, item.depth + 1, item.label,
                                            step=f"拆分 GIF 第 {idx} 帧"))
                    diff = image.frame_diff(frames)
                    if diff:
                        derived.append(Item(f"{item.label}::帧差图", diff, item.depth + 1, item.label,
                                            step="生成相邻帧差异图（逐帧对比找答案）"))
                hidden = image.gif_hidden_frames(data)
                for label, blob in hidden:
                    self._finding(item.label, "★ GIF 帧内藏了第二张图", label, "data", blob)
                    derived.append(Item(f"{item.label}::{label}", blob, item.depth + 1, item.label,
                                        step=f"从 {label} 中提取出隐藏图片"))
            if info.ext in ("jpg", "jpeg"):
                self._finding(item.label, "F5 隐写检测", jpegdct.f5_detect(data), "info")
            # OCR：很多题的 flag 就是图里写的一行字
            if ocr.available():
                texts, ocr_flags = ocr.ocr_flags(data)
                if texts:
                    self._finding(item.label, "图片文字识别(OCR)", " / ".join(texts[:6])[:600], "data")
                for fl in ocr_flags:
                    self.report.flags.append(
                        __import__("ctfmisc.flags", fromlist=["FlagHit"]).FlagHit(
                            fl, f"{item.label} / OCR", 110.0, "", "图片文字识别命中"))
                    self.flag_item.setdefault(fl, f"{item.label} / OCR")

        # 音频
        if info.ext in ("wav", "mp3", "ogg", "flac"):
            for f in audio.analyze(data):
                self._finding(item.label, f.title, f.detail, f.kind, f.data)
                if f.data and f.kind == "data":
                    self._add_flags(f.data, f"{item.label} / {f.title}", f"{item.label}::{f.title}")
                    derived.append(Item(f"{item.label}::{f.title}", f.data, item.depth + 1, item.label,
                                        step=f"音频分析命中：{f.title}"))
                elif f.data and f.kind == "image":
                    for text_val in misc.qr_decode(f.data):
                        self._finding(item.label, "频谱图中的二维码", text_val, "data", text_val.encode())
                        self._add_flags(text_val.encode(), f"{item.label} / 频谱二维码")

        # 压缩包
        if info.ext in ("zip", "gz", "bz2", "xz", "tar", "7z"):
            derived.extend(self._analyze_archive(item, data, info.ext))
        if info.ext == "zip":
            try:
                entries, _c = archive.zip_entries(data)
                if entries and all(e.encrypted for e in entries):
                    content, note = archive.crc_bruteforce(data)
                    self._finding(item.label, "ZIP 短内容 CRC 爆破", note,
                                  "data" if content else "info", content or b"")
                    if content:
                        derived.append(Item(f"{item.label}::CRC爆破内容.txt", content, item.depth + 1,
                                            item.label, step=f"CRC 爆破出条目内容 {content!r}"))
            except Exception:
                pass

        # 流量包
        if info.ext in ("pcap", "pcapng"):
            for f in pcap.analyze(data):
                self._finding(item.label, f.title, f.detail, f.kind, f.data)
                if f.data:
                    self._add_flags(f.data, f"{item.label} / {f.title}", f"{item.label}::{f.title}")
                    derived.append(Item(f"{item.label}::{f.title}", f.data, item.depth + 1, item.label,
                                        step=f"流量分析命中：{f.title}"))
            packets = pcap.parse(data)
            domains = pcap.dns_queries(packets)
            if domains:
                self._finding(item.label, "DNS 查询域名", ", ".join(domains[:30]))
                self._add_flags(" ".join(domains).encode(), f"{item.label} / DNS")
            mouse = pcap.usb_mouse_render(packets)
            if mouse:
                self._finding(item.label, "USB 鼠标轨迹图（可能是画的二维码/文字）", "见右侧预览/导出", "image", mouse)
                for text_val in misc.qr_decode(mouse):
                    self._finding(item.label, "轨迹图中的二维码", text_val, "data", text_val.encode())
                    self._add_flags(text_val.encode(), f"{item.label} / 鼠标轨迹二维码")

        # 二进制 / 逆向
        fmt, items = binary.info_card(data)
        if items:
            summary = "\n".join(f"{it.label}: {it.value}" for it in items[:14])
            self._finding(item.label, f"二进制信息卡（{fmt}）", summary)
            for it in items:
                if it.warn:
                    self._add_flags(it.value.encode("utf-8", "ignore"), f"{item.label} / {it.label}")
        if item.label.lower().endswith((".pyc", ".pyo")) or binary.pyc_version(data).startswith("3."):
            if item.label.lower().endswith((".pyc", ".pyo")):
                dis = binary.pyc_disassemble(data, max_lines=60)
                self._finding(item.label, "Python 字节码反汇编", dis[:2000])
                for s in binary.pyc_suspicious_strings(data):
                    self._finding(item.label, "可疑字符串", s, "data", s.encode())
                    self._add_flags(s.encode(), f"{item.label} / 字节码字符串")
        if binary.has_pyinstaller(data):
            try:
                files, note = binary.pyinstaller_extract(data, max_files=120)
                self._finding(item.label, "PyInstaller 归档", note)
                for name, blob in list(files.items())[:120]:
                    if len(blob) > 8 * 1024 * 1024:
                        continue
                    self._add_flags(blob, f"{item.label} / {name}", f"{item.label}::{name}")
                    if name in ("hello", "__main__", "pyiboot01_bootstrap") and len(blob) < 2 * 1024 * 1024:
                        derived.append(Item(f"{item.label}::{name}.pyc", blob, item.depth + 1, item.label,
                                            step=f"PyInstaller 解出主脚本 {name}"))
                for name, blob in list(files.items()):
                    if name.endswith((".pyd", ".dll", ".zip")):
                        continue
                    if len(blob) < 4 * 1024 * 1024 and not name.startswith("PYZ"):
                        derived.append(Item(f"{item.label}::{name}", blob, item.depth + 1, item.label,
                                            step=f"PyInstaller 解出文件 {name}"))
            except Exception as exc:  # noqa: BLE001
                self._finding(item.label, "PyInstaller 解析失败", str(exc), "warn")

        # PDF
        if info.ext == "pdf":
            pdf_text = extract_pdf_text(data)
            if pdf_text:
                self._finding(item.label, "PDF 文本内容", pdf_text[:1500], "data", pdf_text.encode())
                self._add_flags(pdf_text.encode(), f"{item.label} / PDF 文本")
        # SQLite 数据库
        if data[:15] == b"SQLite format 3":
            for f in docs.sqlite_analyze(data):
                self._finding(item.label, f.title, f.detail, f.kind, f.data)
                self._add_flags(f.detail.encode("utf-8", "ignore"), f"{item.label} / {f.title}")
        # 大文件：内存镜像/磁盘镜像线索
        mem = binary.memory_image_hint(data)
        if mem:
            self._finding(item.label, "镜像 / 取证线索", mem, "info")
        ad1 = forensic.ad1_hint(data)
        if ad1:
            self._finding(item.label, "AD1 / 镜像线索", ad1, "info")

        # 附加数据 / 内嵌文件
        trailing = filetypes.trailing_data(data, info.ext)
        if trailing and len(trailing) > 16:
            derived.append(Item(f"{item.label}::文件尾附加数据", trailing, item.depth + 1, item.label,
                                step=f"取文件尾附加数据（{len(trailing)} 字节）"))
        if len(data) < 16 * 1024 * 1024:
            for hit in carve.carve(data):
                self._say(f"{prefix}  发现内嵌 {hit.desc} @{hit.offset} ({hit.size} 字节)")
                derived.append(Item(f"{item.label}::内嵌{hit.ext}@{hit.offset}", hit.data,
                                    item.depth + 1, item.label,
                                    step=f"雕出内嵌文件 {hit.desc}（偏移 {hit.offset}）"))
        return derived

    # ------------------------------------------------------------------ #
    def _analyze_text(self, item: Item, text: str) -> list[Item]:
        derived: list[Item] = []
        prefix = "  " * item.depth
        stripped = text.strip()
        for title, res in misc.analyze_text(stripped):
            self._finding(item.label, title, res[:1500], "data", res.encode())
            self._add_flags(res.encode(), f"{item.label} / {title}", f"{item.label} / {title}")

        # 已经拿到强 flag 就不再继续爆破式递归，避免组合爆炸与误报
        if any(h.score >= 50 for h in find_flags(stripped, extra_patterns=self.opt.extra_patterns)):
            return derived
        if len(stripped) > 8000:
            return derived
        results = codec.manual_decode(stripped)
        kept = 0
        for name, value, score in results[:16]:
            if score < 10:
                continue
            self._finding(item.label, f"单层解码: {name}", value[:1200], "data",
                          value.encode("utf-8", "ignore"))
            self._add_flags(value.encode("utf-8", "ignore"), f"{item.label} / {name}",
                            f"{item.label}::{name}")
            spec = codec.is_speculative(name)
            if (kept < 4 and item.depth < self.opt.max_depth and len(value) < 20000
                    and (not spec or score >= 30)):
                derived.append(Item(f"{item.label}::{name}", value.encode("utf-8", "ignore"),
                                    item.depth + 1, item.label, step=f"编码/密码变换：{name}"))
                kept += 1
        if self.opt.deep and 6 <= len(stripped) <= 4000 and _looks_like_cipher(stripped):
            budget = min(self.opt.decode_budget, max(3.0, self.deadline - time.time()))
            if budget > 1:
                self._say(f"{prefix}  多层自动解码中（最多 {budget:.0f} 秒）…")
                chains = codec.auto_decode([], stripped, stripped, max_depth=self.opt.max_depth + 3,
                                           beam=8, deadline=time.time() + budget)
                for res in chains[:4]:
                    if res.score < 20:
                        continue
                    self._finding(item.label, "多层解码链", f"{res.path}\n{res.value[:800]}", "data",
                                  res.raw[:4000])
                    self._add_flags(res.raw, f"{item.label} / {res.path}", f"{item.label} / {res.path}")
                    for fl in res.flags:
                        self.report.flags.append(FlagHit(fl, f"{item.label} / {res.path}",
                                                         150.0, res.value[:120], "多层解码命中"))
                        self.flag_item.setdefault(fl, f"{item.label} / {res.path}")
        return derived

    def _analyze_archive(self, item: Item, data: bytes, ext: str) -> list[Item]:
        derived: list[Item] = []
        prefix = "  " * item.depth
        if ext == "zip":
            entries, comment = archive.zip_entries(data)
            if comment:
                self._finding(item.label, "ZIP 注释", codec.to_text(comment)[:800], "data", comment)
                self._add_flags(comment, f"{item.label} / ZIP 注释", f"{item.label} / ZIP 注释")
            if entries:
                names = "\n".join(f"{e.name}  ({e.size} 字节{'，加密' if e.encrypted else ''})" for e in entries[:40])
                self._finding(item.label, f"ZIP 文件列表（{len(entries)} 项）", names)
                for name in archive.interesting_names([e.name for e in entries]):
                    self.report.flags.append(FlagHit(name, f"{item.label} / 文件名", 60.0, "", "可疑文件名"))
                if any(e.encrypted for e in entries):
                    if archive.pseudo_encrypted(data):
                        fixed = archive.fix_pseudo_encryption(data)
                        self._finding(item.label, "检测到 ZIP 伪加密", "已自动清除加密标志位", "warn", fixed)
                        derived.append(Item(f"{item.label}::伪加密修复", fixed, item.depth + 1, item.label,
                                            step="识别并修复 ZIP 伪加密"))
                    else:
                        self._say(f"{prefix}  ZIP 已加密，先试「文件名当密码」再试常见口令…")
                        outer = item.label.split("::")[-1]
                        pw = archive.crack_password(
                            data, extra=archive.name_passwords(data, outer) + self.opt.extra_patterns,
                            limit=5000)
                        if pw is None:
                            pw = archive.crack_password(data, digits=self.opt.zip_digits)
                        if pw is not None:
                            self._finding(item.label, "ZIP 口令命中（文件名/字典）", f"口令 = {pw!r}", "data")
                            files, note = archive.extract_zip(data, pw.encode())
                            for fn, blob in files.items():
                                derived.append(Item(f"{item.label}::{fn}", blob, item.depth + 1, item.label,
                                                    step=f"用爆破出的口令解出 {fn}"))
                        else:
                            self._finding(item.label, "ZIP 口令未命中", "可尝试更大字典或明文攻击", "warn")
        files, note = archive.extract_any(data, item.label)
        if note:
            self._say(f"{prefix}  {note}")
        for fn, blob in files.items():
            if len(blob) <= self.opt.read_cap:
                derived.append(Item(f"{item.label}::{fn}", blob, item.depth + 1, item.label,
                                    step=f"解压得到 {fn}"))
        return derived


def extract_pdf_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        chunks = []
        for page in reader.pages[:30]:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunks).strip()
    except Exception:
        return ""


def analyze_text_quick(text: str, deep: bool = True) -> Report:
    """针对粘贴文本的快速分析（GUI 文本页使用）。"""
    pipe = Pipeline(Options(deep=deep, max_depth=3))
    pipe.deadline = time.time() + pipe.opt.time_budget
    pipe._analyze_text(Item("粘贴内容", text.encode("utf-8", "ignore")), text)
    pipe.report.flags = merge(pipe.report.flags)
    return pipe.report
