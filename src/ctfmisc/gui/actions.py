"""卡片列表对应的具体动作实现。"""

from __future__ import annotations

import io
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .. import (archive, audio, binary, carve, codec, crypto_ext as cx, docs, filetypes, forensic,
                image, jpegdct, misc, ocr, pcap, pwn, report as report_mod, textstego, web)
from ..flags import find_flags


class FieldDialog(tk.Toplevel):
    """简单的多字段输入对话框。"""

    def __init__(self, parent, title: str, fields, on_submit):
        super().__init__(parent)
        self.title(title)
        self.configure(bg="#f3f4f6")
        self.resizable(False, False)
        self.transient(parent)
        self.result = None
        self.on_submit = on_submit
        self.widgets = {}
        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=title, font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(0, 8))
        for label, default, kind in fields:
            ttk.Label(body, text=label).pack(anchor="w", pady=(6, 2))
            if kind == "bigtext":
                txt = tk.Text(body, width=64, height=6, font=("Consolas", 10))
                txt.insert("1.0", default)
                txt.pack(fill="both")
                self.widgets[label] = txt
            elif kind == "choice":
                var = tk.StringVar(value=default)
                ttk.Combobox(body, textvariable=var, values=default if isinstance(default, list) else [],
                             width=60).pack(fill="x")
                self.widgets[label] = var
            else:
                var = tk.StringVar(value=default)
                entry = ttk.Entry(body, textvariable=var, width=64)
                entry.pack(fill="x")
                self.widgets[label] = var
        btns = ttk.Frame(body)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="确定", command=self._ok).pack(side="right")
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right", padx=6)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.update_idletasks()
        x = parent.winfo_rootx() + 80
        y = parent.winfo_rooty() + 80
        self.geometry(f"+{x}+{y}")
        self.grab_set()

    def _ok(self) -> None:
        values = {}
        for label, w in self.widgets.items():
            if isinstance(w, tk.Text):
                values[label] = w.get("1.0", "end").strip()
            else:
                values[label] = w.get().strip()
        self.destroy()
        self.on_submit(values)


class Actions:
    def __init__(self, app):
        self.app = app

    # ------------------------------------------------------------------ #
    # 通用工具
    # ------------------------------------------------------------------ #
    def _need_file(self, prompt: str = "选择题目文件", types=None) -> str | None:
        path = self.app.current_file
        if path and os.path.exists(path):
            return path
        path = self.app.pick_file(prompt, types)
        if path:
            self.app.set_current_file(path)
        return path

    def _read(self, path: str) -> bytes:
        with open(path, "rb") as fh:
            return fh.read(64 * 1024 * 1024)

    def _out(self, title: str, text: str, flags=None, items=None) -> None:
        self.app.show_result(title, text, flags=flags, items=items)

    def ask(self, title: str, fields, on_submit) -> None:
        FieldDialog(self.app, title, fields, on_submit)

    def _file_text(self, data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("gbk")
            except UnicodeDecodeError:
                return data.decode("latin-1")

    # ------------------------------------------------------------------ #
    # ① 一键
    # ------------------------------------------------------------------ #
    def act_auto(self) -> None:
        self.app.run_pipeline(on_current_file=True)

    def act_folder(self) -> None:
        d = filedialog.askdirectory(title="选择题目文件夹")
        if d:
            self.app.run_pipeline(paths=[d])

    def act_text(self) -> None:
        self.app.open_tool("codec")

    def act_selftest(self) -> None:
        self.app.run_selftest_dialog()

    # ------------------------------------------------------------------ #
    # ② 编码
    # ------------------------------------------------------------------ #
    def act_decode_all(self) -> None:
        path = self._need_file("选择含密文的文件（或先复制密文到剪贴板）", [("文本", "*.txt"), ("全部", "*.*")])
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        if len(text) > 20000:
            text = text[:20000]
        rows = codec.manual_decode(text)
        extra = misc.analyze_text(text)
        lines = [f"【输入】{path}\n", "== 单层解码结果（按可能性排序）=="]
        for name, value, score in rows[:40]:
            lines.append(f"[{score:6.1f}] {name}\n        {value[:200]}")
        for title, res in extra:
            lines.append(f"[脑洞] {title}: {res[:200]}")
        hits = find_flags(text)
        self._out("编码全能解码", "\n".join(lines), flags=[h.value for h in hits])

    def act_multi_decode(self) -> None:
        path = self._need_file("选择含多层编码的文件", [("文本", "*.txt"), ("全部", "*.*")])
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        self.app.show_busy(True)
        self.app.status_set("多层解码爆破中…")
        self.app.worker(lambda: codec.auto_decode([], text, text, max_depth=6, beam=10),
                        on_done=self._multi_done)

    def _multi_done(self, results) -> None:
        self.app.show_busy(False)
        lines, flags = [], []
        for i, r in enumerate(results[:25], 1):
            lines.append(f"#{i} 路径：{r.path}\n    评分 {r.score:.0f}\n    结果：{r.value[:300]}\n")
            flags.extend(r.flags)
        self._out("多层编码自动解链", "\n".join(lines) or "没有找到可解码的链路", flags=flags)

    def act_encode(self) -> None:
        self.app.open_tool("codec")

    def act_custom_b64(self) -> None:
        def submit(v):
            alphabet = v.get("自定义字母表", "")
            data = v.get("密文", "")
            if len(alphabet) != 64:
                messagebox.showwarning("提示", "Base64 字母表必须是 64 个字符")
                return
            import base64
            std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            table = str.maketrans(alphabet, std)
            core = re.sub(r"\s", "", data).translate(table)
            core += "=" * (-len(core) % 4)
            try:
                raw = base64.b64decode(core)
            except Exception as exc:
                messagebox.showerror("失败", f"解码失败：{exc}")
                return
            text = codec.to_text(raw)
            hits = find_flags(text)
            self._out("自定义字母表 Base64", f"解出内容：\n{text[:2000]}", flags=[h.value for h in hits])
        self.ask("自定义字母表 Base64", [("自定义字母表（64 个字符）", "", "text"), ("密文", "", "bigtext")], submit)

    def act_base_convert(self) -> None:
        path = self._need_file("选择数字/进制数据文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        lines = []
        for name, fn in (("二进制→字节", codec.dec_binary), ("八进制→字节", codec.dec_octal),
                         ("十进制/点分→字节", codec.dec_decimal), ("十六进制→字节", codec.dec_hex),
                         ("DNA→字节", codec.dec_dna), ("A1Z26→字母", codec.dec_a1z26)):
            try:
                r = fn(text)
            except Exception:
                r = None
            if r:
                lines.append(f"{name}: {codec.to_text(r)[:200] if isinstance(r, bytes) else str(r)[:200]}")
        self._out("进制 / 数字编码转换", "\n".join(lines) or "没有识别出数字编码")

    # ------------------------------------------------------------------ #
    # ③ 古典密码
    # ------------------------------------------------------------------ #
    def act_caesar(self) -> None:
        path = self._need_file("选择密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        ranked = sorted(codec.best_caesar_variants(text), key=lambda kv: -codec.text_score(kv[1]))
        lines = [f"ROT{shift}: {val[:200]}   (评分 {codec.text_score(val):.0f})" for shift, val in ranked]
        flags = [h.value for _s, v in ranked for h in find_flags(v)]
        self._out("凯撒 / ROT 全枚举（按可能性排序）", "\n".join(lines), flags=flags)

    def act_vigenere(self) -> None:
        path = self._need_file("选择维吉尼亚密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        self.app.show_busy(True)
        self.app.status_set("维吉尼亚破解中…")

        def job():
            known = cx.vigenere_known_plaintext_attack(text)
            general = cx.vigenere_crack(text)
            return known, general

        def done(res):
            self.app.show_busy(False)
            known, general = res
            lines, flags = [], []
            if known:
                lines.append("== 已知明文（假定含 flag{）破解 ==")
                for key, plain in known[:5]:
                    lines.append(f"密钥 {key!r}\n  {plain[:300]}")
                    flags += [h.value for h in find_flags(plain)]
            if general:
                lines.append("\n== 频率分析自动破解 ==")
                for key, score, plain in general[:5]:
                    lines.append(f"密钥 {key!r}  评分 {score:.0f}\n  {plain[:300]}")
            self._out("维吉尼亚自动破解", "\n".join(lines) or "未能破解", flags=flags)

        self.app.worker(job, on_done=done)

    def act_substitution(self) -> None:
        path = self._need_file("选择单表替换密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        self.app.show_busy(True)
        self.app.status_set("替换密码爬山法求解中…")
        self.app.worker(lambda: cx.substitution_crack(text, iterations=6000, restarts=8), on_done=self._sub_done)

    def _sub_done(self, results) -> None:
        self.app.show_busy(False)
        if not results:
            self._out("单表替换破解", "文本太短，无法可靠破解（建议 > 100 个字母）")
            return
        lines = []
        for plain, score, mapping in results[:3]:
            lines.append(f"评分 {score:.1f}\n明文：{plain[:400]}\n映射：{mapping}\n")
        flags = [h.value for p, _s, _m in results for h in find_flags(p)]
        self._out("单表替换破解", "\n".join(lines), flags=flags)

    def act_playfair_hill(self) -> None:
        path = self._need_file("选择密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        lines = ["== Playfair（常见密钥尝试）=="]
        for key, score, plain in cx.playfair_crack(text)[:5]:
            lines.append(f"密钥 {key!r} 评分 {score:.0f}\n  {plain[:200]}")
        flags = [h.value for _k, _s, p in cx.playfair_crack(text) for h in find_flags(p)]
        self._out("Playfair / Hill 破解", "\n".join(lines), flags=flags)

    def act_transposition(self) -> None:
        path = self._need_file("选择密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        lines = []
        rail = codec.dec_rail_fence(text)
        if rail:
            lines.append(f"栅栏密码最佳解：\n  {rail[:200]}")
        col = codec.dec_columnar_brute(text)
        if col:
            lines.append(f"列置换最佳解：\n  {col[:200]}")
        flags = [h.value for v in (rail, col) if v for h in find_flags(v)]
        self._out("栅栏 / 列置换暴力", "\n".join(lines) or "两种置换都没找到合理解", flags=flags)

    def act_other_classic(self) -> None:
        path = self._need_file("选择密文文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        lines = []
        for name, fn in (("摩斯电码", codec.dec_morse), ("培根密码", codec.dec_bacon),
                         ("A1Z26", codec.dec_a1z26), ("Polybius 方阵", codec.dec_polybius),
                         ("键盘错位", codec.dec_qwerty_shift), ("Atbash", codec.atbash)):
            try:
                r = fn(text)
            except Exception:
                r = None
            if r:
                lines.append(f"{name}: {str(r)[:200]}")
        self._out("摩斯 / 培根 / A1Z26 / Polybius", "\n".join(lines) or "没有识别出这些经典密码")

    # ------------------------------------------------------------------ #
    # ④ 现代密码
    # ------------------------------------------------------------------ #
    def act_xor(self) -> None:
        path = self._need_file("选择 XOR 密文文件")
        if not path:
            return
        data = self._read(path)
        text_like = sum(1 for b in data[:200] if 32 <= b < 127) / max(min(len(data), 200), 1)
        if text_like < 0.8:            # 可能是 hex/base64 文本
            try:
                candidate = codec.dec_hex(self._file_text(data).strip())
                if candidate:
                    data = candidate
            except Exception:
                pass
        self.app.show_busy(True)
        self.app.status_set("XOR 爆破中…")

        def job():
            return (cx.xor_known_plaintext_attack(data),
                    cx.xor_single_byte(data, 6),
                    cx.xor_repeating(data, 24, 5) if len(data) > 16 else [])

        def done(res):
            self.app.show_busy(False)
            known, single, rep = res
            lines, flags = [], []
            if known:
                lines.append("== 已知明文攻击（假定明文含 flag{）==")
                for key, dec in known[:4]:
                    lines.append(f"密钥(hex) {key.hex()}  长度 {len(key)}\n  {dec[:300]}\n")
                    flags += [h.value for h in find_flags(dec.decode("latin-1"))]
            lines.append("== 单字节密钥爆破（前 6 名）==")
            for key, score, dec in single[:6]:
                lines.append(f"密钥 0x{key:02x} 评分 {score:.0f}: {dec[:120]}")
                flags += [h.value for h in find_flags(dec.decode("latin-1"))]
            if rep:
                lines.append("\n== 重复密钥爆破（前 5 名）==")
                for key, score, dec in rep[:5]:
                    lines.append(f"密钥 {key!r} 评分 {score:.0f}: {dec[:120]}")
                    flags += [h.value for h in find_flags(dec.decode("latin-1"))]
            self._out("XOR 爆破", "\n".join(lines), flags=flags)

        self.app.worker(job, on_done=done)

    def act_symmetric(self) -> None:
        def submit(v):
            data_text = v.get("密文（hex / base64 / 原文）", "")
            key_text = v.get("密钥 key", "")
            iv_text = v.get("初始向量 iv（ECB 可留空）", "")
            data = cx.guess_bytes(data_text)
            key = cx.guess_bytes(key_text)
            iv = cx.guess_bytes(iv_text) if iv_text else None
            outs = cx.symmetric_decrypt(data, key, iv)
            if not outs:
                self._out("对称加密解密", "没有成功解出（检查 key/iv 长度与编码）")
                return
            lines, flags = [], []
            for name, dec in outs:
                text = codec.to_text(dec)
                lines.append(f"[{name}] {text[:300]}")
                flags += [h.value for h in find_flags(text)]
            self._out("对称加密解密（AES/DES/3DES）", "\n".join(lines), flags=flags)
        self.ask("对称加密解密", [("密文（hex / base64 / 原文）", "", "bigtext"),
                                  ("密钥 key", "", "text"),
                                  ("初始向量 iv（ECB 可留空）", "", "text")], submit)

    def act_hash(self) -> None:
        path = self._need_file("选择含哈希值的文件")
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        tokens = re.findall(r"\b[a-fA-F0-9]{16,128}\b", text) or [text.split()[0] if text.split() else ""]
        lines = []
        self.app.show_busy(True)

        def job():
            out = []
            for tok in tokens[:6]:
                kind = misc.hash_identify(tok)
                pw = misc.hash_crack(tok, digits=6)
                out.append((tok, kind, pw))
            return out

        def done(res):
            self.app.show_busy(False)
            for tok, kind, pw in res:
                lines.append(f"{tok}\n  类型：{kind}\n  明文：{pw if pw is not None else '未命中'}")
            self._out("哈希识别与爆破", "\n".join(lines))

        self.app.worker(job, on_done=done)

    def act_jwt(self) -> None:
        path = self._need_file("选择含 JWT 的文件")
        if not path:
            return
        token = self._file_text(self._read(path)).strip().split()[-1]
        data = misc.jwt_decode(token)
        lines = []
        if data:
            import json
            lines.append(json.dumps(data, ensure_ascii=False, indent=2))
        pw = cx.jwt_crack_hs256(token, cx.COMMON_JWT_KEYS)
        lines.append(f"\nHS256 弱密钥爆破：{pw!r}" if pw else "\nHS256 弱密钥爆破：未命中")
        self._out("JWT 解码与爆破", "\n".join(lines))

    def act_rsa(self) -> None:
        def submit(v):
            def num(name):
                s = v.get(name, "").strip()
                if not s:
                    return None
                try:
                    return int(re.sub(r"[^0-9]", "", s) or 0)
                except ValueError:
                    return None
            n, e, c = num("n"), num("e"), num("c")
            if not (n and e and c):
                messagebox.showwarning("提示", "至少需要 n / e / c")
                return
            extra = {}
            for k in ("p", "q", "phi", "n2", "e2", "c2"):
                val = num(k)
                if val:
                    extra[k] = val
            res = cx.rsa_attack_all(n, e, c, extra)
            if not res:
                self._out("RSA 攻击", "常见弱参数攻击都没有成功（可能需要 Coppersmith / 格攻击等高级方法）")
                return
            lines = [f"[{name}] {text}" for name, text in res]
            flags = [h.value for _n, t in res for h in find_flags(t)]
            self._out("RSA 弱参数攻击", "\n".join(lines), flags=flags)
        self.ask("RSA 攻击（填你能拿到的参数）",
                 [("n", "", "text"), ("e", "", "text"), ("c", "", "text"),
                  ("p（可选）", "", "text"), ("q（可选）", "", "text"),
                  ("phi（可选）", "", "text"),
                  ("共模第二个 n2（可选）", "", "text"),
                  ("共模第二个 e2（可选）", "", "text"),
                  ("共模第二个 c2（可选）", "", "text")], submit)

    # ------------------------------------------------------------------ #
    # ⑤ 图片
    # ------------------------------------------------------------------ #
    def act_image_scan(self) -> None:
        path = self._need_file("选择图片", [("图片", "*.png *.jpg *.jpeg *.gif *.bmp *.webp *.tif"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        for f in image.analyze(data, deep_lsb=True):
            lines.append(f"[{f.kind}] {f.title}\n    {f.detail[:400]}")
            flags += [h.value for h in find_flags(codec.to_text(f.data))]
        for text in misc.qr_decode(data):
            lines.append(f"[二维码/条码] {text}")
            flags += [h.value for h in find_flags(text)]
        flag2 = find_flags(codec.to_text(data))
        flags += [h.value for h in flag2]
        self._out(f"图片全方位扫描：{os.path.basename(path)}", "\n".join(lines), flags=flags)

    def act_lsb_matrix(self) -> None:
        path = self._need_file("选择图片")
        if not path:
            return
        img = image.open_image(self._read(path))
        if img is None:
            messagebox.showwarning("提示", "无法解析该图片")
            return
        lines, flags = [], []
        for label, blob in image.lsb_candidates(img, quick=False):
            head = blob[:300]
            printable = "".join(chr(b) if 32 <= b < 127 else "·" for b in head)
            hits = find_flags(head.decode("latin-1"))
            mark = "★ " if hits else ""
            lines.append(f"{mark}[{label}] {printable[:160]}")
            flags += [h.value for h in hits]
        self._out("LSB 矩阵扫描（多通道 / 多比特位 / 多顺序）", "\n".join(lines), flags=flags)

    def act_png_tools(self) -> None:
        path = self._need_file("选择 PNG 图片", [("PNG", "*.png"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines = []
        for f in image.png_analyze(data):
            lines.append(f"[{f.kind}] {f.title}\n    {f.detail[:400]}")
        fixed = image.png_fix_height(data)
        if fixed:
            out = os.path.join(os.path.dirname(path), "fixed_height.png")
            with open(out, "wb") as fh:
                fh.write(fixed[0])
            lines.append(f"\n★ 检测到高度被篡改：已修复为 {fixed[1]}，保存到 {out}")
        else:
            lines.append("\n高度检查：没有发现被篡改的高度")
        self._out("PNG 结构 / 高度修复 / 文本块", "\n".join(lines))

    def act_png_size_brute(self) -> None:
        path = self._need_file("选择宽高被改过的 PNG", [("PNG", "*.png"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        exact = image.png_fix_height(data)
        sheet, notes, flags = image.png_size_sheet(data, limit=12)
        lines = []
        if exact:
            lines.append(f"★ 只改高度的情况：精确还原为高度 {exact[1]}（已自动修复，可直接保存）")
        else:
            lines.append("精确还原不适用（宽度也被改过）→ 下面列出所有合法候选尺寸")
        cands = image.png_bruteforce_size(data, limit=12)
        lines.append("候选尺寸（按可能性排序）：" + ", ".join(f"{w}x{h}" for w, h, _b in cands))
        lines += notes
        outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_宽高爆破")
        os.makedirs(outdir, exist_ok=True)
        for w, h, patched in cands:
            with open(os.path.join(outdir, f"{w}x{h}.png"), "wb") as fh:
                fh.write(patched)
        if sheet:
            spath = os.path.join(outdir, "候选对照图.png")
            with open(spath, "wb") as fh:
                fh.write(sheet)
            lines.append(f"\n候选对照图（一眼看出哪个是正常图片）：{spath}")
            try:
                os.startfile(spath)
            except Exception:
                pass
        lines.append(f"所有候选已导出到：{outdir}")
        self._out("PNG 宽高爆破", "\n".join(lines), flags=flags)

    def act_arnold(self) -> None:
        path = self._need_file("选择被猫脸变换的图片", [("图片", "*.png *.bmp *.jpg"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        img = image.open_image(data)
        if img is None:
            self._out("猫脸变换还原", "无法解析图片")
            return
        self.app.show_busy(True)
        self.app.status_set("枚举猫脸变换次数中…")

        def job():
            sheet, hits = image.arnold_scan(data, max_times=60)
            return sheet, hits

        def done(res):
            self.app.show_busy(False)
            sheet, hits = res
            outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_猫脸还原")
            os.makedirs(outdir, exist_ok=True)
            lines = ["猫脸变换（Arnold）逆向枚举 1~60 次，对照图里找那张“正常图片”即可。"]
            if hits:
                lines += hits
            if sheet:
                spath = os.path.join(outdir, "猫脸逆变换对照图.png")
                with open(spath, "wb") as fh:
                    fh.write(sheet)
                lines.append(f"\n对照图：{spath}")
                try:
                    os.startfile(spath)
                except Exception:
                    pass
            # 逐个次数导出，方便单独细看
            cur = img.convert("RGB")
            for i in range(1, 61):
                cur = image.arnold(cur, 1, 1, 1, inverse=True)
                cur.save(os.path.join(outdir, f"逆变换_{i:02d}次.png"))
            lines.append(f"1~60 次的结果已全部导出到：{outdir}")
            self._out("猫脸变换还原", "\n".join(lines),
                      flags=[h.split("：")[-1] for h in hits if "flag" in h])

        self.app.worker(job, on_done=done)

    def act_geometry(self) -> None:
        path = self._need_file("选择图片")
        if not path:
            return
        data = self._read(path)
        sheet = image.geometry_montage(data)
        if not sheet:
            self._out("图片几何变换排查", "无法解析图片")
            return
        out = os.path.join(os.path.dirname(path), "几何变换对照图.png")
        with open(out, "wb") as fh:
            fh.write(sheet)
        lines = [f"对照图已生成：{out}", "",
                 "包含：原图 / 旋转 90/180/270 / 水平·垂直镜像 / 转置 / R-G·G-B·B-R 通道差分 / 单通道。",
                 "反色、位平面、对比度增强在「图片可视化排查」卡片里。"]
        flags = []
        for label, _im in ():
            pass
        self._out("图片几何变换排查", "\n".join(lines), flags=flags)
        try:
            os.startfile(out)
        except Exception:
            pass

    def act_grid_split(self) -> None:
        path = self._need_file("选择拼图类图片")
        if not path:
            return
        def submit(v):
            try:
                rows = int(v.get("行数", "3") or 3)
                cols = int(v.get("列数", "3") or 3)
            except ValueError:
                rows = cols = 3
            data = self._read(path)
            sheet = image.grid_split(data, rows, cols)
            if not sheet:
                self._out("拼图网格切分", "切分失败（尺寸太小或不是图片）")
                return
            out = os.path.join(os.path.dirname(path), f"网格{rows}x{cols}_对照图.png")
            with open(out, "wb") as fh:
                fh.write(sheet)
            self._out("拼图网格切分", f"{rows}×{cols} 切分对照图：{out}\n\n"
                                      "用途：拼图题先看清每块内容/编号顺序，再手工或按题目规则重排。")
            try:
                os.startfile(out)
            except Exception:
                pass
        self.ask("拼图网格切分", [("行数", "3", "text"), ("列数", "3", "text")], submit)

    def act_jpeg_dct(self) -> None:
        path = self._need_file("选择 JPEG 图片", [("JPEG", "*.jpg *.jpeg"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        try:
            info = jpegdct.probe(data)
            lines.append(f"结构：{info.width}x{info.height}，{info.components} 分量，"
                         f"{'渐进式' if info.progressive else '基线'}"
                         f"{'，量化表标准' if info.standard_tables else '，量化表非标准'}")
        except Exception as exc:
            lines.append(f"结构解析失败：{exc}")
        try:
            streams = jpegdct.candidate_streams(data)
            hit = False
            for name, blob in streams:
                head = blob[:300]
                hits = find_flags(head.decode("latin-1"))
                printable = "".join(chr(b) if 32 <= b < 127 else "·" for b in head)
                if hits or sum(1 for b in head if 32 <= b < 127) / max(len(head), 1) > 0.9:
                    hit = True
                    lines.append(f"★ [{name}] {printable[:200]}")
                    flags += [h.value for h in hits]
            if not hit:
                lines.append("系数域：已按 jsteg 规则扫描（含偏移），未发现文本或 flag")
                lines.append("提示：若题面给了口令，可能是 steghide / outguess / jphide / F5（需要密码）")
        except jpegdct.Unsupported as exc:
            lines.append(f"系数域提取不可用：{exc}")
        self._out("JPEG 系数域分析（jsteg）", "\n".join(lines), flags=flags)

    def act_image_visual(self) -> None:
        path = self._need_file("选择图片")
        if not path:
            return
        png = image.visual_montage(self._read(path))
        if not png:
            messagebox.showwarning("提示", "无法生成可视化拼图")
            return
        out = os.path.join(os.path.dirname(path), "可视化排查.png")
        with open(out, "wb") as fh:
            fh.write(png)
        self._out("图片可视化排查图", f"已生成拼图（原图 / 对比度 / 均衡 / 反相 / 通道 / 位平面）：\n{out}\n\n"
                                     "重点看：位平面里有没有文字、单通道里有没有另一张图、反相后有没有隐藏内容。")
        try:
            os.startfile(out)
        except Exception:
            pass

    def act_qr(self) -> None:
        path = self._need_file("选择含二维码/条码的图片")
        if not path:
            return
        data = self._read(path)
        results = misc.qr_decode(data)
        lines = [f"二维码/条码识别结果（{len(results)} 条）："] + [f"  {r}" for r in results]
        flags = [h.value for r in results for h in find_flags(r)]
        if not results:
            lines.append("  未识别到内容——可以先用“图片可视化排查”做二值化/放大再试")
        self._out("二维码 / 条形码识别", "\n".join(lines), flags=flags)

    def act_ocr(self) -> None:
        path = self._need_file("选择含文字的图片", [("图片", "*.png *.jpg *.jpeg *.bmp *.gif *.webp"), ("全部", "*.*")])
        if not path:
            return
        if not ocr.available():
            self._out("图片文字识别（OCR）", "OCR 组件不可用（需要 rapidocr-onnxruntime）")
            return
        data = self._read(path)
        self.app.show_busy(True)
        self.app.status_set("OCR 识别中…")

        def job():
            texts, flags = ocr.ocr_flags(data)
            # 顺带识别内嵌图片
            extra = []
            if filetypes.identify(data).ext in ("jpg", "jpeg"):
                for f in image.jpeg_analyze(data):
                    if f.data and f.data[:3] == b"\xff\xd8\xff":
                        t2, f2 = ocr.ocr_flags(f.data)
                        extra.append(("内嵌 EXIF 图片", t2, f2))
            return texts, flags, extra

        def done(res):
            self.app.show_busy(False)
            texts, flags, extra = res
            lines = ["识别到的文字："] + ["  " + t for t in texts[:20]]
            for label, t2, f2 in extra:
                lines += [f"\n[{label}]"] + ["  " + t for t in t2[:10]]
                flags += f2
            if not texts and not extra:
                lines.append("  （没有识别到文字）")
            self._out("图片文字识别（OCR）", "\n".join(lines), flags=sorted(set(flags)))

        self.app.worker(job, on_done=done)

    def act_appn(self) -> None:
        path = self._need_file("选择 JPEG", [("JPEG", "*.jpg *.jpeg"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        found_any = False
        for idx, payload in image.iter_appn(data):
            if len(payload) < 64:
                continue
            found_any = True
            lines.append(f"APP{idx} 段：{len(payload)} 字节")
            for sig, ext in ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG", "png"), (b"PK\x03\x04", "zip"),
                             (b"\x1f\x8b", "gz"), (b"%PDF", "pdf")):
                pos = payload.find(sig)
                if pos < 0:
                    continue
                blob = payload[pos:]
                if ext == "jpg":
                    end = blob.rfind(b"\xff\xd9")
                    blob = blob[:end + 2] if end > 0 else blob
                outdir = os.path.join(os.path.dirname(path), "APPn_提取")
                os.makedirs(outdir, exist_ok=True)
                target = os.path.join(outdir, f"APP{idx}_内嵌.{ext}")
                with open(target, "wb") as fh:
                    fh.write(blob)
                lines.append(f"  ★ 发现内嵌 {ext.upper()}（偏移 {pos}，{len(blob)} 字节）→ {target}")
                flags += [h.value for h in find_flags(codec.to_text(blob))]
                if ocr.available() and ext in ("jpg", "png"):
                    t, f2 = ocr.ocr_flags(blob)
                    if t:
                        lines.append("    内嵌图片 OCR：" + " / ".join(t[:4]))
                    flags += f2
                break
        if not found_any:
            lines = ["没有发现体积异常的 APPn / COM 段"]
        self._out("EXIF / APPn 内嵌文件提取", "\n".join(lines), flags=sorted(set(flags)))

    def act_gif_hidden(self) -> None:
        path = self._need_file("选择 GIF", [("GIF", "*.gif"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        hidden = image.gif_hidden_frames(data)
        if not hidden:
            self._out("GIF 帧内隐藏图", "各帧的像素数量都正常，没有发现藏在 LZW 流里的第二张图")
            return
        outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_隐藏图")
        os.makedirs(outdir, exist_ok=True)
        lines, flags = [f"发现 {len(hidden)} 张藏在帧里的图片："], []
        for label, blob in hidden:
            target = os.path.join(outdir, label.replace(" ", "_") + ".png")
            with open(target, "wb") as fh:
                fh.write(blob)
            lines.append(f"  ★ {label} → {target}")
            if ocr.available():
                t, f2 = ocr.ocr_flags(blob)
                if t:
                    lines.append("      OCR：" + " / ".join(t[:4]))
                flags += f2
        self._out("GIF 帧内隐藏图提取", "\n".join(lines), flags=sorted(set(flags)))

    # ------------------------------------------------------------------ #
    # ⑥ 音频
    # ------------------------------------------------------------------ #
    def act_audio_lsb(self) -> None:
        path = self._need_file("选择音频文件", [("音频", "*.wav *.mp3 *.ogg *.flac"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        for label, blob in audio.wav_lsb_candidates(data):
            head = blob[:300]
            printable = "".join(chr(b) if 32 <= b < 127 else "·" for b in head)
            hits = find_flags(head.decode("latin-1"))
            lines.append(f"{'★ ' if hits else ''}[{label}] {printable[:160]}")
            flags += [h.value for h in hits]
        self._out("音频 LSB 提取", "\n".join(lines) or "不是 WAV 或没有可用采样", flags=flags)

    def act_spectrogram(self) -> None:
        path = self._need_file("选择音频文件", [("音频", "*.wav *.mp3 *.ogg *.flac"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        spec = audio.spectrogram(data)
        if not spec:
            messagebox.showwarning("提示", "无法生成频谱图（需要 WAV，且长度足够）")
            return
        out = os.path.join(os.path.dirname(path), "频谱图.png")
        with open(out, "wb") as fh:
            fh.write(spec)
        lines = [f"频谱图已生成：{out}", "重点看图中是否藏着文字或二维码。"]
        flags = []
        for text in misc.qr_decode(spec):
            lines.append(f"频谱图中的二维码：{text}")
            flags += [h.value for h in find_flags(text)]
        self._out("音频频谱图", "\n".join(lines), flags=flags)
        try:
            os.startfile(out)
        except Exception:
            pass

    def act_audio_misc(self) -> None:
        path = self._need_file("选择音频文件")
        if not path:
            return
        data = self._read(path)
        lines = []
        tones = audio.dtmf_decode(data)
        if tones:
            lines.append(f"DTMF 拨号音解码：{tones}")
        morse = audio.morse_from_audio(data)
        if morse:
            lines.append(f"音频摩斯（实验性）：{morse}")
        for f in audio.mp3_tags(data):
            lines.append(f"[{f.title}] {f.detail[:200]}")
        flags = [h.value for line in lines for h in find_flags(line)]
        self._out("DTMF / 摩斯 / 音频元数据", "\n".join(lines) or "没有识别到 DTMF 或摩斯信号", flags=flags)

    # ------------------------------------------------------------------ #
    # ⑦ 压缩包
    # ------------------------------------------------------------------ #
    def act_zip_unpack(self) -> None:
        path = self._need_file("选择压缩包", [("压缩包", "*.zip *.7z *.rar *.gz *.xz *.bz2 *.tar"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_解包")
        os.makedirs(outdir, exist_ok=True)
        files, note = archive.extract_any(data, os.path.basename(path))
        lines, flags, count = [note or "解包完成"], [], 0
        for name, blob in files.items():
            target = os.path.join(outdir, os.path.basename(name))
            try:
                with open(target, "wb") as fh:
                    fh.write(blob)
                count += 1
                hits = find_flags(codec.to_text(blob))
                flags += [h.value for h in hits]
                tag = "★ " if hits else "  "
                lines.append(f"{tag}{name}  ({len(blob)} 字节)")
            except OSError as exc:
                lines.append(f"  写出失败 {name}: {exc}")
        lines.append(f"\n共写出 {count} 个文件到：{outdir}")
        self._out("压缩包解包（含嵌套）", "\n".join(lines), flags=flags)

    def act_zip_pseudo(self) -> None:
        path = self._need_file("选择 ZIP", [("ZIP", "*.zip"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        if not archive.pseudo_encrypted(data):
            self._out("ZIP 伪加密检测", "没有检测到伪加密（或确实加密了）")
            return
        fixed = archive.fix_pseudo_encryption(data)
        out = path + ".fixed.zip"
        with open(out, "wb") as fh:
            fh.write(fixed)
        files, _note = archive.extract_any(fixed, "fixed.zip")
        lines = [f"检测到伪加密！已修复并保存：{out}\n"]
        flags = []
        for name, blob in files.items():
            text = codec.to_text(blob)
            hits = find_flags(text)
            flags += [h.value for h in hits]
            lines.append(f"{'★ ' if hits else ''}{name}: {text[:200]}")
        self._out("ZIP 伪加密修复", "\n".join(lines), flags=flags)

    def act_zip_crack(self) -> None:
        path = self._need_file("选择加密 ZIP", [("ZIP", "*.zip"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        self.app.show_busy(True)
        self.app.status_set("压缩包口令爆破中…")

        def job():
            pw = archive.crack_password(data, digits=6)
            if pw is None:
                return None, {}
            files, _note = archive.extract_any(data, "x.zip")
            return pw, files

        def done(res):
            self.app.show_busy(False)
            pw, files = res
            if pw is None:
                self._out("压缩包口令爆破", "内置字典 + 0000-999999 未命中。\n"
                                             "可以试试：题目里给的关键词、文件名、日期；或使用 hashcat/john 跑更大字典。")
                return
            lines, flags = [f"★ 口令 = {pw!r}\n"], []
            for name, blob in files.items():
                text = codec.to_text(blob)
                hits = find_flags(text)
                flags += [h.value for h in hits]
                lines.append(f"{name}: {text[:200]}")
            self._out("压缩包口令爆破", "\n".join(lines), flags=flags)

        self.app.worker(job, on_done=done)

    def act_name_password(self) -> None:
        path = self._need_file("选择加密 ZIP", [("ZIP", "*.zip"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        cands = archive.name_passwords(data, os.path.basename(path))
        lines = ["按「文件名当密码」思路生成的口令候选："] + ["  " + c for c in cands[:20]]
        pw = archive.crack_password(data, extra=cands, limit=5000)
        flags = []
        if pw is not None:
            lines.append(f"\n★ 命中口令：{pw!r}")
            files, _n = archive.extract_any(data, os.path.basename(path))
            for name, blob in list(files.items())[:10]:
                text = codec.to_text(blob)[:200]
                lines.append(f"  {name}: {text}")
                flags += [h.value for h in find_flags(text)]
        else:
            lines.append("\n文件名候选没命中，可以再试常见字典（见「压缩包口令爆破」卡片）")
        self._out("ZIP 口令 = 文件名", "\n".join(lines), flags=sorted(set(flags)))

    def act_timestamp_stego(self) -> None:
        d = filedialog.askdirectory(title="选择放着大量同类文件的文件夹")
        if not d:
            return
        files = [os.path.join(d, f) for f in sorted(os.listdir(d))]
        res = forensic.timestamps_binary(files)
        if not res:
            self._out("文件时间戳隐写", f"该目录 {len(files)} 个文件的时间戳不足以编码数据"
                                       "（需要大量“大小相同但修改时间只有两种”的文件）")
            return
        lines, flags = [f"目录：{d}（{len(files)} 个文件）", ""], []
        for tag, msg in res:
            lines.append(f"【{tag}】{msg}")
            flags += [h.value for h in find_flags(msg)]
        self._out("文件时间戳隐写（同目录批量文件）", "\n".join(lines), flags=sorted(set(flags)))

    def act_filename_hints(self) -> None:
        path = self._need_file("选择题目附件")
        if not path:
            return
        hints = forensic.filename_hints(path)
        lines = [f"文件名：{os.path.basename(path)}", ""]
        if hints:
            lines += [f"★ {t}：{m}" for t, m in hints]
        else:
            lines.append("文件名里没有明显的 base64/hex/关键字提示")
        # 顺带给出键盘错位变体（DeepSleep 那道题就是 shift 变密码）
        for cand in ["12345678", "qwerty", "1qaz2wsx"]:
            lines.append(f"\n键盘 Shift 变体（{cand}）→ " + ", ".join(forensic.keyboard_shift_variants(cand)))
        self._out("文件名提示 / 键盘错位", "\n".join(lines))

    def act_zip_info(self) -> None:
        path = self._need_file("选择 ZIP", [("ZIP", "*.zip"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        entries, comment = archive.zip_entries(data)
        lines = [f"ZIP 注释：{codec.to_text(comment) if comment else '（无）'}", "",
                 f"共 {len(entries)} 个条目："]
        flags = [h.value for h in find_flags(codec.to_text(comment))]
        for e in entries[:60]:
            lines.append(f"  {e.name}  {e.size} 字节  {'加密' if e.encrypted else ''}  CRC={e.crc:08x}")
            flags += [h.value for h in find_flags(e.name)]
        suspects = archive.interesting_names([e.name for e in entries])
        if suspects:
            lines.append("\n★ 可疑文件名：" + ", ".join(suspects))
        self._out("ZIP 注释 / 文件名 / CRC 分析", "\n".join(lines), flags=flags)

    # ------------------------------------------------------------------ #
    # ⑧ 流量
    # ------------------------------------------------------------------ #
    def act_pcap(self) -> None:
        path = self._need_file("选择流量包", [("流量包", "*.pcap *.pcapng *.cap"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        for f in pcap.analyze(data):
            lines.append(f"[{f.title}]\n    {f.detail[:600]}")
            flags += [h.value for h in find_flags(codec.to_text(f.data))]
        packets = pcap.parse(data)
        domains = pcap.dns_queries(packets)
        if domains:
            lines.append(f"[DNS 查询域名] {', '.join(domains[:20])}")
            flags += [h.value for h in find_flags(" ".join(domains))]
        self._out("流量包分析", "\n".join(lines) or "没有解析出流量内容", flags=flags)

    def act_usb_mouse(self) -> None:
        path = self._need_file("选择 USB 鼠标流量包", [("流量包", "*.pcap *.pcapng"), ("全部", "*.*")])
        if not path:
            return
        packets = pcap.parse(self._read(path))
        png = pcap.usb_mouse_render(packets)
        if not png:
            self._out("USB 鼠标轨迹", "没有找到鼠标移动事件（USB 鼠标题一般是回车/绘图类，另见 USB 键盘还原）")
            return
        out = os.path.join(os.path.dirname(path), "鼠标轨迹.png")
        with open(out, "wb") as fh:
            fh.write(png)
        texts = misc.qr_decode(png)
        lines = [f"轨迹图已保存：{out}", "如果这是画二维码/画字的题，看图即可。"]
        if texts:
            lines.append("★ 轨迹图识别出二维码：" + ", ".join(texts))
        self._out("USB 鼠标轨迹还原", "\n".join(lines), flags=[h.value for t in texts for h in find_flags(t)])
        try:
            os.startfile(out)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # ⑨ 文件取证
    # ------------------------------------------------------------------ #
    def act_carve(self) -> None:
        path = self._need_file("选择要雕复的文件")
        if not path:
            return
        data = self._read(path)
        hits = carve.carve(data)
        if not hits:
            self._out("文件雕复", "没有发现内嵌文件（已做格式校验，不会再有假阳性）")
            return
        outdir = os.path.join(os.path.dirname(path), "carved")
        os.makedirs(outdir, exist_ok=True)
        lines, flags = [], []
        for i, h in enumerate(hits):
            target = os.path.join(outdir, f"{i}_{h.offset}.{h.ext}")
            with open(target, "wb") as fh:
                fh.write(h.data)
            text = codec.to_text(h.data)
            found = find_flags(text)
            flags += [x.value for x in found]
            lines.append(f"{'★ ' if found else '  '}偏移 {h.offset:>8}  {h.desc}  {h.size} 字节 → {target}")
        lines.append(f"\n共雕出 {len(hits)} 个文件到 {outdir}")
        self._out("内嵌文件雕复（binwalk 精简版）", "\n".join(lines), flags=flags)

    def act_strings(self) -> None:
        path = self._need_file("选择要提取字符串的文件")
        if not path:
            return
        data = self._read(path)
        items = pcap.printable_strings(data, 6, 400)
        flags = []
        lines = []
        for s in items:
            hits = find_flags(s)
            flags += [h.value for h in hits]
            lines.append(("★ " if hits else "  ") + s[:200])
        self._out(f"strings 提取（{len(items)} 条）", "\n".join(lines) or "没有可打印字符串", flags=flags)

    def act_hexview(self) -> None:
        path = self._need_file("选择文件")
        if not path:
            return
        with open(path, "rb") as fh:
            data = fh.read(16384)
        self._out("十六进制查看（前 16 KB）", codec.hexdump(data))

    def act_filetype(self) -> None:
        path = self._need_file("选择文件")
        if not path:
            return
        data = self._read(path)
        info = filetypes.identify(data)
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        lines = [f"文件名后缀：.{ext}", f"真实类型：{info.desc}（{info.ext}）",
                 f"文件大小：{len(data)} 字节",
                 f"头部字节：{data[:32].hex(' ')}"]
        if ext and ext != info.ext:
            lines.append(f"\n★ 扩展名与真实类型不一致：把后缀改成 .{info.ext} 再试一次")
        tail = filetypes.trailing_data(data, info.ext)
        if tail:
            lines += ["", f"★ 文件尾有 {len(tail)} 字节附加数据：", repr(tail[:64])]
        self._out("文件类型 / 头尾分析", "\n".join(lines))

    # ------------------------------------------------------------------ #
    # ⑩ 二进制 / 逆向
    # ------------------------------------------------------------------ #
    def act_bincard(self) -> None:
        path = self._need_file("选择可执行文件", [("二进制", "*.exe *.dll *.so *.elf *.bin *.out"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        fmt, items = binary.info_card(data)
        if not items:
            self._out("二进制信息卡", "不是 PE / ELF / Mach-O 文件")
            return
        lines = [f"格式：{fmt}"] + [f"{it.label}: {it.value}" for it in items]
        hints = binary.anti_debug_hints(data)
        if hints:
            lines.append("\n加壳/反调试线索：" + ", ".join(hints))
        self._out("二进制信息卡（checksec 风格）", "\n".join(lines))

    def act_pyc(self) -> None:
        path = self._need_file("选择 .pyc 文件（或裸 code 数据）",
                               [("Python 字节码", "*.pyc *.pyo"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        ver = binary.pyc_version(data)
        lines = [f"Python 版本（按 magic）：{ver}", "", binary.pyc_disassemble(data)]
        suspects = binary.pyc_suspicious_strings(data)
        if suspects:
            lines += ["", "可疑字符串："] + [f"  {s}" for s in suspects]
        flags = [h.value for s in suspects for h in find_flags(s)]
        self._out("Python .pyc 反汇编", "\n".join(lines), flags=flags)

    def act_pyinstaller(self) -> None:
        path = self._need_file("选择 PyInstaller 打包的 exe")
        if not path:
            return
        data = self._read(path)
        files, note = binary.pyinstaller_extract(data)
        lines = [note, ""]
        flags = []
        outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_解包")
        if files:
            os.makedirs(outdir, exist_ok=True)
            for name, blob in list(files.items())[:400]:
                safe = name.replace("\\", "/").split("/")[-1] or "unnamed"
                try:
                    with open(os.path.join(outdir, safe), "wb") as fh:
                        fh.write(blob)
                except OSError:
                    pass
                hits = find_flags(codec.to_text(blob))
                flags += [h.value for h in hits]
                if name in ("hello", "__main__") or name.endswith((".py", ".pyc")) and len(blob) < 100000:
                    lines.append(f"  {name}  ({len(blob)} 字节){'  ★含 flag 字样' if hits else ''}")
            lines.append(f"\n已解出到：{outdir}")
            main = files.get("hello") or files.get("__main__")
            if main:
                lines += ["", "== 主脚本反汇编（前 40 行）==", "\n".join(binary.pyc_disassemble(main, 40).splitlines()[:40])]
        self._out("PyInstaller 解包", "\n".join(lines), flags=flags)

    def act_packers(self) -> None:
        path = self._need_file("选择可疑文件")
        if not path:
            return
        data = self._read(path)
        keys = [b"UPX!", b"UPX0", b"UPX1", b".themida", b"VMProtect", b"ASPack",
                b"PECompact", b"FSG!", b"Petite", b".vmp0", b".vmp1", b"Themida"]
        found = [k.decode("latin-1") for k in keys if k.lower() in data.lower()]
        hints = binary.anti_debug_hints(data)
        lines = []
        if found:
            lines.append("★ 检测到壳特征：" + ", ".join(found))
            lines.append("UPX 可尝试：upx -d 文件（本工具不做脱壳）")
        if hints:
            lines.append("反调试/反虚拟机线索：" + ", ".join(hints))
        ent = binary.entropy(data[:1 << 20])
        lines.append(f"整体熵：{ent:.3f}（>7.2 通常表示加密/压缩数据）")
        self._out("加壳 / 反调试线索扫描", "\n".join(lines) or "没有明显加壳特征")

    def act_help(self) -> None:
        self._out("使用帮助 / 能力边界", HELP_TEXT)

    # ------------------------------------------------------------------ #
    # ⑪ Web 题目
    # ------------------------------------------------------------------ #
    def _get_url(self) -> str | None:
        """（占位：Web 动作统一走 _ask_url / _ask_url_param 的回调形式）"""
        return getattr(self.app, "web_url", "") or None

    def _ask_url(self, title: str, on_submit) -> None:
        def submit(v):
            url = web.normalize_url(v.get(URL_LABEL, ""))
            if not url:
                messagebox.showwarning("提示", "请填写目标 URL")
                return
            self.app.web_url = url
            on_submit(url)
        self.ask(title, [(URL_LABEL, getattr(self.app, "web_url", ""), "text")], submit)

    def _ask_url_param(self, title: str, on_submit) -> None:
        def submit(v):
            url = web.normalize_url(v.get(URL_LABEL, ""))
            param = (v.get(PARAM_LABEL, "") or "").strip()
            if not url or not param:
                messagebox.showwarning("提示", "URL 和参数名都要填")
                return
            self.app.web_url = url
            on_submit(url, param)
        self.ask(title, [(URL_LABEL, getattr(self.app, "web_url", ""), "text"),
                         (PARAM_LABEL, "", "text")], submit)

    def _run_web(self, task, on_done, busy: str = "请求中…") -> None:
        self.app.show_busy(True)
        self.app.status_set(busy)
        self.app.worker(task, on_done=lambda r: (self.app.show_busy(False), on_done(r)))

    def act_web_probe(self) -> None:
        self._ask_url("站点信息探测", lambda url: self._run_web(
            lambda: web.probe_site(url, timeout=10),
            lambda r: self._out(f"站点信息探测：{url}", "\n".join(r[0]), flags=r[1])))

    def act_web_files(self) -> None:
        self._ask_url("敏感文件 / 备份文件扫描", lambda url: self._run_web(
            lambda: web.scan_sensitive(url, on_progress=self.app.log),
            lambda r: self._out("敏感文件 / 备份文件扫描", "\n".join(r[0]), flags=r[1]),
            busy="扫描敏感文件…"))

    def act_web_git(self) -> None:
        outdir = os.path.join(os.path.expanduser("~"), "Desktop", "git泄露恢复")
        self._ask_url(".git 源码泄露恢复", lambda url: self._run_web(
            lambda: web.git_dump(url, outdir, on_progress=self.app.log),
            lambda r: self._out("· git 源码泄露恢复（已保存到桌面「git泄露恢复」文件夹）",
                                "\n".join(r[0]), flags=r[1]),
            busy="拉取 .git 对象…"))

    def act_web_sqli(self) -> None:
        self._ask_url_param("SQL 注入自动检测", lambda url, p: self._run_web(
            lambda: web.sqli_scan(url, p, on_progress=self.app.log),
            lambda r: self._out(f"SQL 注入检测：{p}", "\n".join(r[0]), flags=r[1]),
            busy="SQL 注入检测中（含延时盲注，约 10 秒）…"))

    def act_web_lfi(self) -> None:
        self._ask_url_param("文件包含 / 路径穿越", lambda url, p: self._run_web(
            lambda: web.lfi_scan(url, p, on_progress=self.app.log),
            lambda r: self._out(f"文件包含检测：{p}", "\n".join(r[0]), flags=r[1])))

    def act_web_ssti(self) -> None:
        self._ask_url_param("SSTI 模板注入检测", lambda url, p: self._run_web(
            lambda: web.ssti_scan(url, p, on_progress=self.app.log),
            lambda r: self._out(f"SSTI 检测：{p}", "\n".join(r[0]), flags=r[1])))

    def act_web_rce(self) -> None:
        self._ask_url_param("命令注入检测", lambda url, p: self._run_web(
            lambda: web.rce_scan(url, p, on_progress=self.app.log),
            lambda r: self._out(f"命令注入检测：{p}", "\n".join(r[0]), flags=r[1])))

    def act_web_replay(self) -> None:
        def submit(v):
            raw = v.get("原始 HTTP 请求", "")
            if not raw:
                return
            self.app.show_busy(True)

            def job():
                resp = web.replay_request(raw)
                return resp

            def done(r):
                self.app.show_busy(False)
                head = [f"HTTP {r.status}  ({r.elapsed:.2f}s)"] + \
                       [f"{k}: {v}" for k, v in r.headers.items()]
                body = r.text[:20000]
                hits = [h.value for h in find_flags(body)]
                self._out("请求重放结果（响应头 + 正文）", "\n".join(head) + "\n\n" + body, flags=hits)
            self.app.worker(job, on_done=done)
        self.ask("HTTP 请求重放器（把 Burp 里的原始请求粘进来）",
                 [("原始 HTTP 请求", "GET / HTTP/1.1\nHost: \n\n", "bigtext")], submit)

    def act_web_audit(self) -> None:
        path = self._need_file("选择 HTML / JS / 源码文件", [("网页脚本", "*.html *.js *.php *.py *.txt"), ("全部", "*.*")])
        if not path:
            return
        text = self._file_text(self._read(path))
        lines, flags = web.audit_source(text)
        self._out("源码审计（注释 / 接口 / 密钥）", "\n".join(lines), flags=flags)

    def act_web_cheatsheet(self) -> None:
        self._out("Web 常见 payload 速查表", web.WEB_CHEATSHEET)

    # ------------------------------------------------------------------ #
    # ★ 校赛真题（WZBC 2025）专用卡片：方法 + 自动工具
    # ------------------------------------------------------------------ #
    def act_wzbc_handbook(self) -> None:
        lines = ["# WZBC & CTF 2025 校赛题型解法手册", "",
                 "本手册把校赛每类题的解法固化下来，配合左边的工具卡片使用。", ""]
        for name, body in docs.WZBC_2025.items():
            lines += [f"## {name}", "", body, ""]
        self._out("校赛题型解法手册（WZBC 2025）", "\n".join(lines))

    def act_js_audit_online(self) -> None:
        self._ask_url("前端 JS 抓取审计（babyWeb 那类）", lambda url: self._run_web(
            lambda: web.crawl_and_audit_js(url, on_progress=self.app.log),
            lambda r: self._out(f"前端 JS 审计：{url}", "\n".join(r[0]), flags=r[1]),
            busy="抓取并审计 JS…"))

    def act_pyjail_payloads(self) -> None:
        path = self._need_file("选择 pyjail 题目源码（可取消）",
                               [("Python", "*.py *.txt"), ("全部", "*.*")])
        lines = []
        if path:
            text = self._file_text(self._read(path))
            lines += docs.pyjail_assist(text) + [""]
        lines += docs.PYJAIL_PAYLOADS.splitlines()
        self._out("Python 沙箱逃逸（ezPy 那类）", "\n".join(lines))

    def act_ecc_composite(self) -> None:
        def submit(v):
            def num(x):
                x = (x or "").strip()
                if not x:
                    return None
                try:
                    return int(x, 16) if x.lower().startswith("0x") else int(x)
                except ValueError:
                    return None
            n, a, b = num(v.get("n", "")), num(v.get("a", "")), num(v.get("b", ""))
            x0, y0 = num(v.get("G.x", "")), num(v.get("G.y", ""))
            p_known, q_known = num(v.get("p（已知可填）", "")), num(v.get("q（已知可填）", ""))
            raw_cipher = v.get("密文 c（逗号/换行分隔的整数）", "")
            cipher = [int(t) for t in re.findall(r"\d+", raw_cipher)]
            if not (n and a is not None and b is not None and x0 and y0 and cipher):
                messagebox.showwarning("提示", "n / a / b / G.x / G.y / 密文都要填")
                return
            res = cx.ec_composite_solve(n, a, b, x0, y0, cipher,
                                        p=p_known, q=q_known)
            if not res:
                self._out("椭圆曲线（复合模数）求解",
                          "没能分解 n（可能点没走到不可逆分母，或题目不是这种构造）")
                return
            plain, p, q = res
            text = codec.to_text(plain)
            lines = [f"★ 分解成功：p = {p}", f"            q = {q}", "",
                     f"还原出的明文：", text[:1000]]
            flags = [h.value for h in find_flags(text)]
            self._out("椭圆曲线（复合模数）求解", "\n".join(lines), flags=flags)
        self.ask("椭圆曲线（RSA 模数上）求解 —— 对应 Crypto-Curve",
                 [("n", "", "text"), ("a", "", "text"), ("b", "", "text"),
                  ("G.x", "", "text"), ("G.y", "", "text"),
                  ("p（已知可填）", "", "text"), ("q（已知可填）", "", "text"),
                  ("密文 c（逗号/换行分隔的整数）", "", "bigtext")], submit)

    def act_base_family(self) -> None:
        path = self._need_file("选择 Base 家族密文文件", [("文本", "*.txt"), ("全部", "*.*")])
        if not path:
            return
        text = self._file_text(self._read(path)).strip()
        results = codec.base_family_chain(text)
        if not results:
            self._out("Base 家族连环解码", "没有试出可解的 Base 链（可能还缺前置变换）")
            return
        lines, flags = [], []
        for chain, value in results[:5]:
            lines.append("解码链：" + " → ".join(chain))
            lines.append("    结果：" + value[:300])
            flags += [h.value for h in find_flags(value)]
            lines.append("")
        self._out("Base 家族连环解码（We are Family 那类）", "\n".join(lines),
                  flags=sorted(set(flags)))

    def act_gif_frames(self) -> None:
        path = self._need_file("选择 GIF / APNG", [("动图", "*.gif *.png *.apng"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        frames = image.gif_frames(data, limit=120)
        if len(frames) < 2:
            self._out("GIF 帧提取", "这个文件没有多帧（或不是动图）")
            return
        outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_帧")
        os.makedirs(outdir, exist_ok=True)
        lines, flags = [f"共 {len(frames)} 帧，已导出到：{outdir}", ""], []
        for idx, blob in frames:
            target = os.path.join(outdir, f"frame_{idx:03d}.png")
            with open(target, "wb") as fh:
                fh.write(blob)
            img = image.open_image(blob)
            hit = ""
            if img is not None:
                for label, bits in image.lsb_candidates(img, quick=True):
                    if image.text_like(bits):
                        text = bits[:200].decode("latin-1")
                        found = [h.value for h in find_flags(text)]
                        hit += f"  LSB({label}) 提取到文本：{text[:80]}\n"
                        flags += found
            if hit:
                lines.append(f"帧 {idx}：{hit}")
        diff = image.frame_diff(frames)
        if diff:
            dpath = os.path.join(outdir, "帧差图.png")
            with open(dpath, "wb") as fh:
                fh.write(diff)
            lines.append(f"\n帧差图（相邻帧差异纵向拼接）：{dpath}")
        for t in misc.qr_decode(diff or b""):
            lines.append(f"★ 帧差图里的二维码：{t}")
            flags += [h.value for h in find_flags(t)]
        self._out("GIF 帧提取与帧差", "\n".join(lines), flags=sorted(set(flags)))
        try:
            os.startfile(outdir)
        except Exception:
            pass

    def act_zip_crc(self) -> None:
        path = self._need_file("选择 ZIP", [("ZIP", "*.zip"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        entries, _comment = archive.zip_entries(data)
        if not entries:
            self._out("ZIP CRC 爆破", "不是合法 ZIP")
            return
        info = entries[0]
        self.app.show_busy(True)
        self.app.status_set("CRC 爆破中…")
        self.app.worker(lambda: archive.crc_bruteforce(data),
                        on_done=lambda r: (self.app.show_busy(False), self._crc_done(r, info)))

    def _crc_done(self, result, info) -> None:
        content, note = result
        lines = [f"目标条目：{info.name}（明文 {info.size} 字节，CRC={info.crc:08x}）", "", note]
        flags = []
        if content:
            text = codec.to_text(content)
            lines.append(f"内容预览：{text[:200]}")
            flags = [h.value for h in find_flags(text)]
        else:
            lines += ["", "提示：CRC 爆破只对“内容极短（≤2 字节或纯数字）”的条目有效；",
                      "内容较长时请用明文攻击（pkcrack/bkcrack），或从题目里找线索。"]
        self._out("ZIP 短内容 CRC 爆破", "\n".join(lines), flags=flags)

    def act_memory(self) -> None:
        path = self._need_file("选择内存/磁盘镜像", [("镜像", "*.raw *.mem *.dmp *.vmem *.img *.vmdk *.e01"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines = [f"文件大小：{len(data)/1048576:.1f} MB"]
        hint = binary.memory_image_hint(data)
        if hint:
            lines.append(f"类型判断：{hint}")
        items = pcap.printable_strings(data, 8, 60)
        flags = []
        interesting = []
        for s in items:
            hits = find_flags(s)
            flags += [h.value for h in hits]
            if hits or any(k in s.lower() for k in ("flag", "password", "admin", "cmd", "powershell", "http://")):
                interesting.append(("★ " if hits else "  ") + s[:160])
        if interesting:
            lines += ["", "可疑字符串："] + interesting[:40]
        carved = carve.carve(data, max_items=8)
        if carved:
            outdir = os.path.join(os.path.dirname(path), os.path.basename(path) + "_雕复")
            os.makedirs(outdir, exist_ok=True)
            lines += ["", f"雕出 {len(carved)} 个内嵌文件 → {outdir}"]
            for i, hit in enumerate(carved):
                with open(os.path.join(outdir, f"{i}_{hit.offset}.{hit.ext}"), "wb") as fh:
                    fh.write(hit.data)
                flags += [h.value for h in find_flags(codec.to_text(hit.data))]
        lines += ["", "进阶：这是内存取证题的话，配合 Volatility 分析（vol.py -f 镜像 imageinfo）"]
        self._out("内存镜像快速分析", "\n".join(lines), flags=sorted(set(flags)))

    # ------------------------------------------------------------------ #
    # ⑫ 文档 / 其他
    # ------------------------------------------------------------------ #
    def act_pdf(self) -> None:
        path = self._need_file("选择 PDF", [("PDF", "*.pdf"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        for f in docs.pdf_analyze(data):
            lines.append(f"[{f.kind}] {f.title}\n    {f.detail[:600]}")
            flags += [h.value for h in find_flags(f.detail)]
        self._out("PDF 结构分析", "\n".join(lines), flags=flags)

    def act_office(self) -> None:
        path = self._need_file("选择 Office 文档", [("Office", "*.docx *.xlsx *.pptx *.docm *.xlsm"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        lines, flags = [], []
        for f in docs.office_analyze(data):
            lines.append(f"[{f.kind}] {f.title}\n    {f.detail[:600]}")
            flags += [h.value for h in find_flags(f.detail)]
        if not lines:
            lines = ["不是 zip 结构的 Office 文档（.doc/.xls 老格式请先另存为 docx）"]
        self._out("Office 文档取证（隐藏表 / 内嵌对象 / 元数据）", "\n".join(lines), flags=flags)

    def act_pyjail(self) -> None:
        path = self._need_file("选择 pyjail 题目源码", [("Python", "*.py *.txt"), ("全部", "*.*")])
        if not path:
            return
        text = self._file_text(self._read(path))
        lines = docs.pyjail_assist(text)
        self._out("Python 沙箱（pyjail）绕过助手", "\n".join(lines))

    def act_magic_hash(self) -> None:
        lines = ["PHP 弱类型 / magic hash 常用值：", ""]
        for value, desc, note in docs.MAGIC_HASHES:
            lines.append(f"  {value!r}\n      {desc}   （{note}）")
        lines += ["", "用法：当题目用 == 比较 md5，且两边都能控制时，"
                      "让两边都是 0e 开头的哈希即可绕过。"]
        self._out("PHP 弱类型 / magic hash 速查", "\n".join(lines))

    def act_text_stego(self) -> None:
        path = self._need_file("选择文本类题目文件", [("文本", "*.txt *.md *.py *.html *.log"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        text = self._file_text(data)
        lines, flags = [], []
        for tag, msg in textstego.snow_extract(text):
            lines.append(f"【{tag}】{msg}")
            flags += [h.value for h in find_flags(msg)]
        for tag, msg in textstego.zero_width_extract(text):
            lines.append(f"【{tag}】{msg}")
            flags += [h.value for h in find_flags(msg)]
        for tag, msg in textstego.base64_stego(text):
            lines.append(f"【{tag}】{msg}")
            flags += [h.value for h in find_flags(msg)]
        tap = textstego.tap_code_decode(text)
        if tap:
            lines.append(f"【敲击码】{tap}")
        emo = textstego.emoji_decode(text)
        if emo:
            lines.append(f"【Emoji 编码】{emo}")
        zw_count = sum(1 for c in text if c in textstego.ZW_CHARS)
        if zw_count:
            lines.append(f"（检测到 {zw_count} 个零宽字符）")
        if not lines:
            lines = ["没检测到 SNOW 空格 / 零宽字符 / Base64 填充位 / 敲击码 / Emoji 隐写"]
        self._out("文本类隐写（SNOW / 零宽字符 / Base64 填充位）", "\n".join(lines),
                  flags=sorted(set(flags)))

    def act_sqlite(self) -> None:
        path = self._need_file("选择 SQLite 数据库", [("数据库", "*.db *.sqlite *.sqlite3"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        findings = docs.sqlite_analyze(data)
        if not findings:
            self._out("SQLite 数据库取证", "不是 SQLite 数据库文件（头部应为 'SQLite format 3'）")
            return
        lines, flags = [], []
        for f in findings:
            lines.append(f"[{f.kind}] {f.title}\n    {f.detail[:800]}")
            flags += [h.value for h in find_flags(f.detail)]
        self._out("SQLite 数据库取证", "\n".join(lines), flags=sorted(set(flags)))

    def act_tea(self) -> None:
        def submit(v):
            data = cx.guess_bytes(v.get("密文（hex / base64 / 原文）", ""))
            key = cx.guess_bytes(v.get("密钥 key", ""))
            if not data or not key:
                return
            outs = []
            for name, fn in (("RC4", lambda: cx.rc4(data, key)),
                             ("TEA", lambda: cx.tea_decrypt(data, key)),
                             ("XTEA", lambda: cx.xtea_decrypt(data, key)),
                             ("XXTEA", lambda: cx.xxtea_decrypt(data, key))):
                try:
                    res = fn()
                except Exception:
                    continue
                if res:
                    outs.append((name, res))
            if not outs:
                self._out("RC4 / TEA / XXTEA", "都没有解出可用结果（检查 key/密文编码与加密模式）")
                return
            lines, flags = [], []
            for name, res in outs:
                txt = codec.to_text(res)
                lines.append(f"[{name}] {txt[:300]}")
                flags += [h.value for h in find_flags(txt)]
            self._out("RC4 / TEA / XTEA / XXTEA", "\n".join(lines), flags=sorted(set(flags)))
        self.ask("RC4 / TEA / XXTEA 解密",
                 [("密文（hex / base64 / 原文）", "", "bigtext"), ("密钥 key", "", "text")], submit)

    def act_php_wrapper(self) -> None:
        self._out("PHP 伪协议 & 反序列化 payload",
                  docs.PHP_WRAPPERS + "\n\n" + docs.PHP_SERIALIZE_HELP)

    def act_jwt_forge(self) -> None:
        def submit(v):
            token = v.get("原 JWT", "").strip()
            mode = v.get("伪造方式", "alg=none")
            key = v.get("签名密钥（alg=none 时留空）", "")
            import base64
            import hashlib
            import hmac
            import json
            parts = token.split(".")
            if len(parts) < 2:
                messagebox.showwarning("提示", "不是合法 JWT")
                return
            def b64d(seg):
                seg = seg.replace("-", "+").replace("_", "/")
                seg += "=" * (-len(seg) % 4)
                return base64.b64decode(seg)
            try:
                header = json.loads(b64d(parts[0]))
                payload = json.loads(b64d(parts[1]))
            except Exception as exc:
                messagebox.showerror("解析失败", str(exc))
                return
            if mode.startswith("alg=none"):
                header["alg"] = "none"
                new_token = (base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
                             + "." +
                             base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
                             + ".")
            else:
                header["alg"] = "HS256"
                h = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=")
                p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
                sig = base64.urlsafe_b64encode(hmac.new(key.encode(), h + b"." + p, hashlib.sha256).digest()).rstrip(b"=")
                new_token = (h + b"." + p + b"." + sig).decode()
            self._out("JWT 伪造", f"原 payload：\n{json.dumps(payload, ensure_ascii=False)}\n\n"
                                  f"伪造后的 token（{mode}）：\n{new_token}\n\n"
                                  "提示：alg=none 只有在服务端没校验算法时才有效；"
                                  "有密钥时用 HS256 重新签名即可。")
        self.ask("JWT 伪造", [("原 JWT", "", "bigtext"),
                              ("伪造方式", ["alg=none", "HS256 重新签名"], "choice"),
                              ("签名密钥（alg=none 时留空）", "", "text")], submit)

    # ------------------------------------------------------------------ #
    # Web 一键自动解题
    # ------------------------------------------------------------------ #
    def act_web_autosolve(self) -> None:
        def submit(v):
            url = web.normalize_url(v.get(URL_LABEL, ""))
            if not url:
                messagebox.showwarning("提示", "请填写靶机地址")
                return
            self.app.web_url = url
            outdir = os.path.join(os.path.expanduser("~"), "Desktop", "git泄露恢复")
            self.app.show_busy(True)
            self.app.status_set("Web 自动解题中…")

            def job():
                return web.auto_solve(url, outdir=outdir, on_progress=self.app.log, time_budget=180)

            def done(res):
                self.app.show_busy(False)
                case = report_mod.Case(
                    name=url, category="Web", target=url, steps=res["steps"],
                    flags=res["flags"], evidence=res["evidence"],
                    seconds=0.0)
                self.app.add_case(case)
                body = report_mod.build_quick_report(case)
                self._out(f"Web 一键自动解题：{url}", body, flags=res["flags"])

            self.app.worker(job, on_done=done)
        self.ask("Web 一键自动解题（填靶机地址，例如 http://127.0.0.1:8080）",
                 [(URL_LABEL, getattr(self.app, "web_url", ""), "text")], submit)

    def act_export_writeup(self) -> None:
        self.app.export_writeup()

    # ------------------------------------------------------------------ #
    # Pwn
    # ------------------------------------------------------------------ #
    def act_pwn_offset(self) -> None:
        def submit(v):
            mode = v.get("模式", "由崩溃值算偏移")
            if mode.startswith("由崩溃值"):
                value = v.get("崩溃值（如 0x6161616c 或 'aaab'）", "")
                if not value:
                    return
                off = pwn.cyclic_find(value)
                self._out("溢出偏移计算（cyclic_find）",
                          f"崩溃值 {value}\n→ 偏移 = {off}" if off >= 0 else
                          f"没在模式串里找到 {value}（确认用的是本工具生成的 cyclic）")
            else:
                length = int(v.get("长度", "200") or 200)
                data = pwn.cyclic(length)
                path = os.path.join(os.path.expanduser("~"), "Desktop", "cyclic.txt")
                try:
                    with open(path, "wb") as fh:
                        fh.write(data)
                except OSError:
                    path = os.path.join(os.getcwd(), "cyclic.txt")
                    with open(path, "wb") as fh:
                        fh.write(data)
                self._out("生成循环模式串", f"长度 {len(data)} 字节，已保存到：{path}\n\n"
                                          f"前 64 字节：\n{data[:64]!r}\n\n"
                                          "用法：把这个串发进程序，崩溃后用「由崩溃值算偏移」反查偏移。")
        self.ask("Pwn 溢出偏移", [("模式", ["由崩溃值算偏移", "生成循环模式串"], "choice"),
                                  ("崩溃值（如 0x6161616c 或 'aaab'）", "", "text"),
                                  ("长度", "200", "text")], submit)

    def act_pwn_gadgets(self) -> None:
        path = self._need_file("选择 ELF/PE 二进制", [("二进制", "*.elf *.so *.bin *.exe *.out"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        gadgets = pwn.find_gadgets(data)
        if not gadgets:
            self._out("ROP gadget 扫描", "没有扫到常见 gadget（可能是加壳/非 x86 架构）")
            return
        lines = [f"共扫到 {len(gadgets)} 个常见 gadget（文件偏移 / 虚拟地址）：", ""]
        evidence = []
        for off, va, desc in gadgets:
            va_s = f"0x{va:x}" if va else "（非 ELF：请自行换算）"
            lines.append(f"  {desc:24s} off=0x{off:x}  va={va_s}")
            if va:
                evidence.append(f"{desc} = 0x{va:x}")
        self._out("ROP gadget 扫描（常见模式）", "\n".join(lines),
                  items=None)
        self.app.last_evidence = evidence

    def act_pwn_shellcode(self) -> None:
        lines = ["常用 shellcode（hex）：", ""]
        for name, hexs in pwn.SHELLCODES.items():
            lines.append(f"【{name}】\n  {hexs}\n  python: bytes.fromhex('{hexs}')")
        lines += ["", "用法：把 shellcode 放进可写可执行区域（NX 关闭或 mprotect 后），再跳过去执行。"]
        self._out("常用 shellcode", "\n".join(lines))

    def act_pwn_payload(self) -> None:
        def submit(v):
            def num(x, base=16):
                x = (x or "").strip()
                if not x:
                    return None
                try:
                    return int(x, 16) if x.lower().startswith("0x") else int(x, base)
                except ValueError:
                    return None
            offset = num(v.get("溢出偏移", "40"), 10) or 40
            arch = 64 if "64" in v.get("架构", "64 位") else 32
            ret = num(v.get("返回地址（可留空）", ""))
            canary = num(v.get("canary（可留空）", ""))
            _payload, text = pwn.build_payload(offset, ret_addr=ret, canary=canary, arch=arch)
            self._out("栈溢出 payload 构造", text)
        self.ask("栈溢出 payload 构造",
                 [("溢出偏移", "40", "text"), ("架构", ["64 位", "32 位"], "choice"),
                  ("返回地址（可留空）", "0x", "text"), ("canary（可留空）", "", "text")], submit)

    def act_pwn_fmtstr(self) -> None:
        def submit(v):
            try:
                offset = int(v.get("格式串参数序号", "6"))
                addr = int(v.get("目标地址", "0x0"), 16)
                value = int(v.get("要写入的值", "0x0"), 16)
            except ValueError:
                messagebox.showwarning("提示", "地址和值要用 0x 十六进制")
                return
            text = pwn.fmtstr_payload(offset, {addr: value})
            self._out("格式化字符串 payload", text)
        self.ask("格式化字符串 payload（2 字节粒度写入）",
                 [("格式串参数序号（%6$p 就是 6）", "6", "text"),
                  ("目标地址（如 GOT 表项）", "0x", "text"),
                  ("要写入的值", "0x", "text")], submit)

    def act_pwn_template(self) -> None:
        path = self._need_file("选择要打的 binary")
        if not path:
            return
        def submit(v):
            offset = int(v.get("溢出偏移", "40") or 40)
            script = pwn.pwntools_template(os.path.basename(path), offset=offset,
                                           remote=v.get("远程地址 host:port（可留空）", ""))
            out = os.path.join(os.path.dirname(path), "exp.py")
            try:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(script)
                note = f"已保存到 {out}"
            except OSError:
                note = "（保存失败，下面是内容）"
            self._out("pwntools 脚本模板", f"{note}\n\n```python\n{script}\n```")
        self.ask("生成 pwntools 脚本模板", [("溢出偏移", "40", "text"),
                                            ("远程地址 host:port（可留空）", "", "text")], submit)

    # ------------------------------------------------------------------ #
    # Crypto / Reverse 补充
    # ------------------------------------------------------------------ #
    def act_rsa_pubkey(self) -> None:
        path = self._need_file("选择 RSA 公钥文件", [("公钥", "*.pem *.pub *.key *.txt"), ("全部", "*.*")])
        if not path:
            return
        data = self._read(path)
        try:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_pem_public_key(data)
            nums = key.public_numbers()
            n, e = nums.n, nums.e
        except Exception as exc:  # noqa: BLE001
            self._out("RSA 公钥解析", f"解析失败：{exc}\n（支持 PEM 格式的 SubjectPublicKeyInfo / PKCS1 公钥）")
            return
        lines = [f"n = {n}", f"e = {e}", f"n 的位数：{n.bit_length()}"]
        if e in (3, 5, 17):
            lines.append("★ e 很小，考虑小指数攻击（低加密指数广播 / 直接开方）")
        if e == 65537:
            lines.append("e = 65537（常见值）")
        f = cx.rsa_fermat(n, 200000)
        if f:
            lines.append(f"★ 费马分解成功：p = {f[0]}\n  q = {f[1]}")
        else:
            lines.append("费马分解未成功（p、q 不接近）")
        p = cx.rsa_pollard(n, 300000)
        if p and 1 < p < n:
            lines.append(f"★ Pollard rho 分解出因子：{p}")
        self._out("RSA 公钥解析与弱参数检测", "\n".join(lines))

    def act_crypto_constants(self) -> None:
        path = self._need_file("选择二进制/固件文件")
        if not path:
            return
        data = self._read(path)
        found = binary.identify_crypto(data)
        lines = ["密码算法特征常量扫描：", ""]
        lines += ["  · " + f for f in found] if found else ["  没有命中常见算法常量"]
        lines += ["", "（命中说明程序里用了对应算法，可据此反推加密逻辑）"]
        self._out("加密算法特征识别", "\n".join(lines))


HELP_TEXT = """【推荐流程】
1) 把题目文件拖进窗口（或点“打开文件”），先点【全自动分析】——多数题会直接出 flag。
2) 没出结果时，看右侧“分析发现”里哪一类有线索，再去左边对应分类点专项卡片。
3) 图片/音频题记得点“图片可视化排查”“频谱图”——很多题答案是“看出来的”。

【覆盖的常见题型】
· 编码类：Base64/32/16/58/85/91、Hex、URL、HTML 实体、Unicode、进制、DNA、UUencode、
  摩斯、培根、A1Z26、Polybius、凯撒/ROT、Atbash、维吉尼亚、栅栏、列置换、键盘错位，
  以及多层编码自动解链（A→B→C 全自动）
· 密码类：XOR（单字节/重复密钥/已知明文）、AES/DES/3DES、哈希爆破、JWT、RSA 弱参数攻击
· 图片类：PNG 结构/高度篡改/文本块、LSB 矩阵、JPEG 系数域（jsteg）、追加数据、图片异或、
  通道分离与位平面可视化、二维码/条形码
· 音频类：WAV LSB、频谱图、DTMF、摩斯、MP3 标签
· 压缩包：zip/gz/bz2/xz/tar/7z、嵌套递归、ZIP 伪加密修复、口令爆破、注释/文件名编码
· 流量类：TCP 流重组、HTTP 对象还原、DNS 查询、USB 键盘击键、USB 鼠标轨迹绘图
· 取证类：文件类型/头尾、内嵌文件雕复、strings、十六进制
· 逆向类：PE/ELF/Mach-O 信息卡（checksec 风格）、.pyc 反汇编、PyInstaller 解包、加壳线索

【做不到的（不是工具懒，是方法本身需要额外输入）】
· 需要口令的隐写：steghide / outguess / jphide / F5 —— 必须题目给密码
· 需要远程交互的题：SSRF、反弹 shell、在线服务型题目
· 需要人工推理的题：去模糊、重建被破坏的二维码、数学构造、格攻击（Coppersmith）
· 大型逆向/漏洞利用：ida/gdb/ROP 链这些需要专业工具链
"""

URL_LABEL = "目标 URL（含参数，例如 http://x/?id=1）"
PARAM_LABEL = "参数名（例如 id / file / name / cmd）"


def build_sections(app):
    """返回三级卡片清单：[(大类, 提示, [(小类, 提示, [(标题, 说明, 回调, 徽标?), ...]), ...]), ...]"""
    A = Actions(app)
    return [
        ("★ 校赛真题（温商院 2025）", "每题一个卡片：方法 + 一键工具", [
            ("先看手册", "把校赛每类题的解法读一遍（含 WriteUp 原文要点）", [
                ("校赛题型解法手册", "9 道题（Web/Misc/Crypto/Reverse）的解法要点全在这",
                 A.act_wzbc_handbook, "先看这个"),
            ]),
            ("Web", "babyWeb / ezPy / babyGo", [
                ("前端 JS 抓取审计", "babyWeb：自动抓页面所有 JS 并搜 flag（flag 常硬编码在前端）",
                 A.act_js_audit_online, "校赛 300 分"),
                ("Python 沙箱逃逸 payload", "ezPy：按源码黑名单给绕过思路 + 现成 payload",
                 A.act_pyjail_payloads, "校赛 1000 分"),
                ("JWT 伪造（none/重签）", "babyGo：伪造 is_admin 的 token", A.act_jwt_forge),
                ("SSTI 模板注入", "babyGo：已加入 Go 模板探针 {{ . }} / {{ len \"abcd\" }}",
                 A.act_web_ssti),
            ]),
            ("Misc", "CompressionLab / DeepSleep / Who's Cat", [
                ("ZIP 口令 = 文件名", "CompressionLab：真加密的密码就是压缩包自己的名字",
                 A.act_name_password, "校赛 500 分"),
                ("文件时间戳隐写", "DeepSleep：一堆同大小文件用修改时间编码二进制",
                 A.act_timestamp_stego, "校赛 500 分"),
                ("文件名提示 / 键盘错位", "DeepSleep：文件名 base64 提示 + 12345678→!@#$%^&*",
                 A.act_filename_hints, "校赛 500 分"),
                ("猫脸变换还原", "Who's Cat：长方形先拉正方形，再枚举逆变换",
                 A.act_arnold, "校赛 Normal"),
                ("压缩包解包 / 伪加密", "CompressionLab 的另一半：伪加密修复 + 嵌套递归",
                 A.act_zip_unpack),
            ]),
            ("Crypto", "Curve / We are Family!", [
                ("椭圆曲线（复合模数）求解", "Curve：用“分母不可逆”gcd 分解 n，再 CRT 还原明文",
                 A.act_ecc_composite, "校赛 1000 分"),
                ("Base 家族连环解码", "We are Family!：base36→100→16→85→64→91→58→62→32 自动串",
                 A.act_base_family, "校赛 300 分"),
            ]),
            ("Reverse", "reMe", [
                ("二进制信息卡", "reMe：先看位数/保护/节表", A.act_bincard),
                ("strings 提取", "reMe：找提示与假 flag", A.act_strings),
                ("Python .pyc 反汇编", "Python 逆向题直接反汇编", A.act_pyc),
            ]),
        ]),
        ("★ 一键分析", "最常用，先点这里", [
            ("一键入口", "拖文件进来直接出 flag", [
                ("全自动分析", "拖入/选择文件 → 跑完整流水线 → 直接给 flag 候选", A.act_auto, "推荐"),
                ("分析整个文件夹", "对题目目录批量分析（含 README 提示加分）", A.act_folder),
                ("Web 一键自动解题", "输入靶机地址，自动跑信息收集+漏洞检测拿 flag", A.act_web_autosolve, "新增"),
                ("粘贴文本 / 编码工具台", "直接粘贴密文，批量试 40+ 种编码", A.act_text),
                ("导出解题报告（writeup）", "按 CTF 报告模板导出，只保留解出 flag 的关键步骤",
                 A.act_export_writeup, "报告"),
                ("内置自检", "验证运行环境、依赖与题库是否正常", A.act_selftest),
            ]),
        ]),
        ("Misc 杂项", "编码 / 隐写 / 取证 / 杂项", [
            ("编码转换", "编码题先在这里扫一遍", [
                ("编码全能解码", "40+ 种编码一次性全部试完，按可能性排序", A.act_decode_all, "高频"),
                ("多层编码自动解链", "Base64→Hex→URL… 自动串起来，给出完整路径", A.act_multi_decode, "高频"),
                ("Base64 自定义字母表", "题目换了字母表的 Base64（常见变体）", A.act_custom_b64),
                ("进制 / 数字编码", "二进制、八进制、十进制、点分十进制、DNA、A1Z26", A.act_base_convert),
            ]),
            ("图片隐写", "杂项里最高频的一类", [
                ("图片全方位扫描", "结构 + LSB + 元数据 + 追加数据 + 二维码，一次扫完", A.act_image_scan, "推荐"),
                ("图片文字识别（OCR）", "图里画的 flag 直接读出来（含内嵌图）", A.act_ocr, "新增"),
                ("LSB 矩阵扫描", "多通道 / 多比特位 / 多顺序 / 位平面，全排列", A.act_lsb_matrix),
                ("GIF 帧提取与帧差", "逐帧导出 PNG + 相邻帧差异图（GIF 隐写必用）", A.act_gif_frames, "高频"),
                ("GIF 帧内隐藏图", "某一帧的 LZW 流里藏第二张图（ctfshow 经典）", A.act_gif_hidden, "新增"),
                ("JPEG 系数域（jsteg）", "解 DCT 系数最低位，专治 jsteg 类 JPEG 隐写", A.act_jpeg_dct),
                ("EXIF / APPn 内嵌文件", "从 EXIF 段里挖出藏着的图片/压缩包并 OCR", A.act_appn, "新增"),
                ("PNG 结构 / 高度修复", "块结构、文本块、CRC 异常、高度被篡改自动修复", A.act_png_tools),
                ("PNG 宽高爆破", "宽/高被改过：列出所有合法尺寸 + 对照图 + 逐个查 flag", A.act_png_size_brute, "高频"),
                ("猫脸变换还原", "Arnold 猫脸变换逆向枚举 1~60 次 + 对照图", A.act_arnold, "高频"),
                ("几何变换排查", "旋转/镜像/转置/通道差分 一次出对照图", A.act_geometry),
                ("拼图网格切分", "按 n×m 切块并编号（拼图题第一步）", A.act_grid_split),
                ("二维码 / 条形码", "多码识别 + 放大/反色/二值化增强", A.act_qr),
                ("图片可视化排查", "通道分离/位平面/对比度/反相拼图，看图找答案", A.act_image_visual),
            ]),
            ("音频隐写", "频谱图是重点", [
                ("音频 LSB 提取", "逐采样 LSB、左右声道、高低位", A.act_audio_lsb),
                ("频谱图生成", "出图并自动识别图中二维码", A.act_spectrogram, "高频"),
                ("DTMF / 摩斯 / 元数据", "电话拨号音、节奏摩斯、MP3 标签", A.act_audio_misc),
            ]),
            ("压缩包", "伪加密和爆破是经典", [
                ("压缩包解包", "zip/gz/bz2/xz/tar/7z，支持嵌套递归", A.act_zip_unpack, "高频"),
                ("ZIP 伪加密修复", "标志位造假导致“要密码”，一键修复", A.act_zip_pseudo, "经典"),
                ("ZIP 短内容 CRC 爆破", "已知 CRC 反推很短的条目内容（数字/1-2 字节）", A.act_zip_crc, "高频"),
                ("压缩包口令爆破", "内置字典 + 0000-999999", A.act_zip_crack),
                ("ZIP 口令 = 文件名", "嵌套压缩包题：真加密的密码往往是压缩包/条目自己的名字", A.act_name_password, "校赛真题"),
                ("注释 / 文件名 / CRC", "注释、文件名编码、CRC 逐个查", A.act_zip_info),
            ]),
            ("流量与取证", "pcap 与文件本身藏东西", [
                ("流量包分析", "TCP 流重组、HTTP 对象还原、DNS 查询、USB 键盘击键", A.act_pcap, "高频"),
                ("USB 鼠标轨迹还原", "把鼠标流量画成图（常见“画二维码”）", A.act_usb_mouse),
                ("内存镜像快速分析", "识别镜像类型 + strings + flag 扫描（Volatility 前置）", A.act_memory, "取证"),
                ("文件时间戳隐写", "同目录大量同大小文件，用修改时间编码二进制（校赛真题）", A.act_timestamp_stego, "校赛真题"),
                ("文件名提示 / 键盘错位", "文件名里的 base64 提示、Shift 变换当密码（校赛真题）", A.act_filename_hints, "校赛真题"),
                ("文件类型 / 头尾分析", "真实类型、扩展名不符、尾部附加数据", A.act_filetype, "高频"),
                ("内嵌文件雕复", "binwalk 精简版，带格式校验不会误报", A.act_carve),
                ("strings 提取", "提取可打印字符串并自动找 flag", A.act_strings),
                ("十六进制查看", "看文件头尾、找异常字节", A.act_hexview),
            ]),
            ("文档与脑洞", "PDF / Office / 沙箱", [
                ("PDF 结构分析", "元数据、内嵌 JS/附件、EOF 后附加数据、文本提取", A.act_pdf),
                ("Office 文档取证", "隐藏工作表、内嵌对象、批注、文档属性里的线索", A.act_office),
                ("SQLite 数据库取证", "遍历所有表/列找 flag（.db/.sqlite）", A.act_sqlite, "新增"),
                ("文本类隐写", "SNOW 空格 / 零宽字符 / Base64 填充位 / 敲击码 / Emoji", A.act_text_stego, "新增"),
                ("pyjail 沙箱绕过助手", "读沙箱源码，按黑名单给出绕过思路", A.act_pyjail),
                ("PHP 弱类型 / magic hash", "0e 开头哈希、弱类型比较绕过速查", A.act_magic_hash),
            ]),
        ]),
        ("Web", "需要能访问到目标（本地靶机 / 靶场 / 公网题）", [
            ("信息收集", "先把目标摸清楚", [
                ("Web 一键自动解题", "输入靶机地址，自动信息收集 + 漏洞检测 + 拿 flag",
                 A.act_web_autosolve, "推荐"),
                ("站点信息探测", "响应头、Cookie、标题、注释、表单、外链一次看全", A.act_web_probe),
                ("敏感文件 / 备份扫描", "robots 提示 + 备份文件/源码泄露/.git/.env/.DS_Store", A.act_web_files, "高频"),
                (".git 源码泄露恢复", "把泄露的 .git 整个拉回来，还原出源码", A.act_web_git, "经典"),
                ("源码审计（JS/HTML）", "注释、隐藏字段、接口、API Key、JWT 泄漏", A.act_web_audit),
            ]),
            ("漏洞检测", "按参数自动打", [
                ("SQL 注入自动检测", "报错型 / 布尔盲注 / 时间盲注 / 联合查询取 flag", A.act_web_sqli, "高频"),
                ("文件包含 / 路径穿越", "多级 ../ + php://filter 读源码 + 直接找 flag", A.act_web_lfi, "高频"),
                ("SSTI 模板注入", "Jinja2/Twig/Freemarker/Smarty/ERB 等多种引擎探测", A.act_web_ssti),
                ("命令注入", ";id |id $(id) 等常见分隔符 + 直接 cat /flag", A.act_web_rce),
            ]),
            ("手工工具", "自动没打通时用", [
                ("HTTP 请求重放器", "把 Burp 里的原始请求粘进来重放，手工调 payload", A.act_web_replay, "常用"),
                ("PHP 伪协议 / 反序列化", "php://filter、data://、phar:// 与反序列化 payload 速查", A.act_php_wrapper, "新增"),
                ("JWT 伪造（none / 重签）", "alg=none 绕过 + 已知密钥 HS256 重新签名", A.act_jwt_forge),
                ("Web payload 速查表", "SQLi/LFI/SSTI/RCE/XXE/SSRF/上传/JWT/PHP 特性", A.act_web_cheatsheet),
            ]),
        ]),
        ("Crypto 密码", "古典密码 / 现代密码", [
            ("古典密码", "凯撒、维吉尼亚、替换、栅栏…", [
                ("凯撒 / ROT 全枚举", "26 种偏移全试，按像不像正常文本排序", A.act_caesar, "高频"),
                ("维吉尼亚自动破解", "已知明文（flag{）+ 频率分析双路破解", A.act_vigenere, "高频"),
                ("单表替换自动破解", "爬山法自动求解替换表", A.act_substitution),
                ("Playfair / Hill", "常见密钥尝试 + 已知明文矩阵求解", A.act_playfair_hill),
                ("栅栏 / 列置换暴力", "置换类密码自动枚举", A.act_transposition),
                ("摩斯 / 培根 / A1Z26 / Polybius", "其余常见古典编码", A.act_other_classic),
            ]),
            ("现代密码", "XOR、对称加密、哈希、RSA", [
                ("XOR 爆破", "单字节 + 重复密钥 + 已知明文反推密钥", A.act_xor, "高频"),
                ("对称加密解密", "给 key/iv，自动试 AES/DES/3DES 与 ECB/CBC", A.act_symmetric),
                ("RC4 / TEA / XXTEA", "杂项里常见的自写加密，给 key 直接解", A.act_tea, "新增"),
                ("RSA 公钥解析", "解析 PEM 公钥得到 n/e，并自动试费马/Pollard 分解", A.act_rsa_pubkey, "实用"),
                ("RSA 弱参数攻击", "小指数、费马分解、Pollard、共模、Wiener、已知 p/q/phi", A.act_rsa, "高频"),
                ("哈希识别与爆破", "自动识别类型 + 内置字典/纯数字爆破", A.act_hash),
                ("JWT 解码与爆破", "解出 payload + HS256 弱密钥爆破", A.act_jwt),
            ]),
        ]),
        ("Reverse 逆向", "二进制信息 / 反编译 / 脱壳", [
            ("二进制信息", "先摸清程序保护", [
                ("二进制信息卡", "PE/ELF/Mach-O：位数、PIE、NX、Canary、RELRO、节表熵", A.act_bincard, "对标 checksec"),
                ("加壳 / 反调试线索", "UPX/VMProtect 等壳特征与反调试函数扫描", A.act_packers),
                ("加密算法特征识别", "扫 AES S 盒/MD5/SHA/Base64 表，判断用了什么算法", A.act_crypto_constants),
            ]),
            ("逆向工具", "Python 与打包程序", [
                ("Python .pyc 反汇编", "自动补文件头，直接出反汇编与可疑字符串", A.act_pyc, "高频"),
                ("PyInstaller 解包", "解出 exe 内嵌的 .pyc 与 PYZ 模块并反汇编主脚本", A.act_pyinstaller, "实用"),
                ("strings 提取", "在二进制里找提示与 flag 片段", A.act_strings),
                ("十六进制查看", "手工核对字节", A.act_hexview),
            ]),
        ]),
        ("Pwn 溢出", "偏移 / gadget / payload 构造", [
            ("定位与信息", "先确定怎么打", [
                ("Pwn 溢出偏移计算", "生成 cyclic 模式串 / 由崩溃值反查偏移", A.act_pwn_offset, "起手"),
                ("ROP gadget 扫描", "扫 pop rdi;ret / syscall 等常用 gadget 及虚拟地址", A.act_pwn_gadgets, "实用"),
                ("常用 shellcode", "execve(/bin/sh)、读 /flag 的现成 shellcode", A.act_pwn_shellcode),
                ("二进制信息卡", "看 PIE/NX/Canary/RELRO 决定打法", A.act_bincard),
            ]),
            ("构造 payload", "", [
                ("栈溢出 payload 构造", "偏移 + canary + 返回地址，直接给 bytes 和 pwntools 代码", A.act_pwn_payload),
                ("格式化字符串 payload", "按 2 字节粒度生成 %n 任意写", A.act_pwn_fmtstr),
                ("pwntools 脚本模板", "生成开箱可改的 exp.py", A.act_pwn_template),
            ]),
        ]),
        ("题库与帮助", "", [
            ("离线资源", "", [
                ("内置题库（159 题）", "浏览公开 CTF 题目，一键加载到分析队列", lambda: app.open_tool("library"), "离线可练"),
                ("高级工具面板", "打开经典标签页工具台（编码/图片/压缩包/音频/二维码/其他）", lambda: app.open_advanced()),
                ("使用帮助 / 能力边界", "推荐流程、覆盖题型、以及做不到的部分", A.act_help),
            ]),
        ]),
    ]
