"""入口：python -m ctfmisc / 打包后的 exe。"""

from __future__ import annotations

import io
import os
import sys
import traceback


def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.getcwd()


def _boot_log(msg: str) -> None:
    """启动/崩溃日志：窗口版程序没有控制台，出问题只能靠日志定位。"""
    try:
        with open(os.path.join(_base_dir(), "启动日志.txt"), "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")
    except OSError:
        pass


def run_selftest() -> int:
    """在打包环境下自检关键依赖与引擎（结果写入 exe 同目录的 自检结果.txt）。"""
    # 注意：作为打包入口时本文件是顶层脚本，不能用相对导入
    from ctfmisc import image, misc
    from ctfmisc.pipeline import Item, Options, Pipeline

    report = os.path.join(_base_dir(), "自检结果.txt")
    lines: list[str] = []

    def check(name: str, ok: bool, extra: str = "") -> None:
        lines.append(f"[{'PASS' if ok else 'FAIL'}] {name} {extra}")
        # 立即落盘，便于定位卡住的步骤
        try:
            with open(report, "w", encoding="utf-8") as fh:
                fh.write("CTF-Misc-Tool 自检报告（进行中）\n" + "=" * 40 + "\n")
                fh.write("\n".join(lines) + "\n")
        except OSError:
            pass

    def analyse(data: bytes, label: str) -> list[str]:
        pipe = Pipeline(Options(deep=False, time_budget=30, decode_budget=5))
        return pipe.run_items([Item(label, data)]).text_flags()

    # 二维码（依赖 opencv / pyzbar）
    try:
        png = misc.qr_generate("flag{selftest_qr}")
        got = misc.qr_decode(png) if png else []
        check("二维码生成与识别(OpenCV/pyzbar)", any("selftest_qr" in g for g in got), str(got[:1]))
    except Exception as exc:
        check("二维码生成与识别(OpenCV/pyzbar)", False, repr(exc))

    # PNG LSB
    try:
        from PIL import Image
        secret = b"flag{selftest_lsb}"
        img = Image.new("RGB", (48, 48), (90, 100, 110))
        px = img.load()
        bits = "".join(f"{b:08b}" for b in secret)
        i = 0
        for y in range(48):
            for x in range(48):
                r, g, b = px[x, y]
                for ch in range(3):
                    if i < len(bits):
                        bit = int(bits[i])
                        if ch == 0:
                            r = (r & ~1) | bit
                        elif ch == 1:
                            g = (g & ~1) | bit
                        else:
                            b = (b & ~1) | bit
                        i += 1
                px[x, y] = (r, g, b)
        buf = io.BytesIO()
        img.save(buf, "PNG")
        got = analyse(buf.getvalue(), "lsb.png")
        check("PNG LSB 提取", any("selftest_lsb" in g for g in got), str(got[:1]))
        check("PNG 结构解析", bool(image.analyze(buf.getvalue())))
    except Exception as exc:
        check("PNG LSB 提取", False, repr(exc))

    # 压缩包（zipfile / py7zr 等）
    try:
        import zipfile
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("a.txt", "flag{selftest_zip}")
            zf.comment = b"flag{selftest_zip_comment}"
        got = analyse(zbuf.getvalue(), "a.zip")
        check("ZIP 解包与注释", any("selftest_zip" in g for g in got), str(got[:2]))
    except Exception as exc:
        check("ZIP 解包与注释", False, repr(exc))

    # 编码链
    try:
        import base64
        enc = base64.b64encode(b"flag{selftest_codec}").decode()
        got = analyse(enc.encode(), "c.txt")
        check("多层编码自动解码", any("selftest_codec" in g for g in got), str(got[:1]))
    except Exception as exc:
        check("多层编码自动解码", False, repr(exc))

    # 可选依赖
    for mod, label in (("numpy", "numpy"), ("cv2", "OpenCV"), ("pyzbar", "pyzbar"),
                       ("py7zr", "7z 支持"), ("cryptography", "cryptography"), ("pypdf", "PDF 解析")):
        try:
            __import__(mod)
            check(f"依赖 {label}", True)
        except Exception as exc:
            check(f"依赖 {label}", False, repr(exc))

    # 题库可读性
    try:
        import json
        with open(os.path.join(_base_dir(), "corpus", "index.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        count = data.get("count", 0)
        check(f"题库可读取（{count} 题）", count > 0)
    except Exception as exc:
        check("题库可读取", False, repr(exc))

    # Web / 文档模块
    try:
        from ctfmisc import docs, web
        _lines, flags = web.audit_source("var key='AKIAIOSFODNN7EXAMPLE';\n// flag{selftest_web_ok}\n")
        check("Web 模块（源码审计）", any("selftest_web_ok" in f for f in flags), str(flags[:1]))
        _py = docs.pyjail_assist("if any(c in x for c in '_[]{}'): print('no')")
        check("文档/沙箱辅助模块", any("绕过" in l or "思路" in l for l in _py))
    except Exception as exc:
        check("Web / 文档模块", False, repr(exc))

    failed = sum(1 for line in lines if line.startswith("[FAIL]"))
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("CTF-Misc-Tool 自检报告\n" + "=" * 40 + "\n")
        fh.write("\n".join(lines) + f"\n\n失败项：{failed}\n")
    return 1 if failed else 0


def run_cli(paths: list[str], out_path: str = "") -> int:
    """命令行批量分析：CTF-Misc-Tool.exe --analyze <文件或目录> [--out 报告.txt]"""
    from ctfmisc.pipeline import Options, Pipeline

    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        _boot_log(f"[!] 路径不存在: {missing}")
    targets = [p for p in paths if os.path.exists(p)]
    if not targets:
        return 2
    _boot_log(f"analyze start: {targets}")
    pipe = Pipeline(Options(deep=True, time_budget=600, decode_budget=25))
    report = pipe.run_paths(targets)
    lines = ["CTF 杂项解题助手 — 分析报告", "=" * 40,
             f"分析对象：{len(targets)} 项", f"用时：{report.seconds:.1f} 秒", "",
             "【flag 候选】"]
    if report.flags:
        for hit in report.flags:
            lines.append(f"  {hit.value}    (置信度 {hit.score:.0f}，来源：{hit.source})")
    else:
        lines.append("  （没有直接命中，见下方发现）")
    lines += ["", "【分析发现】"]
    for f in report.findings:
        lines.append(f"  [{f.kind}] {f.title}  <- {f.source}")
        if f.detail:
            lines.append("      " + f.detail[:400].replace("\n", "\n      "))
    lines += ["", "【处理日志】"] + ["  " + l for l in report.log]
    target = out_path or os.path.join(_base_dir(), "分析结果.txt")
    try:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        target = os.path.join(os.environ.get("TEMP", _base_dir()), "分析结果.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    _boot_log(f"报告已写入 {target}，flag 候选 {len(report.flags)} 个")
    return 0


def run() -> int:
    _boot_log(f"--- start {sys.argv!r} frozen={getattr(sys, 'frozen', False)} ---")
    try:
        if "--selftest" in sys.argv:
            code = run_selftest()
            _boot_log(f"selftest done rc={code}")
            return code
        if "--analyze" in sys.argv:
            idx = sys.argv.index("--analyze")
            rest = sys.argv[idx + 1:]
            out = ""
            if "--out" in rest:
                oi = rest.index("--out")
                out = rest[oi + 1] if oi + 1 < len(rest) else ""
                rest = rest[:oi] + rest[oi + 2:]
            return run_cli(rest, out)
        from ctfmisc.gui import main
        return main()
    except Exception:
        _boot_log("CRASH:\n" + traceback.format_exc())
        raise


if __name__ == "__main__":
    sys.exit(run())
