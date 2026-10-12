"""本地漏洞靶场：用于验证 web.py 的探测能力（只在 127.0.0.1 上跑，测试完即关）。"""

from __future__ import annotations

import http.server
import os
import socketserver
import sqlite3
import threading
import urllib.parse


def build_docroot(root: str) -> None:
    os.makedirs(os.path.join(root, "site"), exist_ok=True)
    os.makedirs(os.path.join(root, "etc"), exist_ok=True)
    with open(os.path.join(root, "etc", "passwd"), "w", encoding="utf-8") as fh:
        fh.write("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")
    with open(os.path.join(root, "flag.txt"), "w", encoding="utf-8") as fh:
        fh.write("flag{path_traversal_file_ok}\n")
    with open(os.path.join(root, "site", "robots.txt"), "w", encoding="utf-8") as fh:
        fh.write("User-agent: *\nDisallow: /flag.txt\n")
    with open(os.path.join(root, "site", "flag.txt"), "w", encoding="utf-8") as fh:
        fh.write("decoy file, nothing to see here\n")
    with open(os.path.join(root, "site", "index.php"), "w", encoding="utf-8") as fh:
        fh.write("<?php echo 'hi'; // flag is not here but source matters ?>")
    con = sqlite3.connect(os.path.join(root, "app.db"))
    con.execute("CREATE TABLE items(id INTEGER, name TEXT)")
    con.execute("INSERT INTO items VALUES (1,'apple'),(2,'banana')")
    con.execute("CREATE TABLE flag(secret TEXT)")
    con.execute("INSERT INTO flag VALUES ('flag{sqli_union_extract_ok}')")
    con.commit()
    con.close()


class Handler(http.server.BaseHTTPRequestHandler):
    root = "."

    def log_message(self, *_args):  # 静音
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8"):
        self._send_bytes(code, body.encode("utf-8", "ignore"), ctype)

    def _send_bytes(self, code: int, data: bytes, ctype: str = "text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "ctfmisc-target/1.0")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            self._send(200, """<html><head><title>Test Target</title></head><body>
<!-- TODO: remove before deploy flag{html_comment_ok} -->
<form action="/search" method="get"><input name="q" type="hidden" value="1"></form>
<script src="/static/app.js"></script>
<a href="/login">login</a>
</body></html>""")
            return

        if path == "/sqli":
            raw = qs.get("id", ["1"])[0]
            try:
                con = sqlite3.connect(os.path.join(self.root, "app.db"))
                rows = con.execute(f"SELECT name FROM items WHERE id = {raw}").fetchall()
                con.close()
                out = "".join(f"<p>{r[0]}</p>" for r in rows)
                self._send(200, f"<html><body>{out or 'no result'}</body></html>")
            except Exception as exc:  # noqa: BLE001
                self._send(500, f"<html><body>sqlite3.OperationalError: {exc}</body></html>")
            return

        if path == "/lfi":
            name = qs.get("file", ["index.php"])[0]
            try:
                with open(os.path.join(self.root, "site", name), "r", encoding="utf-8", errors="replace") as fh:
                    self._send(200, fh.read()[:4000])
            except OSError:
                self._send(404, "not found")
            return

        if path == "/ssti":
            name = qs.get("name", [""])[0]
            if "{{7*7}}" in name:
                name = name.replace("{{7*7}}", "49")
            elif "${7*7}" in name:
                name = name.replace("${7*7}", "49")
            self._send(200, f"<html><body>Hello {name}</body></html>")
            return

        if path == "/rce":
            cmd = qs.get("cmd", [""])[0]
            if any(t in cmd for t in (";id", "|id", "$(id)", "`id`", "&&id", "%0aid")):
                self._send(200, "uid=0(root) gid=0(root) groups=0(root)")
            elif "cat /flag" in cmd:
                self._send(200, "flag{rce_command_injection_ok}")
            else:
                self._send(200, "no output")
            return

        # 静态文件（含 .git 泄露）
        rel = path.lstrip("/")
        target = os.path.join(self.root, "site", rel)
        if os.path.isdir(target):
            target = os.path.join(target, "index.html")
        if os.path.isfile(target):
            try:
                with open(target, "rb") as fh:
                    data = fh.read()
                self._send_bytes(200, data, "application/octet-stream")
            except OSError:
                self._send(500, "read error")
            return
        self._send(404, "not found")


class Target:
    def __init__(self, root: str):
        cls = type("H", (Handler,), {"root": root})
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), cls)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
