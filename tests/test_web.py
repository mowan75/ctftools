"""Web 模块自测：用本地靶场验证探测 / 注入 / 源码恢复能力。

用法: python tests/test_web.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))
sys.path.insert(0, HERE)

from ctfmisc import web  # noqa: E402
from web_target import Target, build_docroot  # noqa: E402

GIT = r"C:\Users\kun\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe"
PASS, FAIL = [], []


def check(name: str, ok: bool, extra: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"{'[PASS]' if ok else '[FAIL]'} {name} {extra}")


def make_git_leak(root: str) -> None:
    repo = os.path.join(root, "source")
    os.makedirs(repo, exist_ok=True)
    with open(os.path.join(repo, "config.php"), "w", encoding="utf-8") as fh:
        fh.write("<?php $flag='flag{git_leak_recover_ok}'; ?>")
    with open(os.path.join(repo, "admin.php"), "w", encoding="utf-8") as fh:
        fh.write("<?php // admin secret ?>")
    env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_AUTHOR_EMAIL="a@a",
               GIT_COMMITTER_NAME="a", GIT_COMMITTER_EMAIL="a@a")
    for cmd in (["init", "-q"], ["add", "."],
                ["-c", "user.name=a", "-c", "user.email=a@a", "commit", "-qm", "init"]):
        subprocess.run([GIT, *cmd], cwd=repo, env=env, capture_output=True)
    shutil.copytree(os.path.join(repo, ".git"), os.path.join(root, "site", ".git"))


def main() -> int:
    root = tempfile.mkdtemp(prefix="ctfweb_")
    build_docroot(root)
    if os.path.exists(GIT):
        make_git_leak(root)
    target = Target(root)
    try:
        lines, flags, _resp = web.probe_site(target.base)
        check("站点信息探测（含 HTML 注释 flag）", any("html_comment_ok" in f for f in flags),
              str(flags[:1]))
        check("站点信息探测（识别表单/静态资源）", any("表单" in l or "资源" in l for l in lines))

        lines, flags = web.scan_sensitive(target.base)
        check("敏感文件扫描（robots.txt / flag.txt）",
              any("flag.txt" in l for l in lines), str(lines[:2])[:80])

        lines, flags = web.sqli_scan(target.base + "/sqli?id=1", "id")
        check("SQL 注入：报错型识别", any("报错型注入" in l and "★" in l for l in lines))
        check("SQL 注入：联合查询取 flag", any("sqli_union_extract_ok" in f for f in flags),
              str(flags[:1]))

        lines, flags = web.lfi_scan(target.base + "/lfi?file=index.php", "file")
        check("文件包含 / 路径穿越", any("path_traversal_file_ok" in f for f in flags) or
              any("路径穿越成功" in l for l in lines), str(flags[:1]))

        lines, flags = web.ssti_scan(target.base + "/ssti?name=x", "name")
        check("SSTI 模板注入", any("SSTI 命中" in l for l in lines))

        lines, flags = web.rce_scan(target.base + "/rce?cmd=ping", "cmd")
        check("命令注入", any("命令注入命中" in l for l in lines))

        if os.path.exists(GIT):
            outdir = os.path.join(root, "recovered")
            lines, flags = web.git_dump(target.base, outdir)
            check(".git 源码泄露恢复", any("git_leak_recover_ok" in f for f in flags),
                  str(lines[:2])[:90])
            check(".git 恢复出目录结构",
                  os.path.exists(os.path.join(outdir, "config.php")))

        lines, flags = web.audit_source(
            "var api_key='AKIAIOSFODNN7EXAMPLE';\n// secret: flag{audit_source_ok}\n"
            "fetch('/api/admin/list')")
        check("源码审计（注释/密钥/接口）", any("audit_source_ok" in f for f in flags) or
              any("接口" in l for l in lines), str(flags[:1]))

        # 一键自动解题（信息收集阶段就应该拿到 HTML 注释里的 flag）
        res = web.auto_solve(target.base, outdir=os.path.join(root, "auto_git"), time_budget=60)
        check("Web 一键自动解题", bool(res["flags"]), str(res["flags"][:2]))
        check("一键解题保留关键步骤", any("flag" in s or "站点" in s for s in res["steps"]),
              str(res["steps"][:1])[:70])
    finally:
        target.stop()
        shutil.rmtree(root, ignore_errors=True)
    print(f"\n==== Web 模块：通过 {len(PASS)} / 失败 {len(FAIL)} ====")
    if FAIL:
        print("失败项:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
