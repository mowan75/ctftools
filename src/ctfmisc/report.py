"""解题报告（writeup）生成：只保留“解出 flag 的步骤”，格式对齐常见 CTF 报告模板。"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

CATEGORY_ORDER = ["Misc", "Web", "PWN", "RE", "Crypto"]
CATEGORY_ALIAS = {
    "misc": "Misc", "杂项": "Misc", "web": "Web", "pwn": "PWN", "re": "RE",
    "reverse": "RE", "逆向": "RE", "crypto": "Crypto", "密码": "Crypto",
}


@dataclass
class Case:
    """一道题目（或一个目标）的解题记录。"""

    name: str
    category: str = "Misc"
    target: str = ""
    steps: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def norm_category(self) -> str:
        return CATEGORY_ALIAS.get(self.category.strip().lower(), "Misc")


def guess_category(name: str, findings_kinds: str = "") -> str:
    """按文件名/内容猜一个大类（用于自动分类到 Misc/Web/RE/Crypto）。"""
    low = (name + " " + findings_kinds).lower()
    if low.startswith("http") or "://" in name:
        return "Web"
    if low.endswith((".pyc", ".pyo")) or any(k in low for k in (".elf", "checksec", "reverse")):
        return "RE"
    if any(k in low for k in ("rsa", "aes", "des", "crypto", "cipher", "哈希", "hash", "xor")):
        return "Crypto"
    if low.endswith((".pcap", ".pcapng")) or "流量" in low:
        return "Misc"
    return "Misc"


def cases_from_pipeline(report, name: str = "", category: str = "") -> Case:
    """把一次流水线分析结果转成解题记录（只保留解出 flag 的链条）。"""
    chains = report.solve_chains()
    score_map: dict[str, float] = {}
    for hit in report.flags:
        score_map[hit.value] = max(score_map.get(hit.value, 0), hit.score)

    def good(value: str) -> bool:
        sc = score_map.get(value, 0)
        return sc >= 35 and (("flag{" in value.lower()) or sc >= 40 or "{" in value)

    def rank_key(value: str):
        """真实 flag 通常是 flag{...}；多层的花式解密结果排后面。"""
        low = value.lower()
        prefix = low.split("{", 1)[0]
        if prefix in ("flag", "ctf", "key"):
            pri = 0
        elif "flag" in prefix or "ctf" in prefix:
            pri = 1
        else:
            pri = 2
        return (pri, len(value))
    root_name = name or (os.path.basename(report.items[list(report.items)[0]].label)
                         if report.items else "未命名目标")
    case = Case(name=root_name, category=category or guess_category(root_name),
                target=root_name, seconds=report.seconds)
    flags: list[str] = []
    steps: list[str] = []
    # 先决定最终保留哪些 flag（优先 flag{...}），再只保留对应链条
    all_strong: list[str] = []
    for _root, _chain_steps, hit_flags in chains:
        all_strong += [f for f in hit_flags if good(f)]
    ordered_all = sorted(set(all_strong), key=rank_key)
    keep = [f for f in ordered_all if rank_key(f)[0] == 0] or ordered_all
    keep = set(keep[:8])
    for root, chain_steps, hit_flags in chains:
        strong = [f for f in hit_flags if f in keep]
        if not strong:
            continue
        if root and root != name and len(chains) > 1:
            steps.append(f"【子文件】{root}")
        for desc, evidence, label in chain_steps:
            line = desc
            if evidence:
                line += f"（{evidence}）"
            # 把这一步实际拿到的数据预览附上：一步一步讲清楚“做了什么、得到什么”
            detail = ""
            item = report.items.get(label)
            if item is not None and item.data:
                blob = item.data
                text = ""
                try:
                    text = blob.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        text = blob.decode("gbk")
                    except UnicodeDecodeError:
                        text = ""
                printable = (sum(1 for c in text[:200] if c.isprintable() or c in "\r\n\t")
                             / max(len(text[:200]), 1)) if text else 0
                if text and printable > 0.9:
                    preview = text.strip().replace("\n", " ")[:120]
                    detail = f"得到内容预览：`{preview}`（共 {len(blob)} 字节）"
                else:
                    detail = (f"得到 {len(blob)} 字节二进制数据"
                              f"（头部 {blob[:12].hex(' ')}）")
            steps.append(line + (f"\n    - {detail}" if detail else ""))
        for f in strong:
            steps.append(f"在以上数据中匹配到 flag：`{f}`")
            flags.append(f)
    # 去重（同一个 flag 可能来自多条链）
    seen, uniq_steps = set(), []
    for s in steps:
        if s not in seen:
            seen.add(s)
            uniq_steps.append(s)
    case.steps = uniq_steps
    ordered = sorted(set(flags), key=rank_key)
    case.flags = [f for f in ordered if rank_key(f)[0] == 0] or ordered
    case.flags = case.flags[:8]
    return case


def build_writeup(cases: list[Case], team: str = "XXX战队", ranking: str = "",
                  operator: str = "CTF 杂项解题助手", extra_notes: str = "") -> str:
    """生成 writeup markdown（对齐 渊龙Sec CTF 报告模板 的结构）。"""
    now = time.strftime("%Y-%m-%d %H:%M")
    solved = [c for c in cases if c.flags]
    unsolved = [c for c in cases if not c.flags]
    lines: list[str] = []
    lines += [f"# {team}", "",
              "> 本报告由 **CTF 杂项解题助手** 自动生成：仅保留与 flag 直接相关的关键步骤。", "",
              "## 一、战队信息", "",
              f"- 名称：{team}",
              f"- 排名：{ranking}", "",
              "## 二、解题情况", "",
              f"- 分析时间：{now}",
              f"- 分析目标：{len(cases)} 个（解出 {len(solved)} 个）",
              f"- 使用工具：{operator}", ""]
    if solved:
        lines += ["| 序号 | 题目 | 分类 | 结果 | FLAG |", "| --- | --- | --- | --- | --- |"]
        for i, c in enumerate(cases, 1):
            mark = "✅ 解出" if c.flags else "❌ 未解出"
            flag = f"`{c.flags[0]}`" if c.flags else "—"
            lines.append(f"| {i} | {c.name} | {c.norm_category()} | {mark} | {flag} |")
        lines.append("")
    else:
        lines += ["本次没有解出题目。", ""]
    lines += ["### 三、解题过程", "", "> 题目按照顺序填写（只列出解出 flag 的关键步骤）", ""]
    for cat in CATEGORY_ORDER:
        group = [c for c in solved if c.norm_category() == cat]
        if not group:
            continue
        lines += [f"### {cat}", ""]
        for i, c in enumerate(group, 1):
            lines += [f"#### 题目{i}：{c.name}", ""]
            lines.append(f"- 题目目标：`{c.target or c.name}`")
            if c.seconds:
                lines.append(f"- 自动化耗时：{c.seconds:.1f} 秒")
            lines.append("")
            lines.append("**解题步骤：**")
            lines.append("")
            for j, s in enumerate(c.steps, 1):
                lines.append(f"{j}. {s}")
            if c.evidence:
                lines += ["", "**关键 payload / 脚本：**", "", "```text"]
                lines += c.evidence[:60]
                lines += ["```"]
            lines += ["", f"**FLAG：** `{c.flags[0]}`", ""]
    if unsolved:
        lines += ["### 未解出题目（复盘用）", ""]
        for c in unsolved:
            lines.append(f"- **{c.name}**（{c.norm_category()}）："
                         f"已自动尝试 {len(c.steps) or '若干'} 步，未找到 flag")
        lines.append("")
    if extra_notes:
        lines += ["### 创新技术", "", extra_notes, ""]
    else:
        lines += ["### 创新技术", "",
                  "本次使用自研 CTF 杂项解题助手完成自动化分析："
                  "统一流水线覆盖编码/密码/隐写/取证/逆向/Web 等题型，"
                  "并按“只保留解出 flag 的关键步骤”自动生成解题链路。", ""]
    return "\n".join(lines)


def build_quick_report(case: Case) -> str:
    """单题速览报告（分析完成后直接显示在界面里）。"""
    lines = [f"# {case.name}", "", f"- 分类：{case.norm_category()}",
             f"- 目标：`{case.target or case.name}`",
             f"- 耗时：{case.seconds:.1f} 秒", ""]
    if case.flags:
        lines += [f"## FLAG", "", f"`{case.flags[0]}`", "", "## 关键步骤", ""]
        for i, s in enumerate(case.steps, 1):
            lines.append(f"{i}. {s}")
    else:
        lines += ["## 结果", "", "没有自动解出 flag。可展开左侧对应分类，用专项卡片手工深挖。"]
    return "\n".join(lines)
