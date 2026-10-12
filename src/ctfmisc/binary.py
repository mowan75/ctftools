"""二进制取证与轻量逆向：PE/ELF/Mach-O 信息卡、.pyc 反汇编、PyInstaller 解包。"""

from __future__ import annotations

import io
import math
import re
import struct
import zlib
from collections import Counter
from dataclasses import dataclass


@dataclass
class InfoItem:
    label: str
    value: str
    warn: bool = False


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC(无 PIE)", 3: "DYN(共享库/PIE)", 4: "CORE"}
ELF_MACHINE = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64",
               183: "AArch64", 243: "RISC-V"}


def elf_info(data: bytes) -> list[InfoItem]:
    out: list[InfoItem] = []
    eclass, edata = data[4], data[5]
    is64 = eclass == 2
    endian = "<" if edata == 1 else ">"
    machine = struct.unpack(endian + "H", data[18:20])[0]
    out.append(InfoItem("架构", f"ELF {64 if is64 else 32} 位 {ELF_MACHINE.get(machine, hex(machine))}"
                               f"（{'小端' if edata == 1 else '大端'}）"))
    e_type = struct.unpack(endian + "H", data[16:18])[0]
    out.append(InfoItem("类型", ELF_TYPES.get(e_type, str(e_type))))
    if is64:
        e_entry = struct.unpack(endian + "Q", data[24:32])[0]
        e_phoff, e_shoff = struct.unpack(endian + "QQ", data[32:48])
        e_phentsize, e_phnum = struct.unpack(endian + "HH", data[54:58])
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + "HHH", data[58:64])
    else:
        e_entry = struct.unpack(endian + "I", data[24:28])[0]
        e_phoff, e_shoff = struct.unpack(endian + "II", data[28:36])
        e_phentsize, e_phnum = struct.unpack(endian + "HH", data[42:46])
        e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + "HHH", data[46:52])
    out.append(InfoItem("入口点", hex(e_entry)))
    nx = None
    relro = False
    interp = ""
    dyn_off = dyn_size = 0
    for i in range(min(e_phnum, 128)):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        if is64:
            p_type, p_flags, p_offset, _va, _pa, p_filesz, _msz = struct.unpack(endian + "IIQQQQQ", data[off:off + 56])
        else:
            p_type, p_offset, _va, _pa, p_filesz, _msz, p_flags = struct.unpack(endian + "IIIIIII", data[off:off + 32])
        if p_type == 0x6474E551:
            nx = not (p_flags & 0x1)
        elif p_type == 0x6474E552:
            relro = True
        elif p_type == 3:
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\x00").decode("latin-1", "replace")
        elif p_type == 2:
            dyn_off, dyn_size = p_offset, p_filesz
    out.append(InfoItem("PIE", "开启（ET_DYN）" if e_type == 3 else "关闭", warn=e_type != 3))
    out.append(InfoItem("NX（栈不可执行）", "开启" if nx else ("关闭" if nx is False else "未知"), warn=nx is False))
    bind_now = _elf_bind_now(data, endian, is64, dyn_off, dyn_size) if dyn_off else False
    out.append(InfoItem("RELRO", "Full RELRO" if (relro and bind_now) else
                        ("Partial RELRO" if relro else "No RELRO"), warn=not relro))
    sections = elf_sections(data, endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    all_syms = [s for _n, syms in sections for s in syms]
    canary = "__stack_chk_fail" in all_syms or b"__stack_chk_fail" in data
    out.append(InfoItem("Canary", "发现 __stack_chk_fail" if canary else "未发现", warn=not canary))
    out.append(InfoItem("解释器", interp or "（静态链接/无）"))
    sec_lines = []
    for name, (s_off, s_size) in _elf_ranges(data, endian, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx).items():
        if 0 < s_size < 8 * 1024 * 1024:
            e = entropy(data[s_off:s_off + s_size])
            mark = " ★高熵可疑" if e > 7.5 and s_size > 1024 else ""
            sec_lines.append(f"{name}({s_size}B,熵{e:.2f}{mark})")
    if sec_lines:
        out.append(InfoItem("节表", ", ".join(sec_lines[:18])))
    funcs = [s for s in all_syms if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,40}", s)][:40]
    if funcs:
        out.append(InfoItem("符号（部分）", ", ".join(funcs)))
    return out


def elf_sections(data, endian, is64, shoff, shentsize, shnum, shstrndx):
    def read_sh(i):
        off = shoff + i * shentsize
        if off + shentsize > len(data) or shentsize == 0:
            return None
        fmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
        return struct.unpack(fmt, data[off:off + (64 if is64 else 40)])

    sh = read_sh(shstrndx)
    strtab = data[sh[4]:sh[4] + sh[5]] if sh else b""
    out = []
    for i in range(min(shnum, 64)):
        s = read_sh(i)
        if not s:
            continue
        end = strtab.find(b"\x00", s[0])
        name = strtab[s[0]:end].decode("latin-1", "replace") if end > 0 else str(i)
        syms = []
        if name in (".symtab", ".dynsym") and 0 < s[5] < 4 * 1024 * 1024:
            ent = 24 if is64 else 16
            blob = data[s[4]:s[4] + s[5]]
            strsec = read_sh(s[6]) if s[6] < shnum else None
            strs = data[strsec[4]:strsec[4] + strsec[5]] if strsec else b""
            for k in range(0, len(blob) - ent + 1, ent):
                nm_off = struct.unpack(endian + "I", blob[k:k + 4])[0]
                if 0 < nm_off < len(strs):
                    e2 = strs.find(b"\x00", nm_off)
                    if e2 > 0:
                        nm = strs[nm_off:e2].decode("latin-1", "replace")
                        if nm:
                            syms.append(nm)
        out.append((name, syms))
    return out


def _elf_ranges(data, endian, is64, shoff, shentsize, shnum, shstrndx) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    if not shentsize:
        return out
    def read_sh(i):
        off = shoff + i * shentsize
        if off + shentsize > len(data):
            return None
        fmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
        return struct.unpack(fmt, data[off:off + (64 if is64 else 40)])
    sh = read_sh(shstrndx)
    strtab = data[sh[4]:sh[4] + sh[5]] if sh else b""
    for i in range(min(shnum, 64)):
        s = read_sh(i)
        if not s:
            continue
        end = strtab.find(b"\x00", s[0])
        name = strtab[s[0]:end].decode("latin-1", "replace") if end > 0 else str(i)
        out[name] = (s[4], s[5])
    return out


def _elf_bind_now(data, endian, is64, off, size) -> bool:
    ent = 16 if is64 else 8
    fmt = endian + ("QQ" if is64 else "II")
    for k in range(0, min(size, 1 << 16) - ent + 1, ent):
        tag, val = struct.unpack(fmt, data[off + k:off + k + ent])
        if tag == 0:
            break
        if tag == 0x18 or (tag == 0x1E and val & 0x8):
            return True
    return False


PE_MACHINE = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64"}


def pe_info(data: bytes) -> list[InfoItem]:
    out: list[InfoItem] = []
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return [InfoItem("PE", "签名异常", True)]
    machine, nsec, _ts, _psym, _nsym, optsize, chars = struct.unpack("<HHIIIHH", data[e_lfanew + 4:e_lfanew + 24])
    opt_off = e_lfanew + 24
    magic = struct.unpack("<H", data[opt_off:opt_off + 2])[0]
    out.append(InfoItem("架构", f"PE {PE_MACHINE.get(machine, hex(machine))}，"
                               f"{'64' if magic == 0x20B else '32'} 位"))
    dllchar = struct.unpack("<H", data[opt_off + 0x46:opt_off + 0x48])[0]
    out.append(InfoItem("ASLR (DYNAMIC_BASE)", "开启" if dllchar & 0x40 else "关闭", warn=not (dllchar & 0x40)))
    out.append(InfoItem("DEP/NX", "开启" if dllchar & 0x100 else "关闭", warn=not (dllchar & 0x100)))
    out.append(InfoItem("CFG", "开启" if dllchar & 0x4000 else "关闭"))
    out.append(InfoItem("高熵 ASLR", "开启" if dllchar & 0x20 else "关闭"))
    out.append(InfoItem("重定位表", "已剥离" if chars & 0x0001 else "保留"))
    out.append(InfoItem("文件类型", "DLL" if chars & 0x2000 else "EXE"))
    sec_off = opt_off + optsize
    sections = []
    for i in range(min(nsec, 40)):
        s = data[sec_off + i * 40:sec_off + (i + 1) * 40]
        if len(s) < 40:
            break
        name = s[0:8].rstrip(b"\x00").decode("latin-1", "replace")
        _vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", s[8:24])
        ent = entropy(data[rawptr:rawptr + min(rawsize, 1 << 20)]) if rawsize else 0.0
        sections.append((name, vaddr, rawptr, rawsize))
        suspect = ent > 7.2 and rawsize > 1024
        out.append(InfoItem(f"节 {name}", f"VA={hex(vaddr)} 大小={rawsize} 熵={ent:.2f}"
                                        + (" ★高熵可疑（常见于加壳/加密段）" if suspect else ""), warn=suspect))
    imports = _pe_imports(data, sections, opt_off, magic)
    if imports:
        out.append(InfoItem("导入 DLL", ", ".join(imports[:20])))
    low = data.lower()
    hints = [k.decode() for k in (b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"ptrace",
                                  b"OutputDebugString", b"BeingDebugged", b"vmware", b"vbox",
                                  b"VirtualBox", b"qemu", b"sandbox", b"UPX0", b"UPX1", b".themida",
                                  b"aspack", b"vmprotect") if k.lower() in low]
    if hints:
        out.append(InfoItem("加壳/反调试线索", ", ".join(hints), warn=True))
    return out


def _pe_imports(data: bytes, sections, opt_off: int, magic: int) -> list[str]:
    def rva2off(rva: int) -> int:
        for _n, vaddr, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(rawsize, 0x1000):
                return rawptr + (rva - vaddr)
        return rva
    try:
        dd_off = opt_off + (0x70 if magic == 0x20B else 0x60)
        imp_rva, imp_size = struct.unpack("<II", data[dd_off + 8:dd_off + 16])
        if not imp_rva or imp_size > 1 << 20:
            return []
        out, off = [], rva2off(imp_rva)
        for i in range(64):
            ent = data[off + i * 20: off + i * 20 + 20]
            if len(ent) < 20 or ent == b"\x00" * 20:
                break
            name_rva = struct.unpack("<I", ent[12:16])[0]
            if not name_rva:
                break
            p = rva2off(name_rva)
            end = data.find(b"\x00", p)
            if 0 < end <= len(data):
                out.append(data[p:end].decode("latin-1", "replace"))
        return out
    except Exception:
        return []


def macho_info(data: bytes) -> list[InfoItem]:
    magic = struct.unpack(">I", data[:4])[0]
    out: list[InfoItem] = []
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        is64 = magic == 0xFEEDFACF
        cputype = struct.unpack(">I", data[4:8])[0]
        filetype = struct.unpack(">I", data[12:16])[0]
        flags = struct.unpack(">I", data[24:28])[0] if len(data) > 28 else 0
        names = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64"}
        out.append(InfoItem("架构", f"Mach-O {names.get(cputype, hex(cputype))}（{'64' if is64 else '32'} 位）"))
        out.append(InfoItem("类型", {1: "OBJECT", 2: "EXECUTE", 6: "DYLIB", 8: "BUNDLE"}.get(filetype, str(filetype))))
        out.append(InfoItem("PIE", "开启 (MH_PIE)" if flags & 0x200000 else "关闭", warn=not (flags & 0x200000)))
        segs = re.findall(rb"__TEXT|__DATA|__LINKEDIT", data[:4096])
        if segs:
            out.append(InfoItem("LOAD 段", ", ".join(sorted({s.decode() for s in segs}))))
    elif magic in (0xCAFEBABE, 0xCAFEBABF):
        n = struct.unpack(">I", data[4:8])[0]
        out.append(InfoItem("类型", f"Fat/Universal 二进制，包含 {n} 个架构"))
    return out


def info_card(data: bytes) -> tuple[str, list[InfoItem]]:
    """按格式返回 (格式名, 信息项列表)。"""
    try:
        if data[:4] == b"\x7fELF":
            return "ELF", elf_info(data)
        if data[:2] == b"MZ" and len(data) > 0x40:
            return "PE", pe_info(data)
        if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return "Mach-O", macho_info(data)
    except Exception as exc:  # noqa: BLE001
        return "未知", [InfoItem("解析失败", str(exc), True)]
    return "", []


# --------------------------------------------------------------------------- #
# .pyc 反汇编
# --------------------------------------------------------------------------- #
MAGIC_VERSIONS = {
    3310: "3.7", 3350: "3.7", 3379: "3.8", 3413: "3.8", 3425: "3.9", 3439: "3.9",
    3495: "3.10", 3531: "3.11", 3571: "3.12", 3600: "3.13",
}


def pyc_version(data: bytes) -> str:
    if len(data) < 4:
        return "未知"
    magic = struct.unpack("<H", data[:2])[0]
    return MAGIC_VERSIONS.get(magic, f"未知(magic={magic})")


def pyc_disassemble(data: bytes, max_lines: int = 500) -> str:
    """反汇编 .pyc；文件头被抹掉时自动尝试补常见版本头。"""
    import dis
    import marshal
    attempts: list[tuple[str, bytes]] = []
    if len(data) >= 16:
        attempts.append(("按 3.7+ 头部(16字节)", data[16:]))
    attempts.append(("按裸 code 对象", data))
    for magic in (3571, 3531, 3495, 3425, 3413, 3379, 3350):
        attempts.append((f"补 Python {MAGIC_VERSIONS[magic]} 文件头",
                         struct.pack("<H", magic) + b"\x00" * 14 + data))
    for label, blob in attempts:
        try:
            code = marshal.loads(blob)
        except Exception:
            continue
        if not hasattr(code, "co_code"):
            continue
        sio = io.StringIO()
        try:
            dis.dis(code, file=sio)
        except Exception as exc:  # noqa: BLE001
            return f"（{label}）反汇编失败：{exc}"
        consts = [c for c in code.co_consts if not hasattr(c, "co_code")][:30]
        head = (f"# 解析方式：{label}\n"
                f"# 变量名 co_names: {list(code.co_names)[:40]}\n"
                f"# 常量 co_consts: {consts}\n\n")
        return head + "\n".join(sio.getvalue().splitlines()[:max_lines])
    return "无法反汇编（可能不是 .pyc，或 Python 版本过新）"


def pyc_suspicious_strings(data: bytes) -> list[str]:
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{5,}", data):
        s = m.group(0).decode("latin-1")
        if any(k in s.lower() for k in ("flag", "key", "password", "secret", "ctf",
                                        "correct", "wrong", "input", "token")):
            out.append(s)
        if len(out) >= 30:
            break
    return out


def has_pyinstaller(data: bytes) -> bool:
    return COOKIE_MAGIC in data[-8192:] or COOKIE_MAGIC in data[:4096]


# --------------------------------------------------------------------------- #
# PyInstaller / py2exe 解包（pyinstxtractor 精简版）
# --------------------------------------------------------------------------- #
COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def pyinstaller_extract(data: bytes, max_files: int = 500,
                        limit_each: int = 32 * 1024 * 1024) -> tuple[dict[str, bytes], str]:
    """从 PyInstaller 打包的 exe 中解出内嵌归档里的所有文件（含 PYZ 内的模块）。

    格式依据 PyInstaller.archive.readers.CArchiveReader：
      cookie = '!8sIIII64s'(88 字节)；archive 起点 = cookie起点 + 88 - archive_length
      TOC 条目 = '!IIIIBc'，其中 entry_length 是**整条长度**（含 18 字节头）
    """
    idx = data.rfind(COOKIE_MAGIC)
    if idx < 0:
        return {}, "没有找到 PyInstaller 归档特征（可能不是 PyInstaller，或版本过新）"
    if idx + 88 > len(data):
        return {}, "归档特征位置异常"
    try:
        _magic, archive_len, toc_off, toc_len, pyver, _pylib = struct.unpack("!8sIIII64s", data[idx:idx + 88])
    except struct.error:
        return {}, "归档头部解析失败"
    base = (idx + 88) - archive_len
    if base < 0 or toc_len == 0 or toc_len > 16 * 1024 * 1024 or toc_off > archive_len:
        return {}, "归档参数异常（archive_length / TOC 不正常）"
    out: dict[str, bytes] = {}
    pos = base + toc_off
    end = base + toc_off + toc_len
    while pos + 18 <= end and len(out) < max_files:
        entry_len, offset, data_len, _uncmprs, cmprs, tcode = struct.unpack("!IIIIBc", data[pos:pos + 18])
        if entry_len < 18 or pos + entry_len > end:
            break
        name = data[pos + 18:pos + entry_len].rstrip(b"\x00").decode("utf-8", "replace")
        pos += entry_len
        if tcode == b"o":
            continue
        blob = data[base + offset: base + offset + data_len]
        if cmprs and blob:
            try:
                blob = zlib.decompress(blob)
            except zlib.error:
                pass
        if len(blob) <= limit_each:
            out[name] = blob
    # 解析 PYZ 里的模块
    pyz_modules: dict[str, bytes] = {}
    for name, blob in list(out.items()):
        if blob[:4] == b"PYZ\x00":
            pyz_modules.update(parse_pyz(blob, limit_each))
    ver = f"{pyver // 100}.{pyver % 100}" if pyver >= 100 else str(pyver)
    note = f"PyInstaller 归档解析完成：内嵌文件 {len(out)} 个"
    if pyz_modules:
        note += f"，PYZ 内模块 {len(pyz_modules)} 个"
    note += f"（打包时 Python {ver}）"
    if not out:
        note = (f"找到 PyInstaller 归档头（打包时 Python {ver}），但没有内嵌文件。"
                "如果这是 onedir 目录式打包，.pyc 都在同目录的 _internal/ 里，直接去那里找")
    for k, v in list(pyz_modules.items())[:max_files]:
        out[f"PYZ/{k}.pyc"] = v
    return out, note


def parse_pyz(blob: bytes, limit_each: int = 8 * 1024 * 1024) -> dict[str, bytes]:
    """解析 PyInstaller 的 PYZ-00.pyz，返回 {模块名: 代码数据}。"""
    import marshal
    try:
        toc_off = struct.unpack("!i", blob[8:12])[0]
        toc = marshal.loads(blob[toc_off:])
    except Exception:
        return {}
    out: dict[str, bytes] = {}
    for item in toc:
        try:
            name, (typecode, offset, length) = item
        except Exception:
            continue
        # PyInstaller 6 用整数类型码：0=模块 1=包 2=数据 3=命名空间包
        if typecode not in (0, 1, 2, 3, "s", "m", "M"):
            continue
        raw = blob[offset:offset + length]
        if not raw:
            continue
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
        if len(raw) <= limit_each:
            out[name] = raw
    return out


def anti_debug_hints(data: bytes) -> list[str]:
    keys = [b"DebugActiveProcess", b"NtQueryInformationProcess", b"ptrace", b"LD_PRELOAD",
            b"ollydbg", b"x64dbg", b"UPX!", b".upx", b"VMProtect", b".themida"]
    low = data.lower()
    return [k.decode() for k in keys if k.lower() in low]


# 常见密码算法特征常量（逆向题里用来识别“这是什么加密”）
CRYPTO_SIGNS: list[tuple[bytes, str]] = [
    (bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"), "AES S-Box 起始（出现即可判定用了 AES）"),
    (bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"), "AES 逆 S-Box"),
    (bytes.fromhex("0123456789abcdef"), "标准十六进制字符表（可能是 hex 编码/常量表）"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "标准 Base64 字母表"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "URL-safe Base64 字母表"),
    (b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "Base58 字母表"),
    (bytes.fromhex("67452301efcdab8998badcfe10325476"), "MD5 初始向量（用了 MD5）"),
    (bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a"), "SHA-256 初始向量（用了 SHA-256）"),
    (bytes.fromhex("d76aa478e8c7b756242070dbc1bdceee"), "MD5/SHA-1 轮常量"),
    (bytes.fromhex("edb88320"), "CRC32 反向多项式（用了 CRC32 表）"),
    (b"expand 32-byte k", "ChaCha/Salsa20 常量"),
    (b"RC4", "RC4 相关字符串"),
    (b"DES", "DES 相关字符串"),
    (b"AES", "AES 相关字符串"),
    (b"RSA", "RSA 相关字符串"),
    (b"65537", "RSA 常见公钥指数"),
]


def identify_crypto(data: bytes) -> list[str]:
    """扫描二进制里的密码算法特征常量。"""
    low = data.lower()
    out: list[str] = []
    for sig, desc in CRYPTO_SIGNS:
        needle = sig.lower() if sig.isalpha() else sig
        if needle in (low if sig.isalpha() else data):
            out.append(desc)
    return out


def memory_image_hint(data: bytes) -> str:
    """内存镜像快速判断（Volatility 题的前置识别）。"""
    size = len(data)
    if data[:4] == b"PAGEDU64":
        return "Windows 64 位崩溃转储（PAGEDU64）"
    if data[:4] == b"PAGEDUMP":
        return "Windows 崩溃转储（PAGEDUMP）"
    if data[0:8] == b"MDMP\x93\xa7" or data[:4] == b"MDMP":
        return "Windows minidump（MDMP）"
    if data[:4] in (b"LiME", b"\x00\x00\x00\x00") and size > 64 * 1024 * 1024:
        return f"可能是原始内存镜像（{size/1048576:.0f} MB，LiME/raw 格式）"
    if size > 32 * 1024 * 1024:
        return (f"大于 32MB 且不是常见文件格式，可能是**内存镜像/磁盘镜像**"
                f"（{size/1048576:.0f} MB）——建议配合 Volatility 使用；"
                "本工具已可直接做 strings / 文件雕复 / flag 扫描")
    return ""
