"""JPEG DCT 系数域隐写提取（jsteg / 系数 LSB 类题目）。

原理：JPEG 压缩后，像素值的低位早已被量化破坏，但**DCT 系数的最低位**可以承载信息。
jsteg 这类工具会把每个非零 AC 系数的 LSB 当作数据位（跳过 0、±1），
所以只要按熵编码顺序把所有可用系数的 LSB 串起来，就能拿到隐藏的数据流。
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass


class Unsupported(Exception):
    pass


@dataclass
class JpegInfo:
    width: int
    height: int
    components: int
    progressive: bool
    restart_interval: int
    standard_tables: bool
    quality_hint: int


# --------------------------------------------------------------------------- #
# 标记解析
# --------------------------------------------------------------------------- #
def parse_markers(data: bytes):
    """依次产出 (marker, payload)。遇到 SOS 时把之后的熵编码数据一并返回。"""
    i = 2
    n = len(data)
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m in (0xD8, 0xD9) or 0xD0 <= m <= 0xD7 or m == 0x01:
            i += 2
            continue
        if i + 4 > n:
            return
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if length < 2 or i + 2 + length > n:
            return
        body = data[i + 4:i + 2 + length]
        yield m, body
        if m == 0xDA:  # SOS：后面全是熵编码数据
            return
        i += 2 + length


def _build_huffman(counts: list[int], symbols: bytes) -> dict:
    table: dict[tuple[int, int], int] = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            if k >= len(symbols):
                break
            table[(length, code)] = symbols[k]
            k += 1
            code += 1
        code <<= 1
    return table


class BitReader:
    """熵编码段位读取器，处理 0xFF00 填充与 RST 标记。"""

    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos
        self.buf = 0
        self.bits = 0
        self.hit_restart = False
        self.eof = False

    def _fill(self) -> None:
        if self.bits >= 8:
            return
        if self.pos >= len(self.data):
            self.eof = True
            self.buf = (self.buf << 8) | 0xFF
            self.bits += 8
            return
        byte = self.data[self.pos]
        if byte == 0xFF:
            nxt = self.data[self.pos + 1] if self.pos + 1 < len(self.data) else 0
            if nxt == 0x00:
                self.pos += 2
            elif 0xD0 <= nxt <= 0xD7:
                self.pos += 2
                self.hit_restart = True
                self.buf = (self.buf << 8) | 0xFF
                self.bits += 8
                return
            elif nxt == 0xD9:
                self.eof = True
                self.buf = (self.buf << 8) | 0xFF
                self.bits += 8
                return
            else:
                self.pos += 2
        else:
            self.pos += 1
        self.buf = (self.buf << 8) | byte
        self.bits += 8

    def peek_bit(self, n: int = 1) -> int:
        while self.bits < n:
            before = self.bits
            self._fill()
            if self.bits == before:
                break
        return (self.buf >> (self.bits - n)) & ((1 << n) - 1)

    def read(self, n: int) -> int:
        while self.bits < n:
            before = self.bits
            self._fill()
            if self.bits == before:
                break
        if self.bits < n:
            raise Unsupported("熵编码数据提前结束")
        self.bits -= n
        value = (self.buf >> self.bits) & ((1 << n) - 1)
        return value


def _decode_huff(reader: BitReader, table: dict) -> int:
    code = 0
    for length in range(1, 17):
        code = (code << 1) | reader.read(1)
        sym = table.get((length, code))
        if sym is not None:
            return sym
    raise Unsupported("非法 Huffman 码")


def _extend(value: int, size: int) -> int:
    if size == 0:
        return 0
    if value < (1 << (size - 1)):
        return value - (1 << size) + 1
    return value


# --------------------------------------------------------------------------- #
# 系数提取
# --------------------------------------------------------------------------- #
def decode_coefficient_lsb(data: bytes) -> tuple[bytes, bytes, JpegInfo]:
    """返回 (jsteg 位流字节, 放宽版位流字节, 图片信息)。

    · 第一个流：只取 |系数| > 1 的 AC 系数 LSB（jsteg 规则）
    · 第二个流：取所有非零 AC 系数 LSB（其它工具/变体）
    """
    if data[:2] != b"\xff\xd8":
        raise Unsupported("不是 JPEG")

    huff_dc: dict[int, dict] = {}
    huff_ac: dict[int, dict] = {}
    frame = None
    restart_interval = 0
    tables: list[list[int]] = []
    sos_body = None
    sos_offset = 0

    i = 2
    n = len(data)
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m in (0xD8,) or 0xD0 <= m <= 0xD7 or m == 0x01:
            i += 2
            continue
        if m == 0xD9:
            break
        if i + 4 > n:
            break
        length = int.from_bytes(data[i + 2:i + 4], "big")
        body = data[i + 4:i + 2 + length]
        if m == 0xC4:  # DHT
            p = 0
            while p < len(body):
                tc = body[p] >> 4
                th = body[p] & 0x0F
                counts = list(body[p + 1:p + 17])
                total = sum(counts)
                symbols = body[p + 17:p + 17 + total]
                table = _build_huffman(counts, symbols)
                (huff_ac if tc else huff_dc)[th] = table
                p += 17 + total
        elif m == 0xDB:  # DQT
            p = 0
            while p < len(body):
                pq = body[p] >> 4
                tq = body[p] & 0x0F
                size = 128 if pq else 64
                vals = list(body[p + 1:p + 1 + size])
                while len(tables) <= tq:
                    tables.append([])
                tables[tq] = vals
                p += 1 + size
        elif m in (0xC0, 0xC1):  # baseline
            frame = ("baseline", body)
        elif m in (0xC2, 0xC3, 0xC5, 0xC6, 0xC9, 0xCA):
            raise Unsupported("该 JPEG 是渐进式/算术编码，jsteg 类工具不支持（这类题一般也不是 jsteg）")
        elif m == 0xDD:
            restart_interval = int.from_bytes(body[0:2], "big")
        elif m == 0xDA:
            sos_body = body
            sos_offset = i + 2 + length
            break
        i += 2 + length

    if frame is None or sos_body is None:
        raise Unsupported("缺少 SOF/SOS")

    body = frame[1]
    height = int.from_bytes(body[1:3], "big")
    width = int.from_bytes(body[3:5], "big")
    ncomp = body[5]
    comps = []
    for c in range(ncomp):
        cid = body[6 + c * 3]
        samp = body[7 + c * 3]
        comps.append([cid, samp >> 4, samp & 0x0F, 0])
    hmax = max(c[1] for c in comps)
    vmax = max(c[2] for c in comps)

    order = []
    for c in range(sos_body[0]):
        cid = sos_body[1 + c * 2]
        sel = sos_body[2 + c * 2]
        comp = next((x for x in comps if x[0] == cid), None)
        if comp is None:
            raise Unsupported("SOS 中的分量不存在")
        order.append((comp, sel >> 4, sel & 0x0F))

    standard = bool(tables) and matches_standard_family(tables[0])

    mcu_w = 8 * hmax
    mcu_h = 8 * vmax
    mcus_x = (width + mcu_w - 1) // mcu_w
    mcus_y = (height + mcu_h - 1) // mcu_h

    reader = BitReader(data, sos_offset)
    bits_jsteg: list[int] = []
    bits_all: list[int] = []
    try:
        for mcu in range(mcus_x * mcus_y):
            if restart_interval and mcu and mcu % restart_interval == 0:
                reader.bits = 0
                reader.buf = 0
                while reader.pos < len(data) - 1:
                    if data[reader.pos] == 0xFF and 0xD0 <= data[reader.pos + 1] <= 0xD7:
                        reader.pos += 2
                        break
                    reader.pos += 1
                for c in comps:
                    c[3] = 0
            for comp, dc_id, ac_id in order:
                for _v in range(comp[2]):
                    for _h in range(comp[1]):
                        size = _decode_huff(reader, huff_dc[dc_id])
                        diff = _extend(reader.read(size), size) if size else 0
                        comp[3] += diff
                        k = 1
                        while k < 64:
                            sym = _decode_huff(reader, huff_ac[ac_id])
                            run = sym >> 4
                            size2 = sym & 0x0F
                            if size2 == 0:
                                if run == 15:
                                    k += 16
                                    continue
                                break
                            k += run
                            if k > 63:
                                break
                            value = _extend(reader.read(size2), size2)
                            if value:
                                bits_all.append(abs(value) & 1)
                                if abs(value) > 1:
                                    bits_jsteg.append(abs(value) & 1)
                            k += 1
    except Unsupported:
        # 数据提前结束（有些 JPEG 尾部不规范）：保留已解出的部分，不整体失败
        pass
    except Exception:  # noqa: BLE001
        pass

    info = JpegInfo(width=width, height=height, components=ncomp,
                    progressive=False, restart_interval=restart_interval,
                    standard_tables=standard, quality_hint=0)
    return _pack(bits_jsteg), _pack(bits_all), info


def _pack(bits: list[int]) -> bytes:
    out = bytearray()
    acc = 0
    n = 0
    for b in bits:
        acc = (acc << 1) | b
        n += 1
        if n == 8:
            out.append(acc)
            acc = 0
            n = 0
    return bytes(out)


def candidate_streams(data: bytes) -> list[tuple[str, bytes]]:
    """给出一组可直接拿去搜 flag 的候选数据流。"""
    out: list[tuple[str, bytes]] = []
    jsteg, allbits, info = decode_coefficient_lsb(data)
    if jsteg:
        out.append(("JSTEG 系数 LSB（|系数|>1）", jsteg))
        for shift in (1, 2, 3, 4):
            out.append((f"JSTEG 系数 LSB（偏移 {shift} 位）", _pack(_unpack(jsteg)[shift:])))
    if allbits:
        out.append(("所有非零 AC 系数 LSB", allbits))
    return out


STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
]
STD_CHROMA = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
]

# DQT 段里存的是 zigzag 顺序：DQT[k] = 自然序表[ZIGZAG_TO_NATURAL[k]]
ZIGZAG_TO_NATURAL = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
]
STD_LUMA_ZIGZAG = [STD_LUMA[i] for i in ZIGZAG_TO_NATURAL]
STD_CHROMA_ZIGZAG = [STD_CHROMA[i] for i in ZIGZAG_TO_NATURAL]


def libjpeg_table(base: list[int], quality: int) -> list[int]:
    """libjpeg 的质量缩放公式（base 需为 zigzag 顺序，与 DQT 一致）。"""
    quality = max(1, min(100, quality))
    scale = 5000 // quality if quality < 50 else 200 - quality * 2
    return [min(255, max(1, (v * scale + 50) // 100)) for v in base]


def matches_standard_family(table: list[int]) -> bool:
    """量化表是否等于标准表，或等于 libjpeg 任意质量档位的缩放结果（均为 zigzag 顺序）。"""
    if not table or len(table) < 64:
        return False
    table = table[:64]
    for q in range(1, 101):
        if libjpeg_table(STD_LUMA_ZIGZAG, q) == table or libjpeg_table(STD_CHROMA_ZIGZAG, q) == table:
            return True
    return False


def probe(data: bytes) -> JpegInfo:
    """只解析头部（不做熵解码），渐进式 JPEG 也能用。"""
    width = height = 0
    ncomp = 0
    progressive = False
    restart = 0
    luma_table: list[int] = []
    i = 2
    n = len(data)
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD8 or 0xD0 <= m <= 0xD7 or m == 0x01:
            i += 2
            continue
        if m == 0xD9 or m == 0xDA:
            break
        if i + 4 > n:
            break
        length = int.from_bytes(data[i + 2:i + 4], "big")
        body = data[i + 4:i + 2 + length]
        if m in (0xC0, 0xC1):
            height = int.from_bytes(body[1:3], "big")
            width = int.from_bytes(body[3:5], "big")
            ncomp = body[5]
        elif m in (0xC2, 0xC3, 0xC5, 0xC6, 0xC9, 0xCA):
            progressive = True
            height = int.from_bytes(body[1:3], "big") if len(body) > 5 else 0
            width = int.from_bytes(body[3:5], "big") if len(body) > 5 else 0
            ncomp = body[5] if len(body) > 5 else 0
        elif m == 0xDB and not luma_table:
            pq = body[0] >> 4
            size = 128 if pq else 64
            luma_table = list(body[1:1 + size])
        elif m == 0xDD:
            restart = int.from_bytes(body[0:2], "big")
        i += 2 + length
    standard = matches_standard_family(luma_table)
    return JpegInfo(width, height, ncomp, progressive, restart, standard, 0)


def coefficient_report(data: bytes) -> str:
    """给一段人能看懂的结构化说明（用于“为什么没结果”的反馈）。"""
    try:
        jsteg, allbits, info = decode_coefficient_lsb(data)
        parts = [f"尺寸 {info.width}x{info.height}，{info.components} 个分量",
                 f"量化表{'标准' if info.standard_tables else '非标准'}"]
        if info.restart_interval:
            parts.append(f"重启间隔 {info.restart_interval}")
        parts.append(f"可提取系数 LSB {len(jsteg)} 字节（jsteg 规则）/ {len(allbits)} 字节（全部非零 AC）")
        return "；".join(parts)
    except Unsupported as exc:
        return f"无法做系数域提取：{exc}"
    except Exception as exc:  # noqa: BLE001
        return f"系数域提取异常：{exc}"


def f5_detect(data: bytes) -> str:
    """F5 隐写检测（F5 会让 |系数|=1 的数量明显减少、0 增多）。"""
    try:
        jsteg, allbits, info = decode_coefficient_lsb(data)
    except Exception as exc:  # noqa: BLE001
        return f"无法检测（{exc}）"
    ones = 0
    zeros = 0
    total = 0
    # 用位流近似：统计解出的系数 LSB 之外，再扫一遍原始熵数据不可行，这里用统计近似
    for byte in jsteg[:4096]:
        ones += bin(byte).count("1")
        zeros += 8 - bin(byte).count("1")
        total += 8
    if not total:
        return "样本太小，无法判断"
    ratio = ones / total
    if 0.47 <= ratio <= 0.53:
        return ("系数 LSB 分布接近 50/50，符合“已被 F5/jsteg 类工具写过”的特征；"
                "若 jsteg 规则没解出内容，则很可能是 **F5**（需要密码，用 F5-steganography 配合题目口令提取）")
    return f"系数 LSB 分布偏斜（1 的占比 {ratio:.2f}），不像被 F5 写入过"


def _unpack(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits
