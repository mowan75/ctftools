"""图片隐写与取证：PNG 结构、LSB、附加数据、CRC、尺寸修复、图片异或。"""

from __future__ import annotations

import io
import struct
import zlib
from dataclasses import dataclass, field

from PIL import Image

from . import filetypes
from .flags import find_flags

PNG_SIG = b"\x89PNG\r\n\x1a\n"


@dataclass
class Finding:
    kind: str
    title: str
    detail: str = ""
    data: bytes = b""


def open_image(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return img
    except Exception:
        return None


def preview(raw: bytes, limit: int = 400) -> str:
    txt = raw[:limit].decode("utf-8", "replace")
    return "".join(c if (c.isprintable() or c in "\r\n\t") else "·" for c in txt)


def text_like(blob: bytes) -> bool:
    """判断提取出的比特流是否像文本（允许结尾是填充的 0）。"""
    if not blob:
        return False
    lead = 0
    for b in blob[:600]:
        if 32 <= b < 127 or b in (9, 10, 13):
            lead += 1
        else:
            break
    if lead >= 5 and any(chr(c).isalpha() for c in blob[:lead]):
        return True
    head = blob[:400].decode("latin-1")
    return any(h.score >= 50 for h in find_flags(head))


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #
def png_chunks(data: bytes) -> list[tuple[str, bytes, bytes, bool]]:
    """返回 [(类型, 数据, crc, crc是否正确)]。"""
    out = []
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc = data[pos + 8 + length:pos + 12 + length]
        ok = zlib.crc32(ctype + body) & 0xFFFFFFFF == int.from_bytes(crc, "big") if len(crc) == 4 else False
        out.append((ctype.decode("latin-1"), body, crc, ok))
        pos += 12 + length
        if ctype == b"IEND":
            break
    return out


def _text_chunk_text(ctype: str, body: bytes) -> str:
    try:
        if ctype == "tEXt":
            kw, _, val = body.partition(b"\x00")
            return f"{kw.decode('latin-1')} = {val.decode('utf-8', 'replace')}"
        if ctype == "zTXt":
            kw, _, rest = body.partition(b"\x00")
            return f"{kw.decode('latin-1')} = {zlib.decompress(rest[1:]).decode('utf-8', 'replace')}"
        if ctype == "iTXt":
            kw, _, rest = body.partition(b"\x00")
            comp_flag = rest[0] if rest else 0
            rest2 = rest[2:]
            _lang, _, rest3 = rest2.partition(b"\x00")
            _trans, _, text = rest3.partition(b"\x00")
            if comp_flag:
                text = zlib.decompress(text)
            return f"{kw.decode('latin-1')} = {text.decode('utf-8', 'replace')}"
    except Exception:
        pass
    return ""


def png_analyze(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    chunks = png_chunks(data)
    if not chunks:
        return findings
    names = [c[0] for c in chunks]
    findings.append(Finding("info", "PNG 结构", "块序列: " + " → ".join(names[:24])))
    for ctype, body, _crc, ok in chunks:
        if ctype in ("tEXt", "zTXt", "iTXt"):
            txt = _text_chunk_text(ctype, body)
            if txt:
                findings.append(Finding("data", f"PNG 文本块 {ctype}", txt, body))
        elif ctype not in ("IHDR", "IDAT", "IEND", "PLTE", "tRNS", "pHYs", "gAMA", "sRGB",
                           "bKGD", "tIME", "iCCP", "sBIT", "hIST", "cHRM", "sPLT", "eXIf"):
            findings.append(Finding("warn", f"异常块 {ctype}", f"{len(body)} 字节", body))
        elif not ok:
            findings.append(Finding("warn", f"{ctype} 块 CRC 校验失败", "常见于宽度/高度被篡改"))
    ihdr = next((c for c in chunks if c[0] == "IHDR"), None)
    if ihdr and len(ihdr[1]) >= 8:
        w, h = struct.unpack(">II", ihdr[1][:8])
        findings.append(Finding("info", "图像尺寸", f"{w} x {h}"))
    end = data.rfind(b"IEND")
    if end > 0 and end + 8 < len(data):
        extra = data[end + 8:]
        findings.append(Finding("data", "IEND 之后存在附加数据", f"{len(extra)} 字节", extra))
    return findings


def png_fix_height(data: bytes, max_scan: int = 4096) -> tuple[bytes, int] | None:
    """PNG 高度被改小（图片被裁切）时，暴力恢复正确高度并重算 CRC。"""
    if data[:8] != PNG_SIG or len(data) < 33:
        return None
    w, h, bitdepth, colortype = struct.unpack(">IIBB", data[16:26])
    idat = b"".join(body for ctype, body, _c, _ok in png_chunks(data) if ctype == "IDAT")
    if not idat:
        return None
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return None
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colortype)
    if not channels:
        return None
    row = 1 + (w * channels * max(bitdepth, 1) + 7) // 8
    real_h = len(raw) // row if row else 0
    if real_h <= h or real_h > 200000:
        return None
    patched = bytearray(data)
    patched[20:24] = struct.pack(">I", real_h)
    patched[29:33] = struct.pack(">I", zlib.crc32(bytes(patched[12:29])) & 0xFFFFFFFF)
    try:
        img = Image.open(io.BytesIO(bytes(patched)))
        img.load()
    except Exception:
        return None
    return bytes(patched), real_h


def png_bruteforce_size(data: bytes, max_dim: int = 6000,
                        limit: int = 8) -> list[tuple[int, int, bytes]]:
    """PNG 宽高爆破：宽度和高度都可能被改过。

    原理：IDAT 解压后的原始数据长度 = h * (1 + ceil(w*bpp/8))，
    因此枚举宽度就能反推唯一合法的高度（反之亦然），再用解码器验证。
    """
    if data[:8] != PNG_SIG or len(data) < 33:
        return []
    w0, h0, bitdepth, colortype = struct.unpack(">IIBB", data[16:26])
    idat = b"".join(body for ctype, body, _c, _ok in png_chunks(data) if ctype == "IDAT")
    if not idat:
        return []
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return []
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colortype)
    if not channels:
        return []
    bits_per_pixel = channels * max(bitdepth, 1)
    total = len(raw)
    cands: list[tuple[int, int]] = []
    for w in range(1, max_dim + 1):
        row = 1 + (w * bits_per_pixel + 7) // 8
        if total % row == 0:
            h = total // row
            if 1 <= h <= max_dim:
                cands.append((w, h))
    # 原尺寸优先尝试；再按与原尺寸的接近程度排序
    cands.sort(key=lambda t: abs(t[0] - w0) + abs(t[1] - h0))
    out: list[tuple[int, int, bytes]] = []
    seen = set()
    for w, h in cands:
        if (w, h) in seen:
            continue
        seen.add((w, h))
        patched = _png_patch_size(data, w, h)
        if patched is None:
            continue
        img = open_image(patched)
        if img is None:
            continue
        out.append((w, h, patched))
        if len(out) >= limit * 4:
            break
    # 真实尺寸的图像最“有结构”，重新压缩后每像素体积最小 —— 用它来排序
    scored: list[tuple[float, float, tuple[int, int, bytes]]] = []
    for w, h, patched in out:
        img = open_image(patched)
        if img is None:
            continue
        buf = io.BytesIO()
        small = img.convert("L")
        small.thumbnail((256, 256))
        small.save(buf, "PNG", optimize=False)
        density = len(buf.getvalue()) / max(small.width * small.height, 1)
        # 常见情形是“只改了高度、宽度没动”，所以先按与原宽度的接近程度排，再按结构密度
        width_penalty = 0.0 if w == w0 else abs(w - w0) + 100
        scored.append((width_penalty + density * 8, density, (w, h, patched)))
    scored.sort(key=lambda t: (t[0], t[1]))
    return [item for _c, _p, item in scored[:limit]]


def png_size_sheet(data: bytes, limit: int = 12) -> tuple[bytes, list[str], list[str]]:
    """PNG 宽高爆破的可视化：候选尺寸对照图 + 每个候选里的 flag 线索。"""
    cands = png_bruteforce_size(data, limit=limit)
    if not cands:
        return b"", [], []
    items: list[tuple[str, Image.Image]] = []
    notes: list[str] = []
    flags: list[str] = []
    for w, h, patched in cands:
        img = open_image(patched)
        if img is None:
            continue
        label = f"{w}x{h}"
        items.append((label, img))
        # 逐个候选做 flag / LSB / 二维码检查
        found = [x.value for x in find_flags(preview(patched, 2000))]
        for lab, bits in lsb_candidates(img, quick=True):
            if text_like(bits):
                head = bits[:200].decode("latin-1")
                found += [x.value for x in find_flags(head)]
        try:
            from . import misc as _misc
            found += [t for t in _misc.qr_decode(patched) if t]
        except Exception:
            pass
        if found:
            notes.append(f"★ 候选 {label} 里发现：{', '.join(dict.fromkeys(found))[:120]}")
            flags += found
    sheet = _contact_sheet(items, cols=4)
    return sheet, notes, sorted(set(flags))


def png_size_inconsistent(data: bytes) -> bool:
    """判断 PNG 声明的宽高是否与 IDAT 像素数据长度对不上（对不上才说明被改过）。"""
    if data[:8] != PNG_SIG or len(data) < 33:
        return False
    w, h, bitdepth, colortype = struct.unpack(">IIBB", data[16:26])
    idat = b"".join(body for ctype, body, _c, _ok in png_chunks(data) if ctype == "IDAT")
    if not idat:
        return False
    try:
        raw = zlib.decompress(idat)
    except zlib.error:
        return False
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(colortype)
    if not channels:
        return False
    row = 1 + (w * channels * max(bitdepth, 1) + 7) // 8
    if row <= 1:
        return False
    return len(raw) % row != 0 or (len(raw) // row) != h


def _png_patch_size(data: bytes, w: int, h: int) -> bytes | None:
    patched = bytearray(data)
    patched[16:20] = struct.pack(">I", w)
    patched[20:24] = struct.pack(">I", h)
    patched[29:33] = struct.pack(">I", zlib.crc32(bytes(patched[12:29])) & 0xFFFFFFFF)
    return bytes(patched)


def arnold(img: Image.Image, times: int = 1, a: int = 1, b: int = 1,
           inverse: bool = False) -> Image.Image:
    """Arnold 猫脸变换（inverse=True 为还原）。非正方形图只处理左上 n×n 方块。"""
    rgb = img.convert("RGB")
    n = min(rgb.width, rgb.height)
    if n <= 1:
        return rgb
    src = rgb.load()
    out = Image.new("RGB", rgb.size)
    dst = out.load()
    for y in range(n):
        for x in range(n):
            if inverse:
                nx = ((a * b + 1) * x - b * y) % n
                ny = (-a * x + y) % n
            else:
                nx = (x + b * y) % n
                ny = (a * x + (a * b + 1) * y) % n
            dst[nx, ny] = src[x, y]
    # 非正方形区域原样保留
    if rgb.size != (n, n):
        out.paste(rgb.crop((n, 0, rgb.width, rgb.height)), (n, 0))
    return out


def arnold_scan(data: bytes, max_times: int = 60, a: int = 1, b: int = 1,
                cols: int = 6, square_fit: bool = True) -> tuple[bytes, list[str]]:
    """枚举猫脸变换次数，生成对照拼图；同时检查每次迭代后是否出现文本/二维码。

    square_fit=True 时，对长方形图会先缩放到正方形再变换（很多题就是这么出的）。
    """
    img = open_image(data)
    if img is None:
        return b"", []
    base = img.convert("RGB")
    fitted = False
    if square_fit and base.width != base.height:
        n = max(base.width, base.height)
        base = base.resize((n, n), Image.BILINEAR)
        fitted = True
    hits: list[str] = []
    if fitted:
        hits.append("（原图是长方形，已先拉伸成正方形再逆变换）")
    panels: list[Image.Image] = []
    cur = base
    detected = []
    for i in range(1, max_times + 1):
        cur = arnold(cur, 1, a, b, inverse=True)
        panels.append(cur.copy())
        buf = io.BytesIO()
        cur.save(buf, "PNG")
        blob = buf.getvalue()
        found = [h.value for h in find_flags(preview(blob, 400))]
        try:
            from . import misc as _misc
            for text in _misc.qr_decode(blob):
                found.append(text or "<二维码>")
                hits.append(f"★ 第 {i} 次逆变换后识别到二维码：{text[:60]}")
        except Exception:
            pass
        for label, bits in lsb_candidates(cur, quick=True):
            if text_like(bits):
                head = bits[:200].decode("latin-1")
                found += [h.value for h in find_flags(head)]
        if found:
            hits.append(f"★ 第 {i} 次逆变换后出现 flag：{found[0]}")
            detected.append(i)
    sheet = _contact_sheet([(f"逆变换 {i+1} 次", p) for i, p in enumerate(panels)], cols=cols)
    return sheet, hits


def _contact_sheet(items: list[tuple[str, Image.Image]], cols: int = 6,
                   cell: int = 220) -> bytes:
    """把多张图拼成对照表（带序号），方便肉眼快速扫一遍。"""
    from PIL import ImageDraw, ImageFont
    font = None
    for fp in (r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"):
        try:
            font = ImageFont.truetype(fp, 14)
            break
        except OSError:
            continue
    font = font or ImageFont.load_default()
    thumbs = []
    for label, im in items:
        t = im.copy()
        t.thumbnail((cell, cell))
        thumbs.append((label, t))
    if not thumbs:
        return b""
    cw = max(t.width for _l, t in thumbs) + 10
    chh = max(t.height for _l, t in thumbs) + 28
    rows = (len(thumbs) + cols - 1) // cols
    sheet = Image.new("RGB", (cw * min(cols, len(thumbs)), chh * rows), (245, 246, 248))
    draw = ImageDraw.Draw(sheet)
    for i, (label, t) in enumerate(thumbs):
        x = (i % cols) * cw + 5
        y = (i // cols) * chh + 22
        sheet.paste(t, (x, y))
        draw.text((x, y - 18), label, fill=(30, 41, 59), font=font)
    buf = io.BytesIO()
    sheet.save(buf, "PNG")
    return buf.getvalue()


def geometry_montage(data: bytes, cols: int = 6) -> bytes:
    """几何变换对照表：旋转 / 镜像 / 转置 / 通道差分 / 反色 —— 一次看全。"""
    img = open_image(data)
    if img is None:
        return b""
    base = img.convert("RGB")
    items: list[tuple[str, Image.Image]] = [("原图", base)]
    try:
        items += [
            ("旋转90", base.rotate(-90, expand=True)),
            ("旋转180", base.rotate(180, expand=True)),
            ("旋转270", base.rotate(90, expand=True)),
            ("水平镜像", base.transpose(Image.FLIP_LEFT_RIGHT)),
            ("垂直镜像", base.transpose(Image.FLIP_TOP_BOTTOM)),
            ("转置", base.transpose(Image.TRANSPOSE)),
        ]
        r, g, b = base.getchannel(0), base.getchannel(1), base.getchannel(2)
        from PIL import ImageChops
        items += [
            ("R-G 差分", ImageChops.difference(r, g).convert("RGB")),
            ("G-B 差分", ImageChops.difference(g, b).convert("RGB")),
            ("B-R 差分", ImageChops.difference(b, r).convert("RGB")),
            ("R 通道", r.convert("RGB")),
            ("G 通道", g.convert("RGB")),
            ("B 通道", b.convert("RGB")),
        ]
    except Exception:
        pass
    return _contact_sheet(items, cols=cols)


def grid_split(data: bytes, rows: int = 3, cols: int = 3) -> bytes:
    """按网格切分并编号展示（拼图类题目的第一步：看清每块是什么）。"""
    img = open_image(data)
    if img is None or rows < 1 or cols < 1:
        return b""
    base = img.convert("RGB")
    tw, th = base.width // cols, base.height // rows
    if tw < 4 or th < 4:
        return b""
    items = []
    for r in range(rows):
        for c in range(cols):
            tile = base.crop((c * tw, r * th, (c + 1) * tw, (r + 1) * th))
            items.append((f"第{r+1}行第{c+1}列", tile))
    return _contact_sheet(items, cols=cols)


# --------------------------------------------------------------------------- #
# LSB
# --------------------------------------------------------------------------- #
def _pixel_bytes(img: Image.Image) -> tuple[bytes, int, int]:
    rgba = img.convert("RGBA")
    return rgba.tobytes(), rgba.width, rgba.height


def lsb_sequential(img: Image.Image, channels: tuple[int, ...] = (0, 1, 2), bit: int = 0,
                   msb_first: bool = True, stride: int = 1, start: int = 0) -> bytes:
    raw, w, h = _pixel_bytes(img)
    n = w * h
    out = bytearray()
    acc = 0
    count = 0
    for idx in range(start, n, stride):
        base = idx * 4
        for ch in channels:
            b = raw[base + ch]
            acc = (acc << 1) | ((b >> bit) & 1) if msb_first else (acc | (((b >> bit) & 1) << count))
            count += 1
            if count == 8:
                out.append(acc & 0xFF)
                acc = 0
                count = 0
            if len(out) >= 1024 * 512:
                return bytes(out)
    return bytes(out)


def lsb_bitplane(img: Image.Image, channel: int = 0, plane: int = 0) -> bytes:
    """把第 plane 个位平面按 8 像素一个字节还原。"""
    raw, w, h = _pixel_bytes(img)
    out = bytearray()
    acc = 0
    count = 0
    for i in range(w * h):
        bit = (raw[i * 4 + channel] >> plane) & 1
        acc = (acc << 1) | bit
        count += 1
        if count == 8:
            out.append(acc)
            acc = 0
            count = 0
    return bytes(out)


def lsb_candidates(img: Image.Image, quick: bool = True) -> list[tuple[str, bytes]]:
    """生成常见 LSB 提取配置的结果。"""
    configs: list[tuple[str, tuple[int, ...], int, bool]] = [
        ("RGB-LSB(高位在前)", (0, 1, 2), 0, True),
        ("BGR-LSB(高位在前)", (2, 1, 0), 0, True),
        ("RGB-LSB(低位在前)", (0, 1, 2), 0, False),
        ("R-LSB", (0,), 0, True),
        ("G-LSB", (1,), 0, True),
        ("B-LSB", (2,), 0, True),
        ("A-LSB", (3,), 0, True),
        ("RGBA-LSB", (0, 1, 2, 3), 0, True),
    ]
    if not quick:
        for bit in range(1, 4):
            configs.append((f"RGB-bit{bit}", (0, 1, 2), bit, True))
    out: list[tuple[str, bytes]] = []
    for label, chans, bit, msb in configs:
        try:
            data = lsb_sequential(img, chans, bit, msb)
        except Exception:
            continue
        if data:
            out.append((label, data))
    for ch in (0, 1, 2):
        for plane in (0, 1):
            try:
                data = lsb_bitplane(img, ch, plane)
            except Exception:
                continue
            if data:
                out.append((f"位平面 ch{ch}-bit{plane}", data))
    return out


def zlib_streams(data: bytes, limit: int = 6,
                 skip_ranges: list[tuple[int, int]] | None = None) -> list[tuple[int, bytes]]:
    """扫描 zlib 流并尝试解压（常用于 IDAT 后追加数据）。"""
    out: list[tuple[int, bytes]] = []
    for i in range(len(data) - 2):
        if skip_ranges and any(a <= i < b for a, b in skip_ranges):
            continue
        if data[i] == 0x78 and data[i + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            try:
                dec = zlib.decompressobj()
                res = dec.decompress(data[i:i + 4 * 1024 * 1024])
                if res and len(res) > 24:
                    out.append((i, res))
                    if len(out) >= limit:
                        return out
            except zlib.error:
                continue
    return out


def chunk_ranges(data: bytes, wanted: str = "IDAT") -> list[tuple[int, int]]:
    """返回指定 PNG 块数据区的 (起, 止) 偏移，用来排除“正常压缩数据”的误报。"""
    ranges: list[tuple[int, int]] = []
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8].decode("latin-1", "replace")
        if ctype == wanted:
            ranges.append((pos + 8, pos + 8 + length))
        pos += 12 + length
        if ctype == "IEND":
            break
    return ranges


def xor_images(a: bytes, b: bytes) -> bytes | None:
    ia, ib = open_image(a), open_image(b)
    if not ia or not ib:
        return None
    ia = ia.convert("RGB")
    ib = ib.convert("RGB")
    if ia.size != ib.size:
        ib = ib.resize(ia.size)
    pa, pb = ia.tobytes(), ib.tobytes()
    out = bytes(x ^ y for x, y in zip(pa, pb))
    img = Image.frombytes("RGB", ia.size, out)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def diff_images(a: bytes, b: bytes) -> bytes | None:
    ia, ib = open_image(a), open_image(b)
    if not ia or not ib:
        return None
    ia = ia.convert("RGB")
    ib = ib.convert("RGB")
    if ia.size != ib.size:
        ib = ib.resize(ia.size)
    pa, pb = ia.tobytes(), ib.tobytes()
    out = bytes(min(255, abs(x - y) * 8) for x, y in zip(pa, pb))
    img = Image.frombytes("RGB", ia.size, out)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def to_png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def gif_frames(data: bytes, limit: int = 80) -> list[tuple[int, bytes]]:
    """把 GIF（含 APNG）每一帧导出为 PNG —— 常见的“逐帧看/逐帧 LSB”题型。"""
    out: list[tuple[int, bytes]] = []
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return out
    frames = getattr(img, "n_frames", 1)
    for i in range(min(frames, limit)):
        try:
            img.seek(i)
            frame = img.convert("RGBA")
        except Exception:
            break
        buf = io.BytesIO()
        frame.save(buf, "PNG")
        out.append((i, buf.getvalue()))
    return out


def frame_diff(frames: list[tuple[int, bytes]]) -> bytes | None:
    """相邻帧异或/相减拼成一张图（很多 GIF 题的答案要靠帧差看出来）。"""
    if len(frames) < 2:
        return None
    imgs = []
    for _i, blob in frames[:24]:
        im = open_image(blob)
        if im is None:
            return None
        imgs.append(im.convert("RGB"))
    size = imgs[0].size
    sheet = Image.new("RGB", (size[0], size[1] * len(imgs)), (255, 255, 255))
    prev = None
    for idx, im in enumerate(imgs):
        if prev is None:
            panel = im
        else:
            a, b = prev.tobytes(), im.tobytes()
            diff = bytes(min(255, abs(x - y) * 6) for x, y in zip(a, b))
            panel = Image.frombytes("RGB", size, diff)
        sheet.paste(panel, (0, idx * size[1]))
        prev = im
    buf = io.BytesIO()
    sheet.save(buf, "PNG")
    return buf.getvalue()


def visual_montage(data: bytes, panels: str = "all") -> bytes | None:
    """生成“可视化排查”拼图：原图 / 自动对比度 / 均衡化 / 反相 / 通道分离 / 位平面。

    低对比度隐藏文字、通道隐写、位平面图这类题目，直接看图最快。
    """
    img = open_image(data)
    if img is None:
        return None
    base = img.convert("RGB")
    base.thumbnail((420, 420))
    items: list[tuple[str, Image.Image]] = [("原图", base)]
    try:
        from PIL import ImageOps
        items.append(("自动对比度", ImageOps.autocontrast(base)))
        items.append(("直方图均衡", ImageOps.equalize(base.convert("L")).convert("RGB")))
        items.append(("反相", ImageOps.invert(base)))
        for name, idx in (("仅 R 通道", 0), ("仅 G 通道", 1), ("仅 B 通道", 2)):
            ch = base.getchannel(idx).convert("RGB")
            items.append((name, ch))
        gray = base.convert("L")
        for plane in range(4):
            bp = gray.point(lambda v, p=plane: 255 if (v >> p) & 1 else 0)
            items.append((f"灰度位平面 {plane}", bp.convert("RGB")))
    except Exception:
        pass
    try:
        from PIL import ImageDraw, ImageFont
        font = None
        for fp in (r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"):
            try:
                font = ImageFont.truetype(fp, 16)
                break
            except OSError:
                continue
        font = font or ImageFont.load_default()
    except Exception:
        font = None
    cols = 3
    rows = (len(items) + cols - 1) // cols
    cw, chh = base.width + 12, base.height + 34
    sheet = Image.new("RGB", (cw * cols, chh * rows), (244, 246, 248))
    draw = ImageDraw.Draw(sheet)
    for i, (label, im) in enumerate(items):
        x, y = (i % cols) * cw + 6, (i // cols) * chh + 26
        sheet.paste(im, (x, y))
        if font:
            draw.text((x, y - 22), label, fill=(30, 41, 59), font=font)
    buf = io.BytesIO()
    sheet.save(buf, "PNG")
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# 其它格式
# --------------------------------------------------------------------------- #
def jpeg_analyze(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    from . import jpegdct
    # APPn / EXIF 段整体扫描：常见藏法是把另一张图塞进 EXIF
    for idx, payload in iter_appn(data):
        if len(payload) < 64:
            continue
        findings.append(Finding("info", f"APP{idx} 段", f"{len(payload)} 字节"))
        for sig, ext in ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG", "png"), (b"PK\x03\x04", "zip"),
                         (b"\x1f\x8b", "gz"), (b"%PDF", "pdf")):
            pos = payload.find(sig)
            if pos >= 0:
                blob = payload[pos:]
                if ext == "jpg":
                    end = blob.rfind(b"\xff\xd9")
                    blob = blob[:end + 2] if end > 0 else blob
                findings.append(Finding(
                    "data", f"★ APP{idx} 里内嵌了一个 {ext.upper()} 文件"
                            f"（偏移 {pos}，{len(blob)} 字节）",
                    "已提取，见右侧「内嵌文件」", blob))
                break
    try:
        info = jpegdct.probe(data)
        desc = f"{info.width}x{info.height}，{info.components} 个分量"
        if info.progressive:
            desc += "，渐进式(Progressive)"
        findings.append(Finding("info", "JPEG 结构", desc))
        if not info.standard_tables and not info.progressive:
            findings.append(Finding(
                "info", "量化表不属于 libjpeg 标准质量档位",
                "部分隐写/重编码工具会写入自定义量化表，这条只作线索参考"
                "（手机、图片编辑器同样会这样，不能单独作为判断依据）。"))
    except Exception:
        pass
    try:
        streams = jpegdct.candidate_streams(data)
        hit = False
        for name, blob in streams:
            if len(blob) < 8:
                continue
            flags = find_flags(blob.decode("latin-1", "ignore"))
            if text_like(blob) or flags:
                hit = True
                detail = preview(blob, 600)
                if flags:
                    detail = "flag 命中：" + ", ".join(h.value for h in flags[:3]) + "\n" + detail
                findings.append(Finding("data", f"JPEG 系数域数据（{name}）", detail, blob))
        if not hit:
            findings.append(Finding(
                "info", "JPEG 系数域检查结果（jsteg 类已排除）",
                jpegdct.coefficient_report(data) +
                "；已按 jsteg 规则扫描，未发现文本或 flag。"
                "若题面给了口令，剩下的可能是 steghide / outguess / jphide / F5 这类"
                "**需要密码**的方法（本工具不做带口令的提取）；也可以直接在图片页看图像本身。"))
    except jpegdct.Unsupported as exc:
        findings.append(Finding("warn", "JPEG 系数域提取不可用", str(exc)))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding("warn", "JPEG 系数域提取异常", str(exc)))
    try:
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        if exif:
            items = []
            for k, v in exif.items():
                items.append(f"{k}: {str(v)[:120]}")
            if items:
                findings.append(Finding("data", "JPEG EXIF", "\n".join(items[:20])))
        for key in ("comment", "Comment", "Description"):
            if key in img.info:
                val = img.info[key]
                val = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
                findings.append(Finding("data", f"JPEG {key}", val[:1000]))
    except Exception:
        pass
    idx = data.rfind(b"\xff\xd9")
    if idx > 0 and idx + 2 < len(data):
        findings.append(Finding("data", "JPEG 结尾后附加数据", f"{len(data)-idx-2} 字节", data[idx + 2:]))
    if b"steghide" in data.lower() or b"jphide" in data.lower() or b"outguess" in data.lower():
        findings.append(Finding("warn", "疑似 steghide/outguess 隐写痕迹", "需要口令，建议尝试空口令或题面提示"))
    return findings


def iter_appn(data: bytes):
    """遍历 JPEG 的 APPn/COM 段，返回 [(编号, 数据)]。"""
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
        if m == 0xDA:
            break
        if i + 4 > n:
            break
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if 0xE0 <= m <= 0xEF or m == 0xFE:
            yield m - 0xE0 if m != 0xFE else -1, data[i + 4:i + 2 + length]
        i += 2 + length


def gif_hidden_frames(data: bytes, limit: int = 40) -> list[tuple[str, bytes]]:
    """GIF 帧内隐藏图：某些帧的 LZW 流解出的像素比 w*h 多，多出来的就是藏的另一张图。"""
    out: list[tuple[str, bytes]] = []
    try:
        im = Image.open(io.BytesIO(data))
        palette = im.getpalette()
        w, h = im.size
    except Exception:
        return out
    frames_raw = _gif_frame_streams(data)
    for idx, raw in enumerate(frames_raw[:limit]):
        pixels = gif_lzw_decode(raw, 8)
        extra = pixels[w * h:]
        if len(extra) < w * 4:
            continue
        hh = len(extra) // w
        try:
            hidden = Image.frombytes("P", (w, hh), extra[:w * hh])
            if palette:
                hidden.putpalette(palette)
            buf = io.BytesIO()
            hidden.convert("RGB").save(buf, "PNG")
            out.append((f"第 {idx} 帧 LZW 里多出的 {w}x{hh} 隐藏图", buf.getvalue()))
        except Exception:
            continue
    return out


def _gif_frame_streams(data: bytes) -> list[bytes]:
    """按 GIF 结构取出每一帧的 LZW 压缩数据。"""
    streams: list[bytes] = []
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return streams
    i = 13
    if data[10] & 0x80:
        i += 3 * (2 ** ((data[10] & 7) + 1))
    while i < len(data):
        b = data[i]
        if b == 0x3B:
            break
        if b == 0x21:
            label = data[i + 1]
            if label == 0xF9:
                i += 3 + data[i + 2] + 1
            elif label in (0xFE, 0xFF):
                i += 3 + data[i + 2]
                while i < len(data) and data[i] != 0:
                    i += 1 + data[i]
                i += 1
            else:
                i += 2
        elif b == 0x2C:
            iflags = data[i + 9]
            i += 10
            if iflags & 0x80:
                i += 3 * (2 ** ((iflags & 7) + 1))
            i += 1
            chunk = bytearray()
            while i < len(data) and data[i] != 0:
                ln = data[i]
                chunk += data[i + 1:i + 1 + ln]
                i += 1 + ln
            i += 1
            streams.append(bytes(chunk))
        else:
            i += 1
    return streams


def gif_lzw_decode(data: bytes, min_code_size: int = 8) -> bytes:
    """GIF 变长 LZW 解码（用于取出帧里超出 w*h 的隐藏像素）。"""
    clear = 1 << min_code_size
    end = clear + 1
    code_size = min_code_size + 1
    table = [bytes([i]) for i in range(clear)] + [b"", b""]
    out = bytearray()
    bitpos, prev = 0, None
    total = len(data) * 8
    while bitpos + code_size <= total:
        byte_i, bit_i = divmod(bitpos, 8)
        chunk = int.from_bytes(data[byte_i:byte_i + 3].ljust(3, b"\x00"), "little")
        code = (chunk >> bit_i) & ((1 << code_size) - 1)
        bitpos += code_size
        if code == clear:
            table = [bytes([i]) for i in range(clear)] + [b"", b""]
            code_size = min_code_size + 1
            prev = None
            continue
        if code == end:
            break
        entry = table[code] if code < len(table) else (prev + prev[:1] if prev else b"")
        out += entry
        if prev is not None:
            table.append(prev + entry[:1])
            if len(table) >= (1 << code_size) and code_size < 12:
                code_size += 1
        prev = entry
        if len(out) > 8 * 1024 * 1024:
            break
    return bytes(out)


def gif_analyze(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    try:
        img = Image.open(io.BytesIO(data))
        findings.append(Finding("info", "GIF 帧数", str(getattr(img, "n_frames", 1))))
        for key in ("comment", "Comment"):
            if key in img.info:
                val = img.info[key]
                val = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
                findings.append(Finding("data", "GIF 注释", val[:1000]))
    except Exception:
        pass
    return findings


def analyze(data: bytes, deep_lsb: bool = False) -> list[Finding]:
    """对图片做整体取证分析。"""
    findings: list[Finding] = []
    info = filetypes.identify(data)
    findings.append(Finding("info", "文件类型", f"{info.desc} ({info.ext})"))
    if info.ext == "png":
        findings.extend(png_analyze(data))
    elif info.ext in ("jpg", "jpeg"):
        findings.extend(jpeg_analyze(data))
    elif info.ext == "gif":
        findings.extend(gif_analyze(data))

    trailing = filetypes.trailing_data(data, info.ext)
    if trailing and info.ext not in ("jpg", "jpeg") and len(trailing) > 0:
        findings.append(Finding("data", "文件尾附加数据", f"{len(trailing)} 字节", trailing))

    img = open_image(data)
    if img is not None:
        findings.append(Finding("info", "图像信息", f"{img.format} {img.mode} {img.width}x{img.height}"))
        for label, blob in lsb_candidates(img, quick=not deep_lsb):
            if text_like(blob):
                findings.append(Finding("data", f"LSB 提取: {label}", preview(blob, 600), blob))
    skip = chunk_ranges(data, "IDAT") if info.ext == "png" else []
    for off, dec in zlib_streams(data[: 2 * 1024 * 1024], skip_ranges=skip):
        if text_like(dec) or any(h.score >= 50 for h in find_flags(dec[:4000].decode("latin-1"))):
            findings.append(Finding("data", f"offset {off} 处 zlib 流解压", preview(dec, 400), dec))
    return findings
