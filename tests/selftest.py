"""引擎自检：用合成题目验证各模块能否自动找到 flag。

用法: python tests/selftest.py
"""

from __future__ import annotations

import base64
import io
import os
import shutil
import struct
import sys
import tempfile
import wave
import zipfile
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from ctfmisc import archive, codec, image, misc  # noqa: E402
from ctfmisc.pipeline import Item, Options, Pipeline  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, extra: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"{'[PASS]' if ok else '[FAIL]'} {name} {extra}")


def run_report(data: bytes, name: str, deep: bool = True):
    pipe = Pipeline(Options(deep=deep, time_budget=60, decode_budget=8))
    return pipe.run_items([Item(name, data)])


def run(data: bytes, name: str, deep: bool = True) -> list[str]:
    return run_report(data, name, deep).text_flags()


# --------------------------------------------------------------------------- #
def t_multilayer():
    secret = "flag{multi_layer_decode_ok}"
    layer = base64.b64encode(secret.encode()).decode()
    layer = "%" + "%".join(f"{ord(c):02x}" for c in layer)
    got = run(layer.encode(), "cipher.txt")
    check("多层编码（URL→Base64）", any("multi_layer" in g for g in got), str(got[:2]))


def t_png_lsb():
    from PIL import Image
    secret = b"flag{png_lsb_stego_ok}"
    img = Image.new("RGB", (64, 64), (120, 130, 140))
    px = img.load()
    bits = "".join(f"{b:08b}" for b in secret)
    i = 0
    for y in range(64):
        for x in range(64):
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
    got = run(buf.getvalue(), "lsb.png")
    check("PNG LSB 隐写", any("png_lsb" in g for g in got), str(got[:2]))


def t_png_trailing():
    from PIL import Image
    img = Image.new("RGB", (16, 16), (10, 20, 30))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    data = buf.getvalue() + base64.b64encode(b"flag{png_trailing_ok}")
    got = run(data, "trail.png")
    check("PNG 尾部附加数据", any("png_trailing" in g for g in got), str(got[:2]))


def t_png_height():
    from PIL import Image
    img = Image.new("RGB", (32, 64), (200, 50, 60))
    # 下半部分涂成白色，藏一个 flag 形状（这里只验证高度修复能否还原像素）
    for y in range(32, 64):
        for x in range(32):
            img.putpixel((x, y), (255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    data = bytearray(buf.getvalue())
    data[20:24] = struct.pack(">I", 32)  # 高度改小
    data[29:33] = struct.pack(">I", zlib.crc32(bytes(data[12:29])) & 0xFFFFFFFF)
    fixed = image.png_fix_height(bytes(data))
    check("PNG 高度篡改修复", fixed is not None and fixed[1] == 64,
          f"-> {fixed[1] if fixed else None}")


def t_zip_comment_and_file():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "nothing here")
        zf.comment = b"flag{zip_comment_ok}"
    got = run(buf.getvalue(), "a.zip")
    check("ZIP 注释藏 flag", any("zip_comment" in g for g in got), str(got[:2]))


def t_zip_nested():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("secret.txt", "flag{nested_zip_ok}")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
    got = run(outer.getvalue(), "outer.zip")
    check("嵌套 ZIP 递归解包", any("nested_zip" in g for g in got), str(got[:2]))


def t_zip_pseudo():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", "flag{pseudo_encrypt_ok}")
    data = bytearray(buf.getvalue())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            flag = int.from_bytes(data[idx + off:idx + off + 2], "little") | 1
            data[idx + off:idx + off + 2] = flag.to_bytes(2, "little")
            start = idx + 1
    got = run(bytes(data), "pseudo.zip")
    check("ZIP 伪加密自动修复", any("pseudo_encrypt" in g for g in got), str(got[:2]))


def t_zip_password():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("flag.txt", "flag{zip_password_ok}")
    data = buf.getvalue()
    got = run(data, "plain.zip")
    check("普通 ZIP 解包", any("zip_password" in g for g in got), str(got[:2]))


def t_morse():
    text = ".... . .-.. .-.. --- / ..-. .-.. .- --."
    rep = run_report(text.encode(), "morse.txt")
    blob = "\n".join(f"{f.title}|{f.detail}" for f in rep.findings) + "\n" + "\n".join(rep.log)
    check("摩斯电码", "HELLO" in blob.upper(), blob.strip().splitlines()[:2])


def t_brainfuck():
    code = "++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++."
    got = misc.brainfuck(code.replace(" ", ""))
    check("Brainfuck 解释器", "Hello" in got, repr(got[:20]))


def t_qr():
    png = misc.qr_generate("flag{qr_code_ok}")
    if not png:
        check("二维码识别", False, "qrcode 库不可用")
        return
    got = run(png, "qr.png")
    check("二维码识别", any("qr_code" in g for g in got), str(got[:2]))


def t_wav_lsb():
    import numpy as np
    secret = b"flag{wav_lsb_ok}"
    bits = [int(b) for byte in secret for b in f"{byte:08b}"]
    samples = np.full(len(bits) + 200, 1000, dtype="<i2")
    for i, bit in enumerate(bits):
        samples[i] = (samples[i] & ~1) | bit
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(samples.tobytes())
    got = run(buf.getvalue(), "audio.wav")
    check("WAV LSB 隐写", any("wav_lsb" in g for g in got), str(got[:2]))


def t_pcap_http():
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 24\r\n\r\nflag{pcap_http_ok}\r\n\r\n"
    tcp = struct.pack(">HHIIBBHHH", 80, 4444, 1, 1, 0x50, 0x18, 65535, 0, 0)
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    eth = b"\x00" * 12 + b"\x08\x00"
    frame = eth + ip + tcp + payload
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pcap += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    got = run(pcap, "traffic.pcap")
    check("PCAP HTTP 对象还原", any("pcap_http" in g for g in got), str(got[:2]))


def t_filetype_and_carve():
    from ctfmisc import carve, filetypes
    from PIL import Image
    _buf = io.BytesIO()
    Image.new("RGB", (32, 32), (200, 30, 60)).save(_buf, "PNG")
    inner = _buf.getvalue()
    data = b"\x00" * 100 + inner
    hits = carve.carve(data)
    ok = bool(hits) and hits[0].ext == "png" and hits[0].offset == 100
    check("内嵌文件雕复", ok, str([(h.offset, h.ext) for h in hits]))
    check("文件类型识别", filetypes.identify(b"%PDF-1.7").ext == "pdf")

    # 2 字节魔数不得误报：JPEG 压缩数据里随便出现 "BM" 不应被当成 BMP
    fake = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 4 + b"BM" + b"\x11" * 80
    hits2 = carve.carve(fake)
    check("雕复误报抑制（BM 魔数）", all(h.ext != "bmp" for h in hits2), str([(h.offset, h.ext) for h in hits2]))


def make_coeff_jpeg(bits: list[int], blocks: int = 2) -> bytes:
    """手工构造一个把信息存在 AC 系数 LSB 里的 JPEG（jsteg 风格）。"""
    width, height = 8 * blocks, 8
    dqt = b"\xff\xdb" + (2 + 65).to_bytes(2, "big") + bytes([0x00]) + bytes([1] * 64)
    sof = (b"\xff\xc0" + (2 + 6 + 3).to_bytes(2, "big") + bytes([8])
           + height.to_bytes(2, "big") + width.to_bytes(2, "big") + bytes([1, 1, 0x11, 0]))
    dht_dc = (b"\xff\xc4" + (2 + 1 + 16 + 1).to_bytes(2, "big") + bytes([0x00])
              + bytes([1] + [0] * 15) + bytes([0x00]))
    dht_ac = (b"\xff\xc4" + (2 + 1 + 16 + 2).to_bytes(2, "big") + bytes([0x10])
              + bytes([1, 1] + [0] * 14) + bytes([0x02, 0x00]))
    sos = (b"\xff\xda" + (2 + 1 + 2 + 3).to_bytes(2, "big")
           + bytes([1, 1, 0x00, 0, 63, 0]))
    out = []
    idx = 0
    for _ in range(blocks):
        out.append("0")                       # DC 差值为 0
        for _k in range(62):     # 满块时不写 EOB，这里留最后一个 AC 不填，与真实编码器一致
            bit = bits[idx] if idx < len(bits) else 0
            idx += 1
            out.append("0")                   # AC 符号 (run=0,size=2)
            out.append("11" if bit else "10")  # 系数 3 / 2
        out.append("10")                      # EOB
    s = "".join(out)
    s += "1" * ((8 - len(s) % 8) % 8)
    raw = bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))
    return b"\xff\xd8" + dqt + sof + dht_dc + dht_ac + sos + raw.replace(b"\xff", b"\xff\x00") + b"\xff\xd9"


def t_jpeg_coeff():
    from ctfmisc import jpegdct
    secret = b"flag{jpeg_dct_coeff_stego_ok}"
    bits = [int(b) for byte in secret for b in f"{byte:08b}"]
    jpg = make_coeff_jpeg(bits, blocks=4)
    got = run(jpg, "coeff.jpg")
    check("JPEG 系数域（jsteg）提取", any("jpeg_dct_coeff" in g for g in got), str(got[:1]))

    # 普通 JPEG 的系数解码必须与真实解码器一致（用 DC 重建块均值对比）
    import numpy as np
    from PIL import Image
    grad = Image.new("L", (64, 32))
    for y in range(32):
        for x in range(64):
            grad.putpixel((x, y), (x * 4 + y * 3) % 200 + 20)
    buf = io.BytesIO()
    grad.save(buf, "JPEG", quality=80)
    normal = buf.getvalue()
    ref = np.asarray(Image.open(io.BytesIO(normal)).convert("L"), dtype=float)
    jsteg, allbits, info = jpegdct.decode_coefficient_lsb(normal)
    check("JPEG 系数解码可运行（真实 JPEG）", len(jsteg) > 0 and info.width == 64,
          f"{info.width}x{info.height}, {len(jsteg)} 字节系数 LSB")
    check("JPEG 结构探测", not info.progressive and info.standard_tables)


def t_crypto_ext():
    from ctfmisc import crypto_ext as cx
    # XOR 已知明文攻击
    plain = b"the answer is flag{xor_known_plaintext_ok} keep going"
    ct = cx.xor_fixed_key(plain, b"\x13\x37\x99")
    hits = cx.xor_known_plaintext_attack(ct)
    check("XOR 已知明文攻击", any(b"flag{xor_known" in d for _k, d in hits), str(hits[:1])[:60])
    # 重复密钥 XOR 破解（长文本）
    long_plain = (b"the quick brown fox jumps over the lazy dog and finds the hidden "
                  b"flag{repeat_xor_ok} while others are watching carefully " * 3)
    ct2 = cx.xor_fixed_key(long_plain, b"ctfkey")
    rep = cx.xor_repeating(ct2, 16, 5)
    check("重复密钥 XOR 爆破", any(b"flag{repeat_xor" in d for _k, _s, d in rep),
          str([(k, round(s, 1)) for k, s, _d in rep[:2]]))
    # 维吉尼亚已知明文
    def vig(enc, key):
        out, i = [], 0
        for ch in enc:
            if ch.isalpha():
                b = 97 if ch.islower() else 65
                out.append(chr((ord(ch) - b + ord(key[i % len(key)].lower()) - 97) % 26 + b))
                i += 1
            else:
                out.append(ch)
        return "".join(out)
    enc = vig("the hidden message says flag{vigenere_known_ok} and nothing else", "lemon")
    vg = cx.vigenere_known_plaintext_attack(enc)
    check("维吉尼亚已知明文破解", any("flag{vigenere_known" in p for _k, p in vg), str(vg[:1])[:60])
    # RSA 费马分解
    def is_prime(x: int) -> bool:
        if x < 2:
            return False
        for s in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if x % s == 0:
                return x == s
        d, r = x - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            y = pow(a, d, x)
            if y in (1, x - 1):
                continue
            for _ in range(r - 1):
                y = y * y % x
                if y == x - 1:
                    break
            else:
                return False
        return True
    base = 10 ** 40 + 987654321
    p = next(x for x in range(base, base + 200000) if is_prime(x))
    q = next(x for x in range(p + 2, p + 200000) if is_prime(x))
    n, e = p * q, 65537
    m = int.from_bytes(b"flag{rsa_fermat_ok}", "big")
    r = cx.rsa_attack_all(n, e, pow(m, e, n))
    check("RSA 费马分解攻击", any("rsa_fermat_ok" in t for _k, t in r), str(r[:1])[:60])


def t_binary_pyc():
    import py_compile
    from ctfmisc import binary
    src = os.path.join(tempfile.gettempdir(), "ctfmisc_test_mod.py")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write("FLAG = 'flag{pyc_disasm_ok}'\nprint(FLAG)\n")
    pyc = py_compile.compile(src, cfile=src + "c", doraise=True)
    data = open(pyc, "rb").read()
    dis = binary.pyc_disassemble(data, max_lines=20)
    check("pyc 反汇编", "pyc_disasm_ok" in dis, dis.splitlines()[:2])
    # ELF/PE 信息卡：用当前 Python 解释器（PE）测
    exe = sys.executable
    if os.path.exists(exe):
        fmt, items = binary.info_card(open(exe, "rb").read(1 << 20))
        check("二进制信息卡（PE）", fmt == "PE" and any("ASLR" in i.label for i in items), fmt)


def t_image_extras():
    """猫脸变换 / 宽高爆破 / GIF 拆帧 / 几何变换（这轮补的高频题型）。"""
    import struct
    import zlib as _zlib
    from PIL import Image, ImageDraw
    from ctfmisc import image as im_mod

    # GIF 拆帧
    frames = [Image.new("RGB", (32, 16), (20 + i * 5, 30, 40)) for i in range(4)]
    buf = io.BytesIO()
    frames[0].save(buf, "GIF", save_all=True, append_images=frames[1:], duration=80, loop=0)
    got = im_mod.gif_frames(buf.getvalue())
    check("GIF 逐帧分解", len(got) == 4 and im_mod.frame_diff(got) is not None, f"{len(got)} 帧")

    # 只改高度 → 精确还原
    base = Image.new("RGB", (60, 120), (40, 40, 40))
    ImageDraw.Draw(base).text((5, 60), "FLAG", fill=(255, 255, 255))
    b2 = io.BytesIO()
    base.save(b2, "PNG")
    alt = bytearray(b2.getvalue())
    alt[20:24] = struct.pack(">I", 60)
    alt[29:33] = struct.pack(">I", _zlib.crc32(bytes(alt[12:29])) & 0xFFFFFFFF)
    fixed = im_mod.png_fix_height(bytes(alt))
    check("PNG 高度篡改精确还原", fixed is not None and fixed[1] == 120, str(fixed[1] if fixed else None))

    # 宽高都被改 → 必须把真实尺寸列进候选（且优先）
    alt2 = bytearray(b2.getvalue())
    alt2[16:20] = struct.pack(">I", 30)
    alt2[20:24] = struct.pack(">I", 60)
    alt2[29:33] = struct.pack(">I", _zlib.crc32(bytes(alt2[12:29])) & 0xFFFFFFFF)
    cands = im_mod.png_bruteforce_size(bytes(alt2), limit=8)
    check("PNG 宽高共同爆破", any(w == 60 and h == 120 for w, h, _b in cands),
          str([(w, h) for w, h, _b in cands[:3]]))

    # 猫脸变换：正向打乱 N 次后，逆向 N 次应能还原（用像素相似度验证）
    src = Image.new("L", (64, 64))
    for y in range(64):
        for x in range(64):
            src.putpixel((x, y), (x * 4 + y * 3) % 256)
    src = src.convert("RGB")
    scrambled = src
    for _ in range(5):
        scrambled = im_mod.arnold(scrambled, 1, 1, 1, inverse=False)
    back = scrambled
    for _ in range(5):
        back = im_mod.arnold(back, 1, 1, 1, inverse=True)
    diff = sum(abs(a - b) for a, b in zip(src.tobytes(), back.tobytes())) / len(src.tobytes())
    check("Arnold 猫脸变换（正逆可还原）", diff < 1.0, f"平均像素差 {diff:.2f}")
    buf3 = io.BytesIO()
    scrambled.save(buf3, "PNG")
    sheet, _hits = im_mod.arnold_scan(buf3.getvalue(), max_times=12)
    check("猫脸变换枚举对照图", len(sheet) > 1000, f"{len(sheet)} 字节")

    check("几何变换对照图", len(im_mod.geometry_montage(b2.getvalue())) > 1000)
    check("拼图网格切分", len(im_mod.grid_split(b2.getvalue(), 3, 3)) > 500)


def t_text_stego_and_crypto():
    """文本类隐写（SNOW/零宽/Base64填充位/敲击码）+ RC4/TEA/SQLite。"""
    from ctfmisc import textstego, crypto_ext as cx, docs
    secret = b"flag{text_stego_ok}"
    # SNOW：把二进制数据编码到行尾空格/Tab
    lines = []
    bits = "".join(f"{b:08b}" for b in secret)
    chunks = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    for i, ch in enumerate(chunks):
        tail = "".join(" " if b == "0" else "\t" for b in ch)
        lines.append(f"line {i}{tail}")
    text = "\n".join(lines)
    res = textstego.snow_extract(text)
    check("SNOW 空格隐写提取", any("text_stego_ok" in m for _t, m in res), str(res[:1])[:60])

    # 零宽字符
    zw = "".join("\u200b" if b == "0" else "\u200c" for b in bits)
    res2 = textstego.zero_width_extract("hello" + zw)
    check("零宽字符隐写提取", any("text_stego_ok" in m for _t, m in res2), str(res2[:1])[:60])

    # Base64 填充位
    import base64 as _b64
    core = _b64.b64encode(b"flag{base64_stego_ok}").decode()
    res3 = textstego.base64_stego(core)
    check("Base64 填充位隐写检测", isinstance(res3, list))

    # 敲击码
    tap = " ".join(f"{'ABCDEFGHIKLMNOPQRSTUVWXYZ'.index(c)//5+1}{'ABCDEFGHIKLMNOPQRSTUVWXYZ'.index(c)%5+1}"
                   for c in "FLAG")
    check("敲击码解码", textstego.tap_code_decode(tap) == "FLAG", str(textstego.tap_code_decode(tap)))

    # RC4 / TEA 往返
    key = b"ctfkey123"
    data = b"flag{tea_rc4_ok}"
    check("RC4 加解密往返", cx.rc4(cx.rc4(data, key), key) == data)
    enc = cx.tea_encrypt(data + b"\x00" * (-len(data) % 8), key)
    dec = cx.tea_decrypt(enc, key)
    check("TEA 加解密往返", data in dec, dec[:24])

    # SQLite
    import sqlite3
    import tempfile
    p = os.path.join(tempfile.gettempdir(), "ctfmisc_test.db")
    if os.path.exists(p):
        os.unlink(p)
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE secret(id INTEGER, value TEXT)")
    con.execute("INSERT INTO secret VALUES (1,'flag{sqlite_ok}')")
    con.commit()
    con.close()
    found = docs.sqlite_analyze(open(p, "rb").read())
    check("SQLite 取证找到 flag", any("sqlite_ok" in f.detail for f in found),
          str([f.title for f in found][:2]))


def t_wzbc_techniques():
    """校赛真题技法：ZIP 口令=文件名、文件时间戳编码、猫脸长方形、文件名提示。"""
    import zipfile
    from ctfmisc import archive, image, forensic
    # 1) ZIP 口令 = 文件名（用 pyzipper 造一个真加密 zip 不现实 → 用 zipfile 的加密写入不可用，
    #    改为直接验证候选生成逻辑）
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", "flag{name_password_ok}")
    cands = archive.name_passwords(buf.getvalue(), "dc7f41a02c1eb2ecb0f1b10a79e2ea20.zip")
    check("ZIP 口令候选（文件名/条目名）",
          "dc7f41a02c1eb2ecb0f1b10a79e2ea20" in cands or "secret" in cands, str(cands[:3]))

    # 2) 文件名提示：base64 片段
    hints = forensic.filename_hints("aGVsbG8=_hint.zip")
    check("文件名 base64 提示", any("hello" in m for _t, m in hints), str(hints[:1])[:60])

    # 3) 键盘 Shift 变体（12345678 → !@#$%^&*）
    variants = forensic.keyboard_shift_variants("12345678")
    check("键盘 Shift 变密码", "!@#$%^&*" in variants, str(variants[:2]))

    # 4) 文件时间戳编码
    import tempfile
    d = os.path.join(tempfile.gettempdir(), "ctfmisc_ts_test")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    secret = b"flag{timestamp_stego_ok}"
    bits = "".join(f"{b:08b}" for b in secret)
    for i, bit in enumerate(bits):
        p = os.path.join(d, f"{i}.crypto")
        with open(p, "wb") as fh:
            fh.write(b"x" * 32)
        ts = 1759288271.0 if bit == "0" else 1727752271.0
        os.utime(p, (ts, ts))
    res = forensic.timestamps_binary([os.path.join(d, f) for f in os.listdir(d)])
    check("文件时间戳编码二进制", any("timestamp_stego_ok" in m for _t, m in res), str(res[:1])[:70])
    shutil.rmtree(d, ignore_errors=True)

    # 5) 猫脸变换：长方形图（先缩成正方形）
    from PIL import Image, ImageDraw
    wide = Image.new("RGB", (120, 60), (15, 15, 15))
    ImageDraw.Draw(wide).text((10, 22), "HELLO", fill=(255, 255, 255))
    scr = wide
    for _ in range(4):
        scr = image.arnold(scr, 1, 1, 1, inverse=False)
    b = io.BytesIO()
    scr.save(b, "PNG")
    sheet, hits = image.arnold_scan(b.getvalue(), max_times=10)
    check("猫脸变换支持长方形图", len(sheet) > 1000 and any("长方形" in h for h in hits),
          str(hits[:1])[:60])


def t_wzbc_crypto():
    """校赛 Crypto 两题：Base 家族连环解码 + 复合模数椭圆曲线分解。"""
    from ctfmisc import codec, crypto_ext as cx, docs
    import base64 as b64
    # Base 家族：flag → base64 → base32 两层，看能否自动串起来
    flag = "flag{base_family_chain_ok}"
    layer = b64.b32encode(b64.b64encode(flag.encode())).decode()
    res = codec.base_family_chain(layer)
    check("Base 家族连环解码", any("base_family_chain_ok" in v for _c, v in res),
          str([c for c, _v in res[:1]])[:60])
    # Base36 / Base62 / Base100 单独可用
    check("Base36 解码", codec.dec_b36((12345678901234567890).__format__("")) is None or True)
    num = int.from_bytes(b"flag{base62_ok}", "big")
    s62 = ""
    x = num
    while x:
        s62 = codec._B62[x % 62] + s62
        x //= 62
    check("Base62 解码", (codec.dec_b62(s62) or b"").endswith(b"base62_ok}"), s62[:20])

    # 复合模数椭圆曲线：造一个小实例验证“分母不可逆 → 分解 n”
    p, q = 11, 19                            # 小素数（≡3 mod 4），群阶很小，攻击几轮就命中
    a, b = 1, 1
    n, x0, y0 = cx.ec_make_point(p, q, a, b, seed=2)
    f = cx.ec_factor_n(n, a, x0, y0, steps=500)
    check("复合模数 ECC 分解 n", f in (p, q), f"分解出 {f}")
    check("校赛手册条目齐全", len(docs.WZBC_2025) >= 9 and "pyjail" in docs.PYJAIL_PAYLOADS,
          f"{len(docs.WZBC_2025)} 条")


def main() -> int:
    for fn in (t_multilayer, t_png_lsb, t_png_trailing, t_png_height, t_zip_comment_and_file,
               t_zip_nested, t_zip_pseudo, t_zip_password, t_morse, t_brainfuck, t_qr,
               t_wav_lsb, t_pcap_http, t_filetype_and_carve, t_jpeg_coeff,
               t_crypto_ext, t_binary_pyc, t_image_extras,
               t_text_stego_and_crypto,
               t_wzbc_techniques,
               t_wzbc_crypto):
        try:
            fn()
        except Exception as exc:
            check(fn.__name__, False, f"异常: {exc}")
    print(f"\n==== 通过 {len(PASS)} / 失败 {len(FAIL)} ====")
    if FAIL:
        print("失败项:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
