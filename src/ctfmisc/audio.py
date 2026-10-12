"""音频相关：WAV LSB、频谱图、DTMF、摩斯、MP3 标签。"""

from __future__ import annotations

import io
import math
import re
import struct
import wave
from dataclasses import dataclass

import numpy as np
from PIL import Image

from . import filetypes
from .image import text_like


@dataclass
class Finding:
    kind: str
    title: str
    detail: str = ""
    data: bytes = b""


def preview(raw: bytes, limit: int = 500) -> str:
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "·" for b in raw[:limit])


def read_wav(data: bytes) -> tuple[np.ndarray, int, int] | None:
    try:
        with wave.open(io.BytesIO(data)) as wf:
            ch, width, rate, frames = wf.getnchannels(), wf.getsampwidth(), wf.getframerate(), wf.getnframes()
            raw = wf.readframes(min(frames, rate * 300))
    except Exception:
        return None
    if width == 2:
        arr = np.frombuffer(raw, dtype="<i2").astype(np.int32)
    elif width == 1:
        arr = np.frombuffer(raw, dtype=np.uint8).astype(np.int32) - 128
    elif width == 4:
        arr = np.frombuffer(raw, dtype="<i4").astype(np.int64)
    else:
        return None
    return arr, ch, rate


def wav_lsb_candidates(data: bytes) -> list[tuple[str, bytes]]:
    got = read_wav(data)
    if not got:
        return []
    arr, ch, _rate = got
    out: list[tuple[str, bytes]] = []
    # 逐样本取 LSB（最高位在前 / 最低位在前）
    bits = (arr & 1).astype(np.uint8)
    out.append(("样本 LSB(高位在前)", _bits_to_bytes(bits, True)))
    out.append(("样本 LSB(低位在前)", _bits_to_bytes(bits, False)))
    top = ((arr >> (8 if arr.dtype.itemsize == 2 else 24)) & 1).astype(np.uint8)
    out.append(("样本高位 LSB", _bits_to_bytes(top, True)))
    if ch == 2:
        left = bits[0::2]
        right = bits[1::2]
        out.append(("左声道 LSB", _bits_to_bytes(left, True)))
        out.append(("右声道 LSB", _bits_to_bytes(right, True)))
    return out


def _bits_to_bytes(bits: np.ndarray, msb_first: bool) -> bytes:
    n = (len(bits) // 8) * 8
    if n == 0:
        return b""
    chunk = bits[:n].reshape(-1, 8)
    if msb_first:
        weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint8)
    else:
        weights = np.array([1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint8)
    return (chunk * weights).sum(axis=1).astype(np.uint8).tobytes()


def spectrogram(data: bytes, width: int = 900, height: int = 420,
                fmax: int = 8000, gain: float = 1.0) -> bytes | None:
    got = read_wav(data)
    if not got:
        return None
    arr, ch, rate = got
    if ch > 1:
        arr = arr.reshape(-1, ch).mean(axis=1)
    arr = arr.astype(np.float32)
    if arr.size < 1024:
        return None
    seg = 1024
    hop = max(1, arr.size // max(width, 1))
    win = np.hanning(seg).astype(np.float32)
    cols = []
    for start in range(0, arr.size - seg, hop):
        spec = np.abs(np.fft.rfft(arr[start:start + seg] * win))
        bins = int(len(spec) * fmax / (rate / 2))
        cols.append(spec[:max(bins, 2)])
        if len(cols) >= width:
            break
    if not cols:
        return None
    spec = np.array(cols).T
    spec = np.log1p(spec * gain)
    spec = spec / (spec.max() or 1.0) * 255.0
    img_arr = 255 - spec.astype(np.uint8)
    img = Image.fromarray(img_arr[::-1], mode="L").resize((len(cols), height), Image.BILINEAR)
    img = img.transpose(Image.TRANSPOSE)
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "PNG")
    return buf.getvalue()


_DTMF = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}


def _goertzel(x: np.ndarray, rate: int, freq: float) -> float:
    n = len(x)
    k = int(0.5 + n * freq / rate)
    w = 2 * math.pi * k / n
    c = 2 * math.cos(w)
    s0 = s1 = s2 = 0.0
    for v in x:
        s0 = v + c * s1 - s2
        s2, s1 = s1, s0
    return s1 * s1 + s2 * s2 - c * s1 * s2


def dtmf_decode(data: bytes) -> str:
    got = read_wav(data)
    if not got:
        return ""
    arr, ch, rate = got
    if ch > 1:
        arr = arr.reshape(-1, ch).mean(axis=1)
    x = arr.astype(np.float64)
    block = max(int(rate * 0.04), 64)
    result, active, prev = [], False, ""
    for i in range(0, len(x) - block, block):
        seg = x[i:i + block]
        if np.abs(seg).mean() < (np.abs(x).mean() * 0.25):
            active = False
            continue
        lo = max((697, 770, 852, 941), key=lambda f: _goertzel(seg, rate, f))
        hi = max((1209, 1336, 1477, 1633), key=lambda f: _goertzel(seg, rate, f))
        ch2 = _DTMF.get((lo, hi), "")
        if ch2 and ch2 != prev:
            result.append(ch2)
            prev = ch2
        elif not ch2:
            prev = ""
    return "".join(result)


def morse_from_audio(data: bytes) -> str:
    """按能量包络切分，长/短音映射为 -/.（近似，适合节奏规整的题）。"""
    got = read_wav(data)
    if not got:
        return ""
    arr, ch, rate = got
    if ch > 1:
        arr = arr.reshape(-1, ch).mean(axis=1)
    env = np.abs(arr.astype(np.float32))
    win = max(int(rate * 0.005), 8)
    k = len(env) // win
    if k < 4:
        return ""
    env = env[:k * win].reshape(k, win).mean(axis=1)
    thr = env.max() * 0.25
    on = env > thr
    segs, cur, val = [], 0, on[0]
    for v in on:
        if v == val:
            cur += 1
        else:
            segs.append((val, cur * win / rate))
            val, cur = v, 1
    segs.append((val, cur * win / rate))
    marks = [d for s, d in segs if s]
    if len(marks) < 4:
        return ""
    unit = sorted(marks)[len(marks) // 4]
    text = []
    for s, d in segs:
        if s:
            text.append("." if d < unit * 2 else "-")
        else:
            if d > unit * 6:
                text.append(" / ")
            elif d > unit * 2:
                text.append(" ")
    return "".join(text).strip()


def mp3_tags(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if data[:3] != b"ID3":
        return findings
    try:
        size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
        body = data[10:10 + size]
        pos = 0
        while pos + 10 <= len(body):
            fid = body[pos:pos + 4].decode("latin-1")
            fsize = int.from_bytes(body[pos + 4:pos + 8], "big")
            if not fid.strip("\x00") or fsize <= 0 or fsize > len(body):
                break
            payload = body[pos + 10:pos + 10 + fsize]
            if fid.startswith("T") or fid in ("COMM", "USLT"):
                txt = payload[1:].replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                if txt:
                    findings.append(Finding("data", f"MP3 标签 {fid}", txt[:500], payload))
            pos += 10 + fsize
    except Exception:
        pass
    return findings


def analyze(data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    info = filetypes.identify(data)
    findings.append(Finding("info", "文件类型", f"{info.desc} ({info.ext})"))
    if info.ext == "wav":
        got = read_wav(data)
        if got:
            arr, ch, rate = got
            findings.append(Finding("info", "WAV 参数", f"{rate} Hz, {ch} 声道, {len(arr)} 采样"))
        for label, blob in wav_lsb_candidates(data):
            if text_like(blob):
                findings.append(Finding("data", f"音频 LSB: {label}", preview(blob, 400), blob))
        tones = dtmf_decode(data)
        if tones and len(tones) >= 3:
            findings.append(Finding("data", "DTMF 拨号音解码", tones))
        morse = morse_from_audio(data)
        if morse and morse.count(".") + morse.count("-") >= 6:
            findings.append(Finding("data", "音频摩斯(实验性)", morse))
        spec = spectrogram(data)
        if spec:
            findings.append(Finding("image", "频谱图已生成（看图中文字/二维码）", "见右侧预览", spec))
    elif info.ext in ("mp3",):
        findings.extend(mp3_tags(data))
    return findings
