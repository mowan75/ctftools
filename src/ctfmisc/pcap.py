"""流量包分析：TCP 流重组、HTTP 对象还原、USB 键盘流量、字符串提取。"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from . import filetypes


@dataclass
class Packet:
    index: int
    ts: float
    linktype: int
    data: bytes


def parse(data: bytes) -> list[Packet]:
    """解析 pcap / pcapng，返回报文列表。"""
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return _parse_pcapng(data)
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _parse_pcap(data)
    return []


def _parse_pcap(data: bytes) -> list[Packet]:
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    if len(data) < 24:
        return []
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    out, pos, idx = [], 24, 0
    while pos + 16 <= len(data):
        ts_s, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        if incl > len(data) - pos:
            break
        out.append(Packet(idx, ts_s + ts_frac / (1e9 if nano else 1e6), linktype, data[pos:pos + incl]))
        pos += incl
        idx += 1
    return out


def _parse_pcapng(data: bytes) -> list[Packet]:
    out: list[Packet] = []
    pos, idx = 0, 0
    linktypes: list[int] = []
    if_id = 0
    while pos + 12 <= len(data):
        btype, blen = struct.unpack("<II", data[pos:pos + 8])
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktypes.append(struct.unpack("<H", body[0:2])[0])
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, _t1, _t2, caplen, _olen = struct.unpack("<IIIII", body[0:20])
            pkt = body[20:20 + caplen]
            lt = linktypes[iface] if iface < len(linktypes) else linktypes[-1] if linktypes else 1
            out.append(Packet(idx, 0.0, lt, pkt))
            idx += 1
        elif btype == 3 and len(body) >= 4:  # Simple Packet Block
            pkt = body[4:]
            out.append(Packet(idx, 0.0, linktypes[-1] if linktypes else 1, pkt))
            idx += 1
        pos += blen
    return out


def payload_of(pkt: Packet) -> tuple[int, bytes]:
    """剥掉链路层，返回 (IP 协议号, IP 载荷)；非 IP 报文返回 (0, b"")。"""
    data = pkt.data
    lt = pkt.linktype
    if lt == 1:  # Ethernet
        if len(data) < 14:
            return 0, b""
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype = int.from_bytes(data[16:18], "big")
            offset = 18
        if ethertype not in (0x0800, 0x86DD):
            return 0, b""
        ip = data[offset:]
    elif lt == 113:  # Linux cooked
        if len(data) < 16:
            return 0, b""
        proto = int.from_bytes(data[14:16], "big")
        if proto not in (0x0800, 0x86DD):
            return 0, b""
        ip = data[16:]
    elif lt in (101, 228, 229):  # raw IP
        ip = data
    else:
        return 0, b""
    if not ip:
        return 0, b""
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return 0, b""
        ihl = (ip[0] & 0xF) * 4
        proto = ip[9]
        return proto, ip[ihl:]
    if version == 6:
        if len(ip) < 40:
            return 0, b""
        return ip[6], ip[40:]
    return 0, b""


def l4_of(pkt: Packet) -> tuple[int, bytes, int, int]:
    """返回 (协议号, 载荷, 源端口, 目的端口)。"""
    proto, ip_payload = payload_of(pkt)
    if proto == 6 and len(ip_payload) >= 20:  # TCP
        sport, dport = struct.unpack(">HH", ip_payload[0:4])
        offset = (ip_payload[12] >> 4) * 4
        return proto, ip_payload[offset:], sport, dport
    if proto == 17 and len(ip_payload) >= 8:  # UDP
        sport, dport = struct.unpack(">HH", ip_payload[0:4])
        return proto, ip_payload[8:], sport, dport
    return proto, b"", 0, 0


def _ip_of(pkt: Packet) -> tuple[str, int]:
    proto, ip_payload = payload_of(pkt)
    return "", 0


def ip_addrs(pkt: Packet) -> tuple[str, str]:
    data = pkt.data
    lt = pkt.linktype
    offset = {1: 14, 113: 16, 101: 0, 228: 0, 229: 0}.get(lt, 0)
    ip = data[offset:]
    if not ip:
        return "", ""
    if ip[0] >> 4 == 4 and len(ip) >= 20:
        return ".".join(str(b) for b in ip[12:16]), ".".join(str(b) for b in ip[16:20])
    if ip[0] >> 4 == 6 and len(ip) >= 40:
        return ip[8:24].hex(), ip[24:40].hex()
    return "", ""


def tcp_streams(packets: list[Packet], limit: int = 40) -> dict[tuple, bytes]:
    """按五元组重组 TCP 流（按序列号排序）。"""
    flows: dict[tuple, list[tuple[int, bytes]]] = {}
    for pkt in packets:
        proto, payload, sport, dport = l4_of(pkt)
        if proto != 6 or not payload:
            continue
        src, dst = ip_addrs(pkt)
        key = (src, sport, dst, dport)
        ip_payload = payload_of(pkt)[1]
        if len(ip_payload) < 20:
            continue
        seq = struct.unpack(">I", ip_payload[4:8])[0]
        flows.setdefault(key, []).append((seq, payload))
    out: dict[tuple, bytes] = {}
    for key, chunks in flows.items():
        chunks.sort(key=lambda x: x[0])
        out[key] = b"".join(c for _s, c in chunks)
    return out


def http_objects(streams: dict[tuple, bytes]) -> list[tuple[str, bytes]]:
    """从 TCP 流中还原 HTTP 响应体。"""
    results: list[tuple[str, bytes]] = []
    for key, data in streams.items():
        pos = 0
        while True:
            idx = data.find(b"HTTP/1.", pos)
            if idx < 0:
                break
            end = data.find(b"\r\n\r\n", idx)
            if end < 0:
                break
            head = data[idx:end].decode("latin-1", "replace")
            m = re.search(r"Content-Length:\s*(\d+)", head, re.I)
            ctype = re.search(r"Content-Type:\s*([^\r\n;]+)", head, re.I)
            start = end + 4
            if m:
                length = int(m.group(1))
                body = data[start:start + length]
                pos = start + length
            else:
                body = data[start:]
                pos = len(data)
            if body:
                label = f"{key[0]}:{key[1]} → {key[2]}:{key[3]} [{ctype.group(1).strip() if ctype else '?'}]"
                results.append((label, body))
            if len(results) > 60:
                return results
    return results


def http_hosts(streams: dict[tuple, bytes]) -> list[str]:
    hosts = []
    for data in streams.values():
        for m in re.finditer(rb"(?:GET|POST|Host:)\s*([^\r\n ]+)", data):
            try:
                hosts.append(m.group(1).decode("utf-8", "replace"))
            except Exception:
                pass
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out[:40]


# --------------------------------------------------------------------------- #
# USB 键盘 / 鼠标
# --------------------------------------------------------------------------- #
_HID = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0A: "g",
    0x0B: "h", 0x0C: "i", 0x0D: "j", 0x0E: "k", 0x0F: "l", 0x10: "m", 0x11: "n",
    0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t", 0x18: "u",
    0x19: "v", 0x1A: "w", 0x1B: "x", 0x1C: "y", 0x1D: "z", 0x1E: "1", 0x1F: "2",
    0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9",
    0x27: "0", 0x28: "\n", 0x29: "\x1b", 0x2A: "\b", 0x2B: "\t", 0x2C: " ",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'",
    0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
}
_HID_SHIFT = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&", "8": "*",
    "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|", ";": ":",
    "'": '"', "`": "~", ",": "<", ".": ">", "/": "?",
}


def usb_keyboard(packets: list[Packet]) -> str:
    """还原 USB 键盘流量中的击键（支持 LINKTYPE_USB_LINUX / USBPCAP）。"""
    text: list[str] = []
    for pkt in packets:
        if pkt.linktype not in (220, 249):
            continue
        data = pkt.data
        # 只取中断输入端点（最常见：偏移 64 处开始 8 字节 HID 报文）
        for off in range(max(0, len(data) - 8), -1, -1):
            report = data[off:off + 8]
            if len(report) < 8:
                continue
            key = report[2]
            if key in _HID and 0 < key < 0xA0:
                ch = _HID[key]
                if report[0] & 0x22:  # 左/右 Shift
                    ch = _HID_SHIFT.get(ch, ch.upper() if ch.isalpha() else ch)
                if off > 0:
                    text.append(ch)
                break
    return "".join(text)


def usb_mouse(packets: list[Packet]) -> str:
    """USB 鼠标位移还原（把左右键当作 0/1，常用于画二维码）。"""
    pts = []
    for pkt in packets:
        if pkt.linktype not in (220, 249) or len(pkt.data) < 64 + 4:
            continue
        report = pkt.data[64:64 + 4]
        if len(report) == 4 and report[1]:
            pts.append((report[1], report[2]))
    if len(pts) < 16:
        return ""
    return f"共 {len(pts)} 个移动事件（X 范围 {min(p[0] for p in pts)}~{max(p[0] for p in pts)}）"


def usb_mouse_render(packets: list[Packet], scale: int = 4, margin: int = 40) -> bytes | None:
    """把 USB 鼠标流量画成轨迹图（常用于“画出来是个二维码/文字”的题）。"""
    import io
    from PIL import Image, ImageDraw
    pts = []
    x = y = 0
    for pkt in packets:
        if pkt.linktype not in (220, 249) or len(pkt.data) < 64 + 4:
            continue
        report = pkt.data[64:64 + 4]
        if len(report) < 4:
            continue
        dx = report[1] - 256 if report[1] > 127 else report[1]
        dy = report[2] - 256 if report[2] > 127 else report[2]
        x += dx
        y += dy
        pts.append((x, y))
    if len(pts) < 20:
        return None
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    w = (max(xs) - min(xs)) * scale + margin * 2
    h = (max(ys) - min(ys)) * scale + margin * 2
    if w <= 0 or h <= 0 or w > 20000 or h > 20000:
        return None
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    ox, oy = min(xs), min(ys)
    last = None
    for px, py in pts:
        cur = ((px - ox) * scale + margin, (py - oy) * scale + margin)
        if last:
            draw.line([last, cur], fill=(0, 0, 0), width=2)
        last = cur
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def dns_queries(packets: list[Packet]) -> list[str]:
    """提取 DNS 查询域名（DNS 隧道题的第一步）。"""
    out: list[str] = []
    for pkt in packets:
        proto, payload, sport, dport = l4_of(pkt)
        if proto != 17 or dport != 53 or len(payload) < 13:
            continue
        qdcount = int.from_bytes(payload[4:6], "big")
        if qdcount < 1:
            continue
        pos = 12
        labels = []
        while pos < len(payload):
            ln = payload[pos]
            if ln == 0:
                break
            if ln > 63:
                break
            labels.append(payload[pos + 1:pos + 1 + ln].decode("latin-1", "replace"))
            pos += ln + 1
        if labels:
            out.append(".".join(labels))
    return out


def icmp_payloads(packets: list[Packet]) -> tuple[bytes, list[str]]:
    """提取 ICMP 载荷（ICMP 隧道题：数据藏在 ping 的 payload 里）。"""
    chunks: list[bytes] = []
    for pkt in packets:
        proto, ip_payload = payload_of(pkt)
        if proto != 1 or len(ip_payload) < 8:
            continue
        ihl = (ip_payload[0] & 0xF) * 4 if False else 0
        # payload_of 已剥掉 IP 头，这里按 ICMP 头 8 字节算
        body = ip_payload[8:]
        if body:
            chunks.append(body)
    data = b"".join(chunks)
    texts = []
    if data:
        try:
            texts.append(data.decode("utf-8", "ignore"))
        except Exception:
            pass
        texts += printable_strings(data, 6, 30)
    return data, texts


def printable_strings(data: bytes, min_len: int = 5, limit: int = 400) -> list[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group(0).decode("latin-1"))
        if len(out) >= limit:
            break
    return out


def analyze(data: bytes) -> list:
    """返回 Findings 列表（与 image/audio 模块结构一致）。"""
    from .image import Finding  # 复用同一数据结构，避免循环依赖问题
    findings: list[Finding] = []
    packets = parse(data)
    if not packets:
        return findings
    links = {p.linktype for p in packets}
    findings.append(Finding("info", "流量包概况", f"{len(packets)} 个报文，链路类型 {sorted(links)}"))
    if links & {220, 249}:
        text = usb_keyboard(packets)
        if text:
            findings.append(Finding("data", "USB 键盘击键还原", text[:2000]))
        mouse = usb_mouse(packets)
        if mouse:
            findings.append(Finding("data", "USB 鼠标流量", mouse))
    streams = tcp_streams(packets)
    if streams:
        findings.append(Finding("info", "TCP 流数量", str(len(streams))))
        hosts = http_hosts(streams)
        if hosts:
            findings.append(Finding("data", "HTTP 请求/主机名", "\n".join(hosts[:30])))
        for label, body in http_objects(streams)[:12]:
            findings.append(Finding("data", f"还原对象 {label}", f"{len(body)} 字节", body))
    joined = b"".join(p.data for p in packets)
    icmp_data, icmp_texts = icmp_payloads(packets)
    if icmp_data:
        findings.append(Finding("data", "ICMP 载荷（ICMP 隧道题）",
                                f"共 {len(icmp_data)} 字节\n" + "\n".join(icmp_texts[:10])[:800],
                                icmp_data))
    strs = printable_strings(joined, 8, 40)
    if strs:
        findings.append(Finding("data", "报文中的可打印字符串", "\n".join(strs[:30])))
    return findings
