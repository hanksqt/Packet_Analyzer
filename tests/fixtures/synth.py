"""Synthetic frame builders for flow and statistics tests.

These build real Ethernet/IP/transport bytes with plain ``struct`` - no netsniff
imports - so a test that feeds them through the decoders is still exercising the
decoders rather than comparing the code to itself.

Use them where a test needs a specific *shape* of traffic (a one-sided
conversation, a host that talks to twenty ports) that no real capture happens to
contain. Where a real captured frame will do, use ``headers.py`` instead.
"""

from __future__ import annotations

import socket
import struct

__all__ = [
    "ACK",
    "FIN",
    "PSH",
    "RST",
    "SYN",
    "arp_frame",
    "eth_frame",
    "icmp_frame",
    "tcp_frame",
    "udp_frame",
]

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth_frame(payload: bytes, ethertype: int, *, src: str = MAC_A, dst: str = MAC_B) -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0x1234,
        0x4000,
        ttl,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header[:10] + struct.pack("!H", _checksum(header)) + header[12:] + payload


def tcp_frame(
    src: str,
    src_port: int,
    dst: str,
    dst_port: int,
    *,
    flags: int = ACK,
    payload: bytes = b"",
    seq: int = 1,
    ack: int = 1,
    window: int = 64240,
) -> bytes:
    """A complete Ethernet/IPv4/TCP frame."""
    tcp = (
        struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, window, 0, 0)
        + payload
    )
    return eth_frame(_ipv4(src, dst, 6, tcp), 0x0800)


def udp_frame(
    src: str, src_port: int, dst: str, dst_port: int, *, payload: bytes = b""
) -> bytes:
    """A complete Ethernet/IPv4/UDP frame."""
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    return eth_frame(_ipv4(src, dst, 17, udp), 0x0800)


def icmp_frame(
    src: str, dst: str, *, icmp_type: int = 8, code: int = 0, ident: int = 1, seq: int = 1
) -> bytes:
    """A complete Ethernet/IPv4/ICMP echo frame."""
    body = struct.pack("!BBHHH", icmp_type, code, 0, ident, seq) + b"ping-payload"
    body = body[:2] + struct.pack("!H", _checksum(body)) + body[4:]
    return eth_frame(_ipv4(src, dst, 1, body), 0x0800)


def arp_frame(
    *, operation: int = 1, sender_ip: str = "10.0.0.1", target_ip: str = "10.0.0.2"
) -> bytes:
    """A complete Ethernet/ARP frame."""
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        operation,
        _mac(MAC_A),
        socket.inet_aton(sender_ip),
        _mac(MAC_B) if operation == 2 else b"\x00" * 6,
        socket.inet_aton(target_ip),
    )
    return eth_frame(arp, 0x0806)
