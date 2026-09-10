"""Primitives shared by every decoder.

Two things live here that the rest of ``netsniff.decode`` depends on:

**A truncation discipline.** A capture taken with a snap length can cut a packet
off mid-header, and a hostile packet can lie about its own lengths. Every
decoder therefore checks its buffer *before* unpacking, via :func:`need`, and
raises :class:`Truncated` rather than letting ``struct.error`` escape or - worse
- slicing a short buffer and quietly decoding whatever bytes happen to be next.

The decoders are strict so they are testable. The tolerance lives one level up:
:func:`~netsniff.decode.decode_frame` catches these errors and records a partial
decode, so one malformed packet never stops a capture.

**The internet checksum**, which IPv4, ICMP, TCP and UDP all use. It is a 16-bit
one's-complement sum of the data, itself one's-complemented. Summing a block
that already contains its own correct checksum yields all ones, which is what
:func:`verify_checksum` looks for.
"""

from __future__ import annotations

import socket
import struct

__all__ = [
    "DecodeError",
    "Truncated",
    "checksum16",
    "format_endpoint",
    "ip4_to_str",
    "ip6_to_str",
    "mac_to_str",
    "need",
    "ones_complement_sum",
    "verify_checksum",
]


class DecodeError(Exception):
    """A protocol header could not be decoded."""


class Truncated(DecodeError):
    """The buffer ended before the header did.

    Raised for a snapped capture, a malformed packet, or a length field that
    claims more than the packet actually contains.
    """

    def __init__(self, what: str, needed: int, available: int) -> None:
        self.what = what
        self.needed = needed
        self.available = available
        super().__init__(
            f"truncated {what}: need {needed} bytes, have {available}"
        )


def need(data: bytes, count: int, what: str) -> None:
    """Assert that ``data`` holds at least ``count`` bytes, or raise.

    Call this before every ``struct.unpack``. Slicing in Python silently returns
    a short result instead of failing, which is exactly how a snapped packet
    turns into a plausible-looking wrong answer.
    """
    if len(data) < count:
        raise Truncated(what, count, len(data))


def mac_to_str(raw: bytes) -> str:
    """Format six raw bytes as ``aa:bb:cc:dd:ee:ff``."""
    if len(raw) != 6:
        raise DecodeError(f"MAC address must be 6 bytes, got {len(raw)}")
    return ":".join(f"{b:02x}" for b in raw)


def ip4_to_str(raw: bytes) -> str:
    """Format four raw bytes as dotted quad."""
    if len(raw) != 4:
        raise DecodeError(f"IPv4 address must be 4 bytes, got {len(raw)}")
    return socket.inet_ntoa(raw)


def ip6_to_str(raw: bytes) -> str:
    """Format sixteen raw bytes as a compressed IPv6 address."""
    if len(raw) != 16:
        raise DecodeError(f"IPv6 address must be 16 bytes, got {len(raw)}")
    return socket.inet_ntop(socket.AF_INET6, raw)


def ones_complement_sum(data: bytes) -> int:
    """16-bit one's-complement sum of ``data``, with carries folded back in.

    An odd-length buffer is padded with a zero byte, per RFC 1071.
    """
    if len(data) & 1:
        data += b"\x00"
    total = int(sum(struct.unpack(f"!{len(data) // 2}H", data)))
    # Fold the carry bits back into the low 16 bits until none are left.
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum16(data: bytes) -> int:
    """The internet checksum of ``data`` (RFC 1071).

    To compute a header's checksum, zero its checksum field first and pass the
    header here.
    """
    return (~ones_complement_sum(data)) & 0xFFFF


def verify_checksum(data: bytes) -> bool:
    """True when ``data`` already contains a correct checksum of itself.

    Summing a block that includes its own valid checksum gives 0xFFFF, so there
    is no need to zero the field and recompute.
    """
    return ones_complement_sum(data) == 0xFFFF


def format_endpoint(address: str, port: int | None = None) -> str:
    """Format an address, with a port, the way the rest of the world writes it.

    IPv6 addresses are bracketed when a port is present, because
    ``2001:db8::1:443`` is genuinely ambiguous - that last group could be part
    of the address. ``[2001:db8::1]:443`` is not.
    """
    if port is None:
        return address
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"
