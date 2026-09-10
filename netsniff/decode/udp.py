r"""UDP datagram header decoding.

The simplest header in this project: eight fixed bytes, no options, no variable
length::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Length            |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Two things worth knowing:

``length`` counts the header *and* the payload, so the payload is
``length - 8``. It is not a payload length, and treating it as one shifts every
app-layer hint by eight bytes.

A checksum of zero means "not computed", which is legal over IPv4 and forbidden
over IPv6. Because the field is optional, an all-zero result of a real
computation is transmitted as 0xFFFF instead, so that 0 stays unambiguous.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import need, ones_complement_sum

__all__ = ["UDP_HEADER_LEN", "Udp", "decode_udp", "verify_udp_checksum"]

UDP_HEADER_LEN = 8


@dataclass(frozen=True, slots=True)
class Udp:
    """A decoded UDP header."""

    src_port: int
    dst_port: int

    length: int
    """Header plus payload, as claimed by the sender."""

    checksum: int

    payload_len: int
    """Payload bytes available, clamped to what was actually captured."""

    header_len: int = UDP_HEADER_LEN

    @property
    def claimed_payload_len(self) -> int:
        """Payload length the sender claimed: ``length - 8``, floored at 0."""
        return max(0, self.length - UDP_HEADER_LEN)

    @property
    def checksum_present(self) -> bool:
        """False when the sender declined to compute one (legal over IPv4)."""
        return self.checksum != 0

    @property
    def truncated(self) -> bool:
        """True when less payload was captured than the header claims."""
        return self.payload_len < self.claimed_payload_len

    def __str__(self) -> str:
        return f"{self.src_port} > {self.dst_port} len={self.length}"


def decode_udp(data: bytes) -> Udp:
    """Decode the UDP header at the start of ``data``.

    Args:
        data: Buffer positioned at the first byte of the UDP header.

    Returns:
        The decoded header. Slice ``data[8 : 8 + result.payload_len]`` for the
        datagram payload.

    Raises:
        Truncated: Fewer than eight bytes are available.
    """
    need(data, UDP_HEADER_LEN, "UDP header")

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:UDP_HEADER_LEN])

    available = len(data) - UDP_HEADER_LEN
    claimed = max(0, length - UDP_HEADER_LEN)

    return Udp(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=checksum,
        # A length field of 0 shows up under UDP segmentation offload, the same
        # way IPv4's total_length does; fall back to what we actually hold.
        payload_len=available if length == 0 else min(claimed, available),
    )


def verify_udp_checksum(
    datagram: bytes, src: bytes, dst: bytes, *, ipv6: bool = False
) -> bool | None:
    """Check a UDP checksum, which covers an IP pseudo-header.

    Args:
        datagram: The complete UDP datagram, header and payload.
        src: Source IP address as raw bytes.
        dst: Destination IP address as raw bytes.
        ipv6: Whether to build an IPv6-shaped pseudo-header.

    Returns:
        True or False, or None when the sender sent no checksum at all - which
        is a legal choice over IPv4 and not the same thing as a wrong one.
    """
    need(datagram, UDP_HEADER_LEN, "UDP header")
    if datagram[6:8] == b"\x00\x00":
        return None

    length = len(datagram)
    if ipv6:
        pseudo = src + dst + struct.pack("!IBBBB", length, 0, 0, 0, 17)
    else:
        pseudo = src + dst + struct.pack("!BBH", 0, 17, length)
    return ones_complement_sum(pseudo + datagram) == 0xFFFF
