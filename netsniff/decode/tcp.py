r"""TCP segment header decoding.

Like IPv4, the header is variable length::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Offset|Rsvd |N|C|E|U|A|P|R|S|F|            Window             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Options (0-40 bytes, when Offset > 5)        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Data offset counts 32-bit words**, exactly like IPv4's IHL: ``(off_flags >>
12) * 4`` gives bytes. Options are present whenever it is greater than 5, and
almost every modern SYN has them - MSS, SACK-permitted, timestamps, window
scale - so a decoder that slices payload at a fixed 20 bytes is wrong on nearly
every connection setup it sees.

The flags live in the low nine bits of the same 16-bit field as the offset.

The checksum covers a pseudo-header built from the IP addresses, which is why
:func:`verify_tcp_checksum` needs them passed in. Note that segments captured on
the *sending* host usually fail it: checksum offload means the NIC fills the
field in after the capture point. Real captures are full of this, and reporting
it as corruption would be wrong.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import need, ones_complement_sum

__all__ = [
    "TCP_FLAG_NAMES",
    "TCP_MIN_HEADER_LEN",
    "TCPFlags",
    "Tcp",
    "TcpOption",
    "decode_tcp",
    "parse_tcp_options",
    "verify_tcp_checksum",
]

TCP_MIN_HEADER_LEN = 20
TCP_MAX_HEADER_LEN = 60


class TCPFlags:
    """Bit masks for the nine TCP control flags."""

    FIN = 0x001
    SYN = 0x002
    RST = 0x004
    PSH = 0x008
    ACK = 0x010
    URG = 0x020
    ECE = 0x040
    CWR = 0x080
    NS = 0x100


#: Ordered by ascending bit value, which is how Wireshark lists them - so a
#: SYN-ACK reads "SYN,ACK" rather than the other way round.
TCP_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (TCPFlags.FIN, "FIN"),
    (TCPFlags.SYN, "SYN"),
    (TCPFlags.RST, "RST"),
    (TCPFlags.PSH, "PSH"),
    (TCPFlags.ACK, "ACK"),
    (TCPFlags.URG, "URG"),
    (TCPFlags.ECE, "ECE"),
    (TCPFlags.CWR, "CWR"),
    (TCPFlags.NS, "NS"),
)

# TCP option kinds we name. The two single-byte ones terminate or pad the list
# and carry no length octet, which is the wrinkle in walking the option area.
OPTION_END_OF_LIST = 0
OPTION_NOP = 1

_OPTION_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "window scale",
    4: "SACK permitted",
    5: "SACK",
    8: "timestamps",
    28: "user timeout",
    29: "TCP-AO",
    34: "fast open",
}


@dataclass(frozen=True, slots=True)
class TcpOption:
    """One entry from the TCP option area."""

    kind: int
    data: bytes
    """Option payload, excluding the kind and length octets."""

    @property
    def name(self) -> str:
        return _OPTION_NAMES.get(self.kind, f"option {self.kind}")

    @property
    def mss(self) -> int | None:
        """Maximum segment size, when this is an MSS option."""
        if self.kind == 2 and len(self.data) == 2:
            return int.from_bytes(self.data, "big")
        return None

    @property
    def window_scale(self) -> int | None:
        """Window scale shift count, when this is a window scale option."""
        if self.kind == 3 and len(self.data) == 1:
            return self.data[0]
        return None

    def __str__(self) -> str:
        if (mss := self.mss) is not None:
            return f"mss {mss}"
        if (ws := self.window_scale) is not None:
            return f"wscale {ws}"
        return self.name


def parse_tcp_options(raw: bytes) -> tuple[TcpOption, ...]:
    """Walk the TCP option area.

    Kinds 0 (end of list) and 1 (no-op) are single bytes with no length octet;
    everything else is kind, length, then ``length - 2`` bytes of data, where
    the length *includes* those two octets. A malformed length would otherwise
    loop forever or run off the end, so both are guarded.
    """
    options: list[TcpOption] = []
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == OPTION_END_OF_LIST:
            break
        if kind == OPTION_NOP:
            options.append(TcpOption(kind=kind, data=b""))
            i += 1
            continue
        if i + 1 >= len(raw):
            break  # a length octet was promised but the buffer ended
        length = raw[i + 1]
        if length < 2 or i + length > len(raw):
            break  # malformed; stop rather than loop or over-read
        options.append(TcpOption(kind=kind, data=raw[i + 2 : i + length]))
        i += length
    return tuple(options)


@dataclass(frozen=True, slots=True)
class Tcp:
    """A decoded TCP header."""

    src_port: int
    dst_port: int
    seq: int
    ack: int

    data_offset: int
    """Header length in 32-bit words, straight from the wire."""

    header_len: int
    """Header length in bytes: ``data_offset * 4``."""

    flags: int
    """The nine control-flag bits, as one integer. Use the booleans below."""

    window: int
    checksum: int
    urgent_pointer: int
    options: tuple[TcpOption, ...] = ()

    @property
    def fin(self) -> bool:
        return bool(self.flags & TCPFlags.FIN)

    @property
    def syn(self) -> bool:
        return bool(self.flags & TCPFlags.SYN)

    @property
    def rst(self) -> bool:
        return bool(self.flags & TCPFlags.RST)

    @property
    def psh(self) -> bool:
        return bool(self.flags & TCPFlags.PSH)

    @property
    def ack_flag(self) -> bool:
        """The ACK control bit. Named to avoid colliding with :attr:`ack`."""
        return bool(self.flags & TCPFlags.ACK)

    @property
    def urg(self) -> bool:
        return bool(self.flags & TCPFlags.URG)

    @property
    def ece(self) -> bool:
        return bool(self.flags & TCPFlags.ECE)

    @property
    def cwr(self) -> bool:
        return bool(self.flags & TCPFlags.CWR)

    @property
    def ns(self) -> bool:
        return bool(self.flags & TCPFlags.NS)

    @property
    def is_syn_only(self) -> bool:
        """A connection attempt: SYN set, ACK clear."""
        return self.syn and not self.ack_flag

    @property
    def is_syn_ack(self) -> bool:
        """The other end accepting a connection."""
        return self.syn and self.ack_flag

    @property
    def flag_names(self) -> tuple[str, ...]:
        return tuple(name for bit, name in TCP_FLAG_NAMES if self.flags & bit)

    @property
    def flag_string(self) -> str:
        """Compact flag summary, e.g. ``SYN,ACK`` or ``.`` when none are set."""
        return ",".join(self.flag_names) or "."

    @property
    def has_options(self) -> bool:
        return self.data_offset > 5

    @property
    def mss(self) -> int | None:
        for opt in self.options:
            if (value := opt.mss) is not None:
                return value
        return None

    @property
    def window_scale(self) -> int | None:
        for opt in self.options:
            if (value := opt.window_scale) is not None:
                return value
        return None

    def __str__(self) -> str:
        return f"{self.src_port} > {self.dst_port} [{self.flag_string}] seq={self.seq}"


def decode_tcp(data: bytes) -> Tcp:
    """Decode the TCP header at the start of ``data``.

    Args:
        data: Buffer positioned at the first byte of the TCP header, i.e. the
            IP payload.

    Returns:
        The decoded header. Slice ``data[result.header_len:]`` for the segment
        payload.

    Raises:
        Truncated: The buffer is shorter than the header claims to be.
    """
    need(data, TCP_MIN_HEADER_LEN, "TCP header")

    src_port, dst_port, seq, ack, off_flags, window, checksum, urgent = struct.unpack(
        "!HHIIHHHH", data[:TCP_MIN_HEADER_LEN]
    )

    data_offset = off_flags >> 12  # in 32-bit words
    header_len = data_offset * 4
    flags = off_flags & 0x01FF  # the low nine bits

    options: tuple[TcpOption, ...] = ()
    if header_len > TCP_MIN_HEADER_LEN:
        need(data, header_len, "TCP header with options")
        options = parse_tcp_options(data[TCP_MIN_HEADER_LEN:header_len])
    elif header_len < TCP_MIN_HEADER_LEN:
        # A data offset under 5 cannot describe a real header. Rather than
        # reject the segment, report the minimum so the caller still gets the
        # ports and flags - which is what the flow table actually needs.
        header_len = TCP_MIN_HEADER_LEN

    return Tcp(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        header_len=header_len,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent,
        options=options,
    )


def verify_tcp_checksum(segment: bytes, src: bytes, dst: bytes, *, ipv6: bool = False) -> bool:
    """Check a TCP checksum, which covers an IP pseudo-header.

    Args:
        segment: The complete TCP segment, header and payload.
        src: Source IP address as raw bytes (4 for IPv4, 16 for IPv6).
        dst: Destination IP address as raw bytes.
        ipv6: Whether to build an IPv6-shaped pseudo-header.

    Returns:
        True when the checksum is correct. Expect False for segments captured
        on the sending host, where checksum offload leaves the field unfilled.
    """
    length = len(segment)
    if ipv6:
        pseudo = src + dst + struct.pack("!IBBBB", length, 0, 0, 0, 6)
    else:
        pseudo = src + dst + struct.pack("!BBH", 0, 6, length)
    return ones_complement_sum(pseudo + segment) == 0xFFFF
