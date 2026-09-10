"""IPv4 header decoding.

The IPv4 header is variable length, which is the first thing to get right::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |DSCP   |ECN|          Total Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|     Fragment Offset     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |        Header Checksum        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options (0-40 bytes, when IHL > 5)         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**IHL counts 32-bit words, not bytes.** ``header_len = (byte0 & 0x0F) * 4``.
Options are present whenever IHL > 5, and slicing the payload at a fixed 20
bytes breaks on every packet that has them.

The three flag bits and the 13-bit fragment offset share one 16-bit field, and
the offset counts *8-byte* units, not bytes.

The header checksum is verified here as a feature: sum the header as 16-bit
words in one's complement and the result should be all ones. Note that a packet
captured on the sending host may legitimately fail this, because checksum
offload leaves the field for the NIC to fill in - see :attr:`IPv4.checksum_offloaded`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import DecodeError, ip4_to_str, need, verify_checksum

__all__ = [
    "IPPROTO_ICMP",
    "IPPROTO_TCP",
    "IPPROTO_UDP",
    "IPV4_MIN_HEADER_LEN",
    "IP_PROTOCOL_NAMES",
    "IPv4",
    "decode_ipv4",
    "ip_protocol_name",
]

IPV4_MIN_HEADER_LEN = 20
IPV4_MAX_HEADER_LEN = 60

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

IP_PROTOCOL_NAMES: dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
    137: "MPLS-in-IP",
}


def ip_protocol_name(value: int) -> str:
    """Readable name for an IP protocol number, falling back to the number."""
    return IP_PROTOCOL_NAMES.get(value, f"proto {value}")


@dataclass(frozen=True, slots=True)
class IPv4:
    """A decoded IPv4 header."""

    version: int
    ihl: int
    """Header length in 32-bit words, straight from the wire. Use
    :attr:`header_len` for bytes."""

    header_len: int
    """Header length in bytes: ``ihl * 4``. Slice the payload at this offset."""

    dscp: int
    """Differentiated Services Code Point, the top 6 bits of the ToS byte."""

    ecn: int
    """Explicit Congestion Notification, the low 2 bits of the ToS byte."""

    total_length: int
    """Header plus payload, as claimed by the sender. May be 0 under
    segmentation offload, and may exceed what was captured."""

    identification: int
    reserved_flag: bool
    dont_fragment: bool
    more_fragments: bool

    fragment_offset: int
    """Offset of this fragment's payload in 8-byte units, not bytes."""

    ttl: int
    protocol: int
    checksum: int
    checksum_valid: bool
    src: str
    dst: str

    options: bytes
    """Raw option bytes, empty unless IHL > 5. Not parsed further."""

    payload_len: int
    """Payload bytes available, clamped to what was actually captured."""

    @property
    def protocol_name(self) -> str:
        return ip_protocol_name(self.protocol)

    @property
    def has_options(self) -> bool:
        return self.ihl > 5

    @property
    def is_fragment(self) -> bool:
        """True for any packet that is part of a fragmented datagram."""
        return self.more_fragments or self.fragment_offset > 0

    @property
    def is_first_fragment(self) -> bool:
        """True when this fragment carries the transport header.

        Later fragments start mid-payload, so decoding a TCP or UDP header out
        of them would be nonsense.
        """
        return self.fragment_offset == 0

    @property
    def fragment_offset_bytes(self) -> int:
        return self.fragment_offset * 8

    @property
    def checksum_offloaded(self) -> bool:
        """True when the checksum looks like the NIC was meant to fill it in.

        Captures taken on a sending host routinely contain a zero checksum,
        because the kernel hands the packet to hardware that computes it after
        the capture point. Reporting that as "corrupt" would be wrong.
        """
        return self.checksum == 0

    def __str__(self) -> str:
        frag = f" frag+{self.fragment_offset_bytes}" if self.is_fragment else ""
        return f"{self.src} > {self.dst} {self.protocol_name} ttl={self.ttl}{frag}"


def decode_ipv4(data: bytes) -> IPv4:
    """Decode the IPv4 header at the start of ``data``.

    Args:
        data: Buffer positioned at the first byte of the IPv4 header, i.e. the
            Ethernet payload.

    Returns:
        The decoded header. Slice ``data[result.header_len:]`` for the payload.

    Raises:
        Truncated: The buffer is shorter than the header claims to be.
        DecodeError: The version is not 4, or IHL claims a header under the
            20-byte minimum.
    """
    need(data, IPV4_MIN_HEADER_LEN, "IPv4 header")

    (
        ver_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        src_raw,
        dst_raw,
    ) = struct.unpack("!BBHHHBBH4s4s", data[:IPV4_MIN_HEADER_LEN])

    version = ver_ihl >> 4
    if version != 4:
        raise DecodeError(f"not an IPv4 header: version field is {version}, expected 4")

    ihl = ver_ihl & 0x0F
    header_len = ihl * 4  # IHL counts 32-bit words
    if header_len < IPV4_MIN_HEADER_LEN:
        raise DecodeError(
            f"IPv4 IHL is {ihl} ({header_len} bytes), below the {IPV4_MIN_HEADER_LEN} "
            f"byte minimum"
        )

    # Options only exist when IHL > 5, but we must have the bytes to read them.
    need(data, header_len, "IPv4 header with options")
    options = data[IPV4_MIN_HEADER_LEN:header_len]

    # Three flag bits then a 13-bit offset, sharing one 16-bit field.
    reserved_flag = bool(flags_frag & 0x8000)
    dont_fragment = bool(flags_frag & 0x4000)
    more_fragments = bool(flags_frag & 0x2000)
    fragment_offset = flags_frag & 0x1FFF

    # How much payload is actually here. total_length is what the sender claimed;
    # a snapped capture holds less, and a segmentation-offloaded packet reports 0.
    available = len(data) - header_len
    if total_length == 0:
        payload_len = available
    else:
        payload_len = max(0, min(total_length - header_len, available))

    return IPv4(
        version=version,
        ihl=ihl,
        header_len=header_len,
        dscp=dscp_ecn >> 2,
        ecn=dscp_ecn & 0x03,
        total_length=total_length,
        identification=identification,
        reserved_flag=reserved_flag,
        dont_fragment=dont_fragment,
        more_fragments=more_fragments,
        fragment_offset=fragment_offset,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        checksum_valid=verify_checksum(data[:header_len]),
        src=ip4_to_str(src_raw),
        dst=ip4_to_str(dst_raw),
        options=options,
        payload_len=payload_len,
    )
