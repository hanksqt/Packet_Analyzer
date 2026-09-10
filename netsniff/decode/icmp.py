r"""ICMP and ICMPv6 message decoding.

Every ICMP message starts with the same four bytes, and what follows depends
entirely on the type::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Rest of header (type-specific)             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Two shapes account for nearly everything you see in a capture:

*Echo request and reply* (types 8 and 0) put a 16-bit identifier and a 16-bit
sequence number in the rest-of-header, which is how ``ping`` matches replies to
requests.

*Error messages* (destination unreachable, time exceeded, and friends) quote the
IP header and first eight bytes of the datagram that caused them. Those eight
bytes contain the original source and destination ports, which is what lets you
attribute an unreachable back to the flow that provoked it.

ICMPv6 reuses the layout with a different number space - type 128 is echo
request there, not 8 - so the type names are kept in separate tables.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import need, verify_checksum

__all__ = [
    "ICMPV6_TYPE_NAMES",
    "ICMP_HEADER_LEN",
    "ICMP_TYPE_NAMES",
    "Icmp",
    "decode_icmp",
    "icmp_type_name",
]

ICMP_HEADER_LEN = 4

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_TYPE_NAMES: dict[int, str] = {
    0: "echo reply",
    3: "destination unreachable",
    4: "source quench",
    5: "redirect",
    8: "echo request",
    9: "router advertisement",
    10: "router solicitation",
    11: "time exceeded",
    12: "parameter problem",
    13: "timestamp request",
    14: "timestamp reply",
    17: "address mask request",
    18: "address mask reply",
}

ICMPV6_TYPE_NAMES: dict[int, str] = {
    1: "destination unreachable",
    2: "packet too big",
    3: "time exceeded",
    4: "parameter problem",
    128: "echo request",
    129: "echo reply",
    130: "multicast listener query",
    133: "router solicitation",
    134: "router advertisement",
    135: "neighbor solicitation",
    136: "neighbor advertisement",
    137: "redirect",
}

# Codes worth naming, per type. Destination unreachable is the one people
# actually read in a capture.
_CODE_NAMES: dict[tuple[int, int], str] = {
    (3, 0): "net unreachable",
    (3, 1): "host unreachable",
    (3, 2): "protocol unreachable",
    (3, 3): "port unreachable",
    (3, 4): "fragmentation needed but DF set",
    (3, 9): "net administratively prohibited",
    (3, 10): "host administratively prohibited",
    (3, 13): "communication administratively filtered",
    (11, 0): "TTL exceeded in transit",
    (11, 1): "fragment reassembly time exceeded",
    (5, 0): "redirect for network",
    (5, 1): "redirect for host",
}

_ECHO_TYPES_V4 = frozenset({ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY})
_ECHO_TYPES_V6 = frozenset({128, 129})

#: Types that quote the datagram which triggered them.
_ERROR_TYPES_V4 = frozenset({3, 4, 5, 11, 12})
_ERROR_TYPES_V6 = frozenset({1, 2, 3, 4})


def icmp_type_name(icmp_type: int, *, v6: bool = False) -> str:
    """Readable name for an ICMP or ICMPv6 type."""
    table = ICMPV6_TYPE_NAMES if v6 else ICMP_TYPE_NAMES
    return table.get(icmp_type, f"type {icmp_type}")


@dataclass(frozen=True, slots=True)
class Icmp:
    """A decoded ICMP or ICMPv6 message."""

    type: int
    code: int
    checksum: int

    rest: bytes
    """The four type-specific header bytes, before any payload."""

    payload: bytes
    """Everything after the eight-byte header. For an error message this is the
    quoted original datagram; for an echo it is the ping data."""

    v6: bool = False
    checksum_valid: bool | None = None
    """Whether the checksum verifies. None for ICMPv6, whose checksum covers an
    IPv6 pseudo-header we would need the addresses to build."""

    @property
    def type_name(self) -> str:
        return icmp_type_name(self.type, v6=self.v6)

    @property
    def code_name(self) -> str | None:
        """Name for this type/code pair, when there is a useful one."""
        if self.v6:
            return None
        return _CODE_NAMES.get((self.type, self.code))

    @property
    def is_echo(self) -> bool:
        types = _ECHO_TYPES_V6 if self.v6 else _ECHO_TYPES_V4
        return self.type in types

    @property
    def is_echo_request(self) -> bool:
        return self.type == (128 if self.v6 else ICMP_ECHO_REQUEST)

    @property
    def is_echo_reply(self) -> bool:
        return self.type == (129 if self.v6 else ICMP_ECHO_REPLY)

    @property
    def is_error(self) -> bool:
        """True for messages that quote the datagram that caused them."""
        types = _ERROR_TYPES_V6 if self.v6 else _ERROR_TYPES_V4
        return self.type in types

    @property
    def echo_id(self) -> int | None:
        """Echo identifier, which ping uses to match replies to requests."""
        if not self.is_echo or len(self.rest) < 4:
            return None
        return int.from_bytes(self.rest[:2], "big")

    @property
    def echo_seq(self) -> int | None:
        """Echo sequence number."""
        if not self.is_echo or len(self.rest) < 4:
            return None
        return int.from_bytes(self.rest[2:4], "big")

    def __str__(self) -> str:
        text = self.type_name
        if (code := self.code_name) is not None:
            text = f"{text} ({code})"
        if self.is_echo:
            text = f"{text} id={self.echo_id} seq={self.echo_seq}"
        return text


def decode_icmp(data: bytes, *, v6: bool = False) -> Icmp:
    """Decode the ICMP message at the start of ``data``.

    Args:
        data: Buffer positioned at the ICMP type byte.
        v6: Decode as ICMPv6, which uses a different type number space.

    Returns:
        The decoded message.

    Raises:
        Truncated: Fewer than four bytes are available.
    """
    need(data, ICMP_HEADER_LEN, "ICMP header")

    icmp_type, code, checksum = struct.unpack("!BBH", data[:ICMP_HEADER_LEN])

    # The rest-of-header is four more bytes, but a short capture may not hold
    # them; take what is there rather than raising, since type and code alone
    # are already useful.
    rest = data[ICMP_HEADER_LEN : ICMP_HEADER_LEN + 4]
    payload = data[ICMP_HEADER_LEN + 4 :]

    # ICMPv4's checksum covers the message and nothing else, so it verifies
    # standalone. ICMPv6 folds in an IPv6 pseudo-header, which we do not have
    # here; that is reported as unknown rather than as a failure.
    checksum_valid = None if v6 else verify_checksum(data)

    return Icmp(
        type=icmp_type,
        code=code,
        checksum=checksum,
        rest=rest,
        payload=payload,
        v6=v6,
        checksum_valid=checksum_valid,
    )
