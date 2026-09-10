r"""IPv6 header decoding, including the extension header chain.

The base header is a fixed 40 bytes, which is simpler than IPv4 - there is no
IHL, no options field, and no header checksum::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version| Traffic Class |             Flow Label                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Payload Length        |  Next Header  |   Hop Limit   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Source Address (16 bytes)                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Destination Address (16 bytes)               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The variability moved somewhere else instead. ``next_header`` plays the role
IPv4's ``protocol`` does, but it may name an *extension header* rather than a
transport protocol, and each extension header names the next one in turn. So
finding the actual transport protocol means walking a linked list::

    base(next=Hop-by-Hop) -> Hop-by-Hop(next=Routing) -> Routing(next=TCP) -> TCP

:func:`decode_ipv6` walks that chain and reports the transport protocol it ends
on, so callers dispatch on :attr:`IPv6.protocol` exactly the way they do for
IPv4. The chain is what makes IPv6 firewalling awkward in practice, so the walk
is bounded: a crafted packet must not be able to make us loop.

Two limits, stated here and in the README. The chain stops at an ESP header,
because what follows it is encrypted. And ``payload_length`` of 0 means a jumbo
payload whose real length lives in a hop-by-hop option; those are vanishingly
rare outside HPC fabrics and are not reassembled here.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import DecodeError, ip6_to_str, need

__all__ = [
    "IPV6_HEADER_LEN",
    "ExtensionHeader",
    "IPv6",
    "decode_ipv6",
]

IPV6_HEADER_LEN = 40

#: Beyond this many extension headers we stop walking. Real traffic uses one or
#: two; a long chain is either broken or an evasion attempt.
MAX_EXTENSION_HEADERS = 8

NEXT_HEADER_HOPOPT = 0
NEXT_HEADER_ROUTING = 43
NEXT_HEADER_FRAGMENT = 44
NEXT_HEADER_ESP = 50
NEXT_HEADER_AH = 51
NEXT_HEADER_NONE = 59
NEXT_HEADER_DSTOPTS = 60
NEXT_HEADER_MOBILITY = 135
NEXT_HEADER_HIP = 139
NEXT_HEADER_SHIM6 = 140

#: Extension headers shaped ``next(1) | len(1) | data``, where len counts
#: 8-octet units *not* including the first 8 bytes.
_TLV_EXTENSIONS = frozenset(
    {
        NEXT_HEADER_HOPOPT,
        NEXT_HEADER_ROUTING,
        NEXT_HEADER_DSTOPTS,
        NEXT_HEADER_MOBILITY,
        NEXT_HEADER_HIP,
        NEXT_HEADER_SHIM6,
    }
)

_EXTENSION_NAMES = {
    NEXT_HEADER_HOPOPT: "hop-by-hop options",
    NEXT_HEADER_ROUTING: "routing",
    NEXT_HEADER_FRAGMENT: "fragment",
    NEXT_HEADER_ESP: "ESP",
    NEXT_HEADER_AH: "authentication",
    NEXT_HEADER_NONE: "no next header",
    NEXT_HEADER_DSTOPTS: "destination options",
    NEXT_HEADER_MOBILITY: "mobility",
    NEXT_HEADER_HIP: "host identity",
    NEXT_HEADER_SHIM6: "shim6",
}

#: Everything the walk knows how to skip past.
EXTENSION_HEADERS = frozenset(_EXTENSION_NAMES)


@dataclass(frozen=True, slots=True)
class ExtensionHeader:
    """One link in the extension header chain."""

    type: int
    length: int
    """Size of this extension header in bytes."""

    @property
    def name(self) -> str:
        return _EXTENSION_NAMES.get(self.type, f"extension {self.type}")

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class IPv6:
    """A decoded IPv6 header, with its extension chain already walked."""

    version: int
    traffic_class: int
    """The full 8-bit field. :attr:`dscp` and :attr:`ecn` split it."""

    flow_label: int

    payload_length: int
    """Everything after the 40-byte base header, extension headers included.
    Zero means a jumbo payload, which is not handled here."""

    next_header: int
    """The value in the base header, which may name an extension header.
    :attr:`protocol` is what you want for dispatch."""

    hop_limit: int
    src: str
    dst: str

    header_len: int
    """Base header plus every extension header walked: where the transport
    header actually starts."""

    protocol: int
    """The transport protocol at the end of the chain: 6, 17, 58 and so on.

    Equals :attr:`next_header` when there are no extension headers, which is the
    common case.
    """

    extension_headers: tuple[ExtensionHeader, ...] = ()
    payload_len: int = 0
    """Transport payload bytes available, clamped to what was captured."""

    truncated_chain: bool = False
    """True when the extension chain ran past the captured bytes or hit the
    walk limit, so :attr:`protocol` may not be the real transport protocol."""

    @property
    def dscp(self) -> int:
        """Top 6 bits of the traffic class, same meaning as IPv4's DSCP."""
        return self.traffic_class >> 2

    @property
    def ecn(self) -> int:
        return self.traffic_class & 0x03

    @property
    def protocol_name(self) -> str:
        from netsniff.decode.ipv4 import ip_protocol_name

        return ip_protocol_name(self.protocol)

    @property
    def has_extension_headers(self) -> bool:
        return bool(self.extension_headers)

    @property
    def is_fragment(self) -> bool:
        return any(e.type == NEXT_HEADER_FRAGMENT for e in self.extension_headers)

    @property
    def is_encrypted(self) -> bool:
        """True when the chain ended at ESP, so the transport header is opaque."""
        return self.protocol == NEXT_HEADER_ESP

    def __str__(self) -> str:
        chain = "".join(f" [{e}]" for e in self.extension_headers)
        return f"{self.src} > {self.dst}{chain} {self.protocol_name} hlim={self.hop_limit}"


def _extension_header_length(kind: int, data: bytes) -> int | None:
    """Size in bytes of the extension header at the start of ``data``.

    Returns None when the length cannot be determined - a short buffer, or a
    header type whose contents are opaque.
    """
    if kind == NEXT_HEADER_FRAGMENT:
        return 8  # always exactly 8 bytes
    if kind in _TLV_EXTENSIONS:
        if len(data) < 2:
            return None
        return (data[1] + 1) * 8  # length excludes the first 8 octets
    if kind == NEXT_HEADER_AH:
        if len(data) < 2:
            return None
        return (data[1] + 2) * 4  # AH counts 4-octet units, and excludes 8
    return None  # ESP and anything unrecognised: stop here


def decode_ipv6(data: bytes) -> IPv6:
    """Decode the IPv6 header at the start of ``data``, walking extensions.

    Args:
        data: Buffer positioned at the first byte of the IPv6 header.

    Returns:
        The decoded header. Slice ``data[result.header_len:]`` for the transport
        header - that offset already accounts for every extension header.

    Raises:
        Truncated: Fewer than 40 bytes are available.
        DecodeError: The version field is not 6.
    """
    need(data, IPV6_HEADER_LEN, "IPv6 header")

    ver_tc_flow, payload_length, next_header, hop_limit = struct.unpack("!IHBB", data[:8])

    version = ver_tc_flow >> 28
    if version != 6:
        raise DecodeError(f"not an IPv6 header: version field is {version}, expected 6")

    src = ip6_to_str(data[8:24])
    dst = ip6_to_str(data[24:40])

    # Walk the extension chain to find the real transport protocol.
    chain: list[ExtensionHeader] = []
    offset = IPV6_HEADER_LEN
    protocol = next_header
    truncated_chain = False

    while protocol in EXTENSION_HEADERS and protocol != NEXT_HEADER_NONE:
        rest = data[offset:]
        if len(rest) < 2:
            truncated_chain = True
            break

        length = _extension_header_length(protocol, rest)
        if length is None or length <= 0:
            # ESP, or something we cannot measure. Stop and report where we got
            # to rather than guessing at an offset.
            break
        if offset + length > len(data):
            truncated_chain = True
            break

        chain.append(ExtensionHeader(type=protocol, length=length))
        protocol = rest[0]  # each extension names the next
        offset += length

        if len(chain) >= MAX_EXTENSION_HEADERS:
            truncated_chain = True
            break

    available = len(data) - offset
    # payload_length 0 means a jumbogram (or an offloaded send); fall back to
    # whatever we actually hold. Otherwise subtract the extension headers we
    # already walked past, since payload_length counts those too.
    extension_bytes = offset - IPV6_HEADER_LEN
    claimed = available if payload_length == 0 else payload_length - extension_bytes

    return IPv6(
        version=version,
        traffic_class=(ver_tc_flow >> 20) & 0xFF,
        flow_label=ver_tc_flow & 0xFFFFF,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src=src,
        dst=dst,
        header_len=offset,
        protocol=protocol,
        extension_headers=tuple(chain),
        payload_len=max(0, min(claimed, available)),
        truncated_chain=truncated_chain,
    )
