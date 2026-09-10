"""Ethernet II frame decoding, including 802.1Q VLAN tags.

An Ethernet II header is 14 bytes::

    | dst MAC (6) | src MAC (6) | ethertype (2) | payload ...
    0             6             12              14

with everything big-endian, like the rest of the wire.

Two wrinkles this decoder handles:

*VLAN tags.* When the two bytes at offset 12 hold a TPID (0x8100 and friends), a
four-byte tag follows and the *real* ethertype sits four bytes further on. Tags
can stack, so we loop. :attr:`Ethernet.header_len` is where the payload actually
starts, and callers should slice by it rather than by a hardcoded 14.

*802.3 with LLC.* Historically the same two bytes were a length field. The
convention is that a value of 1500 or less is a length and 1536 (0x0600) or more
is an ethertype. We flag that case instead of dispatching a bogus protocol; LLC
and SNAP payloads are out of scope, and the README says so.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from netsniff.decode.common import mac_to_str, need
from netsniff.decode.vlan import VlanTag, decode_vlan_tag, is_vlan_tpid

__all__ = [
    "ETHERNET_HEADER_LEN",
    "ETHERTYPE_ARP",
    "ETHERTYPE_IPV4",
    "ETHERTYPE_IPV6",
    "ETHERTYPE_NAMES",
    "Ethernet",
    "decode_ethernet",
    "ethertype_name",
]

ETHERNET_HEADER_LEN = 14

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD

#: Below this, the field is an 802.3 length, not an ethertype.
ETHERTYPE_MIN = 0x0600

#: Guard against a crafted frame with an unbounded run of VLAN tags.
MAX_VLAN_TAGS = 4

ETHERTYPE_NAMES: dict[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x0842: "Wake-on-LAN",
    0x22F3: "TRILL",
    0x8035: "RARP",
    0x8100: "802.1Q",
    0x86DD: "IPv6",
    0x8808: "Ethernet flow control",
    0x8809: "LACP",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE discovery",
    0x8864: "PPPoE session",
    0x88A8: "802.1ad QinQ",
    0x88CC: "LLDP",
    0x88E5: "MACsec",
    0x88F7: "PTP",
    0x9000: "Ethernet loopback",
}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def ethertype_name(value: int) -> str:
    """Readable name for an ethertype, falling back to hex."""
    return ETHERTYPE_NAMES.get(value, f"0x{value:04x}")


@dataclass(frozen=True, slots=True)
class Ethernet:
    """A decoded Ethernet II header."""

    dst: str
    """Destination MAC, ``aa:bb:cc:dd:ee:ff``."""

    src: str
    """Source MAC."""

    ethertype: int
    """The *effective* ethertype: the one after any VLAN tags were stripped.

    For an 802.3 frame this is the length field instead; check
    :attr:`is_ethernet_ii` before dispatching on it.
    """

    header_len: int
    """Total header size in bytes, 14 plus 4 per VLAN tag.

    Slice the payload at this offset. Using a hardcoded 14 on a tagged frame is
    the classic silent bug this attribute exists to prevent.
    """

    vlan_tags: tuple[VlanTag, ...] = field(default=())
    """Outermost tag first. Empty for an untagged frame."""

    @property
    def is_ethernet_ii(self) -> bool:
        """False for an 802.3 frame, where the field is a length not a type."""
        return self.ethertype >= ETHERTYPE_MIN

    @property
    def ethertype_name(self) -> str:
        if not self.is_ethernet_ii:
            return f"802.3 length {self.ethertype}"
        return ethertype_name(self.ethertype)

    @property
    def is_tagged(self) -> bool:
        return bool(self.vlan_tags)

    @property
    def vlan_id(self) -> int | None:
        """The innermost VLAN ID, or None when untagged."""
        return self.vlan_tags[-1].vid if self.vlan_tags else None

    @property
    def is_broadcast(self) -> bool:
        return self.dst == BROADCAST_MAC

    @property
    def is_multicast(self) -> bool:
        """True when the low bit of the first destination octet is set.

        Broadcast is a special case of multicast by this rule, and that is
        deliberate - it is how the hardware sees it.
        """
        return bool(int(self.dst[:2], 16) & 0x01)

    @property
    def src_is_locally_administered(self) -> bool:
        """True when the source MAC is not a manufacturer-assigned address.

        The second-least-significant bit of the first octet marks an address as
        locally administered: a VM, a container veth, or a randomised MAC.
        """
        return bool(int(self.src[:2], 16) & 0x02)

    def __str__(self) -> str:
        tags = "".join(f" [{t}]" for t in self.vlan_tags)
        return f"{self.src} > {self.dst}{tags} {self.ethertype_name}"


def decode_ethernet(data: bytes) -> Ethernet:
    """Decode the Ethernet header at the start of ``data``.

    Args:
        data: Raw link-layer bytes, i.e. :attr:`netsniff.capture.base.Frame.data`.

    Returns:
        The decoded header. Slice ``data[result.header_len:]`` for the payload.

    Raises:
        Truncated: The buffer is shorter than the header it describes.
    """
    need(data, ETHERNET_HEADER_LEN, "Ethernet header")

    dst_raw, src_raw, ethertype = struct.unpack("!6s6sH", data[:ETHERNET_HEADER_LEN])
    offset = ETHERNET_HEADER_LEN

    tags: list[VlanTag] = []
    while is_vlan_tpid(ethertype) and len(tags) < MAX_VLAN_TAGS:
        # The tag's two TCI bytes sit at the current offset; the next ethertype
        # (or the next TPID, for stacked tags) is the two bytes after that.
        need(data, offset + 2, "802.1Q TCI")
        tags.append(decode_vlan_tag(data[offset:], tpid=ethertype))
        offset += 2
        need(data, offset + 2, "ethertype after 802.1Q tag")
        (ethertype,) = struct.unpack("!H", data[offset : offset + 2])
        offset += 2

    return Ethernet(
        dst=mac_to_str(dst_raw),
        src=mac_to_str(src_raw),
        ethertype=ethertype,
        header_len=offset,
        vlan_tags=tuple(tags),
    )
