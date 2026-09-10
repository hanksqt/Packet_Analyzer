r"""ARP packet decoding.

ARP is 28 bytes for the usual IPv4-over-Ethernet case::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Hardware Type (1=Eth)     |   Protocol Type (0x0800=IPv4)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    HLEN=6     |    PLEN=4     |    Operation (1=req, 2=reply)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Sender Hardware Address (HLEN bytes)               |
    |            Sender Protocol Address (PLEN bytes)               |
    |            Target Hardware Address (HLEN bytes)               |
    |            Target Protocol Address (PLEN bytes)               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The four address fields are *not* fixed width: their sizes come from the HLEN
and PLEN bytes in the header. In practice they are always 6 and 4, but hardcoding
that is the kind of shortcut that turns into a parsing bug the first time
something unusual appears, so this decoder slices by the declared lengths and
only formats an address as a MAC or a dotted quad when the length agrees.

ARP frames are usually padded, because 28 bytes of ARP plus a 14-byte Ethernet
header is 42, under the 60-byte minimum frame size. The padding is not part of
the packet and is ignored.

Two patterns worth naming, both visible in :attr:`Arp.is_gratuitous` and
:attr:`Arp.is_probe`: a gratuitous ARP announces an address rather than asking
about one (sender and target protocol addresses match), and an ARP probe checks
whether an address is free before claiming it (sender protocol address is all
zeros). A burst of unsolicited replies rewriting a gateway's mapping is what ARP
spoofing looks like on the wire.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import ip4_to_str, mac_to_str, need

__all__ = [
    "ARP_FIXED_LEN",
    "ARP_OPERATION_NAMES",
    "Arp",
    "decode_arp",
]

#: The fixed part: htype, ptype, hlen, plen, oper. Addresses follow.
ARP_FIXED_LEN = 8

#: Total length of a standard IPv4-over-Ethernet ARP packet.
ARP_IPV4_ETHERNET_LEN = 28

HARDWARE_ETHERNET = 1
PROTOCOL_IPV4 = 0x0800

ARP_REQUEST = 1
ARP_REPLY = 2
RARP_REQUEST = 3
RARP_REPLY = 4

ARP_OPERATION_NAMES: dict[int, str] = {
    1: "request",
    2: "reply",
    3: "RARP request",
    4: "RARP reply",
    5: "DRARP request",
    6: "DRARP reply",
    7: "DRARP error",
    8: "InARP request",
    9: "InARP reply",
}

_HARDWARE_NAMES = {1: "Ethernet", 6: "IEEE 802", 15: "Frame Relay", 20: "serial line"}

_UNSPECIFIED_IPV4 = "0.0.0.0"


def _format_hardware(raw: bytes) -> str:
    return mac_to_str(raw) if len(raw) == 6 else raw.hex()


def _format_protocol(raw: bytes) -> str:
    return ip4_to_str(raw) if len(raw) == 4 else raw.hex()


@dataclass(frozen=True, slots=True)
class Arp:
    """A decoded ARP packet."""

    hardware_type: int
    protocol_type: int
    hardware_len: int
    protocol_len: int
    operation: int

    sender_hardware: str
    """Sender MAC, or hex when the hardware length is not 6."""

    sender_protocol: str
    """Sender IPv4 address, or hex when the protocol length is not 4."""

    target_hardware: str
    target_protocol: str

    length: int
    """Bytes of actual ARP packet, excluding any Ethernet padding."""

    @property
    def operation_name(self) -> str:
        return ARP_OPERATION_NAMES.get(self.operation, f"operation {self.operation}")

    @property
    def hardware_type_name(self) -> str:
        return _HARDWARE_NAMES.get(self.hardware_type, f"hardware {self.hardware_type}")

    @property
    def is_request(self) -> bool:
        return self.operation == ARP_REQUEST

    @property
    def is_reply(self) -> bool:
        return self.operation == ARP_REPLY

    @property
    def is_ipv4_over_ethernet(self) -> bool:
        """The standard case, which is what the address formatting assumes."""
        return (
            self.hardware_type == HARDWARE_ETHERNET
            and self.protocol_type == PROTOCOL_IPV4
            and self.hardware_len == 6
            and self.protocol_len == 4
        )

    @property
    def is_gratuitous(self) -> bool:
        """An announcement rather than a question: sender and target IPs match.

        Legitimate after an address change or a failover. Also the shape an ARP
        spoofing attempt takes.
        """
        return (
            self.sender_protocol == self.target_protocol
            and self.sender_protocol != _UNSPECIFIED_IPV4
        )

    @property
    def is_probe(self) -> bool:
        """A duplicate-address check before claiming an address (RFC 5227)."""
        return self.sender_protocol == _UNSPECIFIED_IPV4

    def __str__(self) -> str:
        if self.is_request:
            return f"who-has {self.target_protocol} tell {self.sender_protocol}"
        if self.is_reply:
            return f"{self.sender_protocol} is-at {self.sender_hardware}"
        return f"ARP {self.operation_name}"


def decode_arp(data: bytes) -> Arp:
    """Decode the ARP packet at the start of ``data``.

    Args:
        data: Buffer positioned at the first byte of the ARP packet, i.e. the
            Ethernet payload. Trailing padding is ignored.

    Returns:
        The decoded packet.

    Raises:
        Truncated: The buffer is shorter than the address lengths require.
    """
    need(data, ARP_FIXED_LEN, "ARP header")

    hardware_type, protocol_type, hardware_len, protocol_len, operation = struct.unpack(
        "!HHBBH", data[:ARP_FIXED_LEN]
    )

    # Address widths come from the packet, not from an assumption.
    total = ARP_FIXED_LEN + 2 * hardware_len + 2 * protocol_len
    need(data, total, f"ARP addresses ({hardware_len}-byte hardware, {protocol_len}-byte protocol)")

    offset = ARP_FIXED_LEN
    sender_hardware = data[offset : offset + hardware_len]
    offset += hardware_len
    sender_protocol = data[offset : offset + protocol_len]
    offset += protocol_len
    target_hardware = data[offset : offset + hardware_len]
    offset += hardware_len
    target_protocol = data[offset : offset + protocol_len]

    return Arp(
        hardware_type=hardware_type,
        protocol_type=protocol_type,
        hardware_len=hardware_len,
        protocol_len=protocol_len,
        operation=operation,
        sender_hardware=_format_hardware(sender_hardware),
        sender_protocol=_format_protocol(sender_protocol),
        target_hardware=_format_hardware(target_hardware),
        target_protocol=_format_protocol(target_protocol),
        length=total,
    )
