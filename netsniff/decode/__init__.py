"""The layered decode pipeline.

:func:`decode_frame` takes one :class:`~netsniff.capture.base.Frame` and peels
it, dispatching at each layer on the field the previous layer provides::

        Ethernet  --ethertype-->  IPv4 / IPv6 / ARP
                                    |
                                    +--protocol / next_header-->  TCP / UDP / ICMP
                                                                    |
                                                                    +--port-->  app hint

Every individual decoder is strict: it raises :class:`~netsniff.decode.common.
DecodeError` rather than guessing when a buffer is too short or a field makes no
sense. This function is where that strictness is turned into tolerance. It
catches those errors and records them on the result, so one malformed packet in
a capture of a million produces a :class:`DecodedPacket` with the layers that
did decode plus a note about the one that did not - and never stops the run.

That split is deliberate. Strict decoders are testable; a tolerant pipeline is
usable. Trying to get both properties out of one piece of code gets you neither.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netsniff.capture.base import Frame
from netsniff.decode.arp import Arp, decode_arp
from netsniff.decode.common import DecodeError, Truncated, format_endpoint
from netsniff.decode.ethernet import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    Ethernet,
    decode_ethernet,
)
from netsniff.decode.icmp import Icmp, decode_icmp
from netsniff.decode.ipv4 import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPv4, decode_ipv4
from netsniff.decode.ipv6 import IPv6, decode_ipv6
from netsniff.decode.tcp import Tcp, decode_tcp
from netsniff.decode.udp import Udp, decode_udp
from netsniff.decode.vlan import VlanTag

__all__ = [
    "DecodeError",
    "DecodedPacket",
    "NetworkLayer",
    "TransportLayer",
    "Truncated",
    "decode_frame",
]

IPPROTO_ICMPV6 = 58

NetworkLayer = IPv4 | IPv6 | Arp
TransportLayer = Tcp | Udp | Icmp


@dataclass(frozen=True, slots=True)
class DecodedPacket:
    """Everything that could be decoded from one frame.

    Layers that were absent or undecodable are ``None``, and :attr:`errors`
    explains why. A packet with an error is still worth counting: its Ethernet
    and IP layers usually decoded fine.
    """

    frame: Frame

    ethernet: Ethernet | None = None
    network: NetworkLayer | None = None
    transport: TransportLayer | None = None

    payload: bytes = b""
    """Application-layer bytes: whatever followed the transport header."""

    app: object | None = None
    """Best-effort application-layer hint, or None. See ``decode.apphint``."""

    errors: tuple[str, ...] = field(default=())
    """One entry per layer that failed, most-recent last."""

    # -- convenience accessors, used by the analysis layer ------------------

    @property
    def ok(self) -> bool:
        """True when nothing failed to decode."""
        return not self.errors

    @property
    def timestamp(self) -> float:
        return self.frame.ts

    @property
    def length(self) -> int:
        """Frame length on the wire, which is what byte counts should use.

        Not the captured length: a snapped capture must not make a host look
        like it sent less traffic than it did.
        """
        return self.frame.orig_len

    @property
    def vlan_tags(self) -> tuple[VlanTag, ...]:
        return self.ethernet.vlan_tags if self.ethernet else ()

    @property
    def vlan_id(self) -> int | None:
        return self.ethernet.vlan_id if self.ethernet else None

    @property
    def ip_version(self) -> int | None:
        if isinstance(self.network, IPv4):
            return 4
        if isinstance(self.network, IPv6):
            return 6
        return None

    @property
    def src_addr(self) -> str | None:
        """Source IP, or the sender's protocol address for ARP."""
        if isinstance(self.network, (IPv4, IPv6)):
            return self.network.src
        if isinstance(self.network, Arp):
            return self.network.sender_protocol
        return None

    @property
    def dst_addr(self) -> str | None:
        if isinstance(self.network, (IPv4, IPv6)):
            return self.network.dst
        if isinstance(self.network, Arp):
            return self.network.target_protocol
        return None

    @property
    def src_port(self) -> int | None:
        if isinstance(self.transport, (Tcp, Udp)):
            return self.transport.src_port
        return None

    @property
    def dst_port(self) -> int | None:
        if isinstance(self.transport, (Tcp, Udp)):
            return self.transport.dst_port
        return None

    @property
    def ip_protocol(self) -> int | None:
        """The IP protocol number, for keying flows."""
        if isinstance(self.network, IPv4):
            return self.network.protocol
        if isinstance(self.network, IPv6):
            return self.network.protocol
        return None

    @property
    def protocol(self) -> str:
        """The most specific protocol name we got to.

        This is what the protocol breakdown counts, so it names the deepest
        layer that decoded rather than always saying "IPv4".
        """
        if isinstance(self.transport, Tcp):
            return "TCP"
        if isinstance(self.transport, Udp):
            return "UDP"
        if isinstance(self.transport, Icmp):
            return "ICMPv6" if self.transport.v6 else "ICMP"
        if isinstance(self.network, Arp):
            return "ARP"
        if isinstance(self.network, IPv4):
            return self.network.protocol_name
        if isinstance(self.network, IPv6):
            return self.network.protocol_name
        if self.ethernet is not None:
            return self.ethernet.ethertype_name
        return "unknown"

    def __str__(self) -> str:
        if self.src_addr is None:
            return f"{self.ethernet or 'undecoded frame'}"
        src = format_endpoint(self.src_addr, self.src_port)
        dst = format_endpoint(self.dst_addr or "?", self.dst_port)
        text = f"{src} > {dst} {self.protocol}"
        if isinstance(self.transport, Tcp):
            text += f" [{self.transport.flag_string}]"
        return text


def _decode_transport(
    protocol: int, data: bytes, *, v6: bool
) -> tuple[TransportLayer | None, bytes]:
    """Dispatch on the IP protocol number. Returns the layer and its payload."""
    if protocol == IPPROTO_TCP:
        tcp = decode_tcp(data)
        return tcp, data[tcp.header_len :]
    if protocol == IPPROTO_UDP:
        udp = decode_udp(data)
        return udp, data[udp.header_len : udp.header_len + udp.payload_len]
    if protocol == IPPROTO_ICMP and not v6:
        return decode_icmp(data), b""
    if protocol == IPPROTO_ICMPV6 and v6:
        return decode_icmp(data, v6=True), b""
    return None, b""


def decode_frame(frame: Frame) -> DecodedPacket:
    """Decode one frame through every layer we understand.

    This never raises. A packet that fails partway through comes back with the
    layers that did decode and an entry in :attr:`DecodedPacket.errors`.

    Args:
        frame: A frame from any capture source.

    Returns:
        The decoded packet.
    """
    errors: list[str] = []

    try:
        eth = decode_ethernet(frame.data)
    except DecodeError as exc:
        return DecodedPacket(frame=frame, errors=(f"ethernet: {exc}",))

    rest = frame.data[eth.header_len :]
    network: NetworkLayer | None = None
    transport: TransportLayer | None = None
    payload = b""

    # -- network layer -----------------------------------------------------
    try:
        if eth.ethertype == ETHERTYPE_IPV4:
            network = decode_ipv4(rest)
        elif eth.ethertype == ETHERTYPE_IPV6:
            network = decode_ipv6(rest)
        elif eth.ethertype == ETHERTYPE_ARP:
            network = decode_arp(rest)
    except DecodeError as exc:
        errors.append(f"{eth.ethertype_name}: {exc}")

    # -- transport layer ---------------------------------------------------
    if isinstance(network, (IPv4, IPv6)):
        transport_bytes = rest[network.header_len : network.header_len + network.payload_len]

        # A later fragment starts mid-payload: there is no transport header
        # there to decode, and pretending otherwise invents ports.
        decodable = not (isinstance(network, IPv4) and not network.is_first_fragment)

        if decodable:
            try:
                transport, payload = _decode_transport(
                    network.protocol, transport_bytes, v6=isinstance(network, IPv6)
                )
            except DecodeError as exc:
                errors.append(f"{network.protocol_name}: {exc}")

    return DecodedPacket(
        frame=frame,
        ethernet=eth,
        network=network,
        transport=transport,
        payload=payload,
        errors=tuple(errors),
    )
