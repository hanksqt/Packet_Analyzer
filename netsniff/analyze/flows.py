"""Conversation tracking: turning a pile of packets into "who talked to whom".

Every packet is keyed by its 5-tuple - protocol, source address, source port,
destination address, destination port. The wrinkle is that a conversation has
two directions, and the naive 5-tuple gives them different keys:

    10.0.0.5:52000 -> 93.184.216.34:443     one key
    93.184.216.34:443 -> 10.0.0.5:52000     a different key

Counting those separately would report twice as many conversations as there are,
each with half the traffic. So the key is *normalised*: the two endpoints are
sorted into a canonical order, and which one came first is recorded separately as
the flow's initiator. Per-direction counters are still kept, because "who sent
how much" is most of what a flow table is for.

Sorting compares packed address bytes rather than the strings, since
``"10.0.0.11" < "10.0.0.2"`` is true as text and false as addresses - the kind
of bug that only shows up on the hosts whose numbering happens to disagree.
"""

from __future__ import annotations

import socket
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache

from netsniff.decode import DecodedPacket
from netsniff.decode.common import format_endpoint
from netsniff.decode.tcp import TCP_FLAG_NAMES, Tcp

__all__ = ["Flow", "FlowKey", "FlowTable"]


@lru_cache(maxsize=8192)
def _addr_sort_key(addr: str) -> tuple[int, bytes]:
    """Sortable key for an address: family first, then its packed bytes."""
    try:
        return (4, socket.inet_aton(addr))
    except OSError:
        pass
    try:
        return (6, socket.inet_pton(socket.AF_INET6, addr))
    except OSError:
        return (9, addr.encode())  # not an address at all; sort it last


@dataclass(frozen=True, slots=True)
class FlowKey:
    """A direction-normalised 5-tuple.

    ``a`` is always the endpoint that sorts lower, whichever end actually spoke
    first. :attr:`Flow.initiator` records that separately.
    """

    protocol: str
    a_addr: str
    a_port: int | None
    b_addr: str
    b_port: int | None

    @property
    def endpoint_a(self) -> str:
        return format_endpoint(self.a_addr, self.a_port)

    @property
    def endpoint_b(self) -> str:
        return format_endpoint(self.b_addr, self.b_port)

    def __str__(self) -> str:
        return f"{self.endpoint_a} <-> {self.endpoint_b} {self.protocol}"


def flow_key(packet: DecodedPacket) -> FlowKey | None:
    """Build the normalised key for a packet, or None if it has no addresses.

    Frames with no network layer at all - 802.3 LLC, an undecodable header -
    are not conversations and get no key.
    """
    src, dst = packet.src_addr, packet.dst_addr
    if src is None or dst is None:
        return None

    src_port, dst_port = packet.src_port, packet.dst_port

    # Canonical order: lower endpoint first. Ports break ties between two
    # sockets on the same host.
    if (_addr_sort_key(src), src_port or 0) <= (_addr_sort_key(dst), dst_port or 0):
        a_addr, a_port, b_addr, b_port = src, src_port, dst, dst_port
    else:
        a_addr, a_port, b_addr, b_port = dst, dst_port, src, src_port

    return FlowKey(
        protocol=packet.protocol,
        a_addr=a_addr,
        a_port=a_port,
        b_addr=b_addr,
        b_port=b_port,
    )


@dataclass(slots=True)
class Flow:
    """One conversation, with both directions accounted for separately."""

    key: FlowKey
    first_seen: float
    last_seen: float

    initiator: str = ""
    """Address of whichever endpoint sent the first packet we saw. Not
    necessarily the endpoint that opened the connection, if the capture started
    mid-conversation."""

    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    tcp_flags: int = 0
    """Union of every TCP flag bit seen in either direction."""

    tcp_flags_a_to_b: int = 0
    tcp_flags_b_to_a: int = 0

    app_hints: tuple[str, ...] = field(default=())
    """Application-layer identifiers seen on this flow, in order of first
    appearance. Populated once app hints are decoded."""

    # -- totals ------------------------------------------------------------

    @property
    def packets(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def duration(self) -> float:
        """Seconds between the first and last packet. Zero for a single packet."""
        return self.last_seen - self.first_seen

    @property
    def is_bidirectional(self) -> bool:
        """True when both endpoints sent something.

        A one-way flow is a connection that was never answered - a scan, a
        blocked port, or a host that has gone away.
        """
        return self.packets_a_to_b > 0 and self.packets_b_to_a > 0

    @property
    def responder(self) -> str:
        """The endpoint that did not start the conversation."""
        return self.key.b_addr if self.initiator == self.key.a_addr else self.key.a_addr

    # -- TCP shape ---------------------------------------------------------

    @property
    def flag_names(self) -> tuple[str, ...]:
        return tuple(name for bit, name in TCP_FLAG_NAMES if self.tcp_flags & bit)

    @property
    def flag_string(self) -> str:
        return ",".join(self.flag_names) or "-"

    @property
    def saw_syn(self) -> bool:
        return bool(self.tcp_flags & 0x02)

    @property
    def saw_syn_ack(self) -> bool:
        """True when one direction sent SYN and ACK together."""
        return any(f & 0x12 == 0x12 for f in (self.tcp_flags_a_to_b, self.tcp_flags_b_to_a))

    @property
    def saw_rst(self) -> bool:
        return bool(self.tcp_flags & 0x04)

    @property
    def saw_fin(self) -> bool:
        return bool(self.tcp_flags & 0x01)

    @property
    def is_unanswered_syn(self) -> bool:
        """A connection attempt that never got a SYN-ACK.

        Either the port is closed, a firewall dropped it, or the host is not
        there. Also what one probe of a port scan looks like.
        """
        return self.key.protocol == "TCP" and self.saw_syn and not self.saw_syn_ack

    @property
    def state(self) -> str:
        """A rough TCP disposition, good enough for a summary table."""
        if self.key.protocol != "TCP":
            return "-"
        if self.saw_rst:
            return "reset"
        if self.saw_fin:
            return "closed"
        if self.saw_syn_ack:
            return "established"
        if self.saw_syn:
            return "unanswered"
        return "ongoing"

    def __str__(self) -> str:
        return (
            f"{self.key} {self.packets} pkts {self.bytes} B "
            f"({self.packets_a_to_b}/{self.packets_b_to_a})"
        )


class FlowTable:
    """Accumulates :class:`Flow` records from decoded packets.

    Usage::

        table = FlowTable()
        for frame in source:
            table.add(decode_frame(frame))
        for flow in table.top_by_bytes(10):
            print(flow)
    """

    def __init__(self) -> None:
        self._flows: dict[FlowKey, Flow] = {}
        self.skipped = 0
        """Packets with no network layer, so no conversation to attribute."""

    def add(self, packet: DecodedPacket) -> Flow | None:
        """Fold one packet into the table, returning the flow it landed in."""
        key = flow_key(packet)
        if key is None:
            self.skipped += 1
            return None

        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(
                key=key,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                initiator=packet.src_addr or "",
            )
            self._flows[key] = flow

        # Which way round is this packet, relative to the canonical key?
        forward = packet.src_addr == key.a_addr and (
            packet.src_port == key.a_port or key.a_port is None
        )

        flow.last_seen = max(flow.last_seen, packet.timestamp)
        if forward:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += packet.length
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += packet.length

        if isinstance(packet.transport, Tcp):
            flow.tcp_flags |= packet.transport.flags
            if forward:
                flow.tcp_flags_a_to_b |= packet.transport.flags
            else:
                flow.tcp_flags_b_to_a |= packet.transport.flags

        if packet.app is not None and packet.app.key not in flow.app_hints:
            flow.app_hints = (*flow.app_hints, packet.app.key)

        return flow

    def extend(self, packets: Iterable[DecodedPacket]) -> None:
        """Add many packets."""
        for packet in packets:
            self.add(packet)

    # -- access ------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._flows)

    def __iter__(self) -> Iterator[Flow]:
        return iter(self._flows.values())

    def __contains__(self, key: FlowKey) -> bool:
        return key in self._flows

    def get(self, key: FlowKey) -> Flow | None:
        return self._flows.get(key)

    @property
    def flows(self) -> list[Flow]:
        """Every flow, in the order it was first seen."""
        return list(self._flows.values())

    def top_by_bytes(self, count: int = 10) -> list[Flow]:
        return sorted(self._flows.values(), key=lambda f: (-f.bytes, -f.packets))[:count]

    def top_by_packets(self, count: int = 10) -> list[Flow]:
        return sorted(self._flows.values(), key=lambda f: (-f.packets, -f.bytes))[:count]

    def unanswered_syns(self) -> list[Flow]:
        """Every TCP flow whose SYN was never answered with a SYN-ACK."""
        return [f for f in self._flows.values() if f.is_unanswered_syn]

    @property
    def total_packets(self) -> int:
        return sum(f.packets for f in self._flows.values())

    @property
    def total_bytes(self) -> int:
        return sum(f.bytes for f in self._flows.values())
