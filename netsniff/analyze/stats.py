"""Aggregate statistics over a decoded packet stream.

Everything here is a running total updated one packet at a time, so a capture of
any size costs a fixed amount of memory - nothing accumulates per packet, only
per distinct protocol, host, port and VLAN.

A few counting decisions that are easy to get wrong, and are made explicitly:

*Bytes mean on-wire bytes.* A snapped capture holds less than it saw; using the
captured length would understate every host's traffic in proportion to how
aggressively the capture was snapped.

*The protocol breakdown counts the deepest layer that decoded*, so a TCP segment
counts as TCP rather than as IPv4. Percentages are of total packets, and they
are computed on demand rather than stored, because the totals keep moving while
a live capture runs.

*Top talkers are counted twice on purpose*: once by bytes sent and once by bytes
received, with a combined total. A host pulling a large download and a host
serving one look identical on a combined count and completely different when
you split the directions.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netsniff.decode import DecodedPacket
from netsniff.decode.icmp import Icmp
from netsniff.decode.tcp import TCP_FLAG_NAMES, Tcp
from netsniff.decode.udp import Udp

__all__ = ["ProtocolShare", "StatsCollector", "TalkerStats"]


@dataclass(frozen=True, slots=True)
class ProtocolShare:
    """One row of the protocol breakdown."""

    name: str
    packets: int
    bytes: int
    packet_pct: float
    byte_pct: float


@dataclass(frozen=True, slots=True)
class TalkerStats:
    """One host's traffic, split by direction."""

    address: str
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int

    @property
    def packets(self) -> int:
        return self.packets_sent + self.packets_received

    @property
    def bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass(slots=True)
class StatsCollector:
    """Running aggregates over decoded packets."""

    packets: int = 0
    bytes: int = 0
    captured_bytes: int = 0
    """Bytes actually recorded, which is less than :attr:`bytes` for a snapped
    capture. Keeping both makes the snapping visible instead of invisible."""

    first_seen: float | None = None
    last_seen: float | None = None

    decode_errors: int = 0
    truncated_packets: int = 0

    protocol_packets: Counter[str] = field(default_factory=Counter)
    protocol_bytes: Counter[str] = field(default_factory=Counter)
    ethertype_packets: Counter[str] = field(default_factory=Counter)
    ip_version_packets: Counter[int] = field(default_factory=Counter)

    packets_sent: Counter[str] = field(default_factory=Counter)
    packets_received: Counter[str] = field(default_factory=Counter)
    bytes_sent: Counter[str] = field(default_factory=Counter)
    bytes_received: Counter[str] = field(default_factory=Counter)

    dst_port_packets: Counter[int] = field(default_factory=Counter)
    """Destination ports, which is where the services are. Source ports are
    mostly ephemeral and counting them says nothing."""

    tcp_flag_packets: Counter[str] = field(default_factory=Counter)
    icmp_type_packets: Counter[str] = field(default_factory=Counter)
    vlan_packets: Counter[int] = field(default_factory=Counter)
    app_hint_packets: Counter[str] = field(default_factory=Counter)

    # -- accumulation ------------------------------------------------------

    def add(self, packet: DecodedPacket) -> None:
        """Fold one decoded packet into every aggregate."""
        length = packet.length

        self.packets += 1
        self.bytes += length
        self.captured_bytes += packet.frame.caplen
        if packet.frame.truncated:
            self.truncated_packets += 1
        if packet.errors:
            self.decode_errors += 1

        ts = packet.timestamp
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        self.protocol_packets[packet.protocol] += 1
        self.protocol_bytes[packet.protocol] += length

        if packet.ethernet is not None:
            self.ethertype_packets[packet.ethernet.ethertype_name] += 1
            for tag in packet.ethernet.vlan_tags:
                self.vlan_packets[tag.vid] += 1

        if (version := packet.ip_version) is not None:
            self.ip_version_packets[version] += 1

        if (src := packet.src_addr) is not None:
            self.packets_sent[src] += 1
            self.bytes_sent[src] += length
        if (dst := packet.dst_addr) is not None:
            self.packets_received[dst] += 1
            self.bytes_received[dst] += length

        if isinstance(packet.transport, (Tcp, Udp)):
            self.dst_port_packets[packet.transport.dst_port] += 1

        if isinstance(packet.transport, Tcp):
            for bit, name in TCP_FLAG_NAMES:
                if packet.transport.flags & bit:
                    self.tcp_flag_packets[name] += 1
        elif isinstance(packet.transport, Icmp):
            self.icmp_type_packets[packet.transport.type_name] += 1

        if (label := getattr(packet.app, "label", None)) is not None:
            self.app_hint_packets[label] += 1

    def extend(self, packets: Iterable[DecodedPacket]) -> None:
        for packet in packets:
            self.add(packet)

    # -- derived views -----------------------------------------------------

    @property
    def duration(self) -> float:
        """Seconds spanned by the capture."""
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        return self.packets / self.duration if self.duration > 0 else 0.0

    @property
    def bits_per_second(self) -> float:
        return self.bytes * 8 / self.duration if self.duration > 0 else 0.0

    @property
    def average_packet_size(self) -> float:
        return self.bytes / self.packets if self.packets else 0.0

    @property
    def was_snapped(self) -> bool:
        """True when the capture cut packets short of their on-wire length."""
        return self.truncated_packets > 0

    def protocol_breakdown(self, count: int | None = None) -> list[ProtocolShare]:
        """Protocol shares, busiest first."""
        rows = [
            ProtocolShare(
                name=name,
                packets=packets,
                bytes=self.protocol_bytes[name],
                packet_pct=100.0 * packets / self.packets if self.packets else 0.0,
                byte_pct=100.0 * self.protocol_bytes[name] / self.bytes if self.bytes else 0.0,
            )
            for name, packets in self.protocol_packets.most_common()
        ]
        return rows[:count] if count else rows

    def _talker(self, address: str) -> TalkerStats:
        return TalkerStats(
            address=address,
            packets_sent=self.packets_sent[address],
            packets_received=self.packets_received[address],
            bytes_sent=self.bytes_sent[address],
            bytes_received=self.bytes_received[address],
        )

    @property
    def hosts(self) -> set[str]:
        """Every address seen, in either direction."""
        return set(self.packets_sent) | set(self.packets_received)

    def top_talkers_by_bytes(self, count: int = 10) -> list[TalkerStats]:
        talkers = [self._talker(a) for a in self.hosts]
        return sorted(talkers, key=lambda t: (-t.bytes, -t.packets, t.address))[:count]

    def top_talkers_by_packets(self, count: int = 10) -> list[TalkerStats]:
        talkers = [self._talker(a) for a in self.hosts]
        return sorted(talkers, key=lambda t: (-t.packets, -t.bytes, t.address))[:count]

    def top_ports(self, count: int = 10) -> list[tuple[int, int]]:
        """Busiest destination ports as ``(port, packets)`` pairs."""
        return self.dst_port_packets.most_common(count)

    # -- serialisation -----------------------------------------------------

    def summary(self, *, top: int = 10) -> dict[str, Any]:
        """A plain-data summary, ready for JSON.

        Kept here rather than in the export module so that the console view and
        the JSON file cannot drift apart: both render this one structure.
        """
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "captured_bytes": self.captured_bytes,
            "duration_seconds": round(self.duration, 6),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "average_packet_size": round(self.average_packet_size, 2),
            "packets_per_second": round(self.packets_per_second, 2),
            "bits_per_second": round(self.bits_per_second, 2),
            "hosts": len(self.hosts),
            "decode_errors": self.decode_errors,
            "truncated_packets": self.truncated_packets,
            "protocols": [
                {
                    "protocol": row.name,
                    "packets": row.packets,
                    "bytes": row.bytes,
                    "packet_pct": round(row.packet_pct, 2),
                    "byte_pct": round(row.byte_pct, 2),
                }
                for row in self.protocol_breakdown()
            ],
            # Lists of objects, not integer-keyed maps: JSON object keys must be
            # strings, so {4: 12} would come back as {"4": 12} and the exported
            # shape would depend on whether anyone had read it back yet.
            "ip_versions": [
                {"version": version, "packets": packets}
                for version, packets in sorted(self.ip_version_packets.items())
            ],
            "top_talkers": [
                {
                    "address": t.address,
                    "packets": t.packets,
                    "bytes": t.bytes,
                    "bytes_sent": t.bytes_sent,
                    "bytes_received": t.bytes_received,
                }
                for t in self.top_talkers_by_bytes(top)
            ],
            "top_ports": [
                {"port": port, "packets": packets} for port, packets in self.top_ports(top)
            ],
            "tcp_flags": dict(self.tcp_flag_packets.most_common()),
            "icmp_types": dict(self.icmp_type_packets.most_common()),
            "vlans": [
                {"vlan": vlan, "packets": packets}
                for vlan, packets in sorted(self.vlan_packets.items())
            ],
            "app_hints": dict(self.app_hint_packets.most_common(top)),
        }
