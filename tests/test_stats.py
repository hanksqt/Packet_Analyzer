"""Aggregate statistics.

The counting decisions being pinned down here are the ones that are easy to get
subtly wrong and hard to notice afterwards: bytes measured on the wire rather
than as captured, the protocol breakdown naming the deepest layer that decoded,
and top talkers split by direction so a downloader and a server do not look
identical.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsniff.analyze.stats import StatsCollector
from netsniff.capture.base import Frame
from netsniff.capture.pcap import read_pcap
from netsniff.decode import decode_frame
from tests.fixtures import headers, synth


def packet(raw: bytes, ts: float = 1000.0, *, orig_len: int | None = None):
    return decode_frame(Frame(ts=ts, data=raw, orig_len=orig_len or len(raw)))


def tcp(src: str, sport: int, dst: str, dport: int, ts: float = 1000.0, **kw):
    return packet(synth.tcp_frame(src, sport, dst, dport, **kw), ts)


# --------------------------------------------------------------------------
# totals
# --------------------------------------------------------------------------


def test_empty_collector_is_all_zeros() -> None:
    s = StatsCollector()
    assert s.packets == 0
    assert s.bytes == 0
    assert s.duration == 0.0
    assert s.packets_per_second == 0.0
    assert s.average_packet_size == 0.0
    assert s.protocol_breakdown() == []
    assert s.top_talkers_by_bytes() == []
    assert s.hosts == set()


def test_totals_accumulate() -> None:
    s = StatsCollector()
    frames = [synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80) for _ in range(4)]
    for f in frames:
        s.add(packet(f))
    assert s.packets == 4
    assert s.bytes == sum(len(f) for f in frames)
    assert s.average_packet_size == pytest.approx(s.bytes / 4)


def test_duration_and_rates() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, ts=1000.0))
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, ts=1002.0))
    assert s.first_seen == 1000.0
    assert s.last_seen == 1002.0
    assert s.duration == pytest.approx(2.0)
    assert s.packets_per_second == pytest.approx(1.0)
    assert s.bits_per_second == pytest.approx(s.bytes * 8 / 2.0)


def test_timestamps_out_of_order_still_bracket_correctly() -> None:
    s = StatsCollector()
    for ts in (1005.0, 1000.0, 1010.0):
        s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, ts=ts))
    assert s.first_seen == 1000.0
    assert s.last_seen == 1010.0


def test_bytes_are_on_wire_and_captured_bytes_are_tracked_separately() -> None:
    """A snapped capture: 54 bytes recorded, 1514 on the wire."""
    s = StatsCollector()
    raw = synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80)[:54]
    s.add(packet(raw, orig_len=1514))

    assert s.bytes == 1514, "traffic volume is what crossed the wire"
    assert s.captured_bytes == 54, "what the capture actually holds"
    assert s.truncated_packets == 1
    assert s.was_snapped


def test_unsnapped_capture_reports_no_truncation() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    assert not s.was_snapped
    assert s.bytes == s.captured_bytes


# --------------------------------------------------------------------------
# protocol breakdown
# --------------------------------------------------------------------------


def test_breakdown_names_the_deepest_layer_that_decoded() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    s.add(packet(synth.udp_frame("10.0.0.1", 1000, "10.0.0.2", 53)))
    s.add(packet(synth.icmp_frame("10.0.0.1", "10.0.0.2")))
    s.add(packet(synth.arp_frame()))

    names = [row.name for row in s.protocol_breakdown()]
    assert set(names) == {"TCP", "UDP", "ICMP", "ARP"}
    assert "IPv4" not in names, "a TCP segment counts as TCP, not as IPv4"


def test_percentages_are_of_the_totals_and_sum_to_100() -> None:
    s = StatsCollector()
    for _ in range(3):
        s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    s.add(packet(synth.udp_frame("10.0.0.1", 1000, "10.0.0.2", 53)))

    rows = {r.name: r for r in s.protocol_breakdown()}
    assert rows["TCP"].packets == 3
    assert rows["TCP"].packet_pct == pytest.approx(75.0)
    assert rows["UDP"].packet_pct == pytest.approx(25.0)
    assert sum(r.packet_pct for r in s.protocol_breakdown()) == pytest.approx(100.0)
    assert sum(r.byte_pct for r in s.protocol_breakdown()) == pytest.approx(100.0)


def test_breakdown_is_ordered_busiest_first_and_can_be_limited() -> None:
    s = StatsCollector()
    for _ in range(5):
        s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    for _ in range(2):
        s.add(packet(synth.udp_frame("10.0.0.1", 1000, "10.0.0.2", 53)))
    s.add(packet(synth.icmp_frame("10.0.0.1", "10.0.0.2")))

    rows = s.protocol_breakdown()
    assert [r.name for r in rows] == ["TCP", "UDP", "ICMP"]
    assert len(s.protocol_breakdown(2)) == 2


def test_protocol_bytes_and_packets_are_counted_separately() -> None:
    """Few large packets versus many small ones diverge between the two."""
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, payload=b"x" * 1400))
    for _ in range(10):
        s.add(packet(synth.udp_frame("10.0.0.1", 1000, "10.0.0.2", 53)))

    rows = {r.name: r for r in s.protocol_breakdown()}
    assert rows["UDP"].packets > rows["TCP"].packets
    assert rows["TCP"].bytes > rows["UDP"].bytes


def test_ethertype_and_ip_version_counts() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    s.add(packet(headers.ETH_IPV6_TCP_SYN))
    s.add(packet(synth.arp_frame()))

    assert s.ip_version_packets == {4: 1, 6: 1}
    assert s.ethertype_packets["IPv4"] == 1
    assert s.ethertype_packets["IPv6"] == 1
    assert s.ethertype_packets["ARP"] == 1


def test_vlan_tags_are_counted() -> None:
    s = StatsCollector()
    s.add(packet(headers.ETH_VLAN_IPV4_TCP_SYN))
    s.add(packet(headers.ETH_QINQ_IPV4_ICMP))
    assert s.vlan_packets[100] == 2, "both frames carry an inner VLAN 100"
    assert s.vlan_packets[200] == 1, "only the QinQ frame has the outer tag"


# --------------------------------------------------------------------------
# talkers
# --------------------------------------------------------------------------


def test_talkers_split_sent_from_received() -> None:
    """A host pulling a download and one serving it must not look the same."""
    s = StatsCollector()
    s.add(tcp("10.0.0.5", 52000, "10.0.0.9", 80))  # small request
    s.add(tcp("10.0.0.9", 80, "10.0.0.5", 52000, payload=b"x" * 1400))  # big response

    by_address = {t.address: t for t in s.top_talkers_by_bytes()}
    client, server = by_address["10.0.0.5"], by_address["10.0.0.9"]

    assert client.bytes == server.bytes, "combined totals are identical"
    assert client.bytes_received > client.bytes_sent, "the client mostly received"
    assert server.bytes_sent > server.bytes_received, "the server mostly sent"


def test_talker_totals_are_the_sum_of_both_directions() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.5", 52000, "10.0.0.9", 80))
    s.add(tcp("10.0.0.9", 80, "10.0.0.5", 52000))

    for t in s.top_talkers_by_bytes():
        assert t.bytes == t.bytes_sent + t.bytes_received
        assert t.packets == t.packets_sent + t.packets_received


def test_top_talkers_by_bytes_and_by_packets_can_disagree() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, payload=b"x" * 1400))
    for _ in range(10):
        s.add(tcp("10.0.0.3", 1000, "10.0.0.4", 80))

    assert s.top_talkers_by_bytes(1)[0].address == "10.0.0.1"
    assert s.top_talkers_by_packets(1)[0].address == "10.0.0.3"


def test_hosts_counts_every_address_in_either_direction() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80))
    s.add(tcp("10.0.0.3", 1000, "10.0.0.4", 80))
    assert s.hosts == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}


def test_top_talkers_is_limited_and_deterministic() -> None:
    s = StatsCollector()
    for i in range(1, 21):
        s.add(tcp(f"10.0.0.{i}", 1000, "10.1.1.1", 80))
    assert len(s.top_talkers_by_bytes(5)) == 5
    # Every 10.0.0.x host sent exactly one identical packet, so the tie-break
    # on address keeps the ordering stable rather than set-iteration dependent.
    twice = [t.address for t in s.top_talkers_by_bytes(20)]
    assert twice == [t.address for t in s.top_talkers_by_bytes(20)]


# --------------------------------------------------------------------------
# ports, flags and ICMP types
# --------------------------------------------------------------------------


def test_only_destination_ports_are_counted() -> None:
    """Source ports are ephemeral; counting them would say nothing."""
    s = StatsCollector()
    for i in range(3):
        s.add(tcp("10.0.0.5", 50000 + i, "10.0.0.9", 443))

    assert s.top_ports() == [(443, 3)]
    assert 50000 not in s.dst_port_packets


def test_tcp_flags_counted_per_packet_not_per_flow() -> None:
    s = StatsCollector()
    s.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    s.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=synth.SYN | synth.ACK))
    s.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.ACK))

    assert s.tcp_flag_packets["SYN"] == 2
    assert s.tcp_flag_packets["ACK"] == 2
    assert "FIN" not in s.tcp_flag_packets


def test_icmp_types_are_named() -> None:
    s = StatsCollector()
    s.add(packet(synth.icmp_frame("10.0.0.1", "1.1.1.1", icmp_type=8)))
    s.add(packet(synth.icmp_frame("1.1.1.1", "10.0.0.1", icmp_type=0)))
    assert s.icmp_type_packets == {"echo request": 1, "echo reply": 1}


def test_decode_errors_are_counted_but_the_packet_still_is_too() -> None:
    s = StatsCollector()
    truncated = headers.ETH_IPV4_TCP_SYN[:20]  # Ethernet fine, IPv4 cut short
    pkt = packet(truncated)
    assert pkt.errors
    s.add(pkt)
    assert s.packets == 1, "still a packet that crossed the wire"
    assert s.decode_errors == 1


# --------------------------------------------------------------------------
# the JSON summary
# --------------------------------------------------------------------------


def test_summary_is_plain_json_able_data() -> None:
    import json

    s = StatsCollector()
    s.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    s.add(packet(synth.icmp_frame("10.0.0.1", "1.1.1.1")))

    summary = s.summary()
    round_tripped = json.loads(json.dumps(summary))
    assert round_tripped == summary, (
        "the summary must survive a JSON round-trip unchanged; integer-keyed "
        "maps do not, since JSON object keys are always strings"
    )
    assert summary["ip_versions"] == [{"version": 4, "packets": 2}]


def test_summary_agrees_with_the_collector() -> None:
    s = StatsCollector()
    for i in range(6):
        s.add(tcp(f"10.0.0.{i}", 1000, "10.1.1.1", 443))

    summary = s.summary(top=3)
    assert summary["packets"] == s.packets
    assert summary["bytes"] == s.bytes
    assert summary["hosts"] == len(s.hosts)
    assert len(summary["top_talkers"]) == 3
    assert sum(p["packets"] for p in summary["protocols"]) == s.packets


def test_summary_of_an_empty_capture_does_not_divide_by_zero() -> None:
    summary = StatsCollector().summary()
    assert summary["packets"] == 0
    assert summary["duration_seconds"] == 0
    assert summary["protocols"] == []


# --------------------------------------------------------------------------
# against the real capture
# --------------------------------------------------------------------------


def test_real_capture_totals_are_internally_consistent(sample_pcap: Path) -> None:
    s = StatsCollector()
    for frame in read_pcap(sample_pcap):
        s.add(decode_frame(frame))

    assert s.packets == sum(r.packets for r in s.protocol_breakdown())
    assert s.bytes == sum(r.bytes for r in s.protocol_breakdown())
    assert s.bytes == sum(s.bytes_sent.values()), "every packet has exactly one sender"
    assert s.bytes == sum(s.bytes_received.values())
    assert s.decode_errors == 0
    assert s.duration > 0


def test_real_capture_protocol_percentages_sum_to_100(sample_pcap: Path) -> None:
    s = StatsCollector()
    for frame in read_pcap(sample_pcap):
        s.add(decode_frame(frame))
    assert sum(r.packet_pct for r in s.protocol_breakdown()) == pytest.approx(100.0)
    assert sum(r.byte_pct for r in s.protocol_breakdown()) == pytest.approx(100.0)
