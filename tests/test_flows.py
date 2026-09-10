"""Conversation tracking.

The property that matters most here is bidirectional collapse: A-to-B and
B-to-A have to land in one flow, with per-direction counters preserved. Get it
wrong and the tool reports twice as many conversations as exist, each with half
the traffic - and the numbers still look plausible, which is what makes it worth
this many tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsniff.analyze.flows import Flow, FlowKey, FlowTable, flow_key
from netsniff.capture.base import Frame
from netsniff.capture.pcap import read_pcap
from netsniff.decode import decode_frame
from tests.fixtures import headers, synth


def packet(raw: bytes, ts: float = 1000.0, *, orig_len: int | None = None):
    """Decode synthetic bytes into a packet at a chosen timestamp."""
    return decode_frame(Frame(ts=ts, data=raw, orig_len=orig_len or len(raw)))


def tcp(src: str, sport: int, dst: str, dport: int, ts: float = 1000.0, **kw):
    return packet(synth.tcp_frame(src, sport, dst, dport, **kw), ts)


# --------------------------------------------------------------------------
# bidirectional collapse
# --------------------------------------------------------------------------


def test_both_directions_land_in_one_flow() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "93.184.216.34", 443, flags=synth.SYN))
    table.add(tcp("93.184.216.34", 443, "10.0.0.5", 52000, flags=synth.SYN | synth.ACK))
    table.add(tcp("10.0.0.5", 52000, "93.184.216.34", 443, flags=synth.ACK))

    assert len(table) == 1, "one conversation, not two"
    flow = table.flows[0]
    assert flow.packets == 3
    assert flow.is_bidirectional


def test_per_direction_counters_survive_the_collapse() -> None:
    table = FlowTable()
    for _ in range(3):
        table.add(tcp("10.0.0.5", 52000, "93.184.216.34", 443))
    for _ in range(7):
        table.add(tcp("93.184.216.34", 443, "10.0.0.5", 52000))

    flow = table.flows[0]
    assert flow.packets == 10
    assert sorted([flow.packets_a_to_b, flow.packets_b_to_a]) == [3, 7]
    assert flow.bytes == flow.bytes_a_to_b + flow.bytes_b_to_a


def test_the_key_is_the_same_object_from_either_direction() -> None:
    forward = flow_key(tcp("10.0.0.5", 52000, "93.184.216.34", 443))
    reverse = flow_key(tcp("93.184.216.34", 443, "10.0.0.5", 52000))
    assert forward == reverse
    assert hash(forward) == hash(reverse)


def test_initiator_is_whoever_spoke_first() -> None:
    table = FlowTable()
    table.add(tcp("93.184.216.34", 443, "10.0.0.5", 52000))
    table.add(tcp("10.0.0.5", 52000, "93.184.216.34", 443))

    flow = table.flows[0]
    assert flow.initiator == "93.184.216.34", "recorded independently of key order"
    assert flow.responder == "10.0.0.5"


def test_addresses_are_sorted_as_numbers_not_as_text() -> None:
    """"10.0.0.11" < "10.0.0.2" as strings, and the other way as addresses.

    Both directions must still collapse, whichever way the comparison falls.
    """
    assert "10.0.0.11" < "10.0.0.2", "the string comparison this test guards against"

    table = FlowTable()
    table.add(tcp("10.0.0.11", 1000, "10.0.0.2", 179))
    table.add(tcp("10.0.0.2", 179, "10.0.0.11", 1000))
    assert len(table) == 1

    key = table.flows[0].key
    assert key.a_addr == "10.0.0.2", "the numerically lower address sorts first"
    assert key.b_addr == "10.0.0.11"


def test_different_ports_are_different_flows() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443))
    table.add(tcp("10.0.0.5", 52001, "10.0.0.9", 443))
    assert len(table) == 2


def test_different_protocols_are_different_flows() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 5000, "10.0.0.9", 53))
    table.add(packet(synth.udp_frame("10.0.0.5", 5000, "10.0.0.9", 53)))
    assert len(table) == 2
    assert {f.key.protocol for f in table} == {"TCP", "UDP"}


def test_two_sockets_on_the_same_host_pair_stay_apart() -> None:
    """Same addresses both ways round; only the ports distinguish them."""
    table = FlowTable()
    table.add(tcp("10.0.0.5", 1111, "10.0.0.5", 2222))
    table.add(tcp("10.0.0.5", 3333, "10.0.0.5", 4444))
    assert len(table) == 2


# --------------------------------------------------------------------------
# protocols without ports
# --------------------------------------------------------------------------


def test_icmp_flows_are_keyed_on_hosts_alone() -> None:
    table = FlowTable()
    table.add(packet(synth.icmp_frame("10.0.0.5", "1.1.1.1", icmp_type=8)))
    table.add(packet(synth.icmp_frame("1.1.1.1", "10.0.0.5", icmp_type=0)))

    assert len(table) == 1
    flow = table.flows[0]
    assert flow.key.a_port is None and flow.key.b_port is None
    assert flow.is_bidirectional
    assert flow.state == "-", "TCP state means nothing for ICMP"


def test_arp_flows_use_the_protocol_addresses() -> None:
    table = FlowTable()
    table.add(packet(synth.arp_frame(operation=1, sender_ip="10.0.0.1", target_ip="10.0.0.2")))
    table.add(packet(synth.arp_frame(operation=2, sender_ip="10.0.0.2", target_ip="10.0.0.1")))

    assert len(table) == 1
    assert table.flows[0].key.protocol == "ARP"
    assert table.flows[0].is_bidirectional


def test_frames_with_no_network_layer_are_skipped_not_counted() -> None:
    table = FlowTable()
    assert table.add(packet(headers.ETH_8023_LLC)) is None
    assert len(table) == 0
    assert table.skipped == 1


# --------------------------------------------------------------------------
# timing and volume
# --------------------------------------------------------------------------


def test_first_and_last_seen_bracket_the_flow() -> None:
    table = FlowTable()
    for ts in (1000.0, 1002.5, 1001.0):
        table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, ts=ts))

    flow = table.flows[0]
    assert flow.first_seen == 1000.0
    assert flow.last_seen == 1002.5
    assert flow.duration == pytest.approx(2.5)


def test_single_packet_flow_has_zero_duration() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, ts=1000.0))
    assert table.flows[0].duration == 0.0


def test_byte_counts_use_the_on_wire_length() -> None:
    """A snapped capture must not make a host look quieter than it was."""
    table = FlowTable()
    raw = synth.tcp_frame("10.0.0.5", 52000, "10.0.0.9", 443)
    table.add(packet(raw[:40], orig_len=1514))
    assert table.flows[0].bytes == 1514, "not the 40 bytes that were recorded"


def test_one_sided_flow_is_not_bidirectional() -> None:
    table = FlowTable()
    for _ in range(5):
        table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    flow = table.flows[0]
    assert not flow.is_bidirectional
    assert flow.packets_b_to_a == 0


# --------------------------------------------------------------------------
# TCP shape
# --------------------------------------------------------------------------


def test_flags_accumulate_across_the_whole_flow() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    table.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=synth.SYN | synth.ACK))
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.PSH | synth.ACK))
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.FIN | synth.ACK))

    flow = table.flows[0]
    assert set(flow.flag_names) == {"SYN", "ACK", "PSH", "FIN"}
    assert flow.saw_syn and flow.saw_syn_ack and flow.saw_fin
    assert not flow.saw_rst


def test_syn_ack_must_be_one_packet_not_two() -> None:
    """SYN one way and ACK the other is not a completed handshake.

    Tracking only the union of flags across the flow would call this
    established, which is exactly the false negative that would hide a scan.
    """
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    table.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=synth.ACK))

    flow = table.flows[0]
    assert flow.saw_syn
    assert flow.tcp_flags & 0x12 == 0x12, "the union does contain both bits"
    assert not flow.saw_syn_ack, "but no single packet carried both"
    assert flow.is_unanswered_syn


def test_completed_handshake_is_established() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.SYN))
    table.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=synth.SYN | synth.ACK))
    flow = table.flows[0]
    assert flow.saw_syn_ack
    assert not flow.is_unanswered_syn
    assert flow.state == "established"


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ([synth.SYN], "unanswered"),
        ([synth.SYN, synth.SYN | synth.ACK], "established"),
        ([synth.SYN, synth.SYN | synth.ACK, synth.FIN | synth.ACK], "closed"),
        ([synth.SYN, synth.RST | synth.ACK], "reset"),
        ([synth.ACK], "ongoing"),
    ],
)
def test_flow_state(flags: list[int], expected: str) -> None:
    table = FlowTable()
    for i, f in enumerate(flags):
        if i % 2 == 0:
            table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=f))
        else:
            table.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=f))
    assert table.flows[0].state == expected


def test_reset_wins_over_fin_in_the_state_summary() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.5", 52000, "10.0.0.9", 443, flags=synth.FIN | synth.ACK))
    table.add(tcp("10.0.0.9", 443, "10.0.0.5", 52000, flags=synth.RST))
    assert table.flows[0].state == "reset"


def test_udp_flow_has_no_tcp_flags() -> None:
    table = FlowTable()
    table.add(packet(synth.udp_frame("10.0.0.5", 5000, "10.0.0.9", 53)))
    flow = table.flows[0]
    assert flow.tcp_flags == 0
    assert flow.flag_string == "-"


# --------------------------------------------------------------------------
# table-level queries
# --------------------------------------------------------------------------


def test_top_by_bytes_and_by_packets_can_disagree() -> None:
    """One big transfer versus many small packets - both orderings matter."""
    table = FlowTable()
    table.add(tcp("10.0.0.1", 1000, "10.0.0.2", 80, payload=b"x" * 1400))
    for _ in range(20):
        table.add(tcp("10.0.0.3", 1000, "10.0.0.4", 80))

    assert table.top_by_bytes(1)[0].key.a_addr == "10.0.0.1"
    assert table.top_by_packets(1)[0].key.a_addr == "10.0.0.3"


def test_top_n_limits_the_result() -> None:
    table = FlowTable()
    for port in range(20):
        table.add(tcp("10.0.0.1", 1000 + port, "10.0.0.2", 80))
    assert len(table.top_by_bytes(5)) == 5
    assert len(table.top_by_bytes(100)) == 20


def test_totals_match_the_sum_of_flows() -> None:
    table = FlowTable()
    for i in range(10):
        table.add(tcp("10.0.0.1", 1000 + i, "10.0.0.2", 80))
    assert table.total_packets == 10
    assert table.total_bytes == sum(f.bytes for f in table)


def test_unanswered_syns_finds_only_unanswered_ones() -> None:
    table = FlowTable()
    table.add(tcp("10.0.0.1", 1000, "10.0.0.2", 22, flags=synth.SYN))
    table.add(tcp("10.0.0.1", 1001, "10.0.0.2", 23, flags=synth.SYN))
    table.add(tcp("10.0.0.1", 1002, "10.0.0.2", 80, flags=synth.SYN))
    table.add(tcp("10.0.0.2", 80, "10.0.0.1", 1002, flags=synth.SYN | synth.ACK))

    unanswered = table.unanswered_syns()
    assert len(unanswered) == 2
    assert {f.key.b_port for f in unanswered} == {22, 23}


def test_membership_and_lookup() -> None:
    table = FlowTable()
    pkt = tcp("10.0.0.5", 52000, "10.0.0.9", 443)
    table.add(pkt)
    key = flow_key(pkt)
    assert key is not None
    assert key in table
    assert isinstance(table.get(key), Flow)
    assert table.get(FlowKey("TCP", "1.1.1.1", 1, "2.2.2.2", 2)) is None


def test_extend_matches_repeated_add() -> None:
    packets = [tcp("10.0.0.1", 1000 + i, "10.0.0.2", 80) for i in range(5)]
    one, many = FlowTable(), FlowTable()
    for p in packets:
        one.add(p)
    many.extend(packets)
    assert len(one) == len(many) == 5


def test_key_str_is_readable() -> None:
    key = flow_key(tcp("10.0.0.5", 52000, "10.0.0.9", 443))
    assert key is not None
    assert str(key) == "10.0.0.5:52000 <-> 10.0.0.9:443 TCP"


def test_ipv6_endpoints_are_bracketed_in_the_key() -> None:
    pkt = decode_frame(Frame(1.0, headers.ETH_IPV6_TCP_SYN))
    key = flow_key(pkt)
    assert key is not None
    assert "[2001:db8::1]:40000" in str(key)


# --------------------------------------------------------------------------
# against the real capture
# --------------------------------------------------------------------------


def test_real_capture_produces_a_consistent_flow_table(sample_pcap: Path) -> None:
    table = FlowTable()
    total_packets = 0
    for frame in read_pcap(sample_pcap):
        table.add(decode_frame(frame))
        total_packets += 1

    assert len(table) > 0
    assert table.skipped == 0, "every packet in this capture has a network layer"
    assert table.total_packets == total_packets, "no packet counted twice or dropped"

    for flow in table:
        assert flow.packets == flow.packets_a_to_b + flow.packets_b_to_a
        assert flow.bytes == flow.bytes_a_to_b + flow.bytes_b_to_a
        assert flow.first_seen <= flow.last_seen
        assert flow.packets_a_to_b > 0 or flow.packets_b_to_a > 0


def test_real_capture_flow_count_is_normalisation_independent(sample_pcap: Path) -> None:
    """A second, differently-implemented normalisation must agree.

    The flow table sorts endpoints into a canonical order; this uses an
    unordered frozenset instead. Same answer from a different algorithm.
    """
    table = FlowTable()
    unordered: set[tuple[str, frozenset[tuple[str | None, int | None]]]] = set()

    for frame in read_pcap(sample_pcap):
        pkt = decode_frame(frame)
        table.add(pkt)
        if pkt.src_addr is not None:
            unordered.add(
                (
                    pkt.protocol,
                    frozenset({(pkt.src_addr, pkt.src_port), (pkt.dst_addr, pkt.dst_port)}),
                )
            )

    assert len(table) == len(unordered)
