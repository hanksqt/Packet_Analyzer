"""The golden test: the whole stack, against the committed capture.

Every other test file exercises one layer against fixtures chosen to probe it.
This one runs the real pipeline over a real capture and asserts the numbers that
come out - packet count, protocol split, top talker, conversation count - which
is the check that catches a regression no single-layer test would notice, like a
byte count that is right per packet and wrong in aggregate.

The figures below are specific to ``tests/fixtures/sample.pcap`` and were
cross-checked against ``tcpdump``, which counts TCP 108, UDP 12, ICMP 12 and ARP
2 on the same file. If you regenerate the capture with
``scripts/capture_sample.sh`` you will need to update EXPECTED to match; running
``python scripts/golden_values.py`` prints the replacement block.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from netsniff.analyze.flows import FlowTable
from netsniff.analyze.stats import StatsCollector
from netsniff.capture.pcap import PcapReader, read_pcap
from netsniff.decode import decode_frame

# --------------------------------------------------------------------------
# what the committed capture contains
# --------------------------------------------------------------------------

EXPECTED: dict[str, Any] = {
    "packets": 134,
    "bytes": 20977,
    "hosts": 10,
    "flows": 36,
    "duration": 19.842349,
    "byte_order": "<",
    # protocol -> (packets, bytes)
    "protocols": {
        "TCP": (108, 18374),
        "UDP": (12, 1343),
        "ICMP": (12, 1176),
        "ARP": (2, 84),
    },
    # address -> (packets, bytes, bytes_sent, bytes_received)
    "top_talkers": [
        ("172.18.54.224", 78, 16833, 5675, 11158),
        ("140.82.114.5", 28, 8213, 5212, 3001),
        ("34.223.124.45", 16, 5425, 4665, 760),
    ],
    "top_ports": [(179, 56), (443, 17), (50714, 11), (80, 10), (53, 6)],
    "tcp_flags": {"SYN": 70, "ACK": 36, "PSH": 15, "FIN": 4, "RST": 4},
    "icmp_types": {"echo request": 7, "echo reply": 5},
    "ip_versions": {4: 132},
    "unanswered_syn_flows": 24,
    "app_names": [
        "api.github.com",
        "cloudflare.com",
        "example.com",
        "neverssl.com",
        "neverssl.com/",
        "nxdomain-test-netsniff.example",
        "www.example.com",
    ],
}


@pytest.fixture(scope="module")
def analysed(sample_pcap: Path) -> tuple[StatsCollector, FlowTable]:
    stats, flows = StatsCollector(), FlowTable()
    for frame in read_pcap(sample_pcap):
        packet = decode_frame(frame)
        stats.add(packet)
        flows.add(packet)
    return stats, flows


# --------------------------------------------------------------------------
# the headline numbers
# --------------------------------------------------------------------------


def test_packet_and_byte_totals(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    assert stats.packets == EXPECTED["packets"]
    assert stats.bytes == EXPECTED["bytes"]


def test_nothing_in_the_capture_fails_to_decode(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    stats, _ = analysed
    assert stats.decode_errors == 0
    assert stats.truncated_packets == 0, "this capture was taken with -s 0"


def test_protocol_split_matches_tcpdump(analysed: tuple[StatsCollector, FlowTable]) -> None:
    """tcpdump -r sample.pcap 'tcp' | wc -l  ->  108, and so on for each."""
    stats, _ = analysed
    actual = {row.name: (row.packets, row.bytes) for row in stats.protocol_breakdown()}
    assert actual == EXPECTED["protocols"]


def test_protocol_percentages(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    rows = {row.name: row for row in stats.protocol_breakdown()}
    assert rows["TCP"].packet_pct == pytest.approx(80.6, abs=0.05)
    assert rows["TCP"].byte_pct == pytest.approx(87.6, abs=0.05)
    assert sum(r.packet_pct for r in stats.protocol_breakdown()) == pytest.approx(100.0)


def test_top_talker_and_its_direction_split(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    stats, _ = analysed
    actual = [
        (t.address, t.packets, t.bytes, t.bytes_sent, t.bytes_received)
        for t in stats.top_talkers_by_bytes(3)
    ]
    assert actual == EXPECTED["top_talkers"]

    busiest = stats.top_talkers_by_bytes(1)[0]
    assert busiest.address == "172.18.54.224", "the capturing host"
    assert busiest.bytes_received > busiest.bytes_sent, "it mostly pulled data down"


def test_top_ports(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    assert stats.top_ports(5) == EXPECTED["top_ports"]


def test_tcp_flags_and_icmp_types(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    assert dict(stats.tcp_flag_packets) == EXPECTED["tcp_flags"]
    assert dict(stats.icmp_type_packets) == EXPECTED["icmp_types"]

    # Seven echo requests, five replies: the two pings to the gateway went
    # unanswered, which is also why ARP is in this capture at all.
    assert stats.icmp_type_packets["echo request"] > stats.icmp_type_packets["echo reply"]


def test_ip_versions(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    assert dict(stats.ip_version_packets) == EXPECTED["ip_versions"]
    assert stats.ip_version_packets[4] + EXPECTED["protocols"]["ARP"][0] == stats.packets


def test_timing(analysed: tuple[StatsCollector, FlowTable]) -> None:
    stats, _ = analysed
    assert stats.duration == pytest.approx(EXPECTED["duration"], abs=1e-6)
    assert stats.first_seen is not None and stats.last_seen is not None
    assert stats.first_seen < stats.last_seen


# --------------------------------------------------------------------------
# conversations
# --------------------------------------------------------------------------


def test_conversation_count(analysed: tuple[StatsCollector, FlowTable]) -> None:
    _, flows = analysed
    assert len(flows) == EXPECTED["flows"]
    assert flows.skipped == 0


def test_conversations_account_for_every_packet_and_byte(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    """Nothing double-counted, nothing dropped between the two views."""
    stats, flows = analysed
    assert flows.total_packets == stats.packets
    assert flows.total_bytes == stats.bytes


def test_the_busiest_conversation_is_the_tls_session(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    _, flows = analysed
    top = flows.top_by_bytes(1)[0]

    assert str(top.key) == "140.82.114.5:443 <-> 172.18.54.224:50714 TCP"
    assert (top.packets, top.bytes) == (28, 8213)
    assert top.is_bidirectional
    assert top.state == "reset", "curl closed it abruptly after the HEAD request"
    assert "api.github.com" in top.app_hints, "SNI, decoded out of the ClientHello"


def test_the_http_conversation_carries_both_ends_of_the_exchange(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    _, flows = analysed
    http = flows.top_by_bytes(2)[1]

    assert str(http.key) == "34.223.124.45:80 <-> 172.18.54.224:36494 TCP"
    assert http.state == "closed", "a clean FIN exchange, unlike the TLS one"
    assert "neverssl.com/" in http.app_hints, "the request Host and path"
    assert "200 OK" in http.app_hints, "and the response status line"


def test_unanswered_connection_attempts(analysed: tuple[StatsCollector, FlowTable]) -> None:
    """The BGP mesh retrying, plus the deliberate probe of the gateway."""
    _, flows = analysed
    assert len(flows.unanswered_syns()) == EXPECTED["unanswered_syn_flows"]


# --------------------------------------------------------------------------
# application-layer identifiers
# --------------------------------------------------------------------------


def test_every_expected_name_was_pulled_out_of_a_payload(
    analysed: tuple[StatsCollector, FlowTable],
) -> None:
    stats, _ = analysed
    names = sorted(hint for hint in stats.app_hint_packets if "." in hint)
    assert names == EXPECTED["app_names"]


def test_the_three_hint_protocols_all_fired(sample_pcap: Path) -> None:
    protocols = set()
    for frame in read_pcap(sample_pcap):
        packet = decode_frame(frame)
        if packet.app is not None and packet.app.confident:
            protocols.add(packet.app.protocol)
    assert {"DNS", "HTTP", "TLS"} <= protocols


# --------------------------------------------------------------------------
# the file itself
# --------------------------------------------------------------------------


def test_the_fixture_is_a_classic_little_endian_pcap(sample_pcap: Path) -> None:
    with PcapReader(sample_pcap) as reader:
        assert reader.header.byte_order == EXPECTED["byte_order"]
        assert reader.header.version_major == 2
        assert reader.header.link_type == 1
        assert not reader.header.nanosecond_resolution


def test_framing_accounts_for_the_whole_file(sample_pcap: Path) -> None:
    import os

    frames = list(read_pcap(sample_pcap))
    assert 24 + 16 * len(frames) + sum(f.caplen for f in frames) == os.path.getsize(sample_pcap)


# --------------------------------------------------------------------------
# through the CLI, as a user would run it
# --------------------------------------------------------------------------


def test_cli_json_matches_the_analysis(sample_pcap: Path, tmp_path: Path) -> None:
    """The exported summary must say the same thing the objects do."""
    from netsniff.cli import main

    target = tmp_path / "summary.json"
    assert main(["pcap", str(sample_pcap), "--quiet", "--json", str(target)]) == 0

    data = json.loads(target.read_text(encoding="utf-8"))
    capture = data["capture"]

    assert capture["packets"] == EXPECTED["packets"]
    assert capture["bytes"] == EXPECTED["bytes"]
    assert capture["hosts"] == EXPECTED["hosts"]
    assert data["flow_count"] == EXPECTED["flows"]

    exported = {row["protocol"]: (row["packets"], row["bytes"]) for row in capture["protocols"]}
    assert exported == EXPECTED["protocols"]

    assert sum(flow["packets"] for flow in data["flows"]) == EXPECTED["packets"]
    assert sum(flow["bytes"] for flow in data["flows"]) == EXPECTED["bytes"]


def test_running_as_a_module_produces_the_summary(sample_pcap: Path) -> None:
    """`python -m netsniff` is what CI runs, so it gets its own check."""
    result = subprocess.run(
        [sys.executable, "-m", "netsniff", "pcap", str(sample_pcap), "--top", "5"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Capture summary" in result.stdout
    assert str(EXPECTED["packets"]) in result.stdout
    assert "Traceback" not in result.stderr


def test_ci_summary_checker_passes_on_this_capture(sample_pcap: Path, tmp_path: Path) -> None:
    """The script CI runs to validate its own output, run here too.

    Otherwise a break in it would only surface on a push, which is the one place
    a failing check is most annoying to debug.
    """
    from netsniff.cli import main

    target = tmp_path / "summary.json"
    main(["pcap", str(sample_pcap), "--quiet", "--json", str(target)])

    checker = Path(__file__).resolve().parents[1] / "scripts" / "ci_summary.py"
    result = subprocess.run(
        [sys.executable, str(checker), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "consistency checks passed" in result.stdout
