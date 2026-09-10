"""Console rendering, JSON/CSV export, and the CLI.

The rendering functions return strings rather than printing, so these tests can
assert on the actual output a user sees. The export tests check the two things
that actually break in practice: that the files parse back, and that their
totals still reconcile with the capture they came from.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from netsniff.analyze.flows import FlowTable
from netsniff.analyze.stats import StatsCollector
from netsniff.capture.base import Frame
from netsniff.capture.pcap import read_pcap
from netsniff.cli import build_parser, main, make_filter
from netsniff.decode import decode_frame
from netsniff.report import console, export
from tests.fixtures import synth


def analysed(pcap: Path) -> tuple[StatsCollector, FlowTable]:
    stats, flows = StatsCollector(), FlowTable()
    for frame in read_pcap(pcap):
        packet = decode_frame(frame)
        stats.add(packet)
        flows.add(packet)
    return stats, flows


def packet(raw: bytes, ts: float = 1000.0):  # type: ignore[no-untyped-def]
    return decode_frame(Frame(ts=ts, data=raw))


# ==========================================================================
# value formatting
# ==========================================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0 B"),
        (512, "512 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1024 * 1024, "1.0 MiB"),
        (1024**3, "1.0 GiB"),
    ],
)
def test_format_bytes(value: int, expected: str) -> None:
    assert console.format_bytes(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0000005, "0us"),
        (0.000123, "123us"),
        (0.5, "500ms"),
        (1.5, "1.50s"),
        (59.99, "59.99s"),
        (90.0, "1m30.0s"),
        (7200.0, "2h00m"),
    ],
)
def test_format_duration(value: float, expected: str) -> None:
    assert console.format_duration(value) == expected


def test_format_timestamp_keeps_full_microsecond_precision() -> None:
    """Deriving microseconds from float arithmetic loses the last digit."""
    assert console.format_timestamp(1789061226.145231) == "17:27:06.145231"
    assert console.format_timestamp(1789061226.145231, with_date=True) == (
        "2026-09-10 17:27:06.145231"
    )


def test_format_timestamp_is_utc_not_local() -> None:
    """Epoch 0 is midnight UTC. In any other zone this would not be 00:00:00."""
    assert console.format_timestamp(0.0, with_date=True).startswith("1970-01-01 00:00:00")


def test_format_timestamp_of_none() -> None:
    assert console.format_timestamp(None) == "-"


def test_format_rate() -> None:
    assert console.format_rate(500) == "500 bps"
    assert console.format_rate(8500) == "8.5 kbps"
    assert console.format_rate(1_500_000) == "1.5 Mbps"


# ==========================================================================
# tables
# ==========================================================================


def test_table_sizes_columns_to_the_widest_cell() -> None:
    text = console.table(["A", "B"], [["short", "1"], ["much-longer-value", "22"]])
    lines = text.splitlines()
    assert "much-longer-value" in lines[3]
    # Header, rule and both rows line up on the same column boundary.
    assert len({len(line.rstrip()) - len(line.rstrip().split("  ")[-1]) for line in lines}) <= 2


def test_table_alignment_directives() -> None:
    text = console.table(["N"], [["1"], ["1000"]], align=">")
    assert "     1" in text.splitlines()[2]


def test_empty_table_says_none() -> None:
    assert console.table(["A"], []) == "  (none)"


def test_table_is_pure_ascii() -> None:
    """A legacy Windows code page will raise on box-drawing characters."""
    text = console.table(["HOST", "BYTES"], [["10.0.0.1", "1024"]])
    text.encode("ascii")  # would raise if anything fancy slipped in


# ==========================================================================
# the summary
# ==========================================================================


def test_summary_of_the_real_capture_has_every_section(sample_pcap: Path) -> None:
    stats, flows = analysed(sample_pcap)
    text = console.render_summary(stats, flows, source=str(sample_pcap))

    for heading in (
        "Capture summary",
        "Protocol breakdown",
        "Top talkers",
        "Top destination ports",
        "TCP flags",
        "ICMP types",
        "Conversations",
    ):
        assert heading in text, heading

    assert str(stats.packets) in text
    assert "TCP" in text and "UDP" in text and "ARP" in text


def test_summary_is_ascii_only(sample_pcap: Path) -> None:
    stats, flows = analysed(sample_pcap)
    console.render_summary(stats, flows).encode("ascii")


def test_empty_capture_says_so_instead_of_dividing_by_zero() -> None:
    assert "No packets matched" in console.render_summary(StatsCollector(), FlowTable())


def test_snapped_capture_is_called_out() -> None:
    stats, flows = StatsCollector(), FlowTable()
    raw = synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80)
    pkt = decode_frame(Frame(ts=1.0, data=raw[:40], orig_len=1514))
    stats.add(pkt)
    flows.add(pkt)
    assert "snapped" in console.render_summary(stats, flows)


def test_ports_table_names_well_known_services(sample_pcap: Path) -> None:
    stats, _ = analysed(sample_pcap)
    text = console.render_ports(stats, top=10)
    assert "bgp" in text, "port 179 is the busiest in this capture"
    assert "https" in text
    assert "dns" in text


def test_top_limits_the_table_rows(sample_pcap: Path) -> None:
    stats, flows = analysed(sample_pcap)
    short = console.render_summary(stats, flows, top=3)
    long = console.render_summary(stats, flows, top=10)
    assert len(short.splitlines()) < len(long.splitlines())


def test_print_summary_writes_to_the_given_stream(sample_pcap: Path) -> None:
    import io

    stats, flows = analysed(sample_pcap)
    buffer = io.StringIO()
    console.print_summary(stats, flows, stream=buffer)
    assert "Capture summary" in buffer.getvalue()


# ==========================================================================
# the live view
# ==========================================================================


def test_packet_line_is_tcpdump_shaped() -> None:
    line = console.packet_line(packet(synth.tcp_frame("10.0.0.1", 1234, "10.0.0.2", 80)))
    assert "10.0.0.1:1234 > 10.0.0.2:80 TCP" in line
    assert line.endswith("B")


def test_packet_line_with_index_and_relative_time() -> None:
    pkt = packet(synth.tcp_frame("10.0.0.1", 1234, "10.0.0.2", 80), ts=1000.5)
    line = console.packet_line(pkt, index=7, relative_to=1000.0)
    assert line.startswith("     7 ")
    assert "0.500000" in line


def test_packet_line_reports_a_decode_error() -> None:
    from tests.fixtures import headers

    line = console.packet_line(packet(headers.ETH_IPV4_TCP_SYN[:20]))
    assert "[" in line and "truncated" in line


def test_live_view_prints_packets_and_a_status_line() -> None:
    import io

    buffer = io.StringIO()
    view = console.LiveView(stream=buffer, status_every=3)
    for i in range(6):
        view.add(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80), ts=1000.0 + i))

    output = buffer.getvalue()
    assert output.count("10.0.0.1:1000 > 10.0.0.2:80") == 6
    assert output.count("... ") == 2, "a status line every third packet"
    assert view.count == 6


def test_live_view_can_show_only_status_lines() -> None:
    import io

    buffer = io.StringIO()
    view = console.LiveView(stream=buffer, status_every=2, show_packets=False)
    for i in range(4):
        view.add(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80), ts=1000.0 + i))
    assert "10.0.0.1:1000" not in buffer.getvalue()
    assert buffer.getvalue().count("... ") == 2


def test_supports_color_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    monkeypatch.setenv("NO_COLOR", "1")
    assert not console.supports_color(io.StringIO())


def test_supports_color_is_false_for_a_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    monkeypatch.delenv("NO_COLOR", raising=False)
    assert not console.supports_color(io.StringIO())


# ==========================================================================
# export
# ==========================================================================


def test_json_export_parses_and_reconciles(sample_pcap: Path, tmp_path: Path) -> None:
    stats, flows = analysed(sample_pcap)
    target = export.write_json(tmp_path / "s.json", stats, flows, source=str(sample_pcap))

    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["tool"] == "netsniff"
    assert data["capture"]["packets"] == stats.packets
    assert data["capture"]["bytes"] == stats.bytes
    assert data["flow_count"] == len(flows)
    assert len(data["flows"]) == len(flows)

    assert sum(f["packets"] for f in data["flows"]) == stats.packets
    assert sum(f["bytes"] for f in data["flows"]) == stats.bytes
    assert sum(p["packets"] for p in data["capture"]["protocols"]) == stats.packets


def test_json_flow_limit(sample_pcap: Path, tmp_path: Path) -> None:
    stats, flows = analysed(sample_pcap)
    target = export.write_json(tmp_path / "s.json", stats, flows, flows_in_json=5)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert len(data["flows"]) == 5
    assert data["flow_count"] == len(flows), "the count is still the real one"


def test_json_omits_detections_when_there_are_none(sample_pcap: Path, tmp_path: Path) -> None:
    stats, flows = analysed(sample_pcap)
    data = json.loads(
        export.write_json(tmp_path / "s.json", stats, flows).read_text(encoding="utf-8")
    )
    assert "detections" not in data


def test_csv_export_parses_and_reconciles(sample_pcap: Path, tmp_path: Path) -> None:
    stats, flows = analysed(sample_pcap)
    target = export.write_csv(tmp_path / "f.csv", flows)

    with target.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == len(flows)
    assert list(rows[0]) == list(export.FLOW_CSV_COLUMNS)
    assert sum(int(r["packets"]) for r in rows) == stats.packets
    assert sum(int(r["bytes"]) for r in rows) == stats.bytes

    for row in rows:
        assert int(row["packets"]) == int(row["packets_a_to_b"]) + int(row["packets_b_to_a"])
        assert int(row["bytes"]) == int(row["bytes_a_to_b"]) + int(row["bytes_b_to_a"])


def test_csv_has_no_stray_blank_lines(sample_pcap: Path, tmp_path: Path) -> None:
    """Without newline="" the csv module emits \\r\\r\\n on Windows."""
    _, flows = analysed(sample_pcap)
    target = export.write_csv(tmp_path / "f.csv", flows)
    raw = target.read_bytes()
    assert b"\r\r\n" not in raw


def test_csv_timestamps_are_present_in_both_forms(sample_pcap: Path, tmp_path: Path) -> None:
    _, flows = analysed(sample_pcap)
    target = export.write_csv(tmp_path / "f.csv", flows)
    with target.open(newline="", encoding="utf-8") as handle:
        row = next(iter(csv.DictReader(handle)))

    assert float(row["first_seen"]) > 1_600_000_000
    assert row["first_seen_utc"].endswith("+00:00")
    assert row["first_seen_utc"].startswith("20")


def test_csv_top_limit(sample_pcap: Path, tmp_path: Path) -> None:
    _, flows = analysed(sample_pcap)
    target = export.write_csv(tmp_path / "f.csv", flows, top=4)
    with target.open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 4


def test_export_of_an_empty_capture(tmp_path: Path) -> None:
    stats, flows = StatsCollector(), FlowTable()
    json_path = export.write_json(tmp_path / "s.json", stats, flows)
    csv_path = export.write_csv(tmp_path / "f.csv", flows)

    assert json.loads(json_path.read_text(encoding="utf-8"))["flow_count"] == 0
    with csv_path.open(newline="", encoding="utf-8") as handle:
        assert list(csv.DictReader(handle)) == []


# ==========================================================================
# the CLI
# ==========================================================================


def test_parser_builds_and_has_both_subcommands() -> None:
    parser = build_parser()
    args = parser.parse_args(["pcap", "x.pcap"])
    assert args.command == "pcap"
    assert args.top == 10

    args = parser.parse_args(["live", "--iface", "eth0"])
    assert args.command == "live"
    assert args.iface == "eth0"


def test_no_subcommand_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 1
    assert "usage:" in capsys.readouterr().out


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_pcap_run_prints_a_summary(sample_pcap: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["pcap", str(sample_pcap)]) == 0
    out = capsys.readouterr().out
    assert "Capture summary" in out
    assert "Protocol breakdown" in out


def test_pcap_run_writes_both_exports(sample_pcap: Path, tmp_path: Path) -> None:
    json_path = tmp_path / "s.json"
    csv_path = tmp_path / "f.csv"
    code = main(
        ["pcap", str(sample_pcap), "--quiet", "--json", str(json_path), "--csv", str(csv_path)]
    )
    assert code == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["capture"]["packets"] > 0
    assert csv_path.read_text(encoding="utf-8").startswith("protocol,")


def test_missing_file_is_a_message_not_a_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["pcap", "no-such-file.pcap"]) == 1
    assert "no such capture file" in capsys.readouterr().err


def test_pcapng_file_gets_the_specific_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "capture.pcapng"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    assert main(["pcap", str(bad)]) == 1
    assert "pcapng" in capsys.readouterr().err


def test_bad_top_value(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["pcap", "x.pcap", "--top", "0"]) == 1
    assert "--top must be at least 1" in capsys.readouterr().err


def test_count_stops_early(sample_pcap: Path, tmp_path: Path) -> None:
    json_path = tmp_path / "s.json"
    main(["pcap", str(sample_pcap), "--quiet", "--count", "10", "--json", str(json_path)])
    assert json.loads(json_path.read_text(encoding="utf-8"))["capture"]["packets"] == 10


def test_print_packets_emits_one_line_each(
    sample_pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["pcap", str(sample_pcap), "--count", "5", "--print-packets"])
    out = capsys.readouterr().out
    assert out.count(" > ") >= 5


# -- filters ---------------------------------------------------------------


def test_filter_with_no_options_keeps_everything() -> None:
    keep = make_filter()
    assert keep(packet(synth.tcp_frame("10.0.0.1", 1, "10.0.0.2", 2)))
    assert keep(packet(synth.arp_frame()))


def test_protocol_filter_is_case_insensitive() -> None:
    tcp = packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80))
    udp = packet(synth.udp_frame("10.0.0.1", 1000, "10.0.0.2", 53))

    for spelling in ("tcp", "TCP", "Tcp"):
        keep = make_filter(proto=spelling)
        assert keep(tcp)
        assert not keep(udp)


def test_host_filter_matches_either_direction() -> None:
    keep = make_filter(host="10.0.0.2")
    assert keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80)))
    assert keep(packet(synth.tcp_frame("10.0.0.2", 80, "10.0.0.1", 1000)))
    assert not keep(packet(synth.tcp_frame("10.0.0.3", 1000, "10.0.0.4", 80)))


def test_port_filter_matches_either_end() -> None:
    keep = make_filter(port=443)
    assert keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 443)))
    assert keep(packet(synth.tcp_frame("10.0.0.2", 443, "10.0.0.1", 1000)))
    assert not keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80)))


def test_filters_combine_as_and() -> None:
    keep = make_filter(proto="tcp", host="10.0.0.2", port=443)
    assert keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 443)))
    assert not keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.9", 443)))
    assert not keep(packet(synth.tcp_frame("10.0.0.1", 1000, "10.0.0.2", 80)))


def test_cli_filters_narrow_the_run(sample_pcap: Path, tmp_path: Path) -> None:
    everything = tmp_path / "all.json"
    just_udp = tmp_path / "udp.json"
    main(["pcap", str(sample_pcap), "--quiet", "--json", str(everything)])
    main(["pcap", str(sample_pcap), "--quiet", "--proto", "udp", "--json", str(just_udp)])

    total = json.loads(everything.read_text(encoding="utf-8"))["capture"]
    udp = json.loads(just_udp.read_text(encoding="utf-8"))["capture"]

    assert 0 < udp["packets"] < total["packets"]
    assert [p["protocol"] for p in udp["protocols"]] == ["UDP"]


def test_filter_matching_nothing_says_so(
    sample_pcap: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["pcap", str(sample_pcap), "--host", "203.0.113.99"]) == 0
    assert "No packets matched" in capsys.readouterr().out
