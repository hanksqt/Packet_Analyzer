"""Detection heuristics.

Mostly synthetic traffic, because the shapes being detected - a host touching
forty ports, a host sweeping a subnet - are ones a real capture of ordinary
browsing does not contain, and manufacturing them is the honest way to test for
them.

The tests that matter most are the negative ones. A detector that fires on a
normal web session is worse than no detector, because a summary full of false
alarms gets skipped, and then the real findings go unread too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsniff.analyze.detect import (
    DEFAULT_THRESHOLDS,
    MAX_EVIDENCE,
    Detection,
    Thresholds,
    detect_all,
    detect_horizontal_sweep,
    detect_unanswered_connections,
    detect_vertical_scan,
    render_detections,
)
from netsniff.analyze.flows import FlowTable
from netsniff.capture.base import Frame
from netsniff.capture.pcap import read_pcap
from netsniff.decode import decode_frame
from tests.fixtures import synth


def table_from(frames: list[tuple[bytes, float]]) -> FlowTable:
    table = FlowTable()
    for raw, ts in frames:
        table.add(decode_frame(Frame(ts=ts, data=raw)))
    return table


def scan_frames(
    source: str,
    targets: list[tuple[str, int]],
    *,
    answered: bool = False,
    start: float = 1000.0,
    step: float = 0.01,
) -> list[tuple[bytes, float]]:
    """SYNs from one source to a list of (host, port) pairs."""
    frames = []
    for i, (host, port) in enumerate(targets):
        ts = start + i * step
        frames.append(
            (synth.tcp_frame(source, 40000 + i, host, port, flags=synth.SYN), ts)
        )
        if answered:
            frames.append(
                (
                    synth.tcp_frame(host, port, source, 40000 + i, flags=synth.SYN | synth.ACK),
                    ts + step / 2,
                )
            )
    return frames


# ==========================================================================
# vertical scan: one source, one host, many ports
# ==========================================================================


def test_vertical_scan_is_found() -> None:
    targets = [("10.0.0.9", port) for port in range(20, 60)]
    table = table_from(scan_frames("10.0.0.5", targets))

    findings = detect_vertical_scan(table)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.kind == "vertical-scan"
    assert finding.source == "10.0.0.5"
    assert finding.count == 40
    assert "40 distinct ports" in finding.summary
    assert "10.0.0.9" in finding.summary
    assert finding.caveat, "every heuristic states what benign traffic looks the same"


def test_vertical_scan_below_the_threshold_is_not_reported() -> None:
    targets = [("10.0.0.9", port) for port in range(20, 20 + DEFAULT_THRESHOLDS.vertical_ports - 1)]
    assert detect_vertical_scan(table_from(scan_frames("10.0.0.5", targets))) == []


def test_vertical_scan_threshold_is_configurable() -> None:
    targets = [("10.0.0.9", port) for port in (22, 80, 443, 8080)]
    table = table_from(scan_frames("10.0.0.5", targets))

    assert detect_vertical_scan(table) == [], "four ports is under the default"
    assert len(detect_vertical_scan(table, Thresholds(vertical_ports=4))) == 1


def test_a_scan_spread_over_hours_is_not_reported() -> None:
    """Scans are fast. A host that touches forty ports over a day is working."""
    targets = [("10.0.0.9", port) for port in range(20, 60)]
    slow = scan_frames("10.0.0.5", targets, step=3600.0)
    assert detect_vertical_scan(table_from(slow)) == []


def test_answered_connections_still_count_as_a_scan_but_are_reported_as_such() -> None:
    """An open port answers. A scan that finds forty open ports is still a scan."""
    targets = [("10.0.0.9", port) for port in range(20, 60)]
    findings = detect_vertical_scan(table_from(scan_frames("10.0.0.5", targets, answered=True)))
    assert len(findings) == 1
    assert "(0 got no SYN-ACK)" in findings[0].summary


def test_two_sources_scanning_are_two_findings() -> None:
    frames = scan_frames("10.0.0.5", [("10.0.0.9", p) for p in range(20, 60)])
    frames += scan_frames("10.0.0.6", [("10.0.0.9", p) for p in range(20, 60)], start=1100.0)

    findings = detect_vertical_scan(table_from(frames))
    assert {f.source for f in findings} == {"10.0.0.5", "10.0.0.6"}


def test_scan_direction_follows_the_initiator_not_the_key_order() -> None:
    """The flow key sorts endpoints; the scanner is whoever sent the SYN.

    Here the scanner has the numerically higher address, so it is endpoint B in
    every flow. A detector reading the key instead of the initiator would blame
    the victim.
    """
    targets = [("10.0.0.1", port) for port in range(20, 60)]
    findings = detect_vertical_scan(table_from(scan_frames("10.0.0.99", targets)))
    assert len(findings) == 1
    assert findings[0].source == "10.0.0.99"


# ==========================================================================
# horizontal sweep: one source, one port, many hosts
# ==========================================================================


def test_horizontal_sweep_is_found() -> None:
    targets = [(f"10.0.0.{host}", 445) for host in range(1, 40)]
    findings = detect_horizontal_sweep(table_from(scan_frames("192.168.1.5", targets)))

    assert len(findings) == 1
    assert findings[0].kind == "horizontal-sweep"
    assert findings[0].source == "192.168.1.5"
    assert findings[0].count == 39
    assert "port 445" in findings[0].summary


def test_sweep_below_the_threshold_is_not_reported() -> None:
    targets = [(f"10.0.0.{h}", 445) for h in range(1, DEFAULT_THRESHOLDS.horizontal_hosts)]
    assert detect_horizontal_sweep(table_from(scan_frames("192.168.1.5", targets))) == []


def test_one_host_on_many_ports_is_not_a_sweep() -> None:
    """The two detectors must not fire on each other's shape."""
    targets = [("10.0.0.9", port) for port in range(20, 60)]
    assert detect_horizontal_sweep(table_from(scan_frames("10.0.0.5", targets))) == []


def test_many_hosts_on_many_ports_is_not_a_sweep_on_any_one_port() -> None:
    targets = [(f"10.0.0.{h}", 1000 + h) for h in range(1, 40)]
    assert detect_horizontal_sweep(table_from(scan_frames("10.0.0.200", targets))) == []


# ==========================================================================
# unanswered connections
# ==========================================================================


def test_unanswered_connections_are_found() -> None:
    targets = [(f"10.0.0.{h}", 22) for h in range(1, 30)]
    findings = detect_unanswered_connections(table_from(scan_frames("10.0.0.200", targets)))

    assert len(findings) == 1
    assert findings[0].kind == "unanswered-connections"
    assert findings[0].count == 29
    assert "never" in findings[0].summary


def test_answered_connections_are_not_reported() -> None:
    targets = [(f"10.0.0.{h}", 22) for h in range(1, 30)]
    frames = scan_frames("10.0.0.200", targets, answered=True)
    assert detect_unanswered_connections(table_from(frames)) == []


def test_a_handful_of_failures_is_not_worth_reporting() -> None:
    targets = [(f"10.0.0.{h}", 22) for h in range(1, 4)]
    assert detect_unanswered_connections(table_from(scan_frames("10.0.0.200", targets))) == []


def test_udp_traffic_is_never_a_tcp_finding() -> None:
    table = FlowTable()
    for i in range(40):
        table.add(
            decode_frame(
                Frame(1000.0 + i, synth.udp_frame("10.0.0.5", 40000 + i, "10.0.0.9", 53))
            )
        )
    assert detect_all(table) == []


# ==========================================================================
# not firing on ordinary traffic
# ==========================================================================


def test_a_normal_web_session_triggers_nothing() -> None:
    """The negative case that decides whether anyone reads the output."""
    frames = []
    ts = 1000.0
    for port in (80, 443):
        frames.append((synth.tcp_frame("10.0.0.5", 52000 + port, "93.184.216.34", port,
                                       flags=synth.SYN), ts))
        frames.append((synth.tcp_frame("93.184.216.34", port, "10.0.0.5", 52000 + port,
                                       flags=synth.SYN | synth.ACK), ts + 0.02))
        for i in range(20):
            frames.append((synth.tcp_frame("93.184.216.34", port, "10.0.0.5", 52000 + port,
                                           flags=synth.PSH | synth.ACK,
                                           payload=b"x" * 1400), ts + 0.03 + i * 0.001))
        ts += 1.0

    assert detect_all(table_from(frames)) == []


def test_a_busy_client_with_many_connections_to_one_service_is_not_a_scan() -> None:
    """Twenty connections to one port is a connection pool, not a scan."""
    frames = []
    for i in range(20):
        ts = 1000.0 + i * 0.1
        frames.append((synth.tcp_frame("10.0.0.5", 40000 + i, "10.0.0.9", 443,
                                       flags=synth.SYN), ts))
        frames.append((synth.tcp_frame("10.0.0.9", 443, "10.0.0.5", 40000 + i,
                                       flags=synth.SYN | synth.ACK), ts + 0.01))
    assert detect_all(table_from(frames)) == []


def test_an_empty_capture_produces_nothing() -> None:
    assert detect_all(FlowTable()) == []


# ==========================================================================
# reporting
# ==========================================================================


def test_evidence_is_capped_so_a_big_scan_does_not_flood_the_report() -> None:
    targets = [("10.0.0.9", port) for port in range(1, 500)]
    finding = detect_vertical_scan(table_from(scan_frames("10.0.0.5", targets)))[0]

    assert finding.count == 499
    assert len(finding.evidence) == MAX_EVIDENCE


def test_render_shows_the_finding_the_evidence_and_the_caveat() -> None:
    targets = [("10.0.0.9", port) for port in range(20, 60)]
    text = render_detections(detect_all(table_from(scan_frames("10.0.0.5", targets))))

    assert "Detections" in text
    assert "[vertical-scan]" in text
    assert "seen:" in text
    assert "note:" in text
    assert "reported and not acted on" in text, "say plainly that nothing is blocked"


def test_render_of_nothing_is_empty_not_a_heading() -> None:
    assert render_detections([]) == ""


def test_evidence_line_says_how_many_more_there_were() -> None:
    targets = [("10.0.0.9", port) for port in range(1, 500)]
    text = render_detections(detect_vertical_scan(table_from(scan_frames("10.0.0.5", targets))))
    assert "and 487 more" in text


def test_detection_serialises_to_plain_json_able_data() -> None:
    import json

    targets = [("10.0.0.9", port) for port in range(20, 60)]
    findings = detect_all(table_from(scan_frames("10.0.0.5", targets)))
    payload = [f.to_dict() for f in findings]

    assert json.loads(json.dumps(payload)) == payload
    assert payload[0]["kind"]
    assert payload[0]["caveat"], "the caveat travels with the finding into JSON"


def test_findings_are_ordered_most_significant_first() -> None:
    frames = scan_frames("10.0.0.5", [("10.0.0.9", p) for p in range(20, 100)])
    frames += scan_frames("10.0.0.6", [("10.0.0.8", p) for p in range(20, 35)], start=2000.0)

    findings = detect_all(table_from(frames))
    counts = [f.count for f in findings]
    assert counts == sorted(counts, reverse=True)


def test_detection_duration_is_derived() -> None:
    finding = Detection(
        kind="x", source="1.1.1.1", summary="s", count=1, first_seen=100.0, last_seen=103.5
    )
    assert finding.duration == pytest.approx(3.5)
    assert str(finding) == "s"


# ==========================================================================
# against the real capture and through the CLI
# ==========================================================================


def test_real_capture_produces_no_spurious_findings(sample_pcap: Path) -> None:
    """Whatever the capture contains, every default-threshold finding is earned.

    Written as a property rather than as ``== []`` on purpose. The committed
    capture's deliberate probe currently sits under the default of ten, so today
    this list is empty - but ``scripts/capture_sample.sh`` can be re-run with a
    wider probe, and a test that hardcoded emptiness would fail on a fixture
    that is more useful, not less. What must hold either way is that nothing is
    reported unless the evidence actually crosses the threshold.
    """
    table = FlowTable()
    for frame in read_pcap(sample_pcap):
        table.add(decode_frame(frame))

    for finding in detect_all(table):
        threshold = {
            "vertical-scan": DEFAULT_THRESHOLDS.vertical_ports,
            "horizontal-sweep": DEFAULT_THRESHOLDS.horizontal_hosts,
            "unanswered-connections": DEFAULT_THRESHOLDS.unanswered,
        }[finding.kind]
        assert finding.count >= threshold, f"{finding.kind} reported below its threshold"
        assert finding.duration <= DEFAULT_THRESHOLDS.window_seconds
        assert finding.caveat, "every finding states what benign traffic looks the same"


def test_real_capture_probe_is_found_when_thresholds_match_its_size(
    sample_pcap: Path,
) -> None:
    """The capture script deliberately probes closed ports on the gateway."""
    table = FlowTable()
    for frame in read_pcap(sample_pcap):
        table.add(decode_frame(frame))

    findings = detect_all(table, Thresholds(vertical_ports=4, unanswered=4))
    kinds = {f.kind for f in findings}
    assert "vertical-scan" in kinds
    assert "unanswered-connections" in kinds

    scan = next(f for f in findings if f.kind == "vertical-scan")
    assert scan.count >= 4
    assert all(":" in item for item in scan.evidence)


def test_cli_reports_detections(sample_pcap: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from netsniff.cli import main

    assert main(["pcap", str(sample_pcap), "--scan-ports", "4", "--scan-unanswered", "4"]) == 0
    assert "Detections" in capsys.readouterr().out


def test_cli_can_turn_detection_off(sample_pcap: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from netsniff.cli import main

    main(["pcap", str(sample_pcap), "--scan-ports", "4", "--scan-unanswered", "4", "--no-detect"])
    assert "Detections" not in capsys.readouterr().out


def test_detections_reach_the_json_export(sample_pcap: Path, tmp_path: Path) -> None:
    import json

    from netsniff.cli import main

    target = tmp_path / "s.json"
    main(
        [
            "pcap", str(sample_pcap), "--quiet",
            "--scan-ports", "4", "--scan-unanswered", "4",
            "--json", str(target),
        ]
    )
    data = json.loads(target.read_text(encoding="utf-8"))
    assert "detections" in data
    assert any(d["kind"] == "vertical-scan" for d in data["detections"])
    assert all(d["caveat"] for d in data["detections"])
