#!/usr/bin/env python3
"""Validate a netsniff JSON summary, then publish it to the CI job summary.

This is the step that makes a green check mean something beyond "the tests the
author wrote still pass". It runs the actual tool against the committed capture
and checks the output holds together:

* the per-protocol packet counts add up to the total
* the per-flow packet and byte counts add up to the total
* the percentages sum to 100
* the protocols and application-layer identifiers that are genuinely in that
  capture are genuinely in the output

The assertions are structural rather than a list of magic numbers on purpose.
Exact figures belong in ``tests/test_end_to_end.py``, which is version-controlled
alongside the capture that produces them; duplicating them here would mean
regenerating the fixture broke CI in two places instead of one.

Usage:
    python scripts/ci_summary.py summary.json
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REQUIRED_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP"}
REQUIRED_HINTS = {"DNS", "HTTP", "TLS"}


class CheckFailed(Exception):
    """A consistency check on the summary did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailed(message)


def validate(data: dict[str, Any]) -> list[str]:
    """Run every check, returning a list of one-line results."""
    results: list[str] = []
    capture = data["capture"]

    packets = capture["packets"]
    total_bytes = capture["bytes"]
    check(packets > 0, "the summary reports zero packets")
    results.append(f"{packets} packets, {total_bytes} bytes")

    protocol_packets = sum(row["packets"] for row in capture["protocols"])
    check(
        protocol_packets == packets,
        f"protocol counts sum to {protocol_packets}, but the capture has {packets} packets",
    )
    protocol_bytes = sum(row["bytes"] for row in capture["protocols"])
    check(
        protocol_bytes == total_bytes,
        f"protocol bytes sum to {protocol_bytes}, but the capture has {total_bytes}",
    )
    results.append("protocol breakdown adds up to the totals")

    packet_pct = sum(row["packet_pct"] for row in capture["protocols"])
    check(abs(packet_pct - 100.0) < 0.5, f"protocol percentages sum to {packet_pct}, not 100")
    results.append(f"percentages sum to {packet_pct:.1f}%")

    flow_packets = sum(flow["packets"] for flow in data["flows"])
    flow_bytes = sum(flow["bytes"] for flow in data["flows"])
    check(
        flow_packets == packets,
        f"flows account for {flow_packets} packets, but the capture has {packets}",
    )
    check(
        flow_bytes == total_bytes,
        f"flows account for {flow_bytes} bytes, but the capture has {total_bytes}",
    )
    results.append(f"{data['flow_count']} conversations account for every packet and byte")

    for flow in data["flows"]:
        check(
            flow["packets"] == flow["packets_a_to_b"] + flow["packets_b_to_a"],
            f"flow {flow['addr_a']} <-> {flow['addr_b']} has inconsistent direction counts",
        )
    results.append("every conversation's two directions sum to its total")

    seen_protocols = {row["protocol"] for row in capture["protocols"]}
    missing = REQUIRED_PROTOCOLS - seen_protocols
    check(not missing, f"the capture should contain {sorted(missing)} but the summary has none")
    results.append(f"decoded {', '.join(sorted(seen_protocols))}")

    hints = set(capture["app_hints"])
    hint_protocols = {h for h in hints if h in REQUIRED_HINTS or h.isupper()}
    named = {h for h in hints if "." in h}
    check(
        bool(named),
        "no application-layer names were extracted; DNS, HTTP and TLS hints all failed",
    )
    results.append(
        f"{len(named)} application-layer names extracted, e.g. {sorted(named)[0]}"
    )
    check(bool(hint_protocols), "no application protocols identified at all")

    check(capture["decode_errors"] == 0, f"{capture['decode_errors']} packets failed to decode")
    results.append("no decode errors")

    return results


def markdown(data: dict[str, Any], results: list[str]) -> str:
    capture = data["capture"]
    lines = [
        "## netsniff run against the committed capture",
        "",
        f"`{data['source']}` - {capture['packets']} packets, {capture['bytes']} bytes, "
        f"{capture['duration_seconds']:.2f}s, {capture['hosts']} hosts, "
        f"{data['flow_count']} conversations",
        "",
        "### Protocols",
        "",
        "| Protocol | Packets | Packet % | Bytes | Byte % |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in capture["protocols"]:
        lines.append(
            f"| {row['protocol']} | {row['packets']} | {row['packet_pct']:.1f}% "
            f"| {row['bytes']} | {row['byte_pct']:.1f}% |"
        )

    lines += ["", "### Top talkers", "", "| Host | Packets | Bytes | Sent | Received |",
              "|---|---:|---:|---:|---:|"]
    for talker in capture["top_talkers"][:5]:
        lines.append(
            f"| `{talker['address']}` | {talker['packets']} | {talker['bytes']} "
            f"| {talker['bytes_sent']} | {talker['bytes_received']} |"
        )

    named = sorted(h for h in capture["app_hints"] if "." in h)
    if named:
        lines += ["", "### Application-layer identifiers decoded from payloads", ""]
        lines.append(", ".join(f"`{name}`" for name in named[:15]))

    if data.get("detections"):
        lines += ["", "### Detections", ""]
        for finding in data["detections"]:
            lines.append(f"- **{finding['kind']}** - {finding['summary']}")

    lines += ["", "### Consistency checks", ""]
    lines += [f"- {result}" for result in results]

    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} summary.json", file=sys.stderr)
        return 2

    path = Path(argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))

    try:
        results = validate(data)
    except CheckFailed as exc:
        print(f"summary check failed: {exc}", file=sys.stderr)
        return 1
    except (KeyError, TypeError) as exc:
        print(f"summary is not the expected shape: {exc!r}", file=sys.stderr)
        return 1

    report = markdown(data, results)
    print(report)

    if step_summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(report)

    print(f"all {len(results)} consistency checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
