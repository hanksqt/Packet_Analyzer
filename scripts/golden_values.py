#!/usr/bin/env python3
"""Print the EXPECTED block for tests/test_end_to_end.py.

The end-to-end test asserts exact figures for the committed capture. That is the
point of it - a golden test with tolerances is not a golden test - but it does
mean regenerating ``tests/fixtures/sample.pcap`` invalidates them.

Rather than leaving whoever does that to work the numbers out by hand, this
prints the replacement block:

    python scripts/golden_values.py

Read the diff before pasting it in. These numbers are the assertion; if one of
them changed for a reason other than a new capture, that is a regression and
pasting over it would hide exactly what the test exists to catch.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from netsniff.analyze.flows import FlowTable  # noqa: E402
from netsniff.analyze.stats import StatsCollector  # noqa: E402
from netsniff.capture.pcap import PcapReader, read_pcap  # noqa: E402
from netsniff.decode import decode_frame  # noqa: E402

CAPTURE = REPO / "tests" / "fixtures" / "sample.pcap"


def main() -> int:
    if not CAPTURE.exists():
        print(f"no capture at {CAPTURE}", file=sys.stderr)
        return 1

    with PcapReader(CAPTURE) as reader:
        byte_order = reader.header.byte_order

    stats, flows = StatsCollector(), FlowTable()
    for frame in read_pcap(CAPTURE):
        packet = decode_frame(frame)
        stats.add(packet)
        flows.add(packet)

    protocols = {row.name: (row.packets, row.bytes) for row in stats.protocol_breakdown()}
    talkers = [
        (t.address, t.packets, t.bytes, t.bytes_sent, t.bytes_received)
        for t in stats.top_talkers_by_bytes(3)
    ]
    names = sorted(hint for hint in stats.app_hint_packets if "." in hint)

    def block(indent: str, items: list[str]) -> str:
        return "\n".join(f"{indent}{item}," for item in items)

    print("EXPECTED: dict[str, Any] = {")
    print(f'    "packets": {stats.packets},')
    print(f'    "bytes": {stats.bytes},')
    print(f'    "hosts": {len(stats.hosts)},')
    print(f'    "flows": {len(flows)},')
    print(f'    "duration": {round(stats.duration, 6)},')
    print(f'    "byte_order": "{byte_order}",')
    print("    # protocol -> (packets, bytes)")
    print('    "protocols": {')
    print(block("        ", [f'"{name}": {value}' for name, value in protocols.items()]))
    print("    },")
    print("    # address -> (packets, bytes, bytes_sent, bytes_received)")
    print('    "top_talkers": [')
    print(block("        ", [str(t) for t in talkers]))
    print("    ],")
    print(f'    "top_ports": {stats.top_ports(5)},')
    print(f'    "tcp_flags": {dict(stats.tcp_flag_packets)},')
    print(f'    "icmp_types": {dict(stats.icmp_type_packets)},')
    print(f'    "ip_versions": {dict(stats.ip_version_packets)},')
    print(f'    "unanswered_syn_flows": {len(flows.unanswered_syns())},')
    print('    "app_names": [')
    print(block("        ", [f'"{name}"' for name in names]))
    print("    ],")
    print("}")

    print()
    print("# Other assertions in test_end_to_end.py that name specific traffic:")
    for flow in flows.top_by_bytes(2):
        print(f"#   {flow.key}  {flow.packets} packets, {flow.bytes} bytes, {flow.state}")
        print(f"#     app hints: {list(flow.app_hints)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
