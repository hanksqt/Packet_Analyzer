"""Machine-readable output: a JSON summary and a CSV of conversations.

The JSON is built from :meth:`~netsniff.analyze.stats.StatsCollector.summary`,
the same structure the console tables render, so the two views cannot report
different numbers for the same capture.

The CSV holds one row per conversation with both directions broken out, which is
the shape that drops straight into a spreadsheet or a dataframe. Timestamps go
out twice - as a Unix epoch float for arithmetic and as an ISO-8601 UTC string
for reading - because converting between them afterwards is exactly the kind of
chore that produces off-by-one-timezone mistakes.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from netsniff.analyze.flows import Flow, FlowTable
from netsniff.analyze.stats import StatsCollector

__all__ = [
    "FLOW_CSV_COLUMNS",
    "build_summary",
    "flow_rows",
    "write_csv",
    "write_json",
]

FLOW_CSV_COLUMNS: Sequence[str] = (
    "protocol",
    "addr_a",
    "port_a",
    "addr_b",
    "port_b",
    "initiator",
    "packets",
    "bytes",
    "packets_a_to_b",
    "packets_b_to_a",
    "bytes_a_to_b",
    "bytes_b_to_a",
    "first_seen",
    "last_seen",
    "first_seen_utc",
    "last_seen_utc",
    "duration_seconds",
    "bidirectional",
    "state",
    "tcp_flags",
    "app_hints",
)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


def flow_rows(flows: Iterable[Flow]) -> list[dict[str, Any]]:
    """One dictionary per conversation, keyed by :data:`FLOW_CSV_COLUMNS`."""
    return [
        {
            "protocol": flow.key.protocol,
            "addr_a": flow.key.a_addr,
            "port_a": flow.key.a_port if flow.key.a_port is not None else "",
            "addr_b": flow.key.b_addr,
            "port_b": flow.key.b_port if flow.key.b_port is not None else "",
            "initiator": flow.initiator,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "packets_a_to_b": flow.packets_a_to_b,
            "packets_b_to_a": flow.packets_b_to_a,
            "bytes_a_to_b": flow.bytes_a_to_b,
            "bytes_b_to_a": flow.bytes_b_to_a,
            "first_seen": round(flow.first_seen, 6),
            "last_seen": round(flow.last_seen, 6),
            "first_seen_utc": _iso(flow.first_seen),
            "last_seen_utc": _iso(flow.last_seen),
            "duration_seconds": round(flow.duration, 6),
            "bidirectional": flow.is_bidirectional,
            "state": flow.state,
            "tcp_flags": flow.flag_string,
            "app_hints": ";".join(flow.app_hints),
        }
        for flow in flows
    ]


def build_summary(
    stats: StatsCollector,
    flow_table: FlowTable,
    *,
    source: str = "",
    top: int = 10,
    detections: list[dict[str, Any]] | None = None,
    flows_in_json: int | None = None,
) -> dict[str, Any]:
    """Assemble the full JSON structure.

    Args:
        flows_in_json: How many conversations to include, busiest first. None
            includes every one, which is right for a small capture and very
            wrong for a large one - hence the knob.
    """
    summary: dict[str, Any] = {
        "tool": "netsniff",
        "source": source,
        "capture": stats.summary(top=top),
        "flow_count": len(flow_table),
        "flows": flow_rows(
            flow_table.flows if flows_in_json is None else flow_table.top_by_bytes(flows_in_json)
        ),
    }
    if detections is not None:
        summary["detections"] = detections
    return summary


def write_json(
    path: str | Path,
    stats: StatsCollector,
    flow_table: FlowTable,
    *,
    source: str = "",
    top: int = 10,
    detections: list[dict[str, Any]] | None = None,
    flows_in_json: int | None = None,
    indent: int = 2,
) -> Path:
    """Write the JSON summary. Returns the path written."""
    target = Path(path)
    payload = build_summary(
        stats,
        flow_table,
        source=source,
        top=top,
        detections=detections,
        flows_in_json=flows_in_json,
    )
    # newline="" is not needed for JSON, but UTF-8 is: the summary can contain
    # a DNS name or an HTTP host with non-ASCII characters in it.
    with target.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent, sort_keys=False)
        handle.write("\n")
    return target


def write_csv_stream(handle: TextIO, flows: Iterable[Flow]) -> int:
    """Write conversation rows to an open text handle. Returns the row count."""
    writer = csv.DictWriter(handle, fieldnames=list(FLOW_CSV_COLUMNS))
    writer.writeheader()
    rows = flow_rows(flows)
    writer.writerows(rows)
    return len(rows)


def write_csv(path: str | Path, flow_table: FlowTable, *, top: int | None = None) -> Path:
    """Write one CSV row per conversation. Returns the path written."""
    target = Path(path)
    flows = flow_table.flows if top is None else flow_table.top_by_bytes(top)
    # newline="" is required, or csv emits \r\r\n on Windows.
    with target.open("w", encoding="utf-8", newline="") as handle:
        write_csv_stream(handle, flows)
    return target
