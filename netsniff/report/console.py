"""Console rendering: the end-of-run summary and the live rolling view.

Everything here builds strings and hands them back, rather than printing from
deep inside a helper. That keeps the rendering testable - the tests assert on
returned text - and it means the same functions can feed a file, a pipe or a
terminal without caring which.

Tables are drawn with plain ASCII rather than box-drawing characters. A Windows
console under a legacy code page will happily raise UnicodeEncodeError on a nice
box corner, and a summary that crashes at the last moment is worse than a
summary drawn with dashes.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import TextIO

from netsniff.analyze.flows import Flow, FlowTable
from netsniff.analyze.stats import StatsCollector
from netsniff.decode import DecodedPacket
from netsniff.decode.apphint import service_name

__all__ = [
    "format_bytes",
    "format_duration",
    "format_timestamp",
    "packet_line",
    "print_summary",
    "render_summary",
    "table",
]


# --------------------------------------------------------------------------
# value formatting
# --------------------------------------------------------------------------


def format_bytes(count: float) -> str:
    """Human-readable byte count, using binary units."""
    if count < 1024:
        return f"{int(count)} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        count /= 1024.0
        if count < 1024 or unit == "TiB":
            return f"{count:.1f} {unit}"
    return f"{count:.1f} TiB"  # pragma: no cover - unreachable, loop returns first


def format_duration(seconds: float) -> str:
    """Readable duration, scaled to something a human can read at a glance."""
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f}us"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m{secs:04.1f}s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h{minutes:02d}m"


def format_timestamp(ts: float | None, *, with_date: bool = False) -> str:
    """Format a capture timestamp in UTC.

    UTC rather than local time on purpose: a capture is often analysed
    somewhere other than where it was taken, and a summary that silently shifts
    by the reader's offset is a nuisance to correlate against anything.
    """
    if ts is None:
        return "-"
    moment = datetime.fromtimestamp(ts, tz=timezone.utc)
    pattern = "%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S"
    # Take the microseconds from the datetime, not from (ts % 1) * 1e6: the
    # float version truncates .145231 to .145230 often enough to matter when
    # you are lining timestamps up against another tool's output.
    return f"{moment.strftime(pattern)}.{moment.microsecond:06d}"


def format_rate(bits_per_second: float) -> str:
    if bits_per_second < 1000:
        return f"{bits_per_second:.0f} bps"
    for unit in ("kbps", "Mbps", "Gbps"):
        bits_per_second /= 1000.0
        if bits_per_second < 1000 or unit == "Gbps":
            return f"{bits_per_second:.1f} {unit}"
    return f"{bits_per_second:.1f} Gbps"  # pragma: no cover


# --------------------------------------------------------------------------
# tables
# --------------------------------------------------------------------------


def table(
    headings: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    align: str = "",
    indent: str = "  ",
) -> str:
    """Render an ASCII table, sizing each column to its widest cell.

    Args:
        headings: Column titles.
        rows: Cell text, already stringified.
        align: One character per column, ``<`` for left or ``>`` for right.
            Short strings are padded with ``<``.
        indent: Prefix for every line.
    """
    if not rows:
        return f"{indent}(none)"

    columns = len(headings)
    align = (align + "<" * columns)[:columns]
    widths = [len(h) for h in headings]
    for row in rows:
        for i, cell in enumerate(row[:columns]):
            widths[i] = max(widths[i], len(cell))

    def line(cells: Sequence[str]) -> str:
        parts = [f"{cell:{align[i]}{widths[i]}}" for i, cell in enumerate(cells[:columns])]
        return indent + "  ".join(parts).rstrip()

    rule = indent + "  ".join("-" * w for w in widths)
    return "\n".join([line(headings), rule, *(line(r) for r in rows)])


def _heading(text: str) -> str:
    return f"\n{text}\n{'=' * len(text)}"


# --------------------------------------------------------------------------
# the summary
# --------------------------------------------------------------------------


def render_overview(stats: StatsCollector, *, source: str = "") -> str:
    """The headline block: how much traffic, over how long, from where."""
    lines = [_heading("Capture summary")]
    if source:
        lines.append(f"  source          {source}")
    lines += [
        f"  packets         {stats.packets}",
        f"  bytes on wire   {stats.bytes} ({format_bytes(stats.bytes)})",
    ]
    if stats.was_snapped:
        lines.append(
            f"  bytes captured  {stats.captured_bytes} "
            f"({format_bytes(stats.captured_bytes)}) - "
            f"{stats.truncated_packets} packets were snapped"
        )
    lines += [
        f"  duration        {format_duration(stats.duration)}",
        f"  first packet    {format_timestamp(stats.first_seen, with_date=True)} UTC",
        f"  last packet     {format_timestamp(stats.last_seen, with_date=True)} UTC",
        f"  average size    {stats.average_packet_size:.0f} B",
        f"  rate            {stats.packets_per_second:.1f} pkt/s, "
        f"{format_rate(stats.bits_per_second)}",
        f"  hosts seen      {len(stats.hosts)}",
    ]
    if stats.decode_errors:
        lines.append(f"  decode errors   {stats.decode_errors}")
    return "\n".join(lines)


def render_protocols(stats: StatsCollector) -> str:
    rows = [
        [
            row.name,
            str(row.packets),
            f"{row.packet_pct:.1f}%",
            format_bytes(row.bytes),
            f"{row.byte_pct:.1f}%",
        ]
        for row in stats.protocol_breakdown()
    ]
    return _heading("Protocol breakdown") + "\n" + table(
        ["PROTOCOL", "PACKETS", "PKT %", "BYTES", "BYTE %"], rows, align="<>>>>"
    )


def render_talkers(stats: StatsCollector, *, top: int = 10) -> str:
    rows = [
        [
            t.address,
            str(t.packets),
            format_bytes(t.bytes),
            format_bytes(t.bytes_sent),
            format_bytes(t.bytes_received),
        ]
        for t in stats.top_talkers_by_bytes(top)
    ]
    return _heading(f"Top talkers (by bytes, top {top})") + "\n" + table(
        ["HOST", "PACKETS", "TOTAL", "SENT", "RECEIVED"], rows, align="<>>>>"
    )


def render_ports(stats: StatsCollector, *, top: int = 10) -> str:
    rows = [
        [str(port), service_name(port), str(packets)]
        for port, packets in stats.top_ports(top)
    ]
    return _heading(f"Top destination ports (top {top})") + "\n" + table(
        ["PORT", "SERVICE", "PACKETS"], rows, align="><>"
    )


def render_flows(flows: Iterable[Flow], *, top: int = 10) -> str:
    rows = [
        [
            f.key.protocol,
            f.key.endpoint_a,
            "<->" if f.is_bidirectional else " ->",
            f.key.endpoint_b,
            str(f.packets),
            format_bytes(f.bytes),
            format_duration(f.duration),
            f.state,
            ",".join(f.app_hints)[:28],
        ]
        for f in flows
    ]
    return _heading(f"Top conversations (by bytes, top {top})") + "\n" + table(
        ["PROTO", "ENDPOINT A", "", "ENDPOINT B", "PKTS", "BYTES", "DURATION", "STATE", "APP"],
        rows,
        align="<<^<>>><<",
    )


def render_tcp_flags(stats: StatsCollector) -> str:
    if not stats.tcp_flag_packets:
        return ""
    rows = [[name, str(count)] for name, count in stats.tcp_flag_packets.most_common()]
    return _heading("TCP flags") + "\n" + table(["FLAG", "PACKETS"], rows, align="<>")


def render_icmp(stats: StatsCollector) -> str:
    if not stats.icmp_type_packets:
        return ""
    rows = [[name, str(count)] for name, count in stats.icmp_type_packets.most_common()]
    return _heading("ICMP types") + "\n" + table(["TYPE", "PACKETS"], rows, align="<>")


def render_app_hints(stats: StatsCollector, *, top: int = 15) -> str:
    if not stats.app_hint_packets:
        return ""
    rows = [[name, str(count)] for name, count in stats.app_hint_packets.most_common(top)]
    return _heading(f"Application-layer hints (top {top})") + "\n" + table(
        ["IDENTIFIER", "PACKETS"], rows, align="<>"
    )


def render_vlans(stats: StatsCollector) -> str:
    if not stats.vlan_packets:
        return ""
    rows = [[str(vid), str(count)] for vid, count in sorted(stats.vlan_packets.items())]
    return _heading("VLANs") + "\n" + table(["VLAN", "PACKETS"], rows, align="><")


def render_summary(
    stats: StatsCollector,
    flow_table: FlowTable,
    *,
    top: int = 10,
    source: str = "",
    detections: str = "",
) -> str:
    """The whole end-of-run report."""
    if stats.packets == 0:
        return "\nNo packets matched.\n"

    sections = [
        render_overview(stats, source=source),
        render_protocols(stats),
        render_vlans(stats),
        render_talkers(stats, top=top),
        render_ports(stats, top=top),
        render_tcp_flags(stats),
        render_icmp(stats),
        render_app_hints(stats),
        _heading(f"Conversations ({len(flow_table)} total)")
        + "\n"
        + table(
            ["PROTO", "ENDPOINT A", "", "ENDPOINT B", "PKTS", "BYTES", "DURATION", "STATE", "APP"],
            [
                [
                    f.key.protocol,
                    f.key.endpoint_a,
                    "<->" if f.is_bidirectional else " ->",
                    f.key.endpoint_b,
                    str(f.packets),
                    format_bytes(f.bytes),
                    format_duration(f.duration),
                    f.state,
                    ",".join(f.app_hints)[:28],
                ]
                for f in flow_table.top_by_bytes(top)
            ],
            align="<<^<>>><<",
        ),
        detections,
    ]
    return "\n".join(s for s in sections if s) + "\n"


def print_summary(
    stats: StatsCollector,
    flow_table: FlowTable,
    *,
    top: int = 10,
    source: str = "",
    detections: str = "",
    stream: TextIO | None = None,
) -> None:
    """Write the summary to a stream, defaulting to stdout."""
    print(
        render_summary(
            stats, flow_table, top=top, source=source, detections=detections
        ),
        file=stream or sys.stdout,
    )


# --------------------------------------------------------------------------
# the live rolling view
# --------------------------------------------------------------------------


def packet_line(
    packet: DecodedPacket, *, index: int | None = None, relative_to: float = 0.0
) -> str:
    """One line per packet, in the shape tcpdump uses.

    Args:
        packet: A :class:`~netsniff.decode.DecodedPacket`.
        index: Packet number to print, or None to omit it.
        relative_to: Subtract this from the timestamp, so a live run can show
            seconds since it started rather than a Unix epoch.
    """
    if relative_to:
        stamp = f"{packet.timestamp - relative_to:9.6f}"
    else:
        stamp = format_timestamp(packet.timestamp)

    prefix = f"{index:>6} " if index is not None else ""
    line = f"{prefix}{stamp} {packet}  {packet.length}B"

    if (label := getattr(packet.app, "label", None)) is not None:
        line += f"  {label}"
    if packet.errors:
        line += f"  [{packet.errors[0]}]"
    return line


class LiveView:
    """Prints packets as they arrive, with a periodic one-line status.

    Deliberately line-oriented rather than a full-screen redraw: the output
    stays useful when it is piped to a file or a pager, which a curses-style
    display would not be.
    """

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        status_every: int = 100,
        show_packets: bool = True,
    ) -> None:
        self.stream = stream or sys.stdout
        self.status_every = status_every
        self.show_packets = show_packets
        self.started: float | None = None
        self.count = 0

    def add(self, packet: DecodedPacket) -> None:
        """Print one packet, and a status line every ``status_every`` packets."""
        timestamp = packet.timestamp
        if self.started is None:
            self.started = timestamp
        self.count += 1

        if self.show_packets:
            print(
                packet_line(packet, index=self.count, relative_to=self.started),
                file=self.stream,
                flush=False,
            )

        if self.status_every and self.count % self.status_every == 0:
            self.status(packet)

    def status(self, packet: DecodedPacket) -> None:
        elapsed = packet.timestamp - (self.started or 0.0)
        rate = self.count / elapsed if elapsed > 0 else 0.0
        print(
            f"  ... {self.count} packets, {format_duration(elapsed)}, {rate:.0f} pkt/s",
            file=self.stream,
            flush=True,
        )


def supports_color(stream: TextIO | None = None) -> bool:
    """Whether it is reasonable to emit ANSI colour to this stream.

    Respects the NO_COLOR convention, and refuses when the output is not a
    terminal so that colour codes never end up inside a redirected file.
    """
    if os.environ.get("NO_COLOR"):
        return False
    target = stream or sys.stdout
    return bool(getattr(target, "isatty", lambda: False)())
