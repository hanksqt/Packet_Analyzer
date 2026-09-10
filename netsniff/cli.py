"""Command line entry point.

Two subcommands. ``pcap`` reads a capture file and runs anywhere with no
privileges; ``live`` opens a raw socket and needs Linux and root. Everything
between the capture source and the output is identical, which is the whole point
of the ``Frame`` contract - the analysis code cannot tell the two apart.

Filtering is done with simple predicates applied *after* decoding, not with BPF.
Compiling a BPF expression is a rabbit hole of its own and would not make the
decoders any better, so ``--proto``, ``--host`` and ``--port`` are exactly what
they look like: a test run against each decoded packet. The practical difference
is efficiency, not capability - a real BPF filter would drop packets in the
kernel before they were ever copied to us.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TextIO

from netsniff import __version__
from netsniff.analyze.flows import FlowTable
from netsniff.analyze.stats import StatsCollector
from netsniff.capture.base import CaptureError, Frame
from netsniff.decode import DecodedPacket, decode_frame
from netsniff.report import console, export

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


# --------------------------------------------------------------------------
# argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsniff",
        description=(
            "Decode Ethernet frames from a pcap file or a live interface, track "
            "conversations, and report protocol shares, top talkers and simple anomalies."
        ),
        epilog=(
            "Filters are predicates applied after decoding, not BPF. "
            "Live capture needs Linux and root; the pcap reader needs neither."
        ),
    )
    parser.add_argument("--version", action="version", version=f"netsniff {__version__}")

    subcommands = parser.add_subparsers(dest="command", metavar="{pcap,live}")

    # -- shared options ----------------------------------------------------
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--top", type=int, default=10, metavar="N", help="rows per summary table (default: 10)"
    )
    common.add_argument("--proto", metavar="NAME", help="keep only this protocol, e.g. tcp")
    common.add_argument(
        "--host", metavar="ADDR", help="keep only packets to or from this address"
    )
    common.add_argument(
        "--port", type=int, metavar="PORT", help="keep only packets to or from this port"
    )
    common.add_argument("--json", metavar="FILE", help="write the summary as JSON")
    common.add_argument("--csv", metavar="FILE", help="write conversations as CSV")
    common.add_argument(
        "--quiet", action="store_true", help="suppress the summary, for export-only runs"
    )

    pcap = subcommands.add_parser(
        "pcap",
        parents=[common],
        help="analyse a capture file",
        description="Read a classic libpcap file and summarise it. No privileges needed.",
    )
    pcap.add_argument("file", help="path to a .pcap file (classic libpcap, not pcapng)")
    pcap.add_argument(
        "--count", type=int, metavar="N", help="stop after N packets have matched"
    )
    pcap.add_argument(
        "--print-packets",
        action="store_true",
        help="print one line per packet before the summary",
    )

    live = subcommands.add_parser(
        "live",
        parents=[common],
        help="capture from an interface (Linux, root)",
        description=(
            "Capture live from an interface with AF_PACKET. Linux only, and needs "
            "root or the CAP_NET_RAW capability."
        ),
    )
    live.add_argument("--iface", "-i", required=True, metavar="NAME", help="interface to capture")
    live.add_argument(
        "--count", type=int, metavar="N", help="stop after N packets have matched"
    )
    live.add_argument(
        "--timeout", type=float, metavar="SECONDS", help="stop after this many seconds"
    )
    live.add_argument(
        "--snaplen",
        type=int,
        default=65535,
        metavar="BYTES",
        help="bytes to capture per packet (default: 65535)",
    )
    live.add_argument(
        "--no-promiscuous",
        action="store_true",
        help="do not put the interface into promiscuous mode",
    )
    live.add_argument(
        "--print-packets",
        action="store_true",
        default=True,
        help="print one line per packet as it arrives (default for live)",
    )
    live.add_argument(
        "--no-print-packets",
        dest="print_packets",
        action="store_false",
        help="show only periodic status lines, not every packet",
    )

    return parser


# --------------------------------------------------------------------------
# filtering
# --------------------------------------------------------------------------


def make_filter(
    *, proto: str | None = None, host: str | None = None, port: int | None = None
) -> Callable[[DecodedPacket], bool]:
    """Build a predicate over decoded packets from the CLI filter options.

    Returns a callable that is True for packets to keep. With no options set it
    is a constant True, so the caller does not need a separate no-filter path.
    """
    wanted_proto = proto.upper() if proto else None

    def keep(packet: DecodedPacket) -> bool:
        if wanted_proto is not None and packet.protocol.upper() != wanted_proto:
            return False
        if host is not None and host not in (packet.src_addr, packet.dst_addr):
            return False
        return port is None or port in (packet.src_port, packet.dst_port)

    return keep


# --------------------------------------------------------------------------
# the shared analysis loop
# --------------------------------------------------------------------------


def analyse(
    frames: Iterator[Frame],
    args: argparse.Namespace,
    *,
    stream: TextIO | None = None,
) -> tuple[StatsCollector, FlowTable]:
    """Decode, filter and accumulate. Shared by both subcommands.

    Neither capture source appears here: both hand over ``Frame`` objects and
    this loop cannot tell which one it is reading.
    """
    out = stream or sys.stdout
    stats = StatsCollector()
    flows = FlowTable()
    keep = make_filter(proto=args.proto, host=args.host, port=args.port)

    view = None
    if getattr(args, "print_packets", False) and not args.quiet:
        view = console.LiveView(stream=out, show_packets=True)

    limit = getattr(args, "count", None)
    matched = 0

    for frame in frames:
        packet = decode_frame(frame)
        if not keep(packet):
            continue

        stats.add(packet)
        flows.add(packet)
        matched += 1
        if view is not None:
            view.add(packet)

        if limit is not None and matched >= limit:
            break

    return stats, flows


def report(
    stats: StatsCollector,
    flows: FlowTable,
    args: argparse.Namespace,
    *,
    source: str,
    stream: TextIO | None = None,
) -> None:
    """Render the summary and write any requested exports."""
    out = stream or sys.stdout

    detections_text = ""
    detections_data = None
    if hasattr(args, "detect_results"):
        detections_text, detections_data = args.detect_results

    if not args.quiet:
        console.print_summary(
            stats,
            flows,
            top=args.top,
            source=source,
            detections=detections_text,
            stream=out,
        )

    if args.json:
        path = export.write_json(
            args.json, stats, flows, source=source, top=args.top, detections=detections_data
        )
        print(f"wrote JSON summary to {path}", file=out)

    if args.csv:
        path = export.write_csv(args.csv, flows)
        print(f"wrote {len(flows)} conversations to {path}", file=out)


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------


def run_pcap(args: argparse.Namespace, *, stream: TextIO | None = None) -> int:
    from netsniff.capture.pcap import PcapReader

    path = Path(args.file)
    try:
        with PcapReader(path) as reader:
            stats, flows = analyse(iter(reader), args, stream=stream)
    except CaptureError as exc:
        print(f"netsniff: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report(stats, flows, args, source=str(path), stream=stream)
    return EXIT_OK


def run_live(args: argparse.Namespace, *, stream: TextIO | None = None) -> int:
    from netsniff.capture.live import LiveCapture

    try:
        with LiveCapture(
            args.iface,
            snaplen=args.snaplen,
            promiscuous=not args.no_promiscuous,
            timeout=args.timeout,
        ) as source:
            stats, flows = analyse(iter(source), args, stream=stream)
    except CaptureError as exc:
        print(f"netsniff: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED

    report(stats, flows, args, source=f"live:{args.iface}", stream=stream)
    return EXIT_OK


def main(argv: list[str] | None = None, *, stream: TextIO | None = None) -> int:
    """Entry point. Returns a process exit status rather than calling exit()."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(stream or sys.stdout)
        return EXIT_ERROR

    if args.top < 1:
        print("netsniff: --top must be at least 1", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.command == "pcap":
            return run_pcap(args, stream=stream)
        return run_live(args, stream=stream)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - happens when piped into head
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
