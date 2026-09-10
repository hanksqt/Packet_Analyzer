"""Cheap heuristics over the flow table.

Two things worth saying up front, because they are what separates a useful
detection from an annoying one.

**These report, they do not block.** Nothing here drops a packet or touches a
firewall. The output is a list of findings with the evidence attached, for a
human to judge.

**Every one of them has false positives, and they are named.** A host that opens
many short-lived connections to a load balancer looks like a scanner by packet
shape alone. A monitoring agent polling twenty services looks like a horizontal
sweep. Backup software hammering a dead host produces exactly the same
unanswered-SYN signature as a probe. A detector that hides that is worse than
one that admits it, because the reader cannot calibrate what they are seeing.

Thresholds are arguments with defaults, not constants, for the same reason: the
right number depends on the network, and hardcoding one is a claim this code has
no business making.

The three heuristics:

*Vertical scan* - one source reaching many distinct ports on one destination.
This is the shape of ``nmap -p-`` against a single host.

*Horizontal sweep* - one source reaching the same port on many distinct
destinations. This is the shape of looking for one vulnerable service across a
subnet, and in practice it is the more common of the two.

*Unanswered connections* - SYNs that never got a SYN-ACK. On their own these are
mundane (a service moved, a host is off), so this only reports when a single
source accumulates a lot of them.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from netsniff.analyze.flows import Flow, FlowTable

__all__ = [
    "DEFAULT_THRESHOLDS",
    "Detection",
    "Thresholds",
    "detect_all",
    "detect_horizontal_sweep",
    "detect_unanswered_connections",
    "detect_vertical_scan",
    "render_detections",
]


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Tuning knobs. Defaults are deliberately conservative.

    They are set high enough that ordinary client traffic does not trip them,
    which means a quiet scan will slip under. That trade is the right way round
    for a reporting tool: a summary full of false alarms gets ignored entirely,
    and then the true positives go unread too.
    """

    vertical_ports: int = 10
    """Distinct destination ports on one host before it counts as a scan."""

    horizontal_hosts: int = 10
    """Distinct destination hosts on one port before it counts as a sweep."""

    unanswered: int = 10
    """Unanswered SYNs from one source before it is worth mentioning."""

    window_seconds: float = 60.0
    """How close together the probes must be. Scans are fast; a host that
    happens to touch twenty ports over a day is doing its job."""


DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True, slots=True)
class Detection:
    """One finding, with the evidence that produced it."""

    kind: str
    """``vertical-scan``, ``horizontal-sweep`` or ``unanswered-connections``."""

    source: str
    """The address the behaviour came from."""

    summary: str
    """One line, ready to print."""

    count: int
    """However many of the thing was counted: ports, hosts, or connections."""

    first_seen: float
    last_seen: float
    evidence: tuple[str, ...] = field(default=())
    """A sample of what was actually seen, capped so a big scan does not
    produce a report longer than the capture."""

    caveat: str = ""
    """What benign activity produces this same signature."""

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "summary": self.summary,
            "count": self.count,
            "first_seen": round(self.first_seen, 6),
            "last_seen": round(self.last_seen, 6),
            "duration_seconds": round(self.duration, 6),
            "evidence": list(self.evidence),
            "caveat": self.caveat,
        }

    def __str__(self) -> str:
        return self.summary


#: Never list more than this much evidence per finding.
MAX_EVIDENCE = 12


def _probe_flows(flow_table: FlowTable) -> list[tuple[str, str, int, Flow]]:
    """Connection attempts, as ``(source, destination, port, flow)``.

    A scan is made of attempts, not of conversations, so this looks at TCP flows
    where a SYN was sent - answered or not - and reports them from the point of
    view of whoever sent it, which is not necessarily the flow's canonical
    endpoint A.
    """
    probes = []
    for flow in flow_table:
        if flow.key.protocol != "TCP" or not flow.saw_syn:
            continue
        source = flow.initiator
        if source == flow.key.a_addr:
            destination, port = flow.key.b_addr, flow.key.b_port
        else:
            destination, port = flow.key.a_addr, flow.key.a_port
        if port is None:
            continue
        probes.append((source, destination, port, flow))
    return probes


def detect_vertical_scan(
    flow_table: FlowTable, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> list[Detection]:
    """One source, one destination, many ports."""
    by_pair: dict[tuple[str, str], list[tuple[int, Flow]]] = defaultdict(list)
    for source, destination, port, flow in _probe_flows(flow_table):
        by_pair[(source, destination)].append((port, flow))

    findings = []
    for (source, destination), attempts in by_pair.items():
        ports = {port for port, _flow in attempts}
        if len(ports) < thresholds.vertical_ports:
            continue

        flows = [flow for _port, flow in attempts]
        first = min(f.first_seen for f in flows)
        last = max(f.last_seen for f in flows)
        if last - first > thresholds.window_seconds:
            continue

        unanswered = sum(1 for f in flows if f.is_unanswered_syn)
        listed = sorted(ports)[:MAX_EVIDENCE]

        findings.append(
            Detection(
                kind="vertical-scan",
                source=source,
                summary=(
                    f"{source} attempted {len(ports)} distinct ports on {destination} "
                    f"in {last - first:.1f}s ({unanswered} got no SYN-ACK)"
                ),
                count=len(ports),
                first_seen=first,
                last_seen=last,
                evidence=tuple(
                    f"{destination}:{port}" for port in listed
                ),
                caveat=(
                    "A client opening many services on one host - a database "
                    "cluster, an application with several backends - looks the same."
                ),
            )
        )
    return sorted(findings, key=lambda d: -d.count)


def detect_horizontal_sweep(
    flow_table: FlowTable, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> list[Detection]:
    """One source, one port, many destinations."""
    by_source_port: dict[tuple[str, int], list[tuple[str, Flow]]] = defaultdict(list)
    for source, destination, port, flow in _probe_flows(flow_table):
        by_source_port[(source, port)].append((destination, flow))

    findings = []
    for (source, port), attempts in by_source_port.items():
        hosts = {destination for destination, _flow in attempts}
        if len(hosts) < thresholds.horizontal_hosts:
            continue

        flows = [flow for _host, flow in attempts]
        first = min(f.first_seen for f in flows)
        last = max(f.last_seen for f in flows)
        if last - first > thresholds.window_seconds:
            continue

        unanswered = sum(1 for f in flows if f.is_unanswered_syn)

        findings.append(
            Detection(
                kind="horizontal-sweep",
                source=source,
                summary=(
                    f"{source} attempted port {port} on {len(hosts)} distinct hosts "
                    f"in {last - first:.1f}s ({unanswered} got no SYN-ACK)"
                ),
                count=len(hosts),
                first_seen=first,
                last_seen=last,
                evidence=tuple(f"{host}:{port}" for host in sorted(hosts)[:MAX_EVIDENCE]),
                caveat=(
                    "A monitoring agent, a backup client or a service-discovery "
                    "sweep produces this exact pattern legitimately."
                ),
            )
        )
    return sorted(findings, key=lambda d: -d.count)


def detect_unanswered_connections(
    flow_table: FlowTable, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> list[Detection]:
    """A source accumulating SYNs that never got a SYN-ACK.

    One of these is nothing. A pile of them from one host means it is talking to
    something that is not answering - a firewall dropping silently, a service
    that moved, or a probe.
    """
    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in flow_table:
        if flow.is_unanswered_syn:
            by_source[flow.initiator].append(flow)

    findings = []
    for source, flows in by_source.items():
        if len(flows) < thresholds.unanswered:
            continue

        first = min(f.first_seen for f in flows)
        last = max(f.last_seen for f in flows)
        targets = sorted({f"{f.responder}:{f.key.b_port or f.key.a_port}" for f in flows})

        findings.append(
            Detection(
                kind="unanswered-connections",
                source=source,
                summary=(
                    f"{source} made {len(flows)} connection attempts that were never "
                    f"answered, to {len(targets)} distinct endpoints over "
                    f"{last - first:.1f}s"
                ),
                count=len(flows),
                first_seen=first,
                last_seen=last,
                evidence=tuple(targets[:MAX_EVIDENCE]),
                caveat=(
                    "A host that has gone away, a silently dropping firewall, or "
                    "software retrying a dead peer all look like this."
                ),
            )
        )
    return sorted(findings, key=lambda d: -d.count)


def detect_all(
    flow_table: FlowTable, thresholds: Thresholds = DEFAULT_THRESHOLDS
) -> list[Detection]:
    """Run every heuristic, most significant finding first."""
    findings = (
        detect_vertical_scan(flow_table, thresholds)
        + detect_horizontal_sweep(flow_table, thresholds)
        + detect_unanswered_connections(flow_table, thresholds)
    )
    return sorted(findings, key=lambda d: (-d.count, d.kind, d.source))


def render_detections(findings: list[Detection]) -> str:
    """Format findings for the console summary."""
    if not findings:
        return ""

    lines = ["\nDetections", "=========="]
    for finding in findings:
        lines.append(f"  [{finding.kind}] {finding.summary}")
        if finding.evidence:
            shown = ", ".join(finding.evidence)
            more = finding.count - len(finding.evidence)
            lines.append(f"      seen: {shown}" + (f", and {more} more" if more > 0 else ""))
        if finding.caveat:
            lines.append(f"      note: {finding.caveat}")
    lines.append(
        "\n  These are heuristics over traffic shape, reported and not acted on. "
        "\n  Read the notes: ordinary software produces every one of these patterns."
    )
    return "\n".join(lines)
