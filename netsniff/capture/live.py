"""Live packet capture with ``AF_PACKET``.

This is the one part of netsniff that is platform-specific and privileged, which
is exactly why it was built last and why it sits behind the same ``Frame``
interface as the pcap reader. Nothing downstream of :class:`LiveCapture` knows
it exists: swap this for the file reader and the decoders, the flow table and
the reports behave identically.

``AF_PACKET`` is Linux only, and opening one needs root or the ``CAP_NET_RAW``
capability. Both of those are failure modes an ordinary user hits on their first
run, so they are caught and explained here rather than surfacing as a raw
``PermissionError`` traceback from inside ``socket.socket``.

Three details worth knowing about the socket:

*Promiscuous mode* is a membership request on the interface, not a socket flag,
and it must be dropped again on close. Setting the old ``IFF_PROMISC`` interface
flag directly - the way a lot of examples do - is a change to global system
state that survives the process dying. The membership approach does not: the
kernel reference-counts it and undoes it when the socket closes.

*Snap length* is applied after receiving, not before. The socket always reads a
whole frame so the real on-wire length is known, and the frame is trimmed
afterwards. Truncating in the kernel would save a copy but would also lose the
original length, and then every byte count in the report would silently
understate the traffic.

*Timestamps* come from the kernel via ``SO_TIMESTAMPNS`` when it is available.
Calling ``time.time()`` after ``recv`` returns measures when this process got
round to looking at the packet, which under load is not when it arrived.
"""

from __future__ import annotations

import os
import platform
import socket
import struct
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass

from netsniff.capture.base import CaptureError, Frame, LinkType

__all__ = ["LiveCapture", "LiveCaptureError", "interface_names", "is_supported"]

# Linux constants that Python does not always expose, depending on the build.
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4

SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)
SCM_TIMESTAMPNS = 35

#: Always read this much, whatever the snap length is, so the real on-wire
#: length of every frame is known. Comfortably over a jumbo frame.
READ_BUFFER = 65536

#: Room for the ancillary data carrying the kernel timestamp.
ANCILLARY_BUFFER = 256


class LiveCaptureError(CaptureError):
    """Live capture could not start, or failed while running."""


def is_supported() -> bool:
    """Whether this platform can do live capture at all."""
    return sys.platform.startswith("linux") and hasattr(socket, "AF_PACKET")


def _unsupported_reason() -> str:
    """A specific explanation of why live capture is unavailable here."""
    if not sys.platform.startswith("linux"):
        if sys.platform == "win32":
            route = "  Run it under WSL, or analyse a capture file instead:\n"
        elif sys.platform == "darwin":
            route = (
                "  macOS captures through BPF devices (/dev/bpf*) rather than "
                "AF_PACKET, which netsniff does not implement.\n"
                "  Capture with tcpdump and analyse the file instead:\n"
            )
        else:
            route = "  Capture with tcpdump on this host, then analyse the file:\n"
        return (
            f"live capture needs Linux, and this is {platform.system()}. "
            f"AF_PACKET is a Linux-only socket family, and netsniff deliberately "
            f"does not depend on libpcap or Npcap to work around that.\n"
            f"{route}"
            f"    netsniff pcap yourfile.pcap"
        )
    return (
        "this Python build has no socket.AF_PACKET, so live capture is unavailable. "
        "Analyse a capture file instead: netsniff pcap yourfile.pcap"
    )


def interface_names() -> list[str]:
    """Interfaces this machine has, for error messages that actually help."""
    try:
        return sorted(name for _index, name in socket.if_nameindex())
    except (OSError, AttributeError):  # pragma: no cover - platform dependent
        return []


@dataclass(frozen=True, slots=True)
class CaptureStats:
    """How the socket has been doing.

    ``dropped`` is the kernel's own count of packets it had to discard because
    our receive buffer was full. It matters: a summary computed from a capture
    that silently dropped a third of the traffic is wrong in a way nothing else
    in the output would reveal.
    """

    received: int
    dropped: int


class LiveCapture:
    """Capture frames from an interface, yielding :class:`Frame` objects.

    Usage::

        with LiveCapture("eth0", count=100) as source:
            for frame in source:
                ...

    Args:
        interface: Interface name, e.g. ``eth0``. The ``any`` pseudo-device is
            rejected: it delivers Linux cooked-capture headers rather than
            Ethernet ones.
        snaplen: Bytes to keep per frame. The socket still reads whole frames,
            so :attr:`Frame.orig_len` stays correct.
        promiscuous: Ask the interface to pass up frames not addressed to it.
        timeout: Give up waiting after this many seconds of silence.
        count: Stop after this many frames.
        include_outgoing: Whether to keep frames this host is sending. A raw
            socket sees both directions, unlike a switch port mirror.

    Raises:
        LiveCaptureError: Wrong platform, no privileges, or no such interface.
    """

    link_type: int = int(LinkType.ETHERNET)
    """Always Ethernet.

    Declared on the class, not set per instance, so LiveCapture satisfies the
    Source protocol the same way PcapReader's property does - the CLI's shared
    analysis loop accepts either, and neither is a special case.
    """

    def __init__(
        self,
        interface: str,
        *,
        snaplen: int = 65535,
        promiscuous: bool = True,
        timeout: float | None = None,
        count: int | None = None,
        include_outgoing: bool = True,
    ) -> None:
        if not is_supported():
            raise LiveCaptureError(_unsupported_reason())

        if interface == "any":
            # The kernel's "any" pseudo-device hands up Linux cooked-capture
            # headers, not Ethernet ones. Our decoders would read the first 14
            # bytes of an SLL header as MACs and an ethertype and produce
            # confident nonsense, so refuse rather than mislead.
            raise LiveCaptureError(
                "capturing on 'any' is not supported: the kernel delivers Linux "
                "cooked-capture (SLL) headers there, not Ethernet ones, and "
                "netsniff decodes Ethernet only.\n"
                f"  Name a real interface instead: "
                f"{', '.join(interface_names()) or 'none found'}"
            )

        self.interface = interface
        self.snaplen = max(1, snaplen)
        self.promiscuous = promiscuous
        self.timeout = timeout
        self.count = count
        self.include_outgoing = include_outgoing

        self.packets_seen = 0
        self.packets_dropped_by_filter = 0

        self._promisc_added = False
        self._closed = False
        self._kernel_timestamps = False

        self._socket = self._open()

    # -- setup -------------------------------------------------------------

    def _open(self) -> socket.socket:
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
            )
        except PermissionError as exc:
            raise LiveCaptureError(
                f"permission denied opening a raw socket on {self.interface}.\n"
                f"  AF_PACKET needs root or the CAP_NET_RAW capability. Either:\n"
                f"    sudo netsniff live --iface {self.interface}\n"
                f"  or grant the capability once, to the interpreter:\n"
                f"    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f {sys.executable})\n"
                f"  (running as uid {os.geteuid()})"
            ) from exc
        except OSError as exc:  # pragma: no cover - needs an exotic failure
            raise LiveCaptureError(f"could not open a raw socket: {exc}") from exc

        try:
            self._bind(sock)
            self._enable_timestamps(sock)
            if self.promiscuous:
                self._add_promiscuous(sock)
            if self.timeout is not None:
                sock.settimeout(self.timeout)
        except BaseException:
            sock.close()
            raise

        return sock

    def _bind(self, sock: socket.socket) -> None:
        try:
            sock.bind((self.interface, ETH_P_ALL))
        except OSError as exc:
            available = interface_names()
            hint = f"\n  available: {', '.join(available)}" if available else ""
            raise LiveCaptureError(
                f"cannot capture on {self.interface!r}: {exc.strerror or exc}{hint}"
            ) from exc

    def _enable_timestamps(self, sock: socket.socket) -> None:
        """Ask the kernel to stamp each packet as it arrives.

        Best effort: if the option is unavailable we fall back to reading the
        clock ourselves, which is less accurate but not wrong enough to refuse
        to run over.
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            self._kernel_timestamps = True
        except OSError:  # pragma: no cover - depends on the kernel
            self._kernel_timestamps = False

    def _add_promiscuous(self, sock: socket.socket) -> None:
        """Join the interface's promiscuous group.

        This is reference-counted by the kernel and released when the socket
        closes, so an interrupted run cannot leave the interface promiscuous.
        """
        try:
            index = socket.if_nametoindex(self.interface)
        except OSError as exc:  # pragma: no cover - bind would have failed first
            raise LiveCaptureError(f"no such interface: {self.interface}") from exc

        # struct packet_mreq is native-endian, not network order. Using '!' here
        # is a classic way to make setsockopt fail with EINVAL for no visible
        # reason.
        mreq = struct.pack("=iHH8s", index, PACKET_MR_PROMISC, 0, b"")
        try:
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            self._promisc_added = True
        except OSError as exc:  # pragma: no cover - needs a odd interface
            raise LiveCaptureError(
                f"could not enable promiscuous mode on {self.interface}: {exc}"
            ) from exc

    # -- receiving ---------------------------------------------------------

    def _parse_timestamp(self, ancdata: list[tuple[int, int, bytes]]) -> float | None:
        """Pull a struct timespec out of the ancillary data, if it is there."""
        for level, cmsg_type, data in ancdata:
            if level != socket.SOL_SOCKET or cmsg_type != SCM_TIMESTAMPNS:
                continue
            if len(data) >= 16:
                seconds, nanoseconds = struct.unpack("=qq", data[:16])
            elif len(data) >= 8:  # pragma: no cover - 32-bit kernels
                seconds, nanoseconds = struct.unpack("=ll", data[:8])
            else:  # pragma: no cover
                continue
            return float(seconds) + float(nanoseconds) / 1_000_000_000
        return None

    def __iter__(self) -> Iterator[Frame]:
        index = 0
        while True:
            if self.count is not None and index >= self.count:
                return

            try:
                data, ancdata, _flags, address = self._socket.recvmsg(
                    READ_BUFFER, ANCILLARY_BUFFER
                )
            except TimeoutError:
                return
            except OSError as exc:
                if self._closed:
                    return
                raise LiveCaptureError(f"capture failed on {self.interface}: {exc}") from exc

            if not data:
                continue

            self.packets_seen += 1

            # address is (ifname, proto, pkttype, hatype, hwaddr). pkttype tells
            # us whether this host sent the frame, which a mirror port would
            # never show us but a raw socket does.
            outgoing = len(address) > 2 and address[2] == PACKET_OUTGOING
            if outgoing and not self.include_outgoing:
                self.packets_dropped_by_filter += 1
                continue

            timestamp = self._parse_timestamp(ancdata)
            if timestamp is None:
                timestamp = time.time()

            yield Frame(
                ts=timestamp,
                data=data[: self.snaplen],
                orig_len=len(data),
                index=index,
            )
            index += 1

    # -- statistics --------------------------------------------------------

    def stats(self) -> CaptureStats:
        """Ask the kernel how many packets it had to drop.

        ``tpacket_stats`` is two unsigned ints, and reading it resets the
        counters - so call it once, at the end.
        """
        try:
            raw = self._socket.getsockopt(SOL_PACKET, 6, 8)  # PACKET_STATISTICS
            received, dropped = struct.unpack("=II", raw)
            return CaptureStats(received=received, dropped=dropped)
        except OSError:  # pragma: no cover - platform dependent
            return CaptureStats(received=self.packets_seen, dropped=0)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Drop promiscuous membership and close the socket."""
        if self._closed:
            return
        self._closed = True

        if self._promisc_added:
            try:
                index = socket.if_nametoindex(self.interface)
                mreq = struct.pack("=iHH8s", index, PACKET_MR_PROMISC, 0, b"")
                self._socket.setsockopt(SOL_PACKET, PACKET_DROP_MEMBERSHIP, mreq)
            except OSError:  # pragma: no cover - closing the socket drops it anyway
                pass
            self._promisc_added = False

        self._socket.close()

    def __enter__(self) -> LiveCapture:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"<LiveCapture {self.interface!r} snaplen={self.snaplen} "
            f"promiscuous={self.promiscuous} seen={self.packets_seen}>"
        )
