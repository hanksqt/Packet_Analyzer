"""The contract between capture sources and everything downstream.

A capture source produces :class:`Frame` objects and nothing else. The offline
pcap reader and the live ``AF_PACKET`` socket both satisfy this, which is what
lets the decoders, the flow table and the reports stay completely unaware of
where a packet came from.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol, runtime_checkable


class LinkType(IntEnum):
    """libpcap link-layer header types (the ``network`` field of a pcap file).

    Only :attr:`ETHERNET` is decoded. The others are listed so an unsupported
    capture produces a message that names what it actually is instead of a
    confusing garbage decode.
    """

    NULL = 0
    ETHERNET = 1
    RAW = 101
    LINUX_SLL = 113
    IEEE802_11 = 105
    LINUX_SLL2 = 276

    @classmethod
    def describe(cls, value: int) -> str:
        """Human-readable name for a link type, even one we do not decode."""
        try:
            return cls(value).name
        except ValueError:
            return f"UNKNOWN({value})"


@dataclass(frozen=True, slots=True)
class Frame:
    """One captured link-layer frame.

    Attributes:
        ts: Capture timestamp, seconds since the Unix epoch.
        data: The bytes actually captured. This may be shorter than the frame
            was on the wire, see :attr:`orig_len`.
        orig_len: The frame's real length on the wire. When a capture is taken
            with a snap length, ``orig_len > len(data)`` and the tail of the
            packet - possibly part of a header - was never recorded. Decoders
            must tolerate that rather than assume a full packet.
        index: Zero-based position in the capture, useful for error messages
            and for pointing at a specific packet in a report.
    """

    ts: float
    data: bytes
    orig_len: int = -1
    index: int = -1

    def __post_init__(self) -> None:
        # orig_len defaults to "same as what we captured" so a source that has
        # no snapping concept (a live socket reading whole frames) does not have
        # to supply it.
        if self.orig_len < 0:
            object.__setattr__(self, "orig_len", len(self.data))

    @property
    def caplen(self) -> int:
        """Number of bytes actually captured."""
        return len(self.data)

    @property
    def truncated(self) -> bool:
        """True when the capture cut this frame short of its on-wire length."""
        return self.orig_len > len(self.data)


@runtime_checkable
class Source(Protocol):
    """Anything that yields :class:`Frame` objects.

    Implemented by :class:`~netsniff.capture.pcap.PcapReader` and
    :class:`~netsniff.capture.live.LiveCapture`. Both are also context managers,
    so callers can use ``with``.
    """

    link_type: int

    def __iter__(self) -> Iterator[Frame]:  # pragma: no cover - protocol
        ...

    def close(self) -> None:  # pragma: no cover - protocol
        ...


class CaptureError(Exception):
    """Base class for every capture-source failure.

    Sources raise this (or a subclass) instead of letting a struct error, a
    short read or a raw socket ``PermissionError`` escape, so the CLI can print
    something a human can act on.
    """


class UnsupportedLinkType(CaptureError):
    """The capture's link layer is not Ethernet, which is all we decode."""

    def __init__(self, link_type: int) -> None:
        self.link_type = link_type
        super().__init__(
            f"link type {link_type} ({LinkType.describe(link_type)}) is not supported; "
            f"netsniff decodes Ethernet ({int(LinkType.ETHERNET)}) captures only"
        )
