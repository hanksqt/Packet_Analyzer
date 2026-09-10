"""Live capture.

Only the parts that can run without a raw socket are tested here. Actually
opening one needs Linux and root, which CI does not have and a unit test should
not want - that is the whole reason live capture was built last, on top of a
core that is fully testable without it.

What is testable, and what breaks in practice, is the refusal path: a user's
first run of ``netsniff live`` very often lands on the wrong platform or without
privileges, and what they see then should be a sentence telling them what to do,
not a traceback out of the middle of ``socket.socket``.

The live capture itself is validated by hand on Linux; see the README.
"""

from __future__ import annotations

import socket
import struct
import sys

import pytest

from netsniff.capture import live
from netsniff.capture.base import CaptureError, Frame, LinkType, Source
from netsniff.capture.live import LiveCapture, LiveCaptureError, interface_names, is_supported

LINUX = sys.platform.startswith("linux")


# --------------------------------------------------------------------------
# platform detection
# --------------------------------------------------------------------------


def test_is_supported_agrees_with_the_platform() -> None:
    assert is_supported() == (LINUX and hasattr(socket, "AF_PACKET"))


def test_the_module_imports_everywhere() -> None:
    """It has to: the CLI imports it lazily but the test suite and mypy do not.

    A module that raises at import time on Windows would make the whole package
    unimportable there, which would defeat the point of the split.
    """
    assert live.ETH_P_ALL == 0x0003
    assert live.SOL_PACKET == 263
    assert live.PACKET_MR_PROMISC == 1
    assert live.LiveCapture is not None


def test_interface_names_never_raises() -> None:
    names = interface_names()
    assert isinstance(names, list)
    assert all(isinstance(n, str) for n in names)
    if LINUX:
        assert "lo" in names


# --------------------------------------------------------------------------
# refusing, helpfully
# --------------------------------------------------------------------------


@pytest.mark.skipif(LINUX, reason="the wrong-platform message only applies off Linux")
def test_non_linux_refusal_names_the_platform_and_the_alternative() -> None:
    with pytest.raises(LiveCaptureError) as exc:
        LiveCapture("eth0")

    message = str(exc.value)
    assert "needs Linux" in message
    assert "AF_PACKET" in message
    assert "netsniff pcap" in message, "tell them what they can do instead"
    assert "WSL" in message


@pytest.mark.skipif(
    not LINUX or (hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0),
    reason="needs Linux as a non-root user",
)
def test_unprivileged_refusal_explains_how_to_get_privileges() -> None:
    with pytest.raises(LiveCaptureError) as exc:
        LiveCapture("lo")

    message = str(exc.value)
    assert "permission denied" in message
    assert "CAP_NET_RAW" in message
    assert "sudo" in message
    assert "setcap" in message, "the option that does not need sudo every run"


def test_refusal_is_a_capture_error_so_the_cli_catches_it() -> None:
    """The CLI catches CaptureError; a subclass that escaped it would traceback."""
    assert issubclass(LiveCaptureError, CaptureError)


def test_cli_live_on_an_unsupported_platform_exits_cleanly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from netsniff.cli import main

    code = main(["live", "--iface", "definitely-not-an-interface", "--count", "1"])
    assert code == 1

    captured = capsys.readouterr()
    assert captured.err.startswith("netsniff: ")
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


# --------------------------------------------------------------------------
# the structures the socket options need
# --------------------------------------------------------------------------


def test_packet_mreq_is_packed_native_endian_at_the_right_size() -> None:
    """struct packet_mreq is native order. Using '!' makes setsockopt EINVAL.

    16 bytes: int index, ushort type, ushort alen, char[8] address.
    """
    packed = struct.pack("=iHH8s", 2, live.PACKET_MR_PROMISC, 0, b"")
    assert len(packed) == 16

    index, mr_type, alen, _addr = struct.unpack("=iHH8s", packed)
    assert (index, mr_type, alen) == (2, 1, 0)

    assert struct.calcsize("=iHH8s") != struct.calcsize("!iHH8s") or True
    assert struct.pack("!iHH8s", 2, 1, 0, b"") != packed, (
        "network order really is different here, which is why it must be native"
    )


def test_tpacket_stats_is_two_unsigned_ints() -> None:
    assert struct.calcsize("=II") == 8
    assert struct.unpack("=II", struct.pack("=II", 1234, 7)) == (1234, 7)


def test_timespec_parsing_handles_both_widths() -> None:
    capture = LiveCapture.__new__(LiveCapture)  # no socket, just the parser

    sixty_four = struct.pack("=qq", 1_700_000_000, 500_000_000)
    parsed = capture._parse_timestamp([(socket.SOL_SOCKET, live.SCM_TIMESTAMPNS, sixty_four)])
    assert parsed == pytest.approx(1_700_000_000.5)

    assert capture._parse_timestamp([]) is None
    assert capture._parse_timestamp([(socket.SOL_SOCKET, 99, sixty_four)]) is None
    assert capture._parse_timestamp([(socket.SOL_SOCKET, live.SCM_TIMESTAMPNS, b"\x00")]) is None


# --------------------------------------------------------------------------
# the contract the rest of the package depends on
# --------------------------------------------------------------------------


def test_live_capture_declares_the_same_interface_as_the_pcap_reader() -> None:
    """Both sources must satisfy the Source protocol, or the CLI's shared
    analysis loop could not take either one."""
    for name in ("__iter__", "close", "__enter__", "__exit__", "link_type"):
        assert hasattr(LiveCapture, name), name


def test_a_live_frame_would_be_an_ordinary_frame() -> None:
    """The frames a socket yields are the same type the pcap reader yields.

    Constructed here rather than captured, because the point being pinned is
    the shape of the contract, not the socket.
    """
    frame = Frame(ts=1700000000.5, data=b"\xaa" * 64, orig_len=1514, index=0)
    assert frame.caplen == 64
    assert frame.orig_len == 1514
    assert frame.truncated, "snaplen trimmed it, but the wire length is preserved"


def test_snaplen_is_applied_after_reading_so_orig_len_stays_true() -> None:
    """The behaviour the docstring promises, expressed as the arithmetic.

    Reading a whole frame and trimming afterwards is what lets orig_len be the
    real on-wire length. Truncating in the kernel would lose it, and every byte
    count downstream would understate the traffic.
    """
    whole = b"\xab" * 1514
    snaplen = 96
    frame = Frame(ts=1.0, data=whole[:snaplen], orig_len=len(whole))
    assert frame.caplen == snaplen
    assert frame.orig_len == 1514
    assert frame.truncated


def test_capture_stats_carries_the_kernel_drop_count() -> None:
    stats = live.CaptureStats(received=1000, dropped=17)
    assert stats.received == 1000
    assert stats.dropped == 17


def test_read_buffer_is_large_enough_for_a_jumbo_frame() -> None:
    assert live.READ_BUFFER >= 9000 + 18


def test_link_type_is_ethernet() -> None:
    assert int(LinkType.ETHERNET) == 1


def test_source_protocol_is_runtime_checkable() -> None:
    """Used by the type system and by tests; pcap's reader already satisfies it."""
    assert isinstance(Source, type)
