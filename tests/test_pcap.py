"""Tests for the classic pcap file reader.

Two kinds of test live here:

* Synthetic files built byte by byte in :func:`build_pcap`, which let us assert
  on exact header fields, both byte orders, and every malformed-input path.
* Checks against the committed ``sample.pcap``, which tcpdump wrote. The most
  valuable of those is the byte-accounting test: it proves record framing walks
  the file to EOF without over- or under-reading a single byte.
"""

from __future__ import annotations

import io
import os
import struct
from pathlib import Path

import pytest

from netsniff.capture.base import Frame, LinkType, Source, UnsupportedLinkType
from netsniff.capture.pcap import (
    GLOBAL_HEADER_LEN,
    MAX_RECORD_BYTES,
    RECORD_HEADER_LEN,
    PcapError,
    PcapReader,
    read_pcap,
)

# --------------------------------------------------------------------------
# a minimal pcap writer, used only to build test inputs
# --------------------------------------------------------------------------

MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
MAGIC_BE_NSEC = b"\xa1\xb2\x3c\x4d"
MAGIC_LE_NSEC = b"\x4d\x3c\xb2\xa1"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"


def build_pcap(
    records: list[tuple[int, int, bytes]] | None = None,
    *,
    magic: bytes = MAGIC_LE_USEC,
    snaplen: int = 65535,
    link_type: int = int(LinkType.ETHERNET),
    thiszone: int = 0,
    version: tuple[int, int] = (2, 4),
    orig_lens: list[int] | None = None,
) -> bytes:
    """Build a pcap file in memory.

    Args:
        records: ``(ts_sec, ts_frac, data)`` triples.
        magic: Which of the four magics to write, which also sets byte order.
        orig_lens: Override the on-wire lengths, to simulate snapped packets.
    """
    endian = ">" if magic in (MAGIC_BE_USEC, MAGIC_BE_NSEC) else "<"
    out = bytearray(magic)
    out += struct.pack(
        endian + "HHiIII", version[0], version[1], thiszone, 0, snaplen, link_type
    )
    for i, (ts_sec, ts_frac, data) in enumerate(records or []):
        orig = orig_lens[i] if orig_lens else len(data)
        out += struct.pack(endian + "IIII", ts_sec, ts_frac, len(data), orig)
        out += data
    return bytes(out)


def reader_for(raw: bytes, **kwargs: object) -> PcapReader:
    return PcapReader(io.BytesIO(raw), **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# global header
# --------------------------------------------------------------------------


def test_global_header_fields_parse() -> None:
    raw = build_pcap([], snaplen=262144, thiszone=0, version=(2, 4))
    r = reader_for(raw)
    assert r.header.version_major == 2
    assert r.header.version_minor == 4
    assert r.header.snaplen == 262144
    assert r.header.link_type == LinkType.ETHERNET
    assert r.header.link_type_name == "ETHERNET"
    assert r.header.thiszone == 0
    assert r.header.sigfigs == 0
    assert not r.header.nanosecond_resolution


def test_global_header_is_exactly_24_bytes() -> None:
    assert len(build_pcap([])) == GLOBAL_HEADER_LEN


@pytest.mark.parametrize(
    ("magic", "expected_order"),
    [
        (MAGIC_BE_USEC, ">"),
        (MAGIC_LE_USEC, "<"),
        (MAGIC_BE_NSEC, ">"),
        (MAGIC_LE_NSEC, "<"),
    ],
)
def test_byte_order_detected_from_magic(magic: bytes, expected_order: str) -> None:
    r = reader_for(build_pcap([], magic=magic))
    assert r.header.byte_order == expected_order


def test_both_byte_orders_yield_identical_frames() -> None:
    """The same capture written big- and little-endian must decode the same.

    This is the test that catches a byte-order bug: a reader that ignored the
    magic would produce wildly different lengths and timestamps for one of them.
    """
    records = [(1_700_000_000, 123_456, b"\xaa" * 60), (1_700_000_001, 500_000, b"\xbb" * 74)]
    little = list(reader_for(build_pcap(records, magic=MAGIC_LE_USEC)))
    big = list(reader_for(build_pcap(records, magic=MAGIC_BE_USEC)))

    assert [(f.ts, f.data, f.orig_len) for f in little] == [
        (f.ts, f.data, f.orig_len) for f in big
    ]
    assert little[0].ts == pytest.approx(1_700_000_000.123456)


def test_nanosecond_magic_scales_the_fraction_field() -> None:
    """0xa1b23c4d means the second timestamp field is nanoseconds, not micros."""
    usec = list(reader_for(build_pcap([(100, 500_000, b"x" * 14)], magic=MAGIC_LE_USEC)))
    nsec = list(reader_for(build_pcap([(100, 500_000, b"x" * 14)], magic=MAGIC_LE_NSEC)))

    assert usec[0].ts == pytest.approx(100.5)  # 500000 us = 0.5 s
    assert nsec[0].ts == pytest.approx(100.0005)  # 500000 ns = 0.0005 s

    r = reader_for(build_pcap([], magic=MAGIC_LE_NSEC))
    assert r.header.nanosecond_resolution


def test_thiszone_offset_is_applied_and_signed() -> None:
    raw = build_pcap([(1000, 0, b"z" * 14)], thiszone=-3600)
    assert next(iter(reader_for(raw))).ts == pytest.approx(1000 - 3600)


# --------------------------------------------------------------------------
# record framing
# --------------------------------------------------------------------------


def test_records_walk_to_eof() -> None:
    records = [(10, 0, b"a" * 20), (11, 0, b"b" * 30), (12, 0, b"c" * 40)]
    frames = list(reader_for(build_pcap(records)))
    assert [f.data for f in frames] == [b"a" * 20, b"b" * 30, b"c" * 40]
    assert [f.index for f in frames] == [0, 1, 2]


def test_empty_capture_yields_nothing() -> None:
    assert list(reader_for(build_pcap([]))) == []


def test_incl_len_is_what_gets_sliced_not_orig_len() -> None:
    """A snapped packet: 40 bytes recorded, 1514 on the wire."""
    raw = build_pcap([(5, 0, b"q" * 40)], orig_lens=[1514])
    frame = next(iter(reader_for(raw)))
    assert frame.caplen == 40
    assert len(frame.data) == 40
    assert frame.orig_len == 1514
    assert frame.truncated


def test_orig_len_smaller_than_incl_len_is_clamped() -> None:
    """Some writers emit nonsense; trust the bytes we actually hold."""
    raw = build_pcap([(5, 0, b"q" * 40)], orig_lens=[10])
    frame = next(iter(reader_for(raw)))
    assert frame.orig_len == 40
    assert not frame.truncated


def test_zero_length_packet_record() -> None:
    frames = list(reader_for(build_pcap([(1, 0, b"")])))
    assert len(frames) == 1
    assert frames[0].data == b""


def test_packets_read_counter_tracks_progress() -> None:
    r = reader_for(build_pcap([(1, 0, b"a" * 14), (2, 0, b"b" * 14)]))
    assert r.packets_read == 0
    it = iter(r)
    next(it)
    assert r.packets_read == 1
    next(it)
    assert r.packets_read == 2


# --------------------------------------------------------------------------
# malformed input
# --------------------------------------------------------------------------


def test_pcapng_magic_gets_a_specific_message() -> None:
    raw = MAGIC_PCAPNG + b"\x00" * 40
    with pytest.raises(PcapError, match="pcapng"):
        reader_for(raw)


def test_bad_magic_rejected() -> None:
    raw = b"\xde\xad\xbe\xef" + b"\x00" * 20
    with pytest.raises(PcapError, match="bad magic number"):
        reader_for(raw)


def test_file_too_short_for_global_header() -> None:
    with pytest.raises(PcapError, match="truncated global header"):
        reader_for(MAGIC_LE_USEC + b"\x00" * 4)


def test_truncated_record_header() -> None:
    raw = build_pcap([(1, 0, b"a" * 14)]) + b"\x01\x02\x03"
    with pytest.raises(PcapError, match="truncated record header"):
        list(reader_for(raw))


def test_truncated_packet_data() -> None:
    raw = bytearray(build_pcap([(1, 0, b"a" * 60)]))
    del raw[-20:]  # record header still claims 60 bytes
    with pytest.raises(PcapError, match="truncated packet data"):
        list(reader_for(bytes(raw)))


def test_absurd_incl_len_is_rejected_before_allocating() -> None:
    raw = build_pcap([]) + struct.pack("<IIII", 1, 0, 0xFFFF_FFFF, 0xFFFF_FFFF)
    with pytest.raises(PcapError, match="sanity limit"):
        list(reader_for(raw))
    assert MAX_RECORD_BYTES < 0xFFFF_FFFF


def test_non_ethernet_link_type_rejected() -> None:
    raw = build_pcap([], link_type=int(LinkType.LINUX_SLL))
    with pytest.raises(UnsupportedLinkType, match="LINUX_SLL"):
        reader_for(raw)


def test_non_ethernet_allowed_when_not_required() -> None:
    raw = build_pcap([], link_type=int(LinkType.RAW))
    r = reader_for(raw, require_ethernet=False)
    assert r.header.link_type == LinkType.RAW


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PcapError, match="no such capture file"):
        PcapReader("does-not-exist-anywhere.pcap")


def test_directory_instead_of_file(tmp_path: Path) -> None:
    with pytest.raises(PcapError, match="is a directory"):
        PcapReader(str(tmp_path))


# --------------------------------------------------------------------------
# lifecycle and protocol conformance
# --------------------------------------------------------------------------


def test_context_manager_closes_the_file(sample_pcap: Path) -> None:
    with PcapReader(sample_pcap) as r:
        assert not r._closed
    assert r._closed


def test_read_pcap_helper_iterates_and_closes(sample_pcap: Path) -> None:
    frames = list(read_pcap(sample_pcap))
    assert len(frames) > 0
    assert all(isinstance(f, Frame) for f in frames)


def test_reader_satisfies_the_source_protocol(sample_pcap: Path) -> None:
    with PcapReader(sample_pcap) as r:
        assert isinstance(r, Source)
        assert r.link_type == LinkType.ETHERNET


def test_repr_is_informative(sample_pcap: Path) -> None:
    with PcapReader(sample_pcap) as r:
        text = repr(r)
    assert "PcapReader" in text
    assert "ETHERNET" in text


# --------------------------------------------------------------------------
# the committed capture
# --------------------------------------------------------------------------


def test_sample_is_classic_pcap_ethernet(sample_pcap: Path) -> None:
    with PcapReader(sample_pcap) as r:
        assert r.header.version_major == 2
        assert r.header.link_type == LinkType.ETHERNET
        assert r.header.byte_order in ("<", ">")


def test_sample_framing_accounts_for_every_byte(sample_pcap: Path) -> None:
    """The strongest framing test there is.

    If the reader over-read or under-read even one byte per record, this sum
    would not land exactly on the file size.
    """
    frames = list(read_pcap(sample_pcap))
    expected = (
        GLOBAL_HEADER_LEN
        + RECORD_HEADER_LEN * len(frames)
        + sum(f.caplen for f in frames)
    )
    assert expected == os.path.getsize(sample_pcap)


def test_sample_timestamps_are_sane_and_monotonic(sample_pcap: Path) -> None:
    frames = list(read_pcap(sample_pcap))
    assert len(frames) > 10

    # Plausible epoch range: after 2020, before 2100. A byte-order bug here
    # would produce a timestamp in 1970 or the far future.
    assert all(1_577_836_800 < f.ts < 4_102_444_800 for f in frames)

    timestamps = [f.ts for f in frames]
    assert timestamps == sorted(timestamps), "capture order should be non-decreasing"

    # A capture that took seconds, not milliseconds and not days.
    assert 0 < timestamps[-1] - timestamps[0] < 3600


def test_sample_frame_lengths_are_plausible_ethernet(sample_pcap: Path) -> None:
    frames = list(read_pcap(sample_pcap))
    for f in frames:
        # 14-byte Ethernet header at minimum; jumbo frames aside, nothing should
        # exceed a large-receive-offload sized segment.
        assert 14 <= f.caplen <= 65535, f"packet {f.index} has caplen {f.caplen}"
