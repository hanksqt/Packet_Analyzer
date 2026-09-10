"""Classic libpcap ("pcap") file reader, written against the format directly.

A classic pcap file is a 24-byte global header followed by repeated records,
each a 16-byte record header plus that many bytes of frame data::

    +---------------------------+
    | global header  (24 bytes) |
    +---------------------------+
    | record header  (16 bytes) |
    | frame data     (incl_len) |
    +---------------------------+
    | record header  (16 bytes) |
    | frame data     (incl_len) |
    +---------------------------+
    | ...                       |

The magic number in the first four bytes tells us the file's byte order, and we
use that order for every subsequent unpack. Everything else in this project is
big-endian because that is what the wire uses; the pcap *file* is the one place
where the byte order is whatever the machine that wrote it happened to use.

This reader deliberately does not handle pcapng. pcapng is a different, block
structured format, and Wireshark writes it by default - which is the single most
common reason a capture "will not open". We detect its magic and say so.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from netsniff.capture.base import CaptureError, Frame, LinkType, UnsupportedLinkType

__all__ = ["PcapError", "PcapFileHeader", "PcapReader", "read_pcap"]

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

# Magic numbers, as the literal first four bytes on disk.
#
# The "swapped" variants are the same 32-bit constant written by a machine of the
# opposite byte order; seeing one tells us to read the whole file that way. The
# 0xa1b23c4d pair is the nanosecond-resolution variant, where the second
# timestamp field counts nanoseconds instead of microseconds.
_MAGIC_BE_USEC = b"\xa1\xb2\xc3\xd4"
_MAGIC_LE_USEC = b"\xd4\xc3\xb2\xa1"
_MAGIC_BE_NSEC = b"\xa1\xb2\x3c\x4d"
_MAGIC_LE_NSEC = b"\x4d\x3c\xb2\xa1"
_MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

# magic -> (byte-order character, ticks per second in the sub-second field)
_MAGICS: dict[bytes, tuple[str, int]] = {
    _MAGIC_BE_USEC: (">", 1_000_000),
    _MAGIC_LE_USEC: ("<", 1_000_000),
    _MAGIC_BE_NSEC: (">", 1_000_000_000),
    _MAGIC_LE_NSEC: ("<", 1_000_000_000),
}

# A hard ceiling on how many bytes one record may claim. A corrupt or hostile
# file can put 0xFFFFFFFF in incl_len; without this we would try to allocate 4GB
# on the strength of four bytes we have not validated.
MAX_RECORD_BYTES = 16 * 1024 * 1024


class PcapError(CaptureError):
    """The file is not a classic pcap, or it is malformed or truncated."""


@dataclass(frozen=True, slots=True)
class PcapFileHeader:
    """The parsed 24-byte global header."""

    byte_order: str
    """``<`` or ``>``, as detected from the magic number."""

    version_major: int
    version_minor: int

    thiszone: int
    """GMT offset of the timestamps, in seconds. Effectively always 0."""

    sigfigs: int
    """Timestamp accuracy. Effectively always 0."""

    snaplen: int
    """Maximum bytes captured per packet, as configured by the capture tool."""

    link_type: int
    """Link-layer type; 1 is Ethernet. See :class:`~netsniff.capture.base.LinkType`."""

    ticks_per_second: int
    """1e6 for a normal pcap, 1e9 for the nanosecond-resolution variant."""

    @property
    def nanosecond_resolution(self) -> bool:
        return self.ticks_per_second == 1_000_000_000

    @property
    def link_type_name(self) -> str:
        return LinkType.describe(self.link_type)


def _parse_global_header(raw: bytes) -> PcapFileHeader:
    """Parse the 24-byte global header, detecting byte order from the magic."""
    if len(raw) < GLOBAL_HEADER_LEN:
        raise PcapError(
            f"file is too short to be a pcap: got {len(raw)} bytes, "
            f"need at least {GLOBAL_HEADER_LEN} for the global header"
        )

    magic = raw[:4]
    if magic == _MAGIC_PCAPNG:
        raise PcapError(
            "this is a pcapng file, not a classic pcap. Wireshark saves pcapng by "
            "default; re-save it as 'Wireshark/tcpdump/... - pcap', or capture with "
            "'tcpdump -w', which writes classic pcap."
        )
    if magic not in _MAGICS:
        raise PcapError(
            f"bad magic number {magic.hex()}: this is not a classic pcap file "
            f"(expected a1b2c3d4, d4c3b2a1, a1b23c4d or 4d3cb2a1)"
        )

    endian, ticks = _MAGICS[magic]

    # After the magic: two uint16 version fields, one int32 zone offset (signed,
    # it is an offset), then three uint32 fields.
    version_major, version_minor, thiszone, sigfigs, snaplen, link_type = struct.unpack(
        endian + "HHiIII", raw[4:GLOBAL_HEADER_LEN]
    )

    if snaplen == 0:
        # Not fatal, since we slice by incl_len anyway, but it means the writer
        # told us nothing useful - do not let it be used as a bound later.
        snaplen = MAX_RECORD_BYTES

    return PcapFileHeader(
        byte_order=endian,
        version_major=version_major,
        version_minor=version_minor,
        thiszone=thiszone,
        sigfigs=sigfigs,
        snaplen=snaplen,
        link_type=link_type,
        ticks_per_second=ticks,
    )


class PcapReader:
    """Iterate the frames in a classic pcap file.

    Usage::

        with PcapReader("capture.pcap") as reader:
            for frame in reader:
                ...

    The reader is a one-shot iterator over the file: iterating twice does not
    rewind. It never loads the whole capture into memory, so a large file costs
    one record at a time.

    Args:
        source: Path to a ``.pcap`` file, or an already-open binary file object.
        require_ethernet: Raise :class:`UnsupportedLinkType` up front when the
            capture is not Ethernet. Turn it off to inspect a file header
            without committing to decoding the frames.
    """

    def __init__(self, source: str | Path | BinaryIO, *, require_ethernet: bool = True) -> None:
        self._own_handle = False
        self._closed = False
        self._index = 0

        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise PcapError(f"no such capture file: {path}")
            if path.is_dir():
                raise PcapError(f"{path} is a directory, not a pcap file")
            self._fh: BinaryIO = path.open("rb")
            self._own_handle = True
            self.path: str = str(path)
        else:
            self._fh = source
            self.path = str(getattr(source, "name", "<stream>"))

        try:
            raw = self._read_exactly(GLOBAL_HEADER_LEN, "global header")
            self.header = _parse_global_header(raw)
        except BaseException:
            self.close()
            raise

        if require_ethernet and self.header.link_type != LinkType.ETHERNET:
            self.close()
            raise UnsupportedLinkType(self.header.link_type)

    # -- plumbing ----------------------------------------------------------

    def _read_exactly(self, n: int, what: str) -> bytes:
        """Read exactly n bytes or raise."""
        chunk = self._fh.read(n)
        if len(chunk) != n:
            raise PcapError(
                f"truncated {what}: wanted {n} bytes, got {len(chunk)} (file ends early)"
            )
        return chunk

    @property
    def link_type(self) -> int:
        """Link type of the capture, so this satisfies the ``Source`` protocol."""
        return self.header.link_type

    @property
    def packets_read(self) -> int:
        """How many records have been yielded so far."""
        return self._index

    # -- iteration ---------------------------------------------------------

    def __iter__(self) -> Iterator[Frame]:
        endian = self.header.byte_order
        ticks = self.header.ticks_per_second
        zone = self.header.thiszone
        record_fmt = endian + "IIII"

        while True:
            head = self._fh.read(RECORD_HEADER_LEN)
            if not head:
                return  # clean EOF, landing exactly on a record boundary
            if len(head) != RECORD_HEADER_LEN:
                raise PcapError(
                    f"truncated record header at packet {self._index}: wanted "
                    f"{RECORD_HEADER_LEN} bytes, got {len(head)}"
                )

            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(record_fmt, head)

            if incl_len > MAX_RECORD_BYTES:
                raise PcapError(
                    f"packet {self._index} claims {incl_len} captured bytes, over the "
                    f"{MAX_RECORD_BYTES} byte sanity limit; the file is corrupt or its "
                    f"byte order was misdetected"
                )

            data = self._fh.read(incl_len)
            if len(data) != incl_len:
                raise PcapError(
                    f"truncated packet data at packet {self._index}: the record header "
                    f"claims {incl_len} bytes, only {len(data)} remain in the file"
                )

            # ts_frac counts microseconds or nanoseconds depending on the magic.
            ts = ts_sec + zone + ts_frac / ticks

            # orig_len < incl_len is nonsense, but some writers emit it; trust the
            # bytes we actually hold rather than the claim.
            frame = Frame(
                ts=ts,
                data=data,
                orig_len=max(orig_len, incl_len),
                index=self._index,
            )
            self._index += 1
            yield frame

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        if self._own_handle and not self._closed:
            self._fh.close()
        self._closed = True

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        order = "little" if self.header.byte_order == "<" else "big"
        return (
            f"<PcapReader {self.path!r} link={self.header.link_type_name} "
            f"order={order} snaplen={self.header.snaplen} read={self._index}>"
        )


def read_pcap(path: str | Path, *, require_ethernet: bool = True) -> Iterator[Frame]:
    """Yield every :class:`Frame` in a pcap file, closing the file afterwards."""
    with PcapReader(path, require_ethernet=require_ethernet) as reader:
        yield from reader
