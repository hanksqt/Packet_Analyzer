r"""802.1Q VLAN tag decoding.

A VLAN tag is four bytes inserted into an Ethernet frame right after the source
MAC, where the ethertype would otherwise be::

    | dst MAC (6) | src MAC (6) | TPID (2) | TCI (2) | real ethertype (2) | ...
                                \___________________/
                                    the 802.1Q tag

The first two bytes are the TPID, which sits in the ethertype position and holds
0x8100. That is the whole trick: a tagged frame *looks* like an untagged frame
whose ethertype is 0x8100, and the ethertype you actually want is four bytes
further along. Miss that and every header after it is decoded at the wrong
offset - a silent, plausible-looking wrong answer rather than a crash.

The next two bytes are the TCI, which packs three fields::

    bit  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
         |  PCP  |DE|                VID                |
          \_____/  \/ \_________________________________/
           3 bits  1              12 bits

Stacked tags (QinQ, 802.1ad) repeat the structure with an outer TPID of 0x88a8
or 0x9100, so this module loops rather than handling exactly one tag.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from netsniff.decode.common import need

__all__ = [
    "TPIDS",
    "TPID_8021AD",
    "TPID_8021Q",
    "TPID_9100",
    "VLAN_TAG_LEN",
    "VlanTag",
    "decode_vlan_tag",
    "is_vlan_tpid",
]

VLAN_TAG_LEN = 4

TPID_8021Q = 0x8100
"""Standard customer VLAN tag."""

TPID_8021AD = 0x88A8
"""Service-provider (QinQ) outer tag."""

TPID_9100 = 0x9100
"""Legacy QinQ outer tag, still seen on older gear."""

TPIDS = frozenset({TPID_8021Q, TPID_8021AD, TPID_9100})

# Priority Code Point meanings from IEEE 802.1p. Included because "PCP 5" means
# nothing to a reader, while "voice" does.
_PCP_NAMES = {
    0: "best effort",
    1: "background",
    2: "excellent effort",
    3: "critical apps",
    4: "video",
    5: "voice",
    6: "internetwork control",
    7: "network control",
}


def is_vlan_tpid(ethertype: int) -> bool:
    """True when this ethertype value actually introduces a VLAN tag."""
    return ethertype in TPIDS


@dataclass(frozen=True, slots=True)
class VlanTag:
    """One 802.1Q tag."""

    tpid: int
    """The tag protocol identifier that introduced this tag (0x8100 etc)."""

    pcp: int
    """Priority Code Point, 0-7. Class of service."""

    dei: bool
    """Drop Eligible Indicator (the old CFI bit)."""

    vid: int
    """VLAN ID, 0-4095. 0 means priority-tagged only; 4095 is reserved."""

    @property
    def priority_name(self) -> str:
        return _PCP_NAMES.get(self.pcp, f"pcp {self.pcp}")

    @property
    def is_priority_tagged_only(self) -> bool:
        """VID 0 carries priority but names no VLAN."""
        return self.vid == 0

    def __str__(self) -> str:
        return f"vlan {self.vid} (pcp {self.pcp})"


def decode_vlan_tag(data: bytes, tpid: int) -> VlanTag:
    """Decode the two TCI bytes of a VLAN tag.

    Args:
        data: Buffer positioned at the TCI, i.e. just past the TPID.
        tpid: The TPID value that introduced this tag, kept for reporting.
    """
    need(data, 2, "802.1Q TCI")
    (tci,) = struct.unpack("!H", data[:2])
    return VlanTag(
        tpid=tpid,
        pcp=(tci >> 13) & 0x07,
        dei=bool((tci >> 12) & 0x01),
        vid=tci & 0x0FFF,
    )
