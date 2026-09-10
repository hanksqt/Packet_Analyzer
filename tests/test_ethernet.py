"""Ethernet II and 802.1Q VLAN decoding.

Expected values come from ``tcpdump -e -vv`` run over the same bytes, so these
tests compare our decoder against an independent implementation rather than
against itself.
"""

from __future__ import annotations

import pytest

from netsniff.decode.common import Truncated
from netsniff.decode.ethernet import (
    ETHERNET_HEADER_LEN,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    MAX_VLAN_TAGS,
    Ethernet,
    decode_ethernet,
    ethertype_name,
)
from netsniff.decode.vlan import TPID_8021AD, TPID_8021Q, decode_vlan_tag, is_vlan_tpid
from tests.fixtures import headers

# --------------------------------------------------------------------------
# plain Ethernet II
# --------------------------------------------------------------------------


def test_untagged_frame_matches_tcpdump() -> None:
    """tcpdump: 00:15:5d:01:9d:50 > 00:15:5d:2b:ea:fc, ethertype IPv4 (0x0800)."""
    eth = decode_ethernet(headers.ETH_IPV4_TCP_SYN)
    assert eth.src == "00:15:5d:01:9d:50"
    assert eth.dst == "00:15:5d:2b:ea:fc"
    assert eth.ethertype == ETHERTYPE_IPV4
    assert eth.ethertype_name == "IPv4"
    assert eth.header_len == ETHERNET_HEADER_LEN
    assert eth.vlan_tags == ()
    assert not eth.is_tagged
    assert eth.vlan_id is None
    assert eth.is_ethernet_ii


def test_source_and_destination_are_not_swapped() -> None:
    """Destination comes first on the wire; getting this backwards is easy."""
    raw = headers.ETH_IPV4_TCP_SYN
    eth = decode_ethernet(raw)
    assert raw[0:6].hex(":", 1) == eth.dst
    assert raw[6:12].hex(":", 1) == eth.src


def test_ipv6_ethertype_dispatches() -> None:
    eth = decode_ethernet(headers.ETH_IPV6_TCP_SYN)
    assert eth.ethertype == ETHERTYPE_IPV6
    assert eth.ethertype_name == "IPv6"


def test_arp_ethertype_and_broadcast() -> None:
    eth = decode_ethernet(headers.ETH_ARP_REQUEST)
    assert eth.ethertype == ETHERTYPE_ARP
    assert eth.dst == "ff:ff:ff:ff:ff:ff"
    assert eth.is_broadcast
    assert eth.is_multicast, "broadcast is multicast at the hardware level"


def test_arp_reply_is_unicast() -> None:
    eth = decode_ethernet(headers.ETH_ARP_REPLY)
    assert not eth.is_broadcast
    assert not eth.is_multicast


def test_multicast_without_broadcast() -> None:
    """01:80:c2:00:00:00 is the STP group address: multicast, not broadcast."""
    eth = decode_ethernet(headers.ETH_8023_LLC)
    assert eth.dst == "01:80:c2:00:00:00"
    assert eth.is_multicast
    assert not eth.is_broadcast


def test_locally_administered_source_bit() -> None:
    captured = decode_ethernet(headers.ETH_IPV4_TCP_SYN)
    assert not captured.src_is_locally_administered, "00:15:5d is a real Microsoft OUI"

    # Set bit 1 of the first source octet, which marks a locally administered
    # address (a randomised MAC, a container veth, a VM).
    raw = bytearray(headers.ETH_IPV4_TCP_SYN)
    raw[6] |= 0x02
    assert decode_ethernet(bytes(raw)).src_is_locally_administered


# --------------------------------------------------------------------------
# 802.1Q - the offset shift that silently breaks everything downstream
# --------------------------------------------------------------------------


def test_single_vlan_tag_shifts_the_payload_by_four_bytes() -> None:
    """tcpdump: vlan 100, p 3, ethertype IPv4 (0x0800)."""
    eth = decode_ethernet(headers.ETH_VLAN_IPV4_TCP_SYN)

    assert len(eth.vlan_tags) == 1
    tag = eth.vlan_tags[0]
    assert tag.tpid == TPID_8021Q
    assert tag.vid == 100
    assert tag.pcp == 3
    assert tag.priority_name == "critical apps"
    assert not tag.dei
    assert not tag.is_priority_tagged_only

    # The effective ethertype is the one *after* the tag, not 0x8100.
    assert eth.ethertype == ETHERTYPE_IPV4
    assert eth.header_len == ETHERNET_HEADER_LEN + 4 == 18
    assert eth.vlan_id == 100
    assert eth.is_tagged


def test_vlan_payload_starts_where_header_len_says() -> None:
    """The whole point of header_len: the IPv4 header must begin exactly there."""
    raw = headers.ETH_VLAN_IPV4_TCP_SYN
    eth = decode_ethernet(raw)
    payload = raw[eth.header_len :]
    assert payload[0] >> 4 == 4, "first payload nibble should be IP version 4"

    # Slicing at a hardcoded 14 lands inside the tag and decodes garbage.
    wrong = raw[ETHERNET_HEADER_LEN:]
    assert wrong[0] >> 4 != 4


def test_stacked_qinq_tags() -> None:
    """tcpdump: vlan 200, p 0, ethertype 802.1Q, vlan 100, p 0, ethertype IPv4."""
    eth = decode_ethernet(headers.ETH_QINQ_IPV4_ICMP)

    assert len(eth.vlan_tags) == 2
    outer, inner = eth.vlan_tags
    assert outer.tpid == TPID_8021AD
    assert outer.vid == 200
    assert inner.tpid == TPID_8021Q
    assert inner.vid == 100

    assert eth.ethertype == ETHERTYPE_IPV4
    assert eth.header_len == ETHERNET_HEADER_LEN + 8 == 22
    assert eth.vlan_id == 100, "vlan_id reports the innermost tag"


def test_vlan_tag_field_packing() -> None:
    """PCP is the top 3 bits, DEI the next, VID the low 12."""
    # pcp=7, dei=1, vid=4095  ->  0b111_1_111111111111 == 0xFFFF
    tag = decode_vlan_tag(b"\xff\xff", tpid=TPID_8021Q)
    assert tag.pcp == 7
    assert tag.dei
    assert tag.vid == 4095

    tag = decode_vlan_tag(b"\x00\x00", tpid=TPID_8021Q)
    assert tag.pcp == 0
    assert not tag.dei
    assert tag.vid == 0
    assert tag.is_priority_tagged_only


@pytest.mark.parametrize("tpid", [0x8100, 0x88A8, 0x9100])
def test_all_vlan_tpids_recognised(tpid: int) -> None:
    assert is_vlan_tpid(tpid)


@pytest.mark.parametrize("not_tpid", [0x0800, 0x86DD, 0x0806, 0x0000])
def test_non_vlan_ethertypes_not_treated_as_tags(not_tpid: int) -> None:
    assert not is_vlan_tpid(not_tpid)


def test_runaway_tag_stack_is_capped() -> None:
    """A crafted frame must not make us loop through the whole packet."""
    raw = bytearray(b"\xaa" * 6 + b"\xbb" * 6)
    for _ in range(MAX_VLAN_TAGS + 3):
        raw += b"\x81\x00\x00\x64"
    raw += b"\x08\x00" + b"\x45" + b"\x00" * 40

    eth = decode_ethernet(bytes(raw))
    assert len(eth.vlan_tags) == MAX_VLAN_TAGS


# --------------------------------------------------------------------------
# 802.3, where the field is a length rather than a type
# --------------------------------------------------------------------------


def test_8023_length_field_is_not_treated_as_an_ethertype() -> None:
    eth = decode_ethernet(headers.ETH_8023_LLC)
    assert eth.ethertype == 38, "tcpdump: 802.3, length 38"
    assert not eth.is_ethernet_ii
    assert "802.3 length 38" in eth.ethertype_name


def test_ethertype_boundary_is_1536() -> None:
    def frame_with_type(value: int) -> Ethernet:
        raw = bytearray(headers.ETH_IPV4_TCP_SYN)
        raw[12:14] = value.to_bytes(2, "big")
        return decode_ethernet(bytes(raw))

    assert not frame_with_type(1500).is_ethernet_ii
    assert not frame_with_type(1535).is_ethernet_ii
    assert frame_with_type(1536).is_ethernet_ii  # 0x0600


# --------------------------------------------------------------------------
# short buffers
# --------------------------------------------------------------------------


def test_frame_shorter_than_the_header() -> None:
    with pytest.raises(Truncated) as exc:
        decode_ethernet(headers.ETH_IPV4_TCP_SYN[:13])
    assert exc.value.needed == 14
    assert exc.value.available == 13
    assert "Ethernet header" in str(exc.value)


def test_empty_buffer() -> None:
    with pytest.raises(Truncated):
        decode_ethernet(b"")


def test_frame_cut_off_inside_a_vlan_tag() -> None:
    """A snapped capture can end between the TPID and the real ethertype."""
    with pytest.raises(Truncated):
        decode_ethernet(headers.ETH_VLAN_IPV4_TCP_SYN[:15])
    with pytest.raises(Truncated):
        decode_ethernet(headers.ETH_VLAN_IPV4_TCP_SYN[:17])

    # 18 bytes is exactly the tagged header, so this one must succeed.
    eth = decode_ethernet(headers.ETH_VLAN_IPV4_TCP_SYN[:18])
    assert eth.vlan_id == 100


# --------------------------------------------------------------------------
# naming and formatting
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0x0800, "IPv4"), (0x0806, "ARP"), (0x86DD, "IPv6"), (0x88CC, "LLDP")],
)
def test_known_ethertype_names(value: int, expected: str) -> None:
    assert ethertype_name(value) == expected


def test_unknown_ethertype_falls_back_to_hex() -> None:
    assert ethertype_name(0x1234) == "0x1234"


def test_str_is_readable() -> None:
    assert str(decode_ethernet(headers.ETH_IPV4_TCP_SYN)) == (
        "00:15:5d:01:9d:50 > 00:15:5d:2b:ea:fc IPv4"
    )
    tagged = str(decode_ethernet(headers.ETH_VLAN_IPV4_TCP_SYN))
    assert "[vlan 100 (pcp 3)]" in tagged


def test_every_fixture_decodes_its_ethernet_header() -> None:
    """A sweep: no fixture may crash the outermost decoder."""
    for name, raw in headers.ALL_FRAMES.items():
        eth = decode_ethernet(raw)
        assert len(eth.dst) == 17, name
        assert eth.header_len >= ETHERNET_HEADER_LEN, name
