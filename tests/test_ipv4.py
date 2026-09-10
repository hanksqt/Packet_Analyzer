"""IPv4 header decoding.

The expected values are tcpdump's, taken from ``-e -vv`` output over these exact
bytes. For sample.pcap packet 0 that line reads::

    (tos 0xc0, ttl 254, id 44756, offset 0, flags [DF], proto TCP (6), length 60)
    10.0.0.12.39313 > 10.0.0.1.179
"""

from __future__ import annotations

import pytest

from netsniff.decode.common import DecodeError, Truncated, checksum16, verify_checksum
from netsniff.decode.ethernet import decode_ethernet
from netsniff.decode.ipv4 import (
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    IPV4_MIN_HEADER_LEN,
    decode_ipv4,
    ip_protocol_name,
)
from tests.fixtures import headers


def ip_bytes(frame: bytes) -> bytes:
    """Strip the Ethernet header (VLAN tags included) off a fixture."""
    return frame[decode_ethernet(frame).header_len :]


# --------------------------------------------------------------------------
# every field of a real header
# --------------------------------------------------------------------------


def test_all_fields_match_tcpdump() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_TCP_SYN))

    assert ip.version == 4
    assert ip.ihl == 5
    assert ip.header_len == 20
    assert ip.total_length == 60  # tcpdump: length 60
    assert ip.identification == 44756  # tcpdump: id 44756
    assert ip.ttl == 254  # tcpdump: ttl 254
    assert ip.protocol == IPPROTO_TCP  # tcpdump: proto TCP (6)
    assert ip.protocol_name == "TCP"
    assert ip.src == "10.0.0.12"
    assert ip.dst == "10.0.0.1"

    # tos 0xc0 splits into DSCP 48 (CS6, network control - this is BGP) and ECN 0.
    assert ip.dscp == 48
    assert ip.ecn == 0

    assert ip.dont_fragment  # tcpdump: flags [DF]
    assert not ip.more_fragments
    assert not ip.reserved_flag
    assert ip.fragment_offset == 0  # tcpdump: offset 0
    assert not ip.is_fragment

    assert not ip.has_options
    assert ip.options == b""
    assert ip.payload_len == 40  # 60 total - 20 header


def test_addresses_are_not_swapped() -> None:
    raw = ip_bytes(headers.ETH_IPV4_TCP_SYN)
    ip = decode_ipv4(raw)
    assert raw[12:16] == bytes(int(o) for o in ip.src.split("."))
    assert raw[16:20] == bytes(int(o) for o in ip.dst.split("."))


def test_second_direction_of_the_same_conversation() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_TCP_SYN_ACK))
    assert ip.src == "34.223.124.45"
    assert ip.dst == "172.18.54.224"
    assert ip.ttl == 239  # tcpdump: ttl 239
    assert ip.identification == 0  # tcpdump: id 0


def test_icmp_protocol_dispatch() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))
    assert ip.protocol == IPPROTO_ICMP
    assert ip.protocol_name == "ICMP"
    assert ip.src == "172.18.54.224"
    assert ip.dst == "1.1.1.1"


def test_udp_protocol_dispatch() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_UDP_DNS_QUERY))
    assert ip.protocol == IPPROTO_UDP
    assert ip.protocol_name == "UDP"


# --------------------------------------------------------------------------
# IHL: the variable-length header
# --------------------------------------------------------------------------


def test_ihl_counts_32_bit_words_not_bytes() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    assert ip.ihl == 5
    assert ip.header_len == ip.ihl * 4 == 20


def test_options_present_when_ihl_is_six() -> None:
    """tcpdump: options (RA) - a 4-byte Router Alert, so IHL is 6."""
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_OPTIONS_ICMP))
    assert ip.ihl == 6
    assert ip.header_len == 24
    assert ip.has_options
    assert ip.options == bytes([0x94, 0x04, 0x00, 0x00])
    assert ip.protocol == IPPROTO_ICMP


def test_payload_starts_after_the_options_not_at_twenty() -> None:
    """Slicing at a fixed 20 bytes would put us inside the option."""
    raw = ip_bytes(headers.ETH_IPV4_OPTIONS_ICMP)
    ip = decode_ipv4(raw)
    assert raw[ip.header_len] == 8, "ICMP type 8, echo request"
    assert raw[IPV4_MIN_HEADER_LEN] != 8, "the naive offset lands in the option"


def test_ihl_below_five_is_rejected() -> None:
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[0] = 0x44  # version 4, IHL 4 -> a 16-byte header, which cannot exist
    with pytest.raises(DecodeError, match="below the 20"):
        decode_ipv4(bytes(raw))


def test_options_claimed_but_not_captured() -> None:
    """IHL says 60 bytes of header; the buffer only holds 20."""
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN)[:20])
    raw[0] = 0x4F  # IHL 15 -> 60 bytes
    with pytest.raises(Truncated, match="IPv4 header with options"):
        decode_ipv4(bytes(raw))


# --------------------------------------------------------------------------
# fragmentation
# --------------------------------------------------------------------------


def test_first_fragment() -> None:
    """tcpdump: flags [+], offset 0."""
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_FRAG_FIRST))
    assert ip.more_fragments
    assert not ip.dont_fragment
    assert ip.fragment_offset == 0
    assert ip.is_fragment
    assert ip.is_first_fragment, "carries the transport header"
    assert ip.identification == 0x2A2A


def test_later_fragment() -> None:
    """tcpdump: offset 1480, flags [none]."""
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_FRAG_LATER))
    assert not ip.more_fragments
    assert ip.fragment_offset == 185
    assert ip.fragment_offset_bytes == 1480, "the field counts 8-byte units"
    assert ip.is_fragment
    assert not ip.is_first_fragment, "starts mid-payload, no transport header here"
    assert ip.identification == 0x2A2A, "same datagram as the first fragment"


def test_flag_bits_are_independent() -> None:
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    for value, reserved, df, mf, offset in [
        (0x0000, False, False, False, 0),
        (0x8000, True, False, False, 0),
        (0x4000, False, True, False, 0),
        (0x2000, False, False, True, 0),
        (0x2001, False, False, True, 1),
        (0x1FFF, False, False, False, 0x1FFF),
    ]:
        raw[6:8] = value.to_bytes(2, "big")
        ip = decode_ipv4(bytes(raw))
        assert (ip.reserved_flag, ip.dont_fragment, ip.more_fragments) == (reserved, df, mf)
        assert ip.fragment_offset == offset


# --------------------------------------------------------------------------
# checksum
# --------------------------------------------------------------------------


def test_checksum_validates_on_every_captured_header() -> None:
    """These checksums were computed by real network stacks, not by us."""
    for name in (
        "ETH_IPV4_TCP_SYN",
        "ETH_IPV4_TCP_SYN_ACK",
        "ETH_IPV4_TCP_HTTP_GET",
        "ETH_IPV4_TCP_FIN_ACK",
        "ETH_IPV4_TCP_RST",
        "ETH_IPV4_ICMP_ECHO_REQUEST",
        "ETH_IPV4_ICMP_ECHO_REPLY",
    ):
        ip = decode_ipv4(ip_bytes(getattr(headers, name)))
        assert ip.checksum_valid, f"{name} should have a valid IPv4 checksum"


def test_corrupting_any_header_byte_breaks_the_checksum() -> None:
    good = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    assert decode_ipv4(bytes(good)).checksum_valid

    for pos in (8, 12, 19):  # TTL, first source octet, last destination octet
        bad = bytearray(good)
        bad[pos] ^= 0xFF
        assert not decode_ipv4(bytes(bad)).checksum_valid, f"byte {pos}"


def test_zero_checksum_is_reported_as_offloaded_not_corrupt() -> None:
    """Captures taken on the sending host routinely have an unfilled checksum."""
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[10:12] = b"\x00\x00"
    ip = decode_ipv4(bytes(raw))
    assert not ip.checksum_valid
    assert ip.checksum_offloaded


def test_checksum16_and_verify_agree() -> None:
    header = ip_bytes(headers.ETH_IPV4_TCP_SYN)[:20]
    assert verify_checksum(header)

    zeroed = header[:10] + b"\x00\x00" + header[12:]
    assert checksum16(zeroed) == int.from_bytes(header[10:12], "big")


def test_checksum_of_odd_length_buffer_pads() -> None:
    assert checksum16(b"\x00\x01\x02") == checksum16(b"\x00\x01\x02\x00")


# --------------------------------------------------------------------------
# lengths and truncation
# --------------------------------------------------------------------------


def test_short_buffer_raises_before_unpacking() -> None:
    with pytest.raises(Truncated) as exc:
        decode_ipv4(ip_bytes(headers.ETH_IPV4_TCP_SYN)[:19])
    assert exc.value.needed == IPV4_MIN_HEADER_LEN
    assert exc.value.available == 19


def test_payload_len_clamped_to_what_was_captured() -> None:
    """A snapped packet: total_length claims 60, only 30 bytes are present."""
    raw = ip_bytes(headers.ETH_IPV4_TCP_SYN)[:30]
    ip = decode_ipv4(raw)
    assert ip.total_length == 60
    assert ip.payload_len == 10, "30 captured - 20 header, not the claimed 40"


def test_zero_total_length_means_segmentation_offload() -> None:
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[2:4] = b"\x00\x00"
    ip = decode_ipv4(bytes(raw))
    assert ip.total_length == 0
    assert ip.payload_len == len(raw) - 20


def test_total_length_shorter_than_the_header_gives_no_payload() -> None:
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[2:4] = (10).to_bytes(2, "big")
    assert decode_ipv4(bytes(raw)).payload_len == 0


def test_wrong_version_rejected() -> None:
    raw = bytearray(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[0] = 0x65  # version 6 in an IPv4 slot
    with pytest.raises(DecodeError, match="version field is 6"):
        decode_ipv4(bytes(raw))


# --------------------------------------------------------------------------
# vlan interaction and naming
# --------------------------------------------------------------------------


def test_ipv4_decodes_correctly_behind_a_vlan_tag() -> None:
    """The regression this whole offset dance exists to prevent."""
    ip = decode_ipv4(ip_bytes(headers.ETH_VLAN_IPV4_TCP_SYN))
    assert ip.src == "192.0.2.10"
    assert ip.dst == "198.51.100.20"
    assert ip.protocol == IPPROTO_TCP
    assert ip.checksum_valid


def test_ipv4_decodes_correctly_behind_stacked_tags() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_QINQ_IPV4_ICMP))
    assert ip.src == "192.0.2.10"
    assert ip.protocol == IPPROTO_ICMP
    assert ip.checksum_valid


@pytest.mark.parametrize(
    ("number", "name"),
    [(1, "ICMP"), (6, "TCP"), (17, "UDP"), (47, "GRE"), (89, "OSPF"), (132, "SCTP")],
)
def test_protocol_names(number: int, name: str) -> None:
    assert ip_protocol_name(number) == name


def test_unknown_protocol_number() -> None:
    assert ip_protocol_name(253) == "proto 253"


def test_str_is_readable() -> None:
    ip = decode_ipv4(ip_bytes(headers.ETH_IPV4_TCP_SYN))
    assert str(ip) == "10.0.0.12 > 10.0.0.1 TCP ttl=254"

    frag = decode_ipv4(ip_bytes(headers.ETH_IPV4_FRAG_LATER))
    assert "frag+1480" in str(frag)
