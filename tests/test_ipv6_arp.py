"""IPv6 and ARP decoding.

Expected values are tcpdump's, from ``-e -vv`` over the same bytes. For the
extension-chain fixture that line reads::

    next-header HBH (0), payload length 59 ... HBH (padn) DSTOPT (padn)
    54321 > 53: [udp sum ok] 21845+ A? chain.example.com. (35)

which is the whole point of the chain walk: the base header says "hop-by-hop",
and the transport protocol is two links further along.
"""

from __future__ import annotations

import pytest

from netsniff.decode.arp import (
    ARP_FIXED_LEN,
    ARP_REPLY,
    ARP_REQUEST,
    decode_arp,
)
from netsniff.decode.common import DecodeError, Truncated
from netsniff.decode.ethernet import decode_ethernet
from netsniff.decode.icmp import decode_icmp
from netsniff.decode.ipv6 import (
    IPV6_HEADER_LEN,
    MAX_EXTENSION_HEADERS,
    NEXT_HEADER_DSTOPTS,
    NEXT_HEADER_ESP,
    NEXT_HEADER_FRAGMENT,
    NEXT_HEADER_HOPOPT,
    decode_ipv6,
)
from netsniff.decode.tcp import decode_tcp
from netsniff.decode.udp import decode_udp
from tests.fixtures import headers


def payload_of(frame: bytes) -> bytes:
    """Strip the Ethernet header off a fixture."""
    return frame[decode_ethernet(frame).header_len :]


# ==========================================================================
# IPv6
# ==========================================================================


def test_all_base_header_fields_match_tcpdump() -> None:
    """tcpdump: flowlabel 0x12345, hlim 57, next-header TCP (6), payload length 20."""
    ip = decode_ipv6(payload_of(headers.ETH_IPV6_TCP_SYN))

    assert ip.version == 6
    assert ip.flow_label == 0x12345
    assert ip.hop_limit == 57
    assert ip.next_header == 6
    assert ip.payload_length == 20
    assert ip.src == "2001:db8::1"
    assert ip.dst == "2001:db8:beef::2"
    assert ip.header_len == IPV6_HEADER_LEN == 40
    assert ip.protocol == 6
    assert ip.protocol_name == "TCP"
    assert not ip.has_extension_headers


def test_addresses_are_compressed_correctly() -> None:
    """inet_ntop collapses the longest run of zero groups to '::'."""
    ip = decode_ipv6(payload_of(headers.ETH_IPV6_UDP_DNS_QUERY))
    assert ip.src == "2001:db8::1"
    assert ip.dst == "2001:db8::53"


def test_addresses_are_not_swapped() -> None:
    raw = payload_of(headers.ETH_IPV6_TCP_SYN)
    ip = decode_ipv6(raw)
    import socket

    assert socket.inet_pton(socket.AF_INET6, ip.src) == raw[8:24]
    assert socket.inet_pton(socket.AF_INET6, ip.dst) == raw[24:40]


def test_transport_decodes_at_header_len() -> None:
    raw = payload_of(headers.ETH_IPV6_TCP_SYN)
    ip = decode_ipv6(raw)
    tcp = decode_tcp(raw[ip.header_len :])
    assert (tcp.src_port, tcp.dst_port) == (40000, 80)
    assert tcp.seq == 0xDEADBEEF
    assert tcp.syn


def test_udp_over_ipv6() -> None:
    raw = payload_of(headers.ETH_IPV6_UDP_DNS_QUERY)
    ip = decode_ipv6(raw)
    assert ip.protocol == 17
    assert ip.payload_length == 41
    udp = decode_udp(raw[ip.header_len :])
    assert udp.dst_port == 53
    assert udp.length == 41, "the UDP length equals the IPv6 payload length here"


def test_traffic_class_splits_into_dscp_and_ecn() -> None:
    raw = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN))
    # version 6, traffic class 0xb8 (DSCP 46 = EF, ECN 0), flow label preserved.
    raw[0] = 0x6B
    raw[1] = (0x80) | (raw[1] & 0x0F)
    ip = decode_ipv6(bytes(raw))
    assert ip.traffic_class == 0xB8
    assert ip.dscp == 46
    assert ip.ecn == 0


def test_wrong_version_rejected() -> None:
    raw = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN))
    raw[0] = 0x45
    with pytest.raises(DecodeError, match="version field is 4"):
        decode_ipv6(bytes(raw))


def test_short_ipv6_header() -> None:
    with pytest.raises(Truncated) as exc:
        decode_ipv6(payload_of(headers.ETH_IPV6_TCP_SYN)[:39])
    assert exc.value.needed == IPV6_HEADER_LEN


# -- the extension header chain -------------------------------------------


def test_chain_walk_finds_the_real_transport_protocol() -> None:
    """Base header says hop-by-hop; the transport is two links further on."""
    raw = payload_of(headers.ETH_IPV6_EXT_CHAIN_UDP)
    ip = decode_ipv6(raw)

    assert ip.next_header == NEXT_HEADER_HOPOPT, "what the base header claims"
    assert ip.protocol == 17, "what it actually turns out to be"
    assert ip.protocol_name == "UDP"

    assert [e.type for e in ip.extension_headers] == [
        NEXT_HEADER_HOPOPT,
        NEXT_HEADER_DSTOPTS,
    ]
    assert [e.name for e in ip.extension_headers] == [
        "hop-by-hop options",
        "destination options",
    ]
    assert [e.length for e in ip.extension_headers] == [8, 8]
    assert ip.has_extension_headers
    assert not ip.truncated_chain


def test_header_len_accounts_for_every_extension() -> None:
    """Dispatching at a fixed 40 bytes would land inside the hop-by-hop header."""
    raw = payload_of(headers.ETH_IPV6_EXT_CHAIN_UDP)
    ip = decode_ipv6(raw)
    assert ip.header_len == IPV6_HEADER_LEN + 8 + 8 == 56

    udp = decode_udp(raw[ip.header_len :])
    assert (udp.src_port, udp.dst_port) == (54321, 53)

    # The naive offset decodes the hop-by-hop bytes as ports instead.
    assert decode_udp(raw[IPV6_HEADER_LEN:]).dst_port != 53


def test_payload_len_excludes_the_extension_headers() -> None:
    """payload_length counts extensions; the transport payload does not."""
    ip = decode_ipv6(payload_of(headers.ETH_IPV6_EXT_CHAIN_UDP))
    assert ip.payload_length == 59  # tcpdump: payload length 59
    assert ip.payload_len == 59 - 16, "59 minus the two 8-byte extension headers"


def test_fragment_header_is_always_eight_bytes() -> None:
    """tcpdump: frag (0xcafebabe:0|43)."""
    ip = decode_ipv6(payload_of(headers.ETH_IPV6_FRAGMENT))
    assert [e.type for e in ip.extension_headers] == [NEXT_HEADER_FRAGMENT]
    assert ip.extension_headers[0].length == 8
    assert ip.is_fragment
    assert ip.protocol == 17
    assert ip.header_len == 48


def test_tlv_extension_length_excludes_the_first_eight_octets() -> None:
    """hdr_ext_len counts 8-octet units beyond the first 8, so len=0 means 8."""
    base = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN)[:IPV6_HEADER_LEN])
    base[6] = NEXT_HEADER_DSTOPTS
    for hdr_ext_len, expected in [(0, 8), (1, 16), (3, 32)]:
        ext = bytes([6, hdr_ext_len]) + b"\x00" * (expected - 2)
        ip = decode_ipv6(bytes(base) + ext + b"\x00" * 20)
        assert ip.extension_headers[0].length == expected
        assert ip.header_len == IPV6_HEADER_LEN + expected
        assert ip.protocol == 6


def test_chain_stops_at_esp_because_the_rest_is_encrypted() -> None:
    base = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN)[:IPV6_HEADER_LEN])
    base[6] = NEXT_HEADER_ESP
    ip = decode_ipv6(bytes(base) + b"\x00" * 32)
    assert ip.protocol == NEXT_HEADER_ESP
    assert ip.is_encrypted
    assert ip.extension_headers == (), "we stop before it, not past it"
    assert ip.header_len == IPV6_HEADER_LEN


def test_chain_that_runs_past_the_captured_bytes_is_flagged() -> None:
    base = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN)[:IPV6_HEADER_LEN])
    base[6] = NEXT_HEADER_DSTOPTS
    # Claims a 32-byte extension header but only 4 bytes follow.
    ip = decode_ipv6(bytes(base) + bytes([6, 3, 0, 0]))
    assert ip.truncated_chain
    assert ip.extension_headers == ()


def test_runaway_chain_is_bounded() -> None:
    """A crafted packet must not turn the walk into an unbounded loop."""
    base = bytearray(payload_of(headers.ETH_IPV6_TCP_SYN)[:IPV6_HEADER_LEN])
    base[6] = NEXT_HEADER_DSTOPTS
    # Each header points at another destination-options header, forever.
    chain = bytes([NEXT_HEADER_DSTOPTS, 0] + [0] * 6) * 40
    ip = decode_ipv6(bytes(base) + chain)
    assert len(ip.extension_headers) == MAX_EXTENSION_HEADERS
    assert ip.truncated_chain


def test_icmpv6_over_ipv6() -> None:
    """tcpdump: [icmp6 sum ok] ICMP6, echo request, id 3054, seq 3."""
    raw = payload_of(headers.ETH_IPV6_ICMPV6_ECHO)
    ip = decode_ipv6(raw)
    assert ip.protocol == 58
    assert ip.protocol_name == "ICMPv6"

    icmp = decode_icmp(raw[ip.header_len :], v6=True)
    assert icmp.type == 128
    assert icmp.type_name == "echo request"
    assert icmp.is_echo_request
    assert icmp.echo_id == 0x0BEE == 3054
    assert icmp.echo_seq == 3
    assert icmp.checksum_valid is None, "needs the pseudo-header we do not build here"


def test_ipv6_str_is_readable() -> None:
    plain = decode_ipv6(payload_of(headers.ETH_IPV6_TCP_SYN))
    assert str(plain) == "2001:db8::1 > 2001:db8:beef::2 TCP hlim=57"

    chained = str(decode_ipv6(payload_of(headers.ETH_IPV6_EXT_CHAIN_UDP)))
    assert "[hop-by-hop options]" in chained
    assert "[destination options]" in chained


# ==========================================================================
# ARP
# ==========================================================================


def test_request_matches_tcpdump() -> None:
    """tcpdump: Request who-has 192.0.2.1 tell 192.0.2.10."""
    arp = decode_arp(payload_of(headers.ETH_ARP_REQUEST))

    assert arp.hardware_type == 1
    assert arp.hardware_type_name == "Ethernet"
    assert arp.protocol_type == 0x0800
    assert arp.hardware_len == 6
    assert arp.protocol_len == 4
    assert arp.operation == ARP_REQUEST == 1
    assert arp.operation_name == "request"
    assert arp.is_request
    assert not arp.is_reply

    assert arp.sender_hardware == "00:11:22:33:44:55"
    assert arp.sender_protocol == "192.0.2.10"
    assert arp.target_hardware == "00:00:00:00:00:00", "unknown, that is the question"
    assert arp.target_protocol == "192.0.2.1"

    assert arp.is_ipv4_over_ethernet
    assert arp.length == 28


def test_reply_matches_tcpdump() -> None:
    """tcpdump: Reply 192.0.2.1 is-at 00:1a:2b:3c:4d:5e."""
    arp = decode_arp(payload_of(headers.ETH_ARP_REPLY))
    assert arp.operation == ARP_REPLY == 2
    assert arp.is_reply
    assert arp.sender_protocol == "192.0.2.1"
    assert arp.sender_hardware == "00:1a:2b:3c:4d:5e"
    assert arp.target_protocol == "192.0.2.10"


def test_ethernet_padding_is_ignored() -> None:
    """The frame is padded to 60 bytes; only 28 of them are ARP."""
    frame = headers.ETH_ARP_REQUEST
    assert len(frame) == 60
    assert len(payload_of(frame)) == 46
    assert decode_arp(payload_of(frame)).length == 28


def test_gratuitous_arp_detected() -> None:
    arp = decode_arp(payload_of(headers.ETH_ARP_GRATUITOUS))
    assert arp.is_reply
    assert arp.sender_protocol == arp.target_protocol == "192.0.2.10"
    assert arp.is_gratuitous
    assert not arp.is_probe


def test_ordinary_reply_is_not_gratuitous() -> None:
    assert not decode_arp(payload_of(headers.ETH_ARP_REPLY)).is_gratuitous


def test_arp_probe_detected() -> None:
    """tcpdump: Request who-has 192.0.2.77 tell 0.0.0.0."""
    arp = decode_arp(payload_of(headers.ETH_ARP_PROBE))
    assert arp.is_request
    assert arp.sender_protocol == "0.0.0.0"
    assert arp.target_protocol == "192.0.2.77"
    assert arp.is_probe
    assert not arp.is_gratuitous, "an all-zero sender is a probe, not an announcement"


def test_address_widths_come_from_the_packet_not_an_assumption() -> None:
    """hlen/plen drive the slicing, so a non-standard pairing still parses."""
    # 8-byte hardware addresses, 4-byte protocol addresses.
    raw = (
        bytes([0x00, 0x20, 0x08, 0x00, 8, 4, 0x00, 0x01])
        + bytes(range(0x10, 0x18))
        + bytes([192, 0, 2, 10])
        + bytes(range(0x20, 0x28))
        + bytes([192, 0, 2, 1])
    )
    arp = decode_arp(raw)
    assert arp.hardware_len == 8
    assert arp.length == 8 + 8 + 4 + 8 + 4 == 32
    assert arp.sender_hardware == "1011121314151617", "hex, since it is not a MAC"
    assert arp.sender_protocol == "192.0.2.10"
    assert not arp.is_ipv4_over_ethernet


def test_short_arp_header() -> None:
    with pytest.raises(Truncated) as exc:
        decode_arp(payload_of(headers.ETH_ARP_REQUEST)[:7])
    assert exc.value.needed == ARP_FIXED_LEN


def test_arp_truncated_inside_the_addresses() -> None:
    with pytest.raises(Truncated, match="ARP addresses"):
        decode_arp(payload_of(headers.ETH_ARP_REQUEST)[:20])


def test_unknown_operation_is_named_not_crashed() -> None:
    raw = bytearray(payload_of(headers.ETH_ARP_REQUEST))
    raw[6:8] = (99).to_bytes(2, "big")
    arp = decode_arp(bytes(raw))
    assert arp.operation_name == "operation 99"
    assert not arp.is_request and not arp.is_reply
    assert str(arp) == "ARP operation 99"


def test_arp_str_is_readable() -> None:
    assert str(decode_arp(payload_of(headers.ETH_ARP_REQUEST))) == (
        "who-has 192.0.2.1 tell 192.0.2.10"
    )
    assert str(decode_arp(payload_of(headers.ETH_ARP_REPLY))) == (
        "192.0.2.1 is-at 00:1a:2b:3c:4d:5e"
    )
