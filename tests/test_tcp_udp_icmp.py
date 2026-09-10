"""Transport-layer decoding: TCP, UDP and ICMP.

Every expected value here was read off ``tcpdump -e -vv`` output for the same
bytes. The captured TCP fixtures are the interesting ones: they carry real
option lists (MSS, SACK-permitted, timestamps, window scale) and real sequence
numbers, and half of them have deliberately-unfilled checksums because they were
captured on the sending host.
"""

from __future__ import annotations

import socket

import pytest

from netsniff.decode.common import Truncated
from netsniff.decode.ethernet import decode_ethernet
from netsniff.decode.icmp import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    Icmp,
    decode_icmp,
    icmp_type_name,
)
from netsniff.decode.ipv4 import decode_ipv4
from netsniff.decode.tcp import (
    TCP_MIN_HEADER_LEN,
    TCPFlags,
    decode_tcp,
    parse_tcp_options,
    verify_tcp_checksum,
)
from netsniff.decode.udp import UDP_HEADER_LEN, decode_udp, verify_udp_checksum
from tests.fixtures import headers


def transport_bytes(frame: bytes) -> bytes:
    """Peel Ethernet and IPv4 off a fixture, returning the IP payload."""
    eth = decode_ethernet(frame)
    ip = decode_ipv4(frame[eth.header_len :])
    start = eth.header_len + ip.header_len
    return frame[start : start + ip.payload_len]


def ip_addrs(frame: bytes) -> tuple[bytes, bytes]:
    eth = decode_ethernet(frame)
    ip = decode_ipv4(frame[eth.header_len :])
    return socket.inet_aton(ip.src), socket.inet_aton(ip.dst)


# ==========================================================================
# TCP
# ==========================================================================


def test_syn_matches_tcpdump() -> None:
    """tcpdump: 10.0.0.12.39313 > 10.0.0.1.179: Flags [S], seq 3564783275, win 64240."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN))

    assert tcp.src_port == 39313
    assert tcp.dst_port == 179
    assert tcp.seq == 3564783275
    assert tcp.ack == 0
    assert tcp.window == 64240
    assert tcp.urgent_pointer == 0

    assert tcp.syn
    assert not tcp.ack_flag
    assert not tcp.fin and not tcp.rst and not tcp.psh
    assert tcp.is_syn_only
    assert not tcp.is_syn_ack
    assert tcp.flag_string == "SYN"


def test_syn_ack_matches_tcpdump() -> None:
    """tcpdump: 34.223.124.45.80 > 172.18.54.224.46554: Flags [S.],
    seq 245663023, ack 513946277, win 26847."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN_ACK))

    assert (tcp.src_port, tcp.dst_port) == (80, 46554)
    assert tcp.seq == 245663023
    assert tcp.ack == 513946277
    assert tcp.window == 26847
    assert tcp.syn and tcp.ack_flag
    assert tcp.is_syn_ack
    assert not tcp.is_syn_only
    assert tcp.flag_string == "SYN,ACK", "flags read in Wireshark order"


def test_psh_ack_carrying_http() -> None:
    """tcpdump: Flags [P.], seq 1:77, ack 1 - absolute seq 513946277."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_HTTP_GET))
    assert (tcp.src_port, tcp.dst_port) == (46554, 80)
    assert tcp.seq == 513946277
    assert tcp.ack == 245663024
    assert tcp.psh and tcp.ack_flag
    assert not tcp.syn
    assert tcp.flag_string == "PSH,ACK"


def test_fin_ack() -> None:
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_FIN_ACK))
    assert tcp.fin and tcp.ack_flag
    assert tcp.flag_string == "FIN,ACK"


def test_rst() -> None:
    """tcpdump: Flags [R], seq 622665678, win 0, length 0."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_RST))
    assert tcp.rst
    assert tcp.seq == 622665678
    assert tcp.window == 0
    assert tcp.flag_string == "RST"
    assert tcp.data_offset == 5, "an RST carries no options"
    assert not tcp.has_options


def test_data_offset_counts_32_bit_words() -> None:
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN))
    assert tcp.data_offset == 10
    assert tcp.header_len == 40, "10 words * 4 = 40 bytes, not 10"
    assert tcp.has_options


def test_syn_options_match_tcpdump() -> None:
    """tcpdump: options [mss 1460,sackOK,TS val ... ecr 0,nop,wscale 7]."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN))

    kinds = [o.kind for o in tcp.options]
    assert kinds == [2, 4, 8, 1, 3], "MSS, SACK-permitted, timestamps, NOP, window scale"

    assert tcp.mss == 1460
    assert tcp.window_scale == 7
    assert [o.name for o in tcp.options if o.kind == 4] == ["SACK permitted"]


def test_syn_ack_advertises_a_smaller_mss() -> None:
    """tcpdump: mss 1452 - the far end is behind something with less MTU."""
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN_ACK))
    assert tcp.mss == 1452
    assert tcp.window_scale == 7


def test_established_segment_carries_only_timestamps() -> None:
    tcp = decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_HTTP_GET))
    assert tcp.data_offset == 8
    assert tcp.header_len == 32
    assert [o.kind for o in tcp.options] == [1, 1, 8]  # nop, nop, timestamps
    assert tcp.mss is None
    assert tcp.window_scale is None


def test_payload_starts_after_the_options() -> None:
    """Slicing at a fixed 20 bytes would eat 12 bytes into the HTTP request."""
    raw = transport_bytes(headers.ETH_IPV4_TCP_HTTP_GET)
    tcp = decode_tcp(raw)
    assert raw[tcp.header_len :].startswith(b"GET / HTTP/1.1")
    assert not raw[TCP_MIN_HEADER_LEN:].startswith(b"GET")


def test_all_nine_flag_bits() -> None:
    raw = bytearray(transport_bytes(headers.ETH_IPV4_TCP_SYN))
    for bit, name in [
        (TCPFlags.FIN, "FIN"),
        (TCPFlags.SYN, "SYN"),
        (TCPFlags.RST, "RST"),
        (TCPFlags.PSH, "PSH"),
        (TCPFlags.ACK, "ACK"),
        (TCPFlags.URG, "URG"),
        (TCPFlags.ECE, "ECE"),
        (TCPFlags.CWR, "CWR"),
        (TCPFlags.NS, "NS"),
    ]:
        # Keep data offset 10, replace the flag bits.
        raw[12:14] = ((10 << 12) | bit).to_bytes(2, "big")
        tcp = decode_tcp(bytes(raw))
        assert tcp.flag_names == (name,), name
        assert tcp.flags == bit


def test_no_flags_at_all() -> None:
    raw = bytearray(transport_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[12:14] = ((10 << 12) | 0).to_bytes(2, "big")
    tcp = decode_tcp(bytes(raw))
    assert tcp.flag_names == ()
    assert tcp.flag_string == "."


def test_data_offset_and_flags_do_not_bleed_into_each_other() -> None:
    """They share one 16-bit field; a bad mask mixes them up."""
    raw = bytearray(transport_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[12:14] = ((15 << 12) | 0x1FF).to_bytes(2, "big")
    tcp = decode_tcp(bytes(raw) + b"\x00" * 60)
    assert tcp.data_offset == 15
    assert tcp.flags == 0x1FF
    assert len(tcp.flag_names) == 9


# -- TCP option-area edge cases -------------------------------------------


def test_option_walk_handles_single_byte_kinds() -> None:
    opts = parse_tcp_options(b"\x01\x01\x08\x0a\x11\x22\x33\x44\x55\x66\x77\x88")
    assert [o.kind for o in opts] == [1, 1, 8]
    assert opts[2].data == bytes.fromhex("1122334455667788")


def test_end_of_list_stops_the_walk() -> None:
    opts = parse_tcp_options(b"\x02\x04\x05\xb4\x00\x03\x03\x07")
    assert [o.kind for o in opts] == [2], "everything after EOL is padding"


def test_malformed_option_length_does_not_loop_or_over_read() -> None:
    assert parse_tcp_options(b"\x02\x00\xff\xff") == ()  # length below the 2-byte minimum
    assert parse_tcp_options(b"\x02\x63\x05\xb4") == ()  # length runs past the buffer
    assert parse_tcp_options(b"\x02") == ()  # length octet promised but absent


def test_empty_option_area() -> None:
    assert parse_tcp_options(b"") == ()


def test_data_offset_below_five_does_not_produce_a_negative_slice() -> None:
    raw = bytearray(transport_bytes(headers.ETH_IPV4_TCP_SYN))
    raw[12:14] = ((2 << 12) | TCPFlags.SYN).to_bytes(2, "big")
    tcp = decode_tcp(bytes(raw))
    assert tcp.data_offset == 2
    assert tcp.header_len == TCP_MIN_HEADER_LEN, "clamped, so payload slicing stays sane"
    assert tcp.src_port == 39313, "ports and flags are still worth reporting"


def test_options_claimed_but_not_captured() -> None:
    raw = transport_bytes(headers.ETH_IPV4_TCP_SYN)[:20]
    with pytest.raises(Truncated, match="TCP header with options"):
        decode_tcp(raw)


def test_short_tcp_header() -> None:
    with pytest.raises(Truncated) as exc:
        decode_tcp(transport_bytes(headers.ETH_IPV4_TCP_SYN)[:19])
    assert exc.value.needed == TCP_MIN_HEADER_LEN


# -- TCP checksum ----------------------------------------------------------


def test_checksum_verifies_on_an_inbound_segment() -> None:
    """tcpdump on the SYN-ACK: cksum 0x0216 (correct)."""
    frame = headers.ETH_IPV4_TCP_SYN_ACK
    src, dst = ip_addrs(frame)
    assert verify_tcp_checksum(transport_bytes(frame), src, dst)


def test_checksum_fails_on_an_offloaded_outbound_segment() -> None:
    """tcpdump on the SYN: cksum 0x143b (incorrect).

    Not a bug and not corruption: the capture happened before the NIC filled the
    field in. Any tool that flagged this as an error would be crying wolf on
    roughly half of every locally-taken capture.
    """
    frame = headers.ETH_IPV4_TCP_SYN
    src, dst = ip_addrs(frame)
    assert not verify_tcp_checksum(transport_bytes(frame), src, dst)


def test_checksum_verifies_on_a_hand_built_segment() -> None:
    """tcpdump confirmed this one as cksum (correct) before it was pasted in."""
    frame = headers.ETH_IPV4_TCP_HTTP_REQUEST
    src, dst = ip_addrs(frame)
    assert verify_tcp_checksum(transport_bytes(frame), src, dst)


def test_checksum_notices_a_flipped_payload_byte() -> None:
    frame = headers.ETH_IPV4_TCP_HTTP_REQUEST
    src, dst = ip_addrs(frame)
    seg = bytearray(transport_bytes(frame))
    seg[-5] ^= 0xFF
    assert not verify_tcp_checksum(bytes(seg), src, dst)


def test_checksum_covers_the_pseudo_header() -> None:
    """Change the source IP and the checksum must stop verifying."""
    frame = headers.ETH_IPV4_TCP_HTTP_REQUEST
    _, dst = ip_addrs(frame)
    wrong_src = socket.inet_aton("10.0.0.1")
    assert not verify_tcp_checksum(transport_bytes(frame), wrong_src, dst)


# ==========================================================================
# UDP
# ==========================================================================


def test_udp_fields_match_tcpdump() -> None:
    """tcpdump: 192.0.2.10.54321 > 198.51.100.53.53: [udp sum ok] ... (29)."""
    udp = decode_udp(transport_bytes(headers.ETH_IPV4_UDP_DNS_QUERY))

    assert udp.src_port == 54321
    assert udp.dst_port == 53
    assert udp.header_len == UDP_HEADER_LEN == 8
    assert udp.length == 37, "8 header + 29 DNS payload"
    assert udp.claimed_payload_len == 29
    assert udp.payload_len == 29
    assert not udp.truncated
    assert udp.checksum_present


def test_udp_length_includes_the_header() -> None:
    """Treating length as a payload length shifts every app hint by 8 bytes."""
    raw = transport_bytes(headers.ETH_IPV4_UDP_DNS_QUERY)
    udp = decode_udp(raw)
    assert udp.length == len(raw)
    assert udp.claimed_payload_len == udp.length - UDP_HEADER_LEN
    assert raw[UDP_HEADER_LEN : UDP_HEADER_LEN + 2] == b"\x12\x34", "DNS txid 0x1234"


def test_udp_payload_clamped_when_capture_was_snapped() -> None:
    raw = transport_bytes(headers.ETH_IPV4_UDP_DNS_QUERY)[:20]
    udp = decode_udp(raw)
    assert udp.length == 37
    assert udp.claimed_payload_len == 29
    assert udp.payload_len == 12, "only 20 - 8 bytes were actually captured"
    assert udp.truncated


def test_udp_zero_length_field() -> None:
    raw = bytearray(transport_bytes(headers.ETH_IPV4_UDP_DNS_QUERY))
    raw[4:6] = b"\x00\x00"
    udp = decode_udp(bytes(raw))
    assert udp.payload_len == len(raw) - UDP_HEADER_LEN


def test_udp_absent_checksum_is_not_a_failure() -> None:
    """A zero checksum means 'not computed', which is legal over IPv4."""
    raw = bytearray(transport_bytes(headers.ETH_IPV4_UDP_DNS_QUERY))
    raw[6:8] = b"\x00\x00"
    udp = decode_udp(bytes(raw))
    assert not udp.checksum_present

    src, dst = ip_addrs(headers.ETH_IPV4_UDP_DNS_QUERY)
    assert verify_udp_checksum(bytes(raw), src, dst) is None


def test_udp_checksum_verifies() -> None:
    """tcpdump: [udp sum ok]."""
    frame = headers.ETH_IPV4_UDP_DNS_QUERY
    src, dst = ip_addrs(frame)
    assert verify_udp_checksum(transport_bytes(frame), src, dst) is True


def test_udp_checksum_notices_corruption() -> None:
    frame = headers.ETH_IPV4_UDP_DNS_QUERY
    src, dst = ip_addrs(frame)
    dgram = bytearray(transport_bytes(frame))
    dgram[-1] ^= 0xFF
    assert verify_udp_checksum(bytes(dgram), src, dst) is False


def test_short_udp_header() -> None:
    with pytest.raises(Truncated) as exc:
        decode_udp(b"\x00\x35\x00\x35\x00")
    assert exc.value.needed == UDP_HEADER_LEN


# ==========================================================================
# ICMP
# ==========================================================================


def test_echo_request_matches_tcpdump() -> None:
    """tcpdump: ICMP echo request, id 1, seq 1, length 64."""
    icmp = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))

    assert icmp.type == ICMP_ECHO_REQUEST == 8
    assert icmp.code == 0
    assert icmp.type_name == "echo request"
    assert icmp.is_echo
    assert icmp.is_echo_request
    assert not icmp.is_echo_reply
    assert not icmp.is_error
    assert icmp.echo_id == 1
    assert icmp.echo_seq == 1
    assert icmp.checksum_valid, "ICMPv4 checksums verify standalone"
    assert len(icmp.payload) == 56, "64 byte ICMP message minus the 8 byte header"


def test_echo_reply_pairs_with_the_request() -> None:
    request = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))
    reply = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REPLY))

    assert reply.type == ICMP_ECHO_REPLY == 0
    assert reply.is_echo_reply
    assert reply.checksum_valid
    assert (reply.echo_id, reply.echo_seq) == (request.echo_id, request.echo_seq)
    assert reply.payload == request.payload, "the reply echoes the request data back"


def test_destination_unreachable_quotes_the_original_datagram() -> None:
    """tcpdump: ICMP 198.51.100.53 udp port 53 unreachable."""
    icmp = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_UNREACHABLE))

    assert icmp.type == 3
    assert icmp.code == 3
    assert icmp.type_name == "destination unreachable"
    assert icmp.code_name == "port unreachable"
    assert icmp.is_error
    assert not icmp.is_echo
    assert icmp.echo_id is None, "an error message has no echo identifier"
    assert icmp.checksum_valid

    # The quoted datagram: an IPv4 header, then the first 8 bytes of the UDP one.
    quoted = decode_ipv4(icmp.payload)
    assert quoted.src == "192.0.2.10"
    assert quoted.dst == "198.51.100.53"
    assert decode_udp(icmp.payload[quoted.header_len :]).dst_port == 53


def test_icmp_behind_stacked_vlan_tags() -> None:
    icmp = decode_icmp(transport_bytes(headers.ETH_QINQ_IPV4_ICMP))
    assert icmp.is_echo_request
    assert icmp.echo_id == 1
    assert icmp.checksum_valid


def test_icmp_behind_ipv4_options() -> None:
    icmp = decode_icmp(transport_bytes(headers.ETH_IPV4_OPTIONS_ICMP))
    assert icmp.is_echo_request
    assert icmp.echo_id == 0x4321
    assert icmp.echo_seq == 7
    assert icmp.checksum_valid


def test_corrupt_icmp_checksum_is_detected() -> None:
    raw = bytearray(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))
    raw[-1] ^= 0xFF
    assert not decode_icmp(bytes(raw)).checksum_valid


def test_icmp_truncated_to_just_type_and_code() -> None:
    """Four bytes is enough to report what the message is."""
    raw = transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST)[:4]
    icmp = decode_icmp(raw)
    assert icmp.type == 8
    assert icmp.rest == b""
    assert icmp.echo_id is None, "the identifier was not captured"


def test_icmp_shorter_than_four_bytes() -> None:
    with pytest.raises(Truncated):
        decode_icmp(b"\x08\x00\x12")


def test_icmpv6_uses_a_different_type_number_space() -> None:
    v4 = decode_icmp(b"\x80\x00\x00\x00\x00\x01\x00\x01")
    v6 = decode_icmp(b"\x80\x00\x00\x00\x00\x01\x00\x01", v6=True)

    assert v4.type_name == "type 128", "128 means nothing in ICMPv4"
    assert v6.type_name == "echo request"
    assert v6.is_echo_request
    assert v6.echo_id == 1
    assert v6.checksum_valid is None, "needs the IPv6 pseudo-header we do not have"


@pytest.mark.parametrize(
    ("icmp_type", "v6", "expected"),
    [
        (0, False, "echo reply"),
        (3, False, "destination unreachable"),
        (11, False, "time exceeded"),
        (135, True, "neighbor solicitation"),
        (200, False, "type 200"),
    ],
)
def test_icmp_type_names(icmp_type: int, v6: bool, expected: str) -> None:
    assert icmp_type_name(icmp_type, v6=v6) == expected


def test_icmp_str_is_readable() -> None:
    echo = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))
    assert str(echo) == "echo request id=1 seq=1"

    err = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_UNREACHABLE))
    assert str(err) == "destination unreachable (port unreachable)"


def test_icmp_dataclass_is_frozen() -> None:
    icmp = decode_icmp(transport_bytes(headers.ETH_IPV4_ICMP_ECHO_REQUEST))
    assert isinstance(icmp, Icmp)
    with pytest.raises((AttributeError, TypeError)):
        icmp.type = 0  # type: ignore[misc]
