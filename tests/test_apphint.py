"""Application-layer hints: DNS, HTTP and TLS SNI.

Two halves. The first checks the parsers get the right answer on real captured
payloads - the DNS names, HTTP hosts and TLS server name in ``sample.pcap`` are
the ones tcpdump reports. The second is the half that matters more: these
parsers run on bytes an attacker chose, so a large part of this file is
deliberate garbage, hostile length fields, and compression-pointer loops, all
asserting the same thing - no hint, no exception, capture continues.
"""

from __future__ import annotations

import random
import struct
from pathlib import Path

import pytest

from netsniff.capture.base import Frame
from netsniff.capture.pcap import read_pcap
from netsniff.decode import decode_frame
from netsniff.decode.apphint import (
    AppHint,
    _read_dns_name,
    app_hint,
    parse_dns,
    parse_http,
    parse_tls_client_hello,
    service_name,
)
from tests.fixtures import headers


def transport_payload(frame: bytes) -> bytes:
    """The application-layer bytes of a fixture frame."""
    return decode_frame(Frame(1.0, frame)).payload


# ==========================================================================
# port naming
# ==========================================================================


@pytest.mark.parametrize(
    ("port", "name"),
    [(53, "dns"), (80, "http"), (443, "https"), (179, "bgp"), (22, "ssh"), (3389, "rdp")],
)
def test_well_known_ports(port: int, name: str) -> None:
    assert service_name(port) == name


def test_unknown_port_is_empty_not_the_word_unknown() -> None:
    assert service_name(51234) == ""


# ==========================================================================
# DNS
# ==========================================================================


def test_real_query_matches_tcpdump() -> None:
    """tcpdump: 44745+ [1au] A? example.com."""
    hint = parse_dns(transport_payload(headers.ETH_IPV4_UDP_DNS_QUERY_REAL))
    assert hint is not None
    assert hint.protocol == "DNS"
    assert hint.label == "example.com"
    assert "query A" in hint.detail
    assert "0xaec9" in hint.detail, "44745 == 0xaec9"


def test_real_response_echoes_the_question() -> None:
    """tcpdump: 44745 q: A? example.com. 2/0/1 ... A 172.66.147.243."""
    hint = parse_dns(transport_payload(headers.ETH_IPV4_UDP_DNS_RESPONSE_REAL))
    assert hint is not None
    assert hint.label == "example.com"
    assert "response A NOERROR" in hint.detail
    assert "2 answers" in hint.detail


def test_real_aaaa_query() -> None:
    """tcpdump: 20176+ [1au] AAAA? www.example.com."""
    hint = parse_dns(transport_payload(headers.ETH_IPV4_UDP_DNS_AAAA_QUERY_REAL))
    assert hint is not None
    assert hint.label == "www.example.com"
    assert "AAAA" in hint.detail


def test_real_nxdomain_response() -> None:
    """tcpdump: 58000 NXDomain$ q: A? nxdomain-test-netsniff.example."""
    hint = parse_dns(transport_payload(headers.ETH_IPV4_UDP_DNS_NXDOMAIN_REAL))
    assert hint is not None
    assert hint.label == "nxdomain-test-netsniff.example"
    assert "NXDOMAIN" in hint.detail
    assert "0 answers" in hint.detail


def test_hand_built_query() -> None:
    hint = parse_dns(transport_payload(headers.ETH_IPV4_UDP_DNS_QUERY))
    assert hint is not None
    assert hint.label == "example.com"
    assert "0x1234" in hint.detail


def test_dns_over_ipv6() -> None:
    payload = decode_frame(Frame(1.0, headers.ETH_IPV6_UDP_DNS_QUERY)).payload
    hint = parse_dns(payload)
    assert hint is not None
    assert hint.label == "www.example.com"
    assert "AAAA" in hint.detail


def test_root_query_is_a_single_dot() -> None:
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x00" + struct.pack("!HH", 2, 1)
    hint = parse_dns(message)
    assert hint is not None
    assert hint.label == "."


def test_compression_pointer_is_followed() -> None:
    """A pointer replaces a name with an offset to one written earlier.

    Exercised through _read_dns_name directly. A question's name always begins
    at offset 12 and pointers may only point backwards, so a pointer in the
    question section could never reach anything but the header.
    """
    name = b"\x07example\x03com\x00"
    data = b"\x00" * 12 + name + b"\xc0\x0c"

    assert _read_dns_name(data, 12) == ("example.com", 25)

    resolved, after = _read_dns_name(data, 25)
    assert resolved == "example.com", "followed the pointer back to offset 12"
    assert after == 27, "and resumed just past the two pointer bytes"


def test_partial_name_then_a_pointer() -> None:
    """The common real shape: fresh labels, then a pointer to a shared suffix."""
    data = b"\x00" * 12 + b"\x07example\x03com\x00" + b"\x03www\xc0\x0c"
    resolved, after = _read_dns_name(data, 25)
    assert resolved == "www.example.com"
    assert after == 31


def test_non_standard_opcode_gives_no_name() -> None:
    message = struct.pack("!HHHHHH", 1, 0x2800, 0, 0, 0, 0)  # opcode 5, update
    hint = parse_dns(message)
    assert hint is not None
    assert hint.label == ""
    assert "opcode 5" in hint.detail


def test_no_question_section() -> None:
    message = struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 0, 0)
    hint = parse_dns(message)
    assert hint is not None
    assert "no question" in hint.detail


def test_message_too_short_for_a_header() -> None:
    assert parse_dns(b"\x00" * 11) is None


# -- hostile DNS -----------------------------------------------------------


def test_compression_pointer_loop_is_refused() -> None:
    """A pointer to itself would spin forever if followed naively."""
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
    with pytest.raises(ValueError, match="backwards"):
        parse_dns(message)


def test_forward_pointer_is_refused() -> None:
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\xff" + b"\x00" * 200
    with pytest.raises(ValueError, match="backwards"):
        parse_dns(message)


def test_label_running_past_the_buffer() -> None:
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"ab"
    with pytest.raises(ValueError, match="past the end"):
        parse_dns(message)


def test_unterminated_name() -> None:
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x02ab"
    with pytest.raises(ValueError, match="past the end"):
        parse_dns(message)


def test_absurdly_long_name_is_capped() -> None:
    """255 bytes is the protocol limit; a longer one is malformed."""
    labels = b"".join(b"\x3f" + b"x" * 63 for _ in range(8))
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + b"\x00"
    with pytest.raises(ValueError, match="255"):
        parse_dns(message)


def test_reserved_label_bits() -> None:
    message = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x80abc"
    with pytest.raises(ValueError, match="reserved"):
        parse_dns(message)


# ==========================================================================
# HTTP
# ==========================================================================


def test_real_http_get_matches_tcpdump() -> None:
    """tcpdump printed: GET / HTTP/1.1 / Host: neverssl.com."""
    hint = parse_http(transport_payload(headers.ETH_IPV4_TCP_HTTP_GET))
    assert hint is not None
    assert hint.protocol == "HTTP"
    assert hint.label == "neverssl.com/"
    assert hint.detail == "GET /"


def test_hand_built_request_with_path() -> None:
    hint = parse_http(transport_payload(headers.ETH_IPV4_TCP_HTTP_REQUEST))
    assert hint is not None
    assert hint.label == "www.example.com/index.html"
    assert hint.detail == "GET /index.html"


def test_host_header_is_case_insensitive() -> None:
    payload = b"GET /x HTTP/1.1\r\nHOST: Example.Com\r\n\r\n"
    hint = parse_http(payload)
    assert hint is not None
    assert hint.label == "Example.Com/x"


def test_request_without_a_host_header_still_gives_the_path() -> None:
    hint = parse_http(b"GET /just-a-path HTTP/1.0\r\n\r\n")
    assert hint is not None
    assert hint.label == "/just-a-path"


@pytest.mark.parametrize("method", [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS"])
def test_every_method_is_recognised(method: bytes) -> None:
    hint = parse_http(method + b" /path HTTP/1.1\r\nHost: h.example\r\n\r\n")
    assert hint is not None
    assert hint.detail.startswith(method.decode())


def test_response_status_line() -> None:
    payload = b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.24\r\n\r\n"
    hint = parse_http(payload)
    assert hint is not None
    assert hint.label == "404 Not Found"
    assert "nginx/1.24" in hint.detail


def test_real_http_response() -> None:
    """The captured response: HTTP/1.1 200 OK, Server: Apache/2.4.66 ()."""
    stats_payload = None
    for frame in read_pcap(Path("tests/fixtures/sample.pcap")):
        packet = decode_frame(frame)
        if packet.payload.startswith(b"HTTP/1.1 200"):
            stats_payload = packet.payload
            break
    assert stats_payload is not None

    hint = parse_http(stats_payload)
    assert hint is not None
    assert hint.label == "200 OK"
    assert "Apache" in hint.detail


def test_non_http_payload_gives_nothing() -> None:
    assert parse_http(b"\x00\x01\x02\x03" * 20) is None
    assert parse_http(b"NOTAMETHOD / HTTP/1.1\r\n\r\n") is None
    assert parse_http(b"GET /path\r\n\r\n") is None, "no HTTP version token"


def test_payload_too_short() -> None:
    assert parse_http(b"GET /") is None


def test_header_block_ends_at_the_blank_line() -> None:
    """A Host: in the body must not be mistaken for a header."""
    payload = b"GET /x HTTP/1.1\r\nAccept: */*\r\n\r\nHost: not-a-header.example\r\n"
    hint = parse_http(payload)
    assert hint is not None
    assert hint.label == "/x"


def test_long_but_parseable_values_are_clipped() -> None:
    """A label headed for a table cell must not be a kilobyte long."""
    payload = b"GET /" + b"a" * 400 + b" HTTP/1.1\r\nHost: " + b"b" * 400 + b"\r\n\r\n"
    hint = parse_http(payload)
    assert hint is not None
    assert len(hint.label) <= 120
    assert len(hint.detail) <= 120


def test_request_line_longer_than_the_head_window_gives_nothing() -> None:
    """Only the first 2KB is examined, so a 5KB request line is not parseable.

    Returning nothing is the right answer: the alternative is scanning an
    unbounded payload looking for a line ending that may never come.
    """
    payload = b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\nHost: h.example\r\n\r\n"
    assert parse_http(payload) is None


def test_non_ascii_bytes_do_not_raise() -> None:
    payload = b"GET /\xff\xfe HTTP/1.1\r\nHost: \xc3\x28\r\n\r\n"
    assert parse_http(payload) is not None


# ==========================================================================
# TLS
# ==========================================================================


def test_real_client_hello_sni() -> None:
    """A real ClientHello from the capture, sent to api.github.com."""
    hint = parse_tls_client_hello(transport_payload(headers.ETH_IPV4_TCP_TLS_CLIENT_HELLO))
    assert hint is not None
    assert hint.protocol == "TLS"
    assert hint.label == "api.github.com"
    assert "ClientHello" in hint.detail


def test_real_sni_is_actually_in_the_bytes() -> None:
    """An independent check: the name we report is really in the payload."""
    payload = transport_payload(headers.ETH_IPV4_TCP_TLS_CLIENT_HELLO)
    assert b"api.github.com" in payload


def test_hand_built_minimal_client_hello() -> None:
    hint = parse_tls_client_hello(
        transport_payload(headers.ETH_IPV4_TCP_TLS_CLIENT_HELLO_MINIMAL)
    )
    assert hint is not None
    assert hint.label == "example.com"
    assert "TLS 1.2" in hint.detail


def test_not_a_handshake_record() -> None:
    payload = b"\x17\x03\x03\x00\x40" + b"\x00" * 100  # application data
    assert parse_tls_client_hello(payload) is None


def test_handshake_but_not_a_client_hello() -> None:
    payload = b"\x16\x03\x03\x00\x40\x02" + b"\x00" * 100  # ServerHello
    assert parse_tls_client_hello(payload) is None


def test_payload_too_short_for_a_client_hello() -> None:
    assert parse_tls_client_hello(b"\x16\x03\x01\x00\x10") is None


def test_client_hello_with_no_extensions() -> None:
    """Legal for TLS 1.2 and below; means no SNI, not a parse failure."""
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    hint = parse_tls_client_hello(record)
    assert hint is not None
    assert hint.label == ""
    assert "no extensions" in hint.detail


def test_extensions_present_but_no_sni() -> None:
    ext = struct.pack("!HH", 0x000B, 2) + b"\x01\x00"  # ec_point_formats
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(ext)) + ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    hint = parse_tls_client_hello(record)
    assert hint is not None
    assert hint.label == ""
    assert "no SNI" in hint.detail


def test_lying_length_field_raises_rather_than_reading_past_the_end() -> None:
    """A session id length far beyond the buffer."""
    body = b"\x03\x03" + bytes(32) + b"\xff" + b"\x00" * 4
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    with pytest.raises(ValueError, match="shorter than its length fields"):
        parse_tls_client_hello(record)


def test_extension_length_overrunning_the_list_stops_the_walk() -> None:
    ext = struct.pack("!HH", 0x0000, 500) + b"\x00\x05"  # claims 500 bytes, has 2
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(ext)) + ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    hint = parse_tls_client_hello(record)
    assert hint is not None
    assert hint.label == "", "stopped rather than reading whatever came next"


# ==========================================================================
# dispatch, and the guarantee that nothing here can end a capture
# ==========================================================================


def test_dispatch_picks_the_parser_from_the_port() -> None:
    dns = transport_payload(headers.ETH_IPV4_UDP_DNS_QUERY_REAL)
    hint = app_hint(dns, 37036, 53)
    assert hint is not None
    assert hint.protocol == "DNS"
    assert hint.confident


def test_dispatch_falls_back_to_the_port_name() -> None:
    hint = app_hint(b"\x00" * 40, 51000, 179)
    assert hint is not None
    assert hint.protocol == "BGP"
    assert not hint.confident, "a port number is a guess, not evidence"
    assert hint.key == "BGP", "the key falls back to the protocol when there is no label"


def test_dispatch_with_no_ports_at_all() -> None:
    assert app_hint(b"anything", None, None) is None


def test_dispatch_on_an_unknown_port() -> None:
    assert app_hint(b"\x00" * 40, 51000, 51001) is None


def test_dispatch_with_an_empty_payload_still_names_the_port() -> None:
    hint = app_hint(b"", 51000, 443)
    assert hint is not None
    assert hint.protocol == "HTTPS"
    assert not hint.confident


def test_app_hint_never_raises_on_garbage() -> None:
    """The guarantee the whole module exists to provide.

    Every parser walks length fields chosen by the sender. app_hint wraps them
    so that whatever they throw becomes "no hint" - never an ended capture.
    """
    rng = random.Random(20260910)
    ports = [53, 80, 443, 5353, 8080, 993, 1, 65535]

    for _ in range(3000):
        size = rng.randint(0, 300)
        payload = bytes(rng.getrandbits(8) for _ in range(size))
        result = app_hint(payload, rng.choice(ports), rng.choice(ports))
        assert result is None or isinstance(result, AppHint)


def test_app_hint_never_raises_on_truncated_real_payloads() -> None:
    """Every prefix of a real payload, which is what snapping produces."""
    for name in (
        "ETH_IPV4_UDP_DNS_QUERY_REAL",
        "ETH_IPV4_UDP_DNS_RESPONSE_REAL",
        "ETH_IPV4_UDP_DNS_NXDOMAIN_REAL",
        "ETH_IPV4_TCP_HTTP_GET",
        "ETH_IPV4_TCP_TLS_CLIENT_HELLO",
    ):
        payload = transport_payload(getattr(headers, name))
        for cut in range(len(payload) + 1):
            result = app_hint(payload[:cut], 12345, 53 if "DNS" in name else 443)
            assert result is None or isinstance(result, AppHint), f"{name} cut at {cut}"


def test_app_hint_never_raises_on_bit_flipped_real_payloads() -> None:
    """Corrupt one byte at a time in a real DNS message and a real ClientHello."""
    rng = random.Random(11)
    for name, port in (
        ("ETH_IPV4_UDP_DNS_RESPONSE_REAL", 53),
        ("ETH_IPV4_TCP_TLS_CLIENT_HELLO", 443),
    ):
        payload = bytearray(transport_payload(getattr(headers, name)))
        for _ in range(1500):
            corrupted = bytearray(payload)
            corrupted[rng.randrange(len(corrupted))] ^= 1 << rng.randrange(8)
            result = app_hint(bytes(corrupted), 12345, port)
            assert result is None or isinstance(result, AppHint)


def test_decode_frame_never_raises_on_garbage_frames() -> None:
    """The same guarantee, one level up, through the whole pipeline."""
    rng = random.Random(4242)
    for _ in range(2000):
        size = rng.randint(0, 200)
        raw = bytes(rng.getrandbits(8) for _ in range(size))
        packet = decode_frame(Frame(1.0, raw))
        assert packet.frame.data == raw


# ==========================================================================
# the real capture, end to end
# ==========================================================================


def test_capture_yields_the_expected_hints(sample_pcap: Path) -> None:
    labels = set()
    protocols = set()
    for frame in read_pcap(sample_pcap):
        packet = decode_frame(frame)
        if packet.app is not None:
            protocols.add(packet.app.protocol)
            if packet.app.label:
                labels.add(packet.app.label)

    assert {"DNS", "HTTP", "TLS"} <= protocols

    assert "example.com" in labels
    assert "neverssl.com" in labels
    assert "api.github.com" in labels
    assert "nxdomain-test-netsniff.example" in labels
    assert "neverssl.com/" in labels, "the HTTP request, host plus path"
    assert "200 OK" in labels, "the HTTP response"


def test_no_packet_in_the_capture_produces_a_decode_error(sample_pcap: Path) -> None:
    for frame in read_pcap(sample_pcap):
        assert decode_frame(frame).errors == ()
