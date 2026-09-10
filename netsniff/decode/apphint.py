r"""Best-effort application-layer identification.

These are *hints*, not parsers. The goal is to answer "what is this flow" well
enough for a summary table - a DNS query name, an HTTP host, a TLS server name -
and to fall back to naming the port when nothing better is available.

Nothing here is authoritative. A service can run on any port, an HTTP request
can be split across segments, a TLS ClientHello can be fragmented, and a payload
is attacker-influenced by definition. So the rule for this whole module is:
**give up rather than guess, and never raise**. :func:`app_hint` wraps every
parser in a catch-all, because these functions run on bytes chosen by whoever
sent the packet, and one malformed record must not end a capture that is
otherwise fine.

Three protocols get real parsing:

*DNS* on port 53. The header is 12 fixed bytes, then the question section, whose
name is length-prefixed labels terminated by a zero byte::

    | 07 | e x a m p l e | 03 | c o m | 00 |  -> "example.com"

The compression scheme means a label length byte with its top two bits set is a
pointer to an earlier offset rather than a length. Following pointers can loop,
so this decoder follows them with a budget and refuses to move forward.

*HTTP* on port 80. Just the request line and the Host header, read as text.

*TLS* on 443. The SNI extension inside a ClientHello, which means walking
record -> handshake -> session id -> cipher suites -> compression -> extensions,
every one of which is length-prefixed by a field that cannot be trusted.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "SERVICE_NAMES",
    "AppHint",
    "app_hint",
    "parse_dns",
    "parse_http",
    "parse_tls_client_hello",
    "service_name",
]

#: Well-known ports, used when no payload-based hint is available. Not the
#: system services file: just the ones that show up often enough to be worth
#: naming in a summary.
SERVICE_NAMES: dict[int, str] = {
    7: "echo",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    520: "rip",
    546: "dhcpv6-client",
    547: "dhcpv6-server",
    587: "submission",
    623: "ipmi",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1701: "l2tp",
    1723: "pptp",
    1812: "radius",
    1900: "ssdp",
    2049: "nfs",
    2379: "etcd",
    3128: "squid",
    3306: "mysql",
    3389: "rdp",
    4789: "vxlan",
    5060: "sip",
    5061: "sips",
    5222: "xmpp",
    5353: "mdns",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    6379: "redis",
    6443: "kubernetes-api",
    8080: "http-alt",
    8443: "https-alt",
    9000: "cslistener",
    9090: "prometheus",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    51820: "wireguard",
}

DNS_PORTS = frozenset({53, 5353})
HTTP_PORTS = frozenset({80, 8080, 8000, 3128})
TLS_PORTS = frozenset({443, 8443, 993, 995, 465, 587, 5061})

#: Longest name we will assemble out of DNS labels. RFC 1035 says 255.
MAX_DNS_NAME = 255

#: How many compression pointers to follow before deciding it is a loop.
MAX_DNS_POINTERS = 16

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY",
}

HTTP_METHODS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"PATCH",
    b"TRACE",
    b"CONNECT",
)

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def service_name(port: int) -> str:
    """Name for a well-known port, or an empty string when it is not one.

    Empty rather than something like "unknown", because this goes straight into
    a table cell and a column of the word "unknown" is just noise.
    """
    return SERVICE_NAMES.get(port, "")


@dataclass(frozen=True, slots=True)
class AppHint:
    """What we think an application-layer payload is."""

    protocol: str
    """``DNS``, ``HTTP``, ``TLS``, or a port-derived guess."""

    label: str
    """A short identifier for tables: a query name, a Host header, an SNI."""

    detail: str = ""
    """Extra context, e.g. the DNS response code or the HTTP method and path."""

    confident: bool = True
    """False when the protocol was inferred purely from the port number."""

    @property
    def key(self) -> str:
        """Short identifier for a table cell.

        The label when the payload gave us one, otherwise the protocol name -
        so a port-only guess shows up as "BGP" rather than as a blank row.
        """
        return self.label or self.protocol

    def __str__(self) -> str:
        return f"{self.protocol} {self.label}".strip()


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a length-prefixed DNS name. Returns the name and the next offset.

    Handles message compression: a length byte with its top two bits set means
    the low 14 bits are an offset to continue from. That is a jump within
    attacker-supplied data, so it is budgeted (pointers cannot loop forever)
    and the returned offset is always the one after the *first* pointer, which
    is what the caller needs to keep walking the message.
    """
    labels: list[str] = []
    pointers = 0
    position = offset
    after_pointer: int | None = None
    total = 0

    while True:
        if position >= len(data):
            raise ValueError("DNS name runs past the end of the message")

        length = data[position]

        if length == 0:
            position += 1
            break

        if length & 0xC0 == 0xC0:
            # A compression pointer: two bytes, 14 bits of offset.
            if position + 1 >= len(data):
                raise ValueError("truncated DNS compression pointer")
            pointers += 1
            if pointers > MAX_DNS_POINTERS:
                raise ValueError("DNS compression pointer loop")
            target = ((length & 0x3F) << 8) | data[position + 1]
            if after_pointer is None:
                after_pointer = position + 2
            if target >= position:
                # Pointers must go backwards. Forward or self-referential ones
                # are the shape a loop takes.
                raise ValueError("DNS compression pointer does not point backwards")
            position = target
            continue

        if length & 0xC0:
            raise ValueError(f"reserved DNS label length bits set: 0x{length:02x}")

        position += 1
        if position + length > len(data):
            raise ValueError("DNS label runs past the end of the message")

        total += length + 1
        if total > MAX_DNS_NAME:
            raise ValueError("DNS name exceeds 255 bytes")

        labels.append(data[position : position + length].decode("ascii", errors="replace"))
        position += length

    return (".".join(labels) if labels else ".", after_pointer or position)


def parse_dns(payload: bytes) -> AppHint | None:
    """Pull the question name out of a DNS message.

    Works for both queries and responses: a response echoes the question it is
    answering, so the same field names the flow either way.
    """
    if len(payload) < 12:
        return None

    txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", payload[:12])

    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F

    if opcode != 0:
        # Not a standard query (an update, a notify); no question name to read.
        return AppHint("DNS", "", detail=f"opcode {opcode}")
    if qdcount == 0:
        return AppHint("DNS", "", detail="no question section")

    name, offset = _read_dns_name(payload, 12)

    qtype = 0
    if offset + 4 <= len(payload):
        qtype, _qclass = struct.unpack("!HH", payload[offset : offset + 4])

    type_name = DNS_TYPES.get(qtype, str(qtype))
    if is_response:
        status = DNS_RCODES.get(rcode, f"rcode {rcode}")
        detail = f"response {type_name} {status} {ancount} answers txid=0x{txid:04x}"
    else:
        detail = f"query {type_name} txid=0x{txid:04x}"

    return AppHint("DNS", name, detail=detail)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def parse_http(payload: bytes) -> AppHint | None:
    """Read an HTTP request line, or a response status line.

    Only looks at the head of the payload, and only at text it can find on the
    first few lines. A request split across TCP segments will simply not match,
    which is the correct outcome for a hint: this project does not reassemble
    streams, and pretending otherwise would produce confident nonsense.
    """
    if len(payload) < 16:
        return None

    head = payload[:2048]
    first_line, _, rest = head.partition(b"\r\n")

    # A response: HTTP/1.1 200 OK
    if first_line.startswith(b"HTTP/"):
        parts = first_line.split(b" ", 2)
        status = parts[1].decode("ascii", "replace") if len(parts) > 1 else "?"
        reason = parts[2].decode("ascii", "replace") if len(parts) > 2 else ""
        server = _http_header(rest, b"server")
        return AppHint(
            "HTTP",
            f"{status} {reason}".strip(),
            detail=f"response{f' server={server}' if server else ''}",
        )

    # A request: GET /path HTTP/1.1
    if not first_line.startswith(HTTP_METHODS):
        return None

    parts = first_line.split(b" ")
    if len(parts) < 2 or not parts[-1].startswith(b"HTTP/"):
        return None

    method = parts[0].decode("ascii", "replace")
    path = parts[1].decode("ascii", "replace")
    host = _http_header(rest, b"host")

    label = f"{host}{path}" if host else path
    return AppHint("HTTP", label[:120], detail=f"{method} {path}"[:120])


def _http_header(block: bytes, name: bytes) -> str:
    """Find one header's value, case-insensitively, in a block of headers."""
    wanted = name.lower() + b":"
    for line in block.split(b"\r\n"):
        if not line:
            break  # blank line ends the header block
        if line.lower().startswith(wanted):
            return line[len(wanted) :].strip().decode("ascii", "replace")[:120]
    return ""


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------


def parse_tls_client_hello(payload: bytes) -> AppHint | None:
    """Extract the SNI server name from a TLS ClientHello.

    Every step walks a length field supplied by the sender, so every step is
    bounds-checked against the buffer we actually have. The structure::

        record   : type(1) version(2) length(2)
        handshake: type(1) length(3) client_version(2) random(32)
                   session_id(1+n) cipher_suites(2+n) compression(1+n)
                   extensions(2+n)
        extension: type(2) length(2) data
        SNI data : list_length(2) [ name_type(1) name_length(2) name ]
    """
    if len(payload) < 45:
        return None

    if payload[0] != 0x16:  # handshake record
        return None

    record_version = struct.unpack("!H", payload[1:3])[0]
    if record_version not in TLS_VERSIONS and record_version != 0x0300:
        return None

    if payload[5] != 0x01:  # ClientHello
        return None

    client_version = struct.unpack("!H", payload[9:11])[0]
    version_name = TLS_VERSIONS.get(client_version, f"0x{client_version:04x}")

    pos = 11 + 32  # past client_version and the 32-byte random

    def take(count: int) -> bytes:
        nonlocal pos
        if pos + count > len(payload):
            raise ValueError("TLS ClientHello is shorter than its length fields claim")
        chunk = payload[pos : pos + count]
        pos += count
        return chunk

    def take_u8_block() -> bytes:
        return take(take(1)[0])

    def take_u16_block() -> bytes:
        return take(struct.unpack("!H", take(2))[0])

    take_u8_block()  # session id
    take_u16_block()  # cipher suites
    take_u8_block()  # compression methods

    if pos + 2 > len(payload):
        # No extensions at all. Legal for TLS 1.0-1.2, and means no SNI.
        return AppHint("TLS", "", detail=f"ClientHello {version_name}, no extensions")

    extensions = take_u16_block()
    server_name = _tls_sni_from_extensions(extensions)

    return AppHint(
        "TLS",
        server_name,
        detail=f"ClientHello {version_name}" + ("" if server_name else ", no SNI"),
    )


def _tls_sni_from_extensions(extensions: bytes) -> str:
    """Walk the extension list looking for extension type 0, server_name."""
    pos = 0
    while pos + 4 <= len(extensions):
        ext_type, ext_len = struct.unpack("!HH", extensions[pos : pos + 4])
        pos += 4
        if pos + ext_len > len(extensions):
            break  # a length field that overruns the buffer; stop, do not guess
        if ext_type == 0x0000:
            return _tls_server_name(extensions[pos : pos + ext_len])
        pos += ext_len
    return ""


def _tls_server_name(data: bytes) -> str:
    """Read the first host_name entry out of a server_name extension."""
    if len(data) < 5:
        return ""
    list_len = struct.unpack("!H", data[:2])[0]
    entries = data[2 : 2 + list_len]

    pos = 0
    while pos + 3 <= len(entries):
        name_type = entries[pos]
        name_len = struct.unpack("!H", entries[pos + 1 : pos + 3])[0]
        pos += 3
        if pos + name_len > len(entries):
            break
        if name_type == 0:  # host_name
            return entries[pos : pos + name_len].decode("ascii", "replace")[:253]
        pos += name_len
    return ""


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------


def app_hint(payload: bytes, src_port: int | None, dst_port: int | None) -> AppHint | None:
    """Identify an application-layer payload, best effort.

    Tries the payload-based parsers first, since a real DNS message is far
    better evidence than a port number, and falls back to naming the port.

    Never raises. Every parser here runs on bytes the sender chose, so the whole
    dispatch sits inside one catch-all: a malformed payload yields no hint or a
    port-based guess, and the capture carries on.
    """
    ports = {p for p in (src_port, dst_port) if p is not None}
    if not ports:
        return None

    parser: Callable[[bytes], AppHint | None] | None = None
    if ports & DNS_PORTS:
        parser = parse_dns
    elif ports & TLS_PORTS:
        parser = parse_tls_client_hello
    elif ports & HTTP_PORTS:
        parser = parse_http

    if payload and parser is not None:
        try:
            if (hint := parser(payload)) is not None:
                return hint
        except Exception:
            # Deliberately broad. These parsers walk attacker-supplied length
            # fields; anything they can raise - struct.error, IndexError,
            # ValueError, UnicodeError - must degrade to "no hint" rather than
            # stop a capture. The port-based fallback below still applies.
            pass

    # Nothing parsed. Name the port if it is one we recognise.
    for port in sorted(ports):
        if name := service_name(port):
            return AppHint(name.upper(), "", detail=f"port {port}", confident=False)
    return None
