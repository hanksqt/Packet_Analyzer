"""Best-effort application-layer identification.

These are *hints*, not parsers. The goal is to answer "what is this flow" well
enough for a summary table - a DNS query name, an HTTP host, a TLS server name -
and to fall back to naming the port when nothing better is available.

Nothing here is authoritative. A service can run on any port, an HTTP request
can be split across segments, and a payload is attacker-influenced by
definition. So every function in this module is written to give up rather than
guess, and to return None rather than raise. A malformed DNS record must produce
no hint; it must never end a capture.
"""

from __future__ import annotations

__all__ = ["SERVICE_NAMES", "service_name"]

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


def service_name(port: int) -> str:
    """Name for a well-known port, or an empty string when it is not one.

    Empty rather than something like "unknown", because this goes straight into
    a table cell and a column of the word "unknown" is just noise.
    """
    return SERVICE_NAMES.get(port, "")
