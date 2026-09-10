"""netsniff - a from-scratch network packet analyzer.

Every protocol header in this package is decoded by hand from raw bytes. There is
no scapy, no libpcap binding, and no third-party runtime dependency: the core is
pure standard library.

The package is deliberately split into four layers that do not know about each
other's internals:

``netsniff.capture``
    Produces :class:`~netsniff.capture.base.Frame` objects. Two sources exist: an
    offline classic-pcap file reader (works anywhere, no privileges) and a live
    ``AF_PACKET`` socket source (Linux, root). Both emit the same ``Frame``.

``netsniff.decode``
    Pure functions: bytes in, dataclasses out. No sockets, no privileges, no
    platform assumptions. This is the part that is fully unit tested against
    hand-built byte fixtures on any machine.

``netsniff.analyze``
    Conversation (flow) tracking, aggregate statistics, and cheap detection
    heuristics, all computed over decoded packets.

``netsniff.report``
    Console tables and JSON/CSV export.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
