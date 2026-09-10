# Architecture

## The problem this layout solves

Live packet capture needs a raw socket. A raw socket needs root, and `AF_PACKET`
is Linux only. If that were the only way into the tool, nobody could clone the
repo and run it, CI could not test it, and the interesting part — decoding the
wire — would be locked behind a privilege check.

So the design splits along that fault line. Everything that needs privileges is
pushed into one small, late module, and everything else is written so it never
touches a socket at all.

```
  capture source                 decode                  analyse                 output
  --------------                 ------                  -------                 ------

  live.py   (AF_PACKET, root) \
                               \
                                >--->  Frame(ts, data)  --->  decode_frame()  --->  FlowTable  ---\
                               /            |                       |                            |
  pcap.py   (file, anywhere)  /             |                       |                     StatsCollector
                                            |                       |                            |
                                     the one contract        layered dataclasses                 |
                                     both sources emit       Ethernet -> IP -> TCP        +-------+-------+
                                                             -> app hint                  |       |       |
                                                                                     console  export  detect
                                                                                      (tables) (JSON/  (scan
                                                                                               CSV)  heuristics)
```

`Frame(ts, data, orig_len, index)` is the whole interface. Both sources produce
it; everything downstream consumes it. Neither source knows the other exists,
and the decoders cannot tell which one they are reading — which is exactly what
makes the offline path a real test of the live path.

## The four layers

### `netsniff.capture`

Produces `Frame` objects and nothing else.

- **`base.py`** — the `Frame` dataclass, the `Source` protocol, `LinkType`, and
  the `CaptureError` hierarchy that both sources raise instead of letting a
  `struct.error` or a `PermissionError` escape.
- **`pcap.py`** — classic libpcap file reader. Pure standard library, no
  privileges, works anywhere. This is what makes the repo cloneable.
- **`live.py`** — `AF_PACKET` raw socket. Linux, root. Built last, on top of a
  core that was already tested without it.

### `netsniff.decode`

Pure functions: bytes in, dataclasses out. No sockets, no privileges, no
platform assumptions, no third-party imports. This is the layer that is fully
unit tested against byte fixtures on any machine, and it is where most of the
work lives.

```
        Ethernet II  [ + 802.1Q / QinQ tags ]
                          |
                          v  ethertype
             +------------+------------+
           0x0800       0x86DD       0x0806
            IPv4         IPv6          ARP
              |            |
              |            v  next_header, after walking the extension chain
              v  protocol  |
         +----+----+-------+
         6        17       1 / 58
        TCP      UDP     ICMP / ICMPv6
              |
              v  destination or source port (best effort)
       DNS 53   |   HTTP 80   |   TLS SNI 443
```

### `netsniff.analyze`

- **`flows.py`** — direction-normalised 5-tuple conversation tracking.
- **`stats.py`** — running aggregates: protocol shares, talkers, ports, flags.
- **`detect.py`** — three heuristics over the flow table. Reports, never blocks.

### `netsniff.report`

- **`console.py`** — the summary tables and the live rolling view.
- **`export.py`** — JSON summary and CSV of conversations.

## Strict decoders, tolerant pipeline

This is the design decision that shapes the decode layer most, so it is worth
stating on its own.

Every individual decoder is **strict**. `decode_ipv4` raises `Truncated` if the
buffer is shorter than the header claims, and `DecodeError` if the version field
is not 4. It never guesses, never pads, never returns a half-filled object.

`decode_frame` is **tolerant**. It catches those errors and records them on the
result, so one malformed packet in a capture of a million produces a
`DecodedPacket` with whatever layers did decode plus a note about the one that
did not — and the run continues.

Both properties matter, and trying to get them from a single piece of code gets
you neither. Strict decoders are testable: you can assert exactly which byte
count triggered the failure. A tolerant pipeline is usable: a capture full of
snapped packets and malformed payloads still produces a summary.

The application-layer hints go one step further. They run on bytes an attacker
chose, so `app_hint` wraps every parser in a catch-all and is documented as
never raising. `decode_frame` calls it *without* a try of its own, deliberately —
so a bug in our dispatch is not hidden by the same silence hostile payloads get.

## What the offset attributes are for

Three header dataclasses carry a `header_len`, and every one of them exists to
prevent the same class of bug:

| Layer | Naive assumption | What actually happens |
|---|---|---|
| `Ethernet.header_len` | payload starts at 14 | an 802.1Q tag pushes it to 18, QinQ to 22 |
| `IPv4.header_len` | payload starts at 20 | IHL > 5 means options; IHL counts 32-bit **words** |
| `Tcp.header_len` | payload starts at 20 | data offset > 5 means options, on nearly every SYN |
| `IPv6.header_len` | payload starts at 40 | an extension header chain can push it arbitrarily far |

None of these produce an exception when you get them wrong. They produce a
plausible-looking wrong answer, which is the worst kind. Slicing by
`header_len` rather than by a constant is the entire defence, and the tests
assert it by checking that the naive offset decodes *garbage* — not just that
the correct one decodes correctly.

## Byte order

Everything on the wire is big-endian, so every `struct` format string in
`netsniff/decode/` starts with `!`.

There are exactly three deliberate exceptions, all outside the decoders:

1. **The pcap file header and record headers** (`capture/pcap.py`) use whatever
   byte order the machine that wrote the file used. That is what the magic
   number is for: read it first, decide `<` or `>`, then use that for every
   subsequent unpack in the file.
2. **`struct packet_mreq`** (`capture/live.py`), passed to `setsockopt` for
   promiscuous mode, is a native C struct and must be packed `=`. Using `!`
   there gets you `EINVAL` with no useful explanation.
3. **`struct timespec` and `tpacket_stats`** (`capture/live.py`), for the same
   reason.

## Why live capture is not in CI

No hosted runner grants a test `CAP_NET_RAW`, and none should. That is not a gap
in the test strategy — it is the reason for it. The offline core was built first
precisely so that everything except the socket itself is verifiable on a stock
runner with no privileges:

- every decoder, against committed byte fixtures
- the pcap reader, including both byte orders and every malformed-input path
- flows, statistics and detections, against synthetic and real traffic
- the whole pipeline end to end, against a real committed capture
- that live capture **refuses cleanly** without privileges, which CI can check
  because the runner is unprivileged

What is left over is one manual check, `scripts/verify_live.sh`, run on Linux as
root. The README says so, rather than letting a green badge imply more than it
covers.
