# netsniff

[![CI](https://github.com/hanksqt/Packet_Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/hanksqt/Packet_Analyzer/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A packet analyzer that decodes every protocol layer by hand from raw bytes. It reads
Ethernet frames, live from an interface or offline from a `.pcap`, peels each header
itself, tracks conversations, and reports protocol breakdowns, top talkers,
application-layer identifiers and a few anomalies.

No scapy, no libpcap binding, no third-party runtime dependency at all. The point of
the project is parsing the wire rather than calling something that already does it.
If you have Python 3.10, you can run this.

## Run it

```bash
git clone https://github.com/hanksqt/Packet_Analyzer.git
cd Packet_Analyzer
pip install -e .
netsniff pcap tests/fixtures/sample.pcap
```

Works on Linux, macOS and Windows. No privileges needed, nothing to configure. The
capture it analyses ships with the repo.

```
Capture summary
===============
  source          tests/fixtures/sample.pcap
  packets         134
  bytes on wire   20977 (20.5 KiB)
  duration        19.84s
  hosts seen      10

Protocol breakdown
==================
  PROTOCOL  PACKETS  PKT %     BYTES  BYTE %
  --------  -------  -----  --------  ------
  TCP           108  80.6%  17.9 KiB   87.6%
  UDP            12   9.0%   1.3 KiB    6.4%
  ICMP           12   9.0%   1.1 KiB    5.6%
  ARP             2   1.5%      84 B    0.4%

Application-layer hints (top 15)
================================
  IDENTIFIER                      PACKETS
  ------------------------------  -------
  BGP                                  56
  api.github.com                        3
  example.com                           2
  nxdomain-test-netsniff.example        2
  neverssl.com/                         1
```

Everything there came out of raw bytes: the DNS names from the question section, the
HTTP host from the request headers, the TLS server name from a ClientHello's SNI
extension.

## Why it is split this way

Live capture needs a raw socket. A raw socket needs root, and `AF_PACKET` is Linux
only. If that were the only way in, nobody could clone this and run it, CI could not
test it, and the interesting part would sit behind a privilege check.

So the design splits along that line.

The decoders are pure functions. Bytes in, a dataclass out. No sockets, no
privileges, no platform assumptions, nothing imported from outside the standard
library. That is where the actual work is, and it is unit tested against captured
byte fixtures on any machine.

Two capture sources feed those decoders: a live `AF_PACKET` source (Linux, root) and
an offline `.pcap` reader (anywhere, no privileges). Both produce
`Frame(ts, data, orig_len, index)` and nothing else. That one dataclass is the whole
interface between them and everything downstream.

Analysis and output sit on top of decoded packets and never touch a socket.

Building the privileged, platform-specific part last means there is always a working
artifact. It also means the offline path genuinely tests the live path, since the
decoders cannot tell which source they are reading.

## What it decodes

| Layer | Protocols |
|---|---|
| Link | Ethernet II, 802.1Q VLAN, 802.1ad QinQ (stacked tags), 802.3 detection |
| Network | IPv4 (options, fragmentation, checksum validation), IPv6 (extension header chain), ARP |
| Transport | TCP (options, all nine flags, pseudo-header checksum), UDP, ICMP, ICMPv6 |
| Application | DNS query and response names, HTTP request line and Host, TLS SNI, ~70 well-known ports |

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
              v  port (best effort)
       DNS 53   |   HTTP 80   |   TLS SNI 443
```

The byte layout of each one, and the thing about it that is easy to get wrong, is in
[`docs/protocols.md`](docs/protocols.md).

## Usage

```
netsniff pcap <file.pcap> [--top 10] [--proto tcp] [--host 10.0.0.5] [--port 443]
                          [--count N] [--print-packets]
                          [--json out.json] [--csv flows.csv] [--quiet]

netsniff live --iface eth0 [--count 1000] [--timeout 30] [--snaplen 65535]
                           [--no-promiscuous] [--proto ...] [--host ...] [--port ...]
                           [--json out.json]
```

Detection thresholds are `--scan-ports`, `--scan-hosts`, `--scan-unanswered` and
`--scan-window`. `--no-detect` turns the heuristics off.

A few things to try against the bundled capture:

```bash
# just the DNS
netsniff pcap tests/fixtures/sample.pcap --proto udp --port 53

# one host's conversations, as CSV
netsniff pcap tests/fixtures/sample.pcap --host 172.18.54.224 --csv flows.csv

# packet by packet, like tcpdump
netsniff pcap tests/fixtures/sample.pcap --count 20 --print-packets

# the scan heuristics, thresholds scaled down to a 134-packet sample
netsniff pcap tests/fixtures/sample.pcap --scan-ports 4 --scan-unanswered 4
```

### Filters are not BPF

`--proto`, `--host` and `--port` are predicates applied after decoding, not compiled
BPF programs. Writing a BPF compiler is a rabbit hole that would not make the
decoders any better, so it is out of scope. Saying so here beats implying otherwise.

The difference is efficiency, not capability. A real BPF filter drops packets in the
kernel before they are ever copied to userspace. For a capture file it changes
nothing.

### Live capture

```bash
sudo netsniff live --iface eth0 --count 100
```

Linux only, and it wants root or `CAP_NET_RAW`. To skip the `sudo` every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
```

On the wrong platform, or without privileges, it prints a sentence saying which of
the two it is and what to do instead. Not a `PermissionError` traceback from inside
`socket.socket`.

Three implementation details worth knowing:

- Promiscuous mode uses a kernel-refcounted membership rather than the `IFF_PROMISC`
  interface flag, so an interrupted run cannot leave your NIC promiscuous.
- Snap length is applied after receiving rather than in the kernel, which keeps
  `orig_len` as the true on-wire length so byte counts never understate traffic.
- Timestamps come from the kernel via `SO_TIMESTAMPNS`. Calling `time.time()` after
  `recv` measures when the process got round to looking at the packet, which under
  load is not when it arrived.

## Tests

```
429 tests, no network access, no privileges, about a second
```

**Per-header unit tests against byte fixtures.** `tests/fixtures/headers.py` holds 33
complete frames as hex. Fourteen are real frames pulled out of a tcpdump capture. The
rest were hand-built for what the capture did not contain: VLAN and QinQ tags, ARP,
IPv6 extension chains, fragments, IPv4 options, 802.3 LLC. Every hand-built one went
through `tcpdump -e -vv` first, which confirmed each field and reported
`cksum (correct)` before the bytes were pasted in. The expected values in the tests
are tcpdump's, so they compare against an independent implementation rather than
against themselves.

**The offset bugs are tested by asserting the wrong answer is wrong.** Slicing at
`header_len` working is not enough. The tests also assert that slicing at the naive
constant decodes garbage, or they would pass whether or not the VLAN shift was
handled.

**Checksums that are supposed to fail.** One test asserts a TCP checksum is invalid.
That segment was captured on the sending host, where checksum offload leaves the
field for the NIC to fill in after the capture point. Roughly half of any locally
taken capture looks corrupt by that measure, and flagging it would be crying wolf.

**Hostile input, around 6,500 cases.** The application-layer parsers run on bytes an
attacker picked, so they get random garbage on every hint port, every prefix of five
real payloads (which is what snapping produces), single-bit corruption of a real DNS
response and a real TLS ClientHello, and random frames through the whole pipeline.
All of it has to produce a hint or nothing. Never an exception, never a dead capture.

**Detectors that stay quiet.** A normal web session and a twenty-connection pool are
tested to trigger nothing. A summary full of false alarms gets skipped, and it takes
the true positives with it.

**Cross-checked against another tool.** The protocol breakdown matches `tcpdump`'s
own per-protocol counts on the same file exactly. The pcap reader's framing is
checked by arithmetic that only closes if it over-reads and under-reads by zero:
`24 + 16 × packets + Σ incl_len` has to land on the file size.

### What CI does not cover

Live capture is not tested in CI, deliberately. No hosted runner will grant a test
`CAP_NET_RAW`, and none should. That is the reason the offline core was built first.
Everything except the socket itself is verifiable on a stock runner with no
privileges, including that live capture refuses cleanly without them, which CI can
check precisely because the runner is unprivileged.

What is left over is one manual check, run on Linux as root:

```bash
sudo ./scripts/verify_live.sh eth0
```

```
[OK] captured and decoded 40 live frames
[OK] live frames decoded through the same pipeline as the pcap reader
[OK] eth0 was left out of promiscuous mode
[OK] --iface any refused with an explanation, not a traceback
```

## Design decisions

**Parsing bytes instead of using scapy.** Parsing the bytes is the skill on display.
scapy is good and I would reach for it at work, but here it would decode every header
in this repo and leave nothing to show.

**Both a pcap reader and live capture.** Live capture alone makes the project
unrunnable for anyone who clones it and untestable in CI. A pcap reader alone dodges
the part that needs a raw socket. Building both, offline first, means the repo demos
from the first commit and the privileged path is a thin layer on a tested core.

**Big-endian everywhere.** Everything on the wire is network byte order, so every
`struct` format string in `netsniff/decode/` starts with `!`. Three deliberate
exceptions live outside the decoders: the pcap file header, whose byte order the
magic number tells you, and `struct packet_mreq` and `struct timespec` in the live
socket, which are native C structs where `!` earns you an `EINVAL` and no
explanation.

**Strict decoders, tolerant pipeline.** Every decoder raises rather than guessing on
a short buffer, which is what makes them testable, since you can assert exactly which
byte count failed. `decode_frame` catches those and records a partial decode, so one
malformed packet never ends a run. Getting both properties out of one piece of code
gets you neither.

**The app-layer parsers are called hints.** A service can run on any port, an HTTP
request can be split across segments, a ClientHello can be fragmented. These give up
rather than guess, and a port-based identification is marked `confident=False`. A
port number is a guess. A parsed payload is evidence.

**The detections state their own false positives.** A monitoring agent, a connection
pool and backup software retrying a dead peer all look like scans by traffic shape
alone. Every finding carries the benign behaviour that produces the same signature,
and that caveat rides along into the JSON export. A detector that hides its false
positives cannot be calibrated by whoever reads it.

**Bytes mean on-wire bytes.** A snapped capture holds less than it saw. Counting
captured bytes would understate every host's traffic in proportion to how hard the
capture was snapped, so `orig_len` drives every byte count. The difference is tracked
and reported so the snapping stays visible.

## Scope

Left out on purpose, so the rest could be done properly:

- **TCP stream reassembly.** App hints read single segments. A request split across
  two will not match, which is the correct answer rather than a guess.
- **IP fragment reassembly.** Fragments are decoded and identified, and a later
  fragment correctly gets no transport decode since it starts mid-payload, but they
  are not reassembled.
- **BPF filter compilation.** See above.
- **pcapng.** A different, block-structured format. The reader detects its magic and
  names the problem instead of failing obscurely.
- **LLC/SNAP payloads.** 802.3 frames are identified as such rather than dispatched
  on a bogus ethertype, but their payloads are not decoded.
- **Non-Ethernet link types.** Linux cooked capture (SLL), raw IP and the rest get
  named in the error rather than misparsed, which is why `--iface any` is refused.

## Layout

```
netsniff/
  capture/     base.py (the Frame contract) | pcap.py (offline) | live.py (AF_PACKET)
  decode/      ethernet, vlan, ipv4, ipv6, arp, tcp, udp, icmp, apphint, common
               __init__.py holds decode_frame(), the layered pipeline
  analyze/     flows.py (conversations) | stats.py (aggregates) | detect.py (heuristics)
  report/      console.py (tables, live view) | export.py (JSON, CSV)
  cli.py       argparse entry point: the pcap and live subcommands
tests/
  fixtures/    headers.py (33 hex frames) | synth.py (builders) | sample.pcap
scripts/       capture_sample.sh | verify_live.sh | ci_summary.py | golden_values.py
docs/          architecture.md | protocols.md
```

[`docs/architecture.md`](docs/architecture.md) covers the layering in more detail.

## Regenerating the capture

`tests/fixtures/sample.pcap` is a real capture written by tcpdump rather than by
anything in this repo, so the end-to-end test cannot pass just because the reader and
a writer share a bug. To make a fresh one:

```bash
sudo ./scripts/capture_sample.sh eth0
```

It generates a traffic mix (DNS, HTTP, TLS, ICMP, ARP, and some SYNs to closed ports
on your own gateway for the detectors), checks the magic bytes are classic pcap, and
reports what actually landed in the file. The figures in `tests/test_end_to_end.py`
are specific to the committed capture. `python scripts/golden_values.py` prints the
replacement block when you regenerate it.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy netsniff
```

## License

MIT, see [LICENSE](LICENSE).
