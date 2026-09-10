# netsniff

[![CI](https://github.com/hanksqt/Packet_Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/hanksqt/Packet_Analyzer/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A network packet analyzer that decodes every protocol layer by hand from raw
bytes. It reads Ethernet frames — live from an interface, or offline from a
`.pcap` — peels each header itself, tracks conversations, and reports protocol
breakdowns, top talkers, application-layer identifiers and simple anomalies.

**No scapy, no libpcap binding, no third-party runtime dependency at all.** The
whole point is parsing the wire rather than calling something that already does.
If you have Python 3.10, you have everything you need to run it.

---

## Run it in two minutes

```bash
git clone https://github.com/hanksqt/Packet_Analyzer.git
cd Packet_Analyzer
pip install -e .
netsniff pcap tests/fixtures/sample.pcap
```

That works on Linux, macOS and Windows, needs no privileges, and analyses a real
capture that ships with the repo. There is nothing to configure and nothing to
install beyond the package itself.

<!-- SAMPLE-OUTPUT-START -->
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
<!-- SAMPLE-OUTPUT-END -->

Everything in that output was decoded from raw bytes by this repo: the DNS query
names out of the question section, the HTTP host out of the request headers, the
TLS server name out of a ClientHello's SNI extension.

---

## Why it is built this way

Live capture needs a raw socket. A raw socket needs root, and `AF_PACKET` is
Linux only. If that were the only way in, nobody could clone this and run it, CI
could not test it, and the interesting part would be locked behind a privilege
check.

So the design splits along exactly that fault line:

**Decoders are pure functions.** Bytes in, a dataclass out. No sockets, no
privileges, no platform assumptions, no imports outside the standard library.
This is where the actual work is, and it is fully unit tested against captured
byte fixtures on any machine.

**Two capture sources feed the same decoders.** A live `AF_PACKET` source
(Linux, root) and an offline `.pcap` reader (anywhere, no privileges). They both
produce `Frame(ts, data, orig_len, index)` and nothing else — that one dataclass
is the entire interface between them and everything downstream.

**Analysis and output sit on top** of decoded packets and never touch a socket.

Building the risky, privileged, platform-specific part **last**, on top of a
core that was already tested without it, means there is always a working
artifact — and it means the offline path is a genuine test of the live path,
because the decoders cannot tell which source they are reading.

---

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

The byte layout of every one of these, and the specific thing about each that is
easy to get wrong, is written up in [`docs/protocols.md`](docs/protocols.md).

---

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
`--scan-window`; `--no-detect` turns the heuristics off entirely.

Some things to try against the bundled capture:

```bash
# Just the DNS
netsniff pcap tests/fixtures/sample.pcap --proto udp --port 53

# One host's conversations, as CSV
netsniff pcap tests/fixtures/sample.pcap --host 172.18.54.224 --csv flows.csv

# Packet-by-packet, like tcpdump
netsniff pcap tests/fixtures/sample.pcap --count 20 --print-packets

# The scan heuristics, with thresholds scaled to a 134-packet sample
netsniff pcap tests/fixtures/sample.pcap --scan-ports 4 --scan-unanswered 4
```

### Filters are not BPF

`--proto`, `--host` and `--port` are predicates applied **after** decoding, not
compiled BPF programs. Implementing BPF is a rabbit hole that would not make the
decoders any better, so it is out of scope and said so here rather than implied.

The practical difference is efficiency, not capability: a real BPF filter drops
packets in the kernel before they are ever copied to userspace. For a capture
file it makes no difference at all.

### Live capture

```bash
sudo netsniff live --iface eth0 --count 100
```

Linux only, and it needs root or `CAP_NET_RAW`. If you would rather not use
`sudo` every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
```

On the wrong platform or without privileges, it prints a sentence explaining
which of the two it is and what to do about it — not a `PermissionError`
traceback out of the middle of `socket.socket`.

Three details of the implementation worth knowing:

- **Promiscuous mode** is a kernel-refcounted membership, not the `IFF_PROMISC`
  interface flag. An interrupted run cannot leave your interface promiscuous.
- **Snap length is applied after receiving**, not in the kernel, so `orig_len`
  stays the true on-wire length and byte counts never understate the traffic.
- **Timestamps come from the kernel** via `SO_TIMESTAMPNS`. Calling `time.time()`
  after `recv` returns measures when the process got round to looking at the
  packet, which under load is not when it arrived.

---

## The test story

```
408 tests, no network access, no privileges, ~1 second
```

The tests are what make this credible, so here is what they actually check.

**Per-header unit tests against byte fixtures.** `tests/fixtures/headers.py`
holds 33 complete frames as hex. Thirteen are real frames lifted out of a
tcpdump capture; the rest were hand-built for what the capture did not contain —
VLAN and QinQ tags, ARP, IPv6 extension chains, fragments, IPv4 options, 802.3
LLC. **Every hand-built one was run through `tcpdump -e -vv` first**, which
confirmed each field and reported `cksum (correct)` before the bytes were pasted
in. The expected values in the tests are tcpdump's, so these compare against an
independent implementation rather than against themselves.

**The offset bugs are tested by asserting the wrong answer is wrong.** It is not
enough that slicing at `header_len` works; the tests also assert that slicing at
the naive constant decodes garbage. Otherwise a test passes whether or not the
VLAN shift was handled.

**Checksums that are supposed to fail.** One test asserts a TCP checksum is
*invalid* — the segment was captured on the sending host, where checksum offload
leaves the field for the NIC to fill in after the capture point. Roughly half of
any locally-taken capture looks "corrupt" by that measure, and a tool that
flagged it would be crying wolf.

**Hostile input, about 6,500 cases.** The application-layer parsers run on bytes
an attacker chose, so they get random garbage on every hint port, every prefix
of five real payloads (which is what snapping produces), single-bit corruption
of a real DNS response and a real TLS ClientHello, and random frames through the
whole pipeline. All of it must produce a hint or nothing — never an exception,
never an ended capture.

**Detectors that do not fire.** A normal web session and a twenty-connection
pool are tested to trigger *nothing*, because a summary full of false alarms
gets skipped and takes the true positives with it.

**Cross-checked against an independent tool.** The protocol breakdown matches
`tcpdump`'s own per-protocol counts on the same file exactly. The pcap reader's
framing is checked by arithmetic that only closes if it over-reads and
under-reads by exactly zero: `24 + 16 × packets + Σ incl_len` must land on the
file size.

### What CI does not cover

**Live capture is not tested in CI**, and that is deliberate rather than a gap.
No hosted runner will grant a test `CAP_NET_RAW`, and none should. It is the
reason the offline core was built first: everything except the socket itself is
verifiable on a stock runner with no privileges — including that live capture
*refuses cleanly* without them, which CI can check precisely because the runner
is unprivileged.

The remainder is one manual check, run on Linux as root:

```bash
sudo ./scripts/verify_live.sh eth0
```

It confirms `AF_PACKET` really captures, that those frames decode through the
same pipeline the pcap reader feeds, that the interface is **not** left
promiscuous afterwards, and that `--iface any` is refused rather than silently
decoding Linux cooked-capture headers as Ethernet.

---

## Design decisions

**Why parse bytes instead of using scapy.** Because parsing the bytes is the
skill on display. scapy is excellent and I would reach for it at work; here it
would decode every header in this repo and leave nothing to demonstrate.

**Why both a pcap reader and live capture.** Live capture alone would make the
project unrunnable for anyone who cloned it and untestable in CI. A pcap reader
alone would dodge the part that needs a raw socket. Building both, with the
offline one first, means the repo is demoable from the first commit and the
privileged path is a thin layer on a tested core.

**Why big-endian everywhere.** Everything on the wire is network byte order, so
every `struct` format string in `netsniff/decode/` starts with `!`. There are
exactly three deliberate exceptions, all outside the decoders: the pcap file
header, whose byte order the magic number tells you; and `struct packet_mreq`
and `struct timespec` in the live socket, which are native C structs where `!`
gets you `EINVAL` with no explanation.

**Why strict decoders and a tolerant pipeline.** Every decoder raises rather
than guessing when a buffer is short — that is what makes them testable, since
you can assert exactly which byte count failed. `decode_frame` catches those and
records a partial decode, so one malformed packet never ends a run. Trying to
get both properties out of one piece of code gets you neither.

**Why the app-layer hints are called hints.** A service can run on any port, an
HTTP request can be split across segments, a ClientHello can be fragmented.
These parsers give up rather than guess, and a port-based identification is
marked `confident=False` — because a port number is a guess and a parsed payload
is evidence.

**Why the detections state their own false positives.** A monitoring agent, a
connection pool and backup software retrying a dead peer all look like scans by
traffic shape alone. Every finding carries the benign behaviour that produces
the same signature, and that caveat travels into the JSON export too. A detector
that hides its false positives cannot be calibrated by whoever reads it.

**Why bytes mean on-wire bytes.** A snapped capture holds less than it saw.
Counting captured bytes would understate every host's traffic in proportion to
how aggressively the capture was snapped — so `orig_len` drives every byte
count, and the difference is tracked and reported so the snapping is visible
rather than invisible.

---

## Scope

Deliberately not implemented, so that what is here can be done properly:

- **TCP stream reassembly.** App hints read single segments; a request split
  across two will simply not match, which is the correct answer rather than a
  guess.
- **IP fragment reassembly.** Fragments are decoded and identified — a later
  fragment correctly gets no transport decode, since it starts mid-payload —
  but they are not reassembled.
- **BPF filter compilation.** See above.
- **pcapng.** A different, block-structured format. The reader detects its magic
  and names the problem instead of failing obscurely.
- **LLC/SNAP payloads.** 802.3 frames are identified as such rather than
  dispatched on a bogus ethertype, but their payloads are not decoded.
- **Non-Ethernet link types.** Linux cooked capture (SLL), raw IP and the rest
  are named in the error rather than misparsed — which is why `--iface any` is
  refused.

---

## Repo layout

```
netsniff/
  capture/     base.py (the Frame contract) | pcap.py (offline) | live.py (AF_PACKET)
  decode/      ethernet, vlan, ipv4, ipv6, arp, tcp, udp, icmp, apphint, common
               __init__.py holds decode_frame(), the layered pipeline
  analyze/     flows.py (conversations) | stats.py (aggregates) | detect.py (heuristics)
  report/      console.py (tables, live view) | export.py (JSON, CSV)
  cli.py       argparse entry point: the pcap and live subcommands
tests/
  fixtures/    headers.py (33 hex frames) | synth.py (builders) | sample.pcap (the real capture)
scripts/       capture_sample.sh (regenerate the fixture) | verify_live.sh | ci_summary.py
docs/          architecture.md | protocols.md
```

## Regenerating the capture

`tests/fixtures/sample.pcap` is a real capture, written by tcpdump rather than
by anything in this repo — so the end-to-end test cannot pass merely because the
reader and a writer share a bug. To make a fresh one:

```bash
sudo ./scripts/capture_sample.sh eth0
```

It generates a deliberate traffic mix (DNS, HTTP, TLS, ICMP, ARP, and some SYNs
to closed ports on your own gateway for the detectors), verifies the magic bytes
are classic pcap, and reports the packet count. The exact figures in
`tests/test_end_to_end.py` are specific to the committed capture and will need
regenerating with it.

## Development

```bash
pip install -e ".[dev]"
pytest          # 408 tests
ruff check .
mypy netsniff
```

## License

MIT — see [LICENSE](LICENSE).
