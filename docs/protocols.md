# The byte layouts

Every header netsniff decodes, and the specific thing about each one that is
easy to get wrong. All of it is big-endian, so every format string starts `!`.

---

## Classic libpcap file

A 24-byte global header, then repeated records.

**Global header (24 bytes)**

| Field | Size | Notes |
|---|---|---|
| `magic_number` | 4 | `a1b2c3d4` or byte-swapped `d4c3b2a1`; tells you the byte order |
| `version_major` | 2 | 2 |
| `version_minor` | 2 | 4 |
| `thiszone` | 4 | GMT offset, **signed**, effectively always 0 |
| `sigfigs` | 4 | 0 |
| `snaplen` | 4 | max bytes captured per packet |
| `network` | 4 | link type; **1 = Ethernet** |

**Record header (16 bytes)**: `ts_sec`, `ts_usec`, `incl_len`, `orig_len`. Then
`incl_len` bytes of frame data.

**Traps**

- Read the magic first and decide endianness from it, then use that for every
  subsequent unpack. Getting this wrong gives plausible garbage, not an error.
- `a1b23c4d` / `4d3cb2a1` are the **nanosecond** variants: the second timestamp
  field counts nanoseconds, not microseconds. netsniff handles all four.
- `0a0d0d0a` is **pcapng**, a completely different block-structured format.
  Wireshark saves it by default. This is the single most common reason a
  capture "will not open"; netsniff detects the magic and says so by name.
- **Always slice by `incl_len`, never `orig_len`.** A snapped capture has
  `incl_len < orig_len`, and the difference is the part that was never written.
- `incl_len` is four unvalidated bytes from a file. `0xFFFFFFFF` there would
  otherwise mean a 4 GB allocation; netsniff caps it at 16 MiB first.

**Verification worth knowing**: `24 + 16 × packets + Σ incl_len` must equal the
file size exactly. If framing over-reads or under-reads by even one byte per
record, it will not. That is `test_sample_framing_accounts_for_every_byte`.

---

## Ethernet II — `decode/ethernet.py`

```
| dst MAC (6) | src MAC (6) | ethertype (2) | payload ...
0             6             12              14
```

`struct.unpack('!6s6sH', data[:14])`. Dispatch on ethertype: `0x0800` IPv4,
`0x86DD` IPv6, `0x0806` ARP.

**Traps**

- **Destination comes first.** Swapping them is easy and silent.
- A value of **1500 or less is an 802.3 length field**, not an ethertype. 1536
  (`0x0600`) and above is a type. netsniff flags the 802.3 case rather than
  dispatching on a bogus protocol number.
- The low bit of the first destination octet is the **multicast** bit;
  broadcast is a special case of it. The second-lowest bit of the *source*
  marks a **locally administered** address — a VM, a container veth, a
  randomised MAC.

---

## 802.1Q VLAN tag — `decode/vlan.py`

```
| dst MAC (6) | src MAC (6) | TPID (2) | TCI (2) | real ethertype (2) | ...
                            \___________________/
                               the four-byte tag
```

The TPID sits in the ethertype position and holds `0x8100`. The TCI packs three
fields:

```
bit  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
     |  PCP  |DE|                VID                |
      \_____/  \/ \_________________________________/
       3 bits  1              12 bits
```

**Traps**

- **This is the classic silent offset bug.** A tagged frame looks like an
  untagged frame whose ethertype is `0x8100`, and the real ethertype is four
  bytes further along. Every header after it shifts. Nothing raises — you just
  decode the wrong bytes and get a confident wrong answer.
- Tags **stack**. QinQ uses an outer TPID of `0x88a8` (or the legacy `0x9100`)
  around an inner `0x8100`, so the walk has to loop — and be bounded, since a
  crafted frame could otherwise be an unbroken run of tags.
- `Ethernet.header_len` is 14 + 4 per tag, and it is what the payload should be
  sliced at.

---

## IPv4 — `decode/ipv4.py`

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Version|  IHL  |    DSCP/ECN   |          Total Length         |
+-------+-------+---------------+-----+-------------------------+
|         Identification              |Flags|  Fragment Offset  |
+---------------+---------------+-----+-------------------------+
| Time to Live  |    Protocol   |        Header Checksum        |
+---------------+---------------+-------------------------------+
|                       Source Address                          |
+---------------------------------------------------------------+
|                    Destination Address                        |
+---------------------------------------------------------------+
|              Options (0-40 bytes, present when IHL > 5)       |
+---------------------------------------------------------------+
```

`struct.unpack('!BBHHHBBH4s4s', data[:20])`, then `socket.inet_ntoa` for the
addresses. Dispatch on protocol: 6 TCP, 17 UDP, 1 ICMP.

**Traps**

- **IHL counts 32-bit words.** `header_len = (byte0 & 0x0F) * 4`. Slicing at a
  fixed 20 bytes breaks on every packet carrying options.
- The three flag bits and the 13-bit fragment offset **share one 16-bit field**:
  reserved `0x8000`, DF `0x4000`, MF `0x2000`, offset `& 0x1FFF`.
- **The fragment offset counts 8-byte units**, not bytes. Multiply by 8.
- A fragment with a non-zero offset **has no transport header** — it starts
  mid-payload. Decoding TCP out of one invents ports from payload bytes.
- `total_length` is what the sender claimed. It can exceed what was captured
  (snapping) and it can be **zero** under segmentation offload.
- **A zero checksum is not corruption.** On a capture taken at the sending
  host, checksum offload leaves the field for the NIC to fill in after the
  capture point. netsniff distinguishes `checksum_valid` from
  `checksum_offloaded`.

---

## IPv6 — `decode/ipv6.py`

A fixed 40-byte header: version/traffic-class/flow-label packed into the first
four bytes, then `payload_length` (2), `next_header` (1), `hop_limit` (1),
source (16), destination (16). `socket.inet_ntop(AF_INET6, ...)` for addresses.

**Traps**

- **`next_header` may not be the transport protocol.** It can name an extension
  header, which names the next one, and so on — a linked list you have to walk
  before you know whether this is TCP:

  ```
  base(next=Hop-by-Hop) -> Hop-by-Hop(next=Routing) -> Routing(next=TCP) -> TCP
  ```

- Extension header lengths are in **8-octet units excluding the first 8 bytes**,
  so `hdr_ext_len = 0` means the header is 8 bytes long, not 0.
- A **fragment header is always exactly 8 bytes** and carries no length field.
- **Authentication headers count 4-octet units**, excluding 8. Different unit
  from every other extension header.
- The chain must be **bounded**. A crafted packet can point each header at
  another one indefinitely.
- The chain **stops at ESP** — what follows is encrypted.
- `payload_length` counts the extension headers too, so the transport payload
  is `payload_length` minus the extension bytes already walked.
- There is **no header checksum** in IPv6.

---

## ARP — `decode/arp.py`

28 bytes for the usual IPv4-over-Ethernet case: htype (2), ptype (2), hlen (1),
plen (1), oper (2), then sender hardware, sender protocol, target hardware and
target protocol addresses. `oper` 1 = request, 2 = reply.

**Traps**

- **The four address fields are not fixed width.** Their sizes come from the
  HLEN and PLEN bytes in the packet itself. In practice they are always 6 and 4,
  but slicing by the declared lengths costs nothing and is simply correct.
- ARP frames are **padded**. 14 bytes of Ethernet plus 28 of ARP is 42, under
  the 60-byte minimum frame size, so the tail is padding and not part of the
  packet. (Captures on virtual interfaces often skip the padding — netsniff
  handles both.)
- Sender IP == target IP is a **gratuitous ARP**: an announcement rather than a
  question. Legitimate after a failover; also the shape ARP spoofing takes.
- Sender IP of `0.0.0.0` is an **ARP probe** (RFC 5227), checking an address is
  free before claiming it.

---

## TCP — `decode/tcp.py`

```
| src port (2) | dst port (2) | seq (4) | ack (4) | off/flags (2) | window (2) | cksum (2) | urg (2) |
```

`struct.unpack('!HHIIHHHH', data[:20])`.

- `data_offset = (off_flags >> 12) * 4`
- flags are the low 9 bits: FIN `0x01`, SYN `0x02`, RST `0x04`, PSH `0x08`,
  ACK `0x10`, URG `0x20`, ECE `0x40`, CWR `0x80`, NS `0x100`

**Traps**

- **Data offset counts 32-bit words**, exactly like IHL. And nearly every modern
  SYN carries options — MSS, SACK-permitted, timestamps, window scale — so a
  fixed 20-byte slice is wrong on almost every connection setup you will see.
- Walking the option area: kinds **0 (EOL) and 1 (NOP) are single bytes with no
  length octet**; everything else is kind, length, data, where the length
  *includes* the kind and length octets. A malformed length must not loop or
  over-read.
- The **checksum covers a pseudo-header** built from the IP addresses, so it
  cannot be verified from the segment alone.
- **Expect outbound checksums to fail.** Segments captured on the sending host
  routinely have unfilled checksums because of offload. Roughly half of any
  locally-taken capture looks "corrupt" by this measure, and reporting that as
  an error is crying wolf.
- A completed handshake means **SYN and ACK in the same packet**, not both bits
  appearing somewhere in the flow. Tracking only the union across a flow would
  report every scan as an established connection.

---

## UDP — `decode/udp.py`

Eight bytes: `struct.unpack('!HHHH', data[:8])` — source port, destination port,
length, checksum.

**Traps**

- **`length` covers the header and the payload.** The payload is `length - 8`.
  Treating it as a payload length shifts every app-layer hint by eight bytes.
- **A zero checksum means "not computed"**, which is legal over IPv4 and
  forbidden over IPv6. It is not the same as a wrong one, so `verify_udp_checksum`
  returns `None` there rather than `False`.
- Because zero is reserved for that meaning, a real computation that comes out
  as zero is transmitted as `0xFFFF` instead.

---

## ICMP — `decode/icmp.py`

Four bytes — type, code, checksum — then a type-specific remainder.

Two shapes cover nearly everything:

- **Echo request (8) and reply (0)** put a 16-bit identifier and sequence number
  in the rest-of-header. That is how `ping` matches replies to requests.
- **Error messages** (destination unreachable 3, time exceeded 11, …) quote the
  IP header and first eight bytes of the datagram that caused them. Those eight
  bytes hold the original ports, which is what lets you attribute an unreachable
  back to the flow that provoked it.

**Traps**

- **ICMPv6 is a different number space.** Echo request is type 128 there, not 8.
- **ICMPv4's checksum verifies standalone**; ICMPv6's covers an IPv6
  pseudo-header, so it cannot be checked without the addresses. netsniff reports
  that as `None` — unknown — rather than as a failure.

---

## Application-layer hints — `decode/apphint.py`

Identifiers, not parsers. Everything here is best-effort and none of it may
raise.

**DNS (port 53)** — a 12-byte header, then the question section. The name is
length-prefixed labels terminated by a zero byte:

```
| 07 | e x a m p l e | 03 | c o m | 00 |   ->   "example.com"
```

- A length byte with its **top two bits set is a compression pointer**, not a
  length: the low 14 bits are an offset to continue from.
- Pointers must go **backwards**. A forward or self-referential pointer is how
  that parser becomes an infinite loop; netsniff refuses both and budgets the
  number it will follow.
- Names are capped at 255 bytes, per RFC 1035.

**HTTP (port 80)** — the request line and the `Host` header, read as text from a
bounded window at the head of the payload. A request split across TCP segments
simply will not match, which is the right answer: netsniff does not reassemble
streams, and pretending otherwise would produce confident nonsense.

**TLS (port 443)** — the SNI from a ClientHello, which means walking
`record → handshake → session id → cipher suites → compression → extensions →
server_name`. Every one of those is length-prefixed by a field the sender chose,
so every one is bounds-checked before it is trusted.

Anything unrecognised falls back to naming the port, marked `confident=False` —
because a port number is a guess and a parsed payload is evidence.
