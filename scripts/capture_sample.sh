#!/usr/bin/env bash
#
# capture_sample.sh - produce tests/fixtures/sample.pcap, the committed golden
# fixture the end-to-end test and CI run against.
#
# The fixture is a REAL capture, not a synthesised file. It is written by tcpdump
# (an independent, canonical implementation of the classic libpcap format) rather
# than by anything in this repo, so the end-to-end test cannot pass just because
# our reader and our writer happen to share a bug.
#
# Requires Linux + root (AF_PACKET needs CAP_NET_RAW). On Windows, run it from a
# WSL shell.
#
# Usage:
#   sudo ./scripts/capture_sample.sh [interface]
#
# Privacy note: the capture window is only as long as the scripted traffic burst
# below, and it only sees the interface named. It records this machine's local
# MAC and RFC1918 address plus the public addresses of the handful of sites the
# script itself contacts. Do not generate other traffic on that interface while
# it runs, since the result gets committed to a public repository.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/tests/fixtures/sample.pcap"
MAX_PACKETS=600
TMP_PCAP="$(mktemp /tmp/netsniff-sample.XXXXXX.pcap)"

die() { printf '\n[!] %s\n' "$*" >&2; exit 1; }
say() { printf '[*] %s\n' "$*"; }

[[ "$(uname -s)" == "Linux" ]] || die "This script needs Linux (AF_PACKET). On Windows use WSL."
[[ "${EUID}" -eq 0 ]] || die "Needs root for packet capture. Re-run with: sudo $0"

# The user tcpdump should drop privileges to, and who should own the result.
REAL_USER="${SUDO_USER:-root}"

# --- 1. dependencies -------------------------------------------------------
missing=()
command -v tcpdump >/dev/null 2>&1 || missing+=(tcpdump)
command -v curl    >/dev/null 2>&1 || missing+=(curl)
command -v ping    >/dev/null 2>&1 || missing+=(iputils-ping)
if (( ${#missing[@]} )); then
    say "Installing: ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "${missing[@]}" >/dev/null
fi

# --- 2. pick the interface -------------------------------------------------
IFACE="${1:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ -n "$IFACE" ]] || die "Could not determine the default interface. Pass one: sudo $0 eth0"
say "Capturing on interface: $IFACE"

# --- 3. start the capture --------------------------------------------------
# -s 0     full packets, no snapping (so payload-based app hints have something
#          to read; the reader handles snapped packets too, that is just not
#          what we want baked into the golden fixture)
# -n       no name resolution, so tcpdump's own DNS lookups do not pollute it
# -w       classic libpcap format (this is the default for -w; NOT pcapng)
tcpdump -i "$IFACE" -s 0 -n -c "$MAX_PACKETS" -w "$TMP_PCAP" 2>/tmp/netsniff-tcpdump.log &
TCPDUMP_PID=$!

cleanup() { kill -INT "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Give tcpdump a moment to actually attach to the interface before we make noise.
sleep 2
say "Generating a traffic mix (DNS, HTTP, TLS, ICMP)..."

run_as_user() { su -s /bin/bash -c "$1" "$REAL_USER" 2>/dev/null || true; }

# DNS over UDP/53 - gives the app-hint decoder query names to find.
for host in example.com neverssl.com api.github.com cloudflare.com; do
    run_as_user "getent ahostsv4 $host >/dev/null"
done

# Plaintext HTTP over TCP/80 - method line and Host header for the HTTP hint.
run_as_user "curl -s --max-time 10 -o /dev/null http://example.com/"
run_as_user "curl -s --max-time 10 -o /dev/null http://neverssl.com/"

# TLS over TCP/443 - ClientHello carries the SNI extension.
run_as_user "curl -s --max-time 10 -o /dev/null https://example.com/"
run_as_user "curl -s --max-time 10 -o /dev/null -I https://api.github.com/"

# ICMP echo request/reply.
run_as_user "ping -c 3 -W 2 1.1.1.1 >/dev/null"
run_as_user "ping -c 2 -W 2 8.8.8.8 >/dev/null"

# A connection that gets refused, so there is a SYN with no SYN-ACK for the
# detection heuristics to find.
run_as_user "curl -s --max-time 3 -o /dev/null http://127.0.0.1:9/ " || true
run_as_user "curl -s --max-time 3 -o /dev/null http://example.com:81/" || true

sleep 3
say "Stopping capture..."
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
trap - EXIT

# --- 4. verify and install the fixture ------------------------------------
[[ -s "$TMP_PCAP" ]] || die "tcpdump produced nothing. Log: $(cat /tmp/netsniff-tcpdump.log)"

MAGIC=$(head -c 4 "$TMP_PCAP" | od -An -tx1 | tr -d ' \n')
case "$MAGIC" in
    a1b2c3d4) ORDER="big-endian (a1b2c3d4)" ;;
    d4c3b2a1) ORDER="little-endian (d4c3b2a1)" ;;
    a1b23c4d|4d3cb2a1) die "This is a nanosecond-resolution pcap ($MAGIC). Re-run; the reader wants microsecond pcap." ;;
    0a0d0d0a) die "tcpdump wrote pcapng, not classic pcap. This reader parses classic pcap only." ;;
    *)        die "Unexpected magic bytes: $MAGIC - not a classic pcap file." ;;
esac

PKTS=$(tcpdump -r "$TMP_PCAP" 2>/dev/null | wc -l)
SIZE=$(stat -c %s "$TMP_PCAP")

mkdir -p "$(dirname "$OUT")"
cp "$TMP_PCAP" "$OUT"
chown "$REAL_USER" "$OUT" 2>/dev/null || true
chmod 644 "$OUT"
rm -f "$TMP_PCAP"

printf '\n'
say "Wrote $OUT"
say "  magic   : $ORDER"
say "  packets : $PKTS"
say "  size    : $SIZE bytes"
printf '\n'

if (( PKTS < 20 )); then
    printf '[!] Only %s packets captured - that is thin for a fixture.\n' "$PKTS" >&2
    printf '    Check that %s has connectivity, then re-run.\n' "$IFACE" >&2
fi
