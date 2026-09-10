#!/usr/bin/env bash
#
# verify_live.sh - the manual check for Phase 8's live capture.
#
# CI cannot do this. Granting a test runner CAP_NET_RAW is not something a
# hosted runner will do, and it should not: the whole reason the offline core
# was built first is so that everything except this is verifiable without
# privileges. So live capture is validated by hand, on Linux, with this script -
# and the README says so rather than pretending the green badge covers it.
#
# It checks four things:
#   1. AF_PACKET actually captures frames from a real interface
#   2. those frames decode through the same pipeline the pcap reader feeds
#   3. the interface is NOT left promiscuous afterwards
#   4. --iface any is refused rather than silently decoding SLL as Ethernet
#
# Usage:
#   sudo ./scripts/verify_live.sh [interface]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { printf '\n[FAIL] %s\n' "$*" >&2; exit 1; }
say() { printf '[*] %s\n' "$*"; }
ok()  { printf '[OK] %s\n' "$*"; }

[[ "$(uname -s)" == "Linux" ]] || die "This needs Linux (AF_PACKET). On Windows use WSL."
[[ "${EUID}" -eq 0 ]] || die "Needs root for packet capture. Re-run with: sudo $0"

REAL_USER="${SUDO_USER:-root}"
IFACE="${1:-$(ip -4 route show default | awk '/default/ {print $5; exit}')}"
[[ -n "$IFACE" ]] || die "Could not determine the default interface. Pass one: sudo $0 eth0"

# Find an interpreter that can import netsniff.
PY="$ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
[[ -n "$PY" ]] || die "No python3 found."

cd "$ROOT"
export PYTHONPATH="$ROOT"

say "Interface: $IFACE"
say "Python:    $PY"
printf '\n'

# --- 1. capture and decode -------------------------------------------------
say "Capturing 40 live frames (generating some traffic to be sure there are some)..."

( sleep 1
  su -s /bin/bash -c "ping -c 3 -W 2 1.1.1.1 >/dev/null 2>&1" "$REAL_USER" 2>/dev/null || \
      ping -c 3 -W 2 1.1.1.1 >/dev/null 2>&1 || true
  su -s /bin/bash -c "curl -s --max-time 5 -o /dev/null http://example.com/" "$REAL_USER" 2>/dev/null || true
  su -s /bin/bash -c "dig +time=2 +tries=1 @1.1.1.1 example.com >/dev/null" "$REAL_USER" 2>/dev/null || true
) &
TRAFFIC_PID=$!

set +e
OUTPUT=$("$PY" -m netsniff live --iface "$IFACE" --count 40 --timeout 20 --no-print-packets 2>&1)
STATUS=$?
set -e
wait "$TRAFFIC_PID" 2>/dev/null || true

printf '%s\n' "$OUTPUT"
printf '\n'

[[ $STATUS -eq 0 ]] || die "netsniff live exited $STATUS"
grep -q "Capture summary" <<<"$OUTPUT" || die "no summary was printed"
grep -q "live:$IFACE" <<<"$OUTPUT"    || die "the summary did not name the live source"

PACKETS=$(grep -oP '(?<=packets\s{9})\d+' <<<"$OUTPUT" | head -1)
[[ -n "$PACKETS" && "$PACKETS" -gt 0 ]] || die "captured 0 packets"
ok "captured and decoded $PACKETS live frames"

grep -qE '^\s+(TCP|UDP|ICMP|ARP)\s' <<<"$OUTPUT" \
    || die "no protocol was decoded from the live frames"
ok "live frames decoded through the same pipeline as the pcap reader"

# --- 2. promiscuous mode was released --------------------------------------
if ip link show "$IFACE" | head -1 | grep -q PROMISC; then
    die "$IFACE is still in promiscuous mode after the capture exited"
fi
ok "$IFACE was left out of promiscuous mode"

# --- 3. 'any' is refused ---------------------------------------------------
set +e
ANY_OUTPUT=$("$PY" -m netsniff live --iface any --count 1 2>&1)
ANY_STATUS=$?
set -e
[[ $ANY_STATUS -ne 0 ]] || die "--iface any should have been refused"
grep -q "cooked-capture" <<<"$ANY_OUTPUT" \
    || die "the 'any' refusal did not explain why: $ANY_OUTPUT"
grep -qv "Traceback" <<<"$ANY_OUTPUT" || die "the 'any' refusal printed a traceback"
ok "--iface any refused with an explanation, not a traceback"

printf '\n'
ok "Phase 8 live capture verified on $IFACE"
