#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <output.pcapng> [usbmon-interface]" >&2
  echo "Example: sudo $0 runs/host-linux.pcapng usbmon0" >&2
  exit 2
fi
OUT=$1
IFACE=${2:-usbmon0}
mkdir -p "$(dirname "$OUT")"

if ! command -v tshark >/dev/null 2>&1; then echo 'tshark is not installed; install Wireshark/tshark first.' >&2; exit 1; fi
sudo modprobe usbmon || true
if ! tshark -D | grep -Fq "$IFACE"; then
  echo "Capture interface '$IFACE' was not listed by tshark -D." >&2
  tshark -D >&2 || true
  exit 1
fi

echo "Capturing USB host stack events on $IFACE into $OUT. Press Ctrl+C to stop."
exec sudo tshark -i "$IFACE" -w "$OUT"
