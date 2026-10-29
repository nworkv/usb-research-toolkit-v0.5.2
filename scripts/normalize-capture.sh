#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <input.pcapng> <output.jsonl> <linux_host|windows_host>" >&2
  exit 2
fi
INPUT=$1
OUTPUT=$2
SOURCE=$3
case "$SOURCE" in linux_host|windows_host) ;; *) echo 'source must be linux_host or windows_host' >&2; exit 2;; esac
mkdir -p "$(dirname "$OUTPUT")"
AVAILABLE_FIELDS=$(tshark -G fields 2>/dev/null | awk -F '\t' '$1 == "F" { print $3 }')
if printf '%s\n' "$AVAILABLE_FIELDS" | grep -Fxq 'usb.bmRequestType'; then
  REQUEST_TYPE_FIELD='usb.bmRequestType'
elif printf '%s\n' "$AVAILABLE_FIELDS" | grep -Fxq 'usb.setup.bmRequestType'; then
  REQUEST_TYPE_FIELD='usb.setup.bmRequestType'
else
  echo 'TShark has no bmRequestType field (usb.bmRequestType / usb.setup.bmRequestType).' >&2
  exit 2
fi
tshark -r "$INPUT" -T fields -E header=y -E separator=/t -E quote=d -E occurrence=f \
  -e frame.time_epoch \
  -e usb.device_address \
  -e usb.endpoint_address \
  -e usb.transfer_type \
  -e usb.urb_type \
  -e usb.data_len \
  -e "$REQUEST_TYPE_FIELD" \
  -e usb.setup.bRequest \
  -e usb.setup.wValue \
  -e usb.setup.wIndex \
  -e usb.setup.wLength \
  -e usb.capdata \
  | "$(dirname "$0")/normalize-tshark.py" --source "$SOURCE" > "$OUTPUT"
echo "Normalized events written to $OUTPUT"
