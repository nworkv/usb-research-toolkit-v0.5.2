#!/usr/bin/env python3
"""Normalize tshark -T fields TSV output to the toolkit's JSONL schema."""
import argparse
import csv
import json
import re
import sys
from decimal import Decimal, InvalidOperation

FIELDS = [
    "frame.time_epoch", "usb.device_address", "usb.endpoint_address",
    "usb.transfer_type", "usb.urb_type", "usb.data_len",
    "usb.setup.bRequest", "usb.setup.wValue", "usb.setup.wIndex",
    "usb.setup.wLength", "usb.capdata"
]
REQUEST_TYPE_FIELD_ALIASES = ("usb.bmRequestType", "usb.setup.bmRequestType")
OPTIONAL_FIELDS = ["frame.number", "usb.bus_id", "usb.urb_id", "usb.urb_status", "usb.usbd_status", "usb.control.Response", "usb.getDescriptor.Response"]


def num(s):
    if s is None or s == "":
        return None
    s = str(s).strip()
    try:
        return int(s, 0)
    except ValueError:
        try:
            return int(s, 10)
        except ValueError:
            # Some Wireshark versions render numeric fields as "LABEL (0xNN)".
            match = re.search(r"\(\s*(-?0x[0-9a-fA-F]+|-?\d+)\s*\)", s)
            if match:
                try:
                    return int(match.group(1), 0)
                except ValueError:
                    return None
            return None


REQUEST_LABELS = {
    "GET STATUS": 0x00, "CLEAR FEATURE": 0x01,
    "SET FEATURE": 0x03, "SET ADDRESS": 0x05,
    "GET DESCRIPTOR": 0x06, "SET DESCRIPTOR": 0x07,
    "GET CONFIGURATION": 0x08, "SET CONFIGURATION": 0x09,
    "GET INTERFACE": 0x0A, "SET INTERFACE": 0x0B,
    "SYNCH FRAME": 0x0C,
}


def request_num(value):
    parsed = num(value)
    if parsed is not None:
        return parsed
    label = re.sub(r"\s+", " ", str(value or "").strip().upper().replace("_", " "))
    for name, code in REQUEST_LABELS.items():
        if label == name or label.startswith(name + " "):
            return code
    return None


def decode_status(raw):
    """Return (code, normalized status) for common numeric/label status fields."""
    if raw is None or not str(raw).strip():
        return None, None
    text = str(raw).strip()
    code = num(text)
    if code is None:
        # Wireshark can display a label followed by the numeric value.
        match = re.search(r"\(\s*(-?0x[0-9a-fA-F]+|-?\d+)\s*\)", text)
        if match:
            try:
                code = int(match.group(1), 0)
            except ValueError:
                code = None
    lower = text.lower()
    if code is not None:
        return code, "completed" if code == 0 else "error"
    if any(word in lower for word in ("success", "complete", "completed", "status_success")):
        return None, "completed"
    if any(word in lower for word in ("error", "stall", "timeout", "timed out", "failed", "cancelled", "canceled")):
        return None, "error"
    return None, "observed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["linux_host", "windows_host"], required=True)
    args = ap.parse_args()
    reader = csv.DictReader(sys.stdin, delimiter="\t")
    if reader.fieldnames is None:
        print("Expected TSV output from tshark with a header row. See README.", file=sys.stderr)
        return 2
    # Windows PowerShell 5.1 Set-Content -Encoding UTF8 adds a BOM.
    reader.fieldnames = [name.lstrip("\ufeff") for name in reader.fieldnames]
    missing = [f for f in FIELDS if f not in reader.fieldnames]
    request_type_field = next((f for f in REQUEST_TYPE_FIELD_ALIASES if f in reader.fieldnames), None)
    if request_type_field is None:
        missing.append("usb.bmRequestType (or legacy usb.setup.bmRequestType)")
    if missing:
        print("Missing tshark fields: " + ", ".join(missing), file=sys.stderr)
        print("Available columns: " + ", ".join(reader.fieldnames), file=sys.stderr)
        return 2
    for seq, row in enumerate(reader, 1):
        e = {
            "schema_version": 1,
            "run_id": "host-capture",
            "sequence": seq,
            "source": args.source,
            "event": "HOST_USB_TRANSFER",
            "state": "HOST_CAPTURED",
        }
        try:
            e["timestamp_wall_ns"] = int(Decimal(row["frame.time_epoch"]) * Decimal(1_000_000_000))
        except (InvalidOperation, KeyError, TypeError):
            e["timestamp_wall_ns"] = None
        e["frame_number"] = num(row.get("frame.number"))
        e["device_address"] = num(row.get("usb.device_address"))
        e["bus_id"] = num(row.get("usb.bus_id"))
        e["urb_id"] = num(row.get("usb.urb_id"))
        e["endpoint"] = num(row.get("usb.endpoint_address"))
        e["transfer_type"] = row.get("usb.transfer_type") or None
        e["urb_type"] = row.get("usb.urb_type") or None
        raw_payload = row.get("usb.capdata") or row.get("usb.control.Response") or row.get("usb.getDescriptor.Response") or ""
        payload_hex = raw_payload.replace(":", "").replace(" ", "").replace("-", "").strip().lower()
        e["payload_hex"] = payload_hex or None
        actual_length = num(row.get("usb.data_len"))
        if actual_length is None and payload_hex:
            actual_length = len(payload_hex) // 2
        e["actual_length"] = actual_length
        raw_status = row.get("usb.urb_status") or row.get("usb.usbd_status") or ""
        code, status = decode_status(raw_status)
        if raw_status:
            e["host_status_raw"] = raw_status
        if code is not None:
            e["host_status_code"] = code
        if status:
            e["status"] = status
        elif (row.get("usb.urb_type") or "").strip().upper() == "E":
            # Linux usbmon and USBPcap can emit explicit URB error events.
            e["status"] = "error"
        setup_names = ["bmRequestType", "bRequest", "wValue", "wIndex", "wLength"]
        setup = {}
        for key in setup_names:
            if key == "bmRequestType":
                raw = row.get("usb.bmRequestType") or row.get("usb.setup.bmRequestType")
                setup[key] = num(raw)
            elif key == "bRequest":
                setup[key] = request_num(row.get("usb.setup." + key))
            else:
                setup[key] = num(row.get("usb.setup." + key))
        if any(v is not None for v in setup.values()):
            e["request"] = setup
            # SETUP/data stage belongs to control endpoint zero; separate direction
            # from the IN bit that some disectors include in endpoint_address.
            e["endpoint"] = 0
            e["direction"] = "device_to_host" if (setup["bmRequestType"] or 0) & 0x80 else "host_to_device"
        elif e["endpoint"] is not None:
            e["direction"] = "device_to_host" if (e["endpoint"] & 0x80) else "host_to_device"
        print(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
