#!/usr/bin/env python3
"""Regression test for cross-platform tshark TSV normalization (including UTF-8 BOM)."""
import csv
import io
import json
import subprocess
import sys

normalizer = sys.argv[1]
fields = [
    "frame.time_epoch", "usb.device_address", "usb.endpoint_address",
    "usb.transfer_type", "usb.urb_type", "usb.data_len",
    "usb.bmRequestType", "usb.setup.bRequest", "usb.setup.wValue",
    "usb.setup.wIndex", "usb.setup.wLength", "usb.capdata",
    "frame.number", "usb.bus_id", "usb.urb_id", "usb.urb_status", "usb.usbd_status",
]
buffer = io.StringIO(newline="")
writer = csv.writer(buffer, delimiter="\t", lineterminator="\n")
writer.writerow(fields)
writer.writerow(["1234.5", "4", "129", "2", "C", "4", "", "", "", "", "", "01:02:03:04", "42", "1", "9876", "0", ""])
writer.writerow(["1234.6", "4", "1", "2", "E", "4", "", "", "", "", "", "aabbccdd", "43", "1", "9877", "-32", ""])
writer.writerow(["1234.7", "4", "0", "2", "C", "18", "128", "GET DESCRIPTOR", "DEVICE (0x0100)", "0", "18", "", "44", "1", "9878", "0", ""])
# Windows PowerShell 5.1 Set-Content -Encoding UTF8 emits this BOM.
source = "\ufeff" + buffer.getvalue()
result = subprocess.run(
    [sys.executable, normalizer, "--source", "windows_host"],
    input=source,
    text=True,
    capture_output=True,
    check=False,
)
assert result.returncode == 0, result.stderr
rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
assert len(rows) == 3, result.stdout
row = rows[0]
assert row["source"] == "windows_host"
assert row["endpoint"] == 129
assert row["actual_length"] == 4
assert row["payload_hex"] == "01020304"
assert row["timestamp_wall_ns"] == 1234500000000
assert row["frame_number"] == 42
assert row["urb_id"] == 9876
assert row["status"] == "completed"
error_row = rows[1]
assert error_row["status"] == "error"
assert error_row["host_status_code"] == -32
setup_row = rows[2]
assert setup_row["request"]["bmRequestType"] == 128
assert setup_row["request"]["bRequest"] == 6
assert setup_row["request"]["wValue"] == 0x0100

# Backward-compatibility regression: legacy tshark builds used the setup-prefixed name.
legacy_fields = ["usb.setup.bmRequestType" if f == "usb.bmRequestType" else f for f in fields]
legacy_buffer = io.StringIO(newline="")
legacy_writer = csv.writer(legacy_buffer, delimiter="\t", lineterminator="\n")
legacy_writer.writerow(legacy_fields)
legacy_writer.writerow(["1234.7", "4", "0", "2", "C", "18", "128", "GET DESCRIPTOR", "DEVICE (0x0100)", "0", "18", "", "44", "1", "9878", "0", ""])
legacy_result = subprocess.run(
    [sys.executable, normalizer, "--source", "windows_host"],
    input=legacy_buffer.getvalue(), text=True, capture_output=True, check=False,
)
assert legacy_result.returncode == 0, legacy_result.stderr
legacy_row = json.loads(legacy_result.stdout.strip())
assert legacy_row["request"]["bmRequestType"] == 128
print("Normalizer tests passed (current and legacy bmRequestType names)")
