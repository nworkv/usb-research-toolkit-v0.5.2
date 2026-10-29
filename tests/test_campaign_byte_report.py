#!/usr/bin/env python3
"""Unit/integration tests for report-usb-campaign.py using a fake tshark."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "scripts/report-usb-campaign.py"
ROOT = SCRIPT.resolve().parents[1]
spec = importlib.util.spec_from_file_location("campaign_byte_report", SCRIPT)
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)
verifier_spec = importlib.util.spec_from_file_location("verify_usb_case", ROOT / "scripts/verify-usb-case.py")
verifier = importlib.util.module_from_spec(verifier_spec)
verifier_spec.loader.exec_module(verifier)

FIELDS = [
    "frame.number", "frame.time_epoch", "usb.bus_id", "usb.device_address", "usb.urb_id",
    "usb.urb_type", "usb.endpoint_address", "usb.transfer_type", "usb.urb_status",
    "usb.bmRequestType", "usb.setup.bRequest", "usb.setup.wValue", "usb.setup.wIndex",
    "usb.setup.wLength", "usb.data_len", "usb.capdata", "usb.control.Response",
    "usb.getDescriptor.Response", "usb.idVendor", "usb.idProduct",
]


def rows_for_descriptor(payload_hex):
    def base(frame, timestamp, urb, typ):
        row = {f: "" for f in FIELDS}
        row.update({"frame.number": str(frame), "frame.time_epoch": str(timestamp), "usb.bus_id": "1",
                    "usb.device_address": "0", "usb.urb_id": str(urb), "usb.urb_type": typ,
                    "usb.endpoint_address": "0", "usb.urb_status": "", "usb.data_len": ""})
        return row
    out = []
    r = base(1, 1001.0, 123, "S")
    r.update({"usb.bmRequestType": "128", "usb.setup.bRequest": "6", "usb.setup.wValue": "256",
              "usb.setup.wIndex": "0", "usb.setup.wLength": "64"})
    out.append(r)
    r = base(2, 1001.01, 123, "C")
    r.update({"usb.urb_status": "0", "usb.getDescriptor.Response": payload_hex,
              "usb.data_len": str(len(payload_hex.split(":")))})
    out.append(r)
    r = base(3, 1002.0, 124, "S")
    r.update({"usb.bmRequestType": "0", "usb.setup.bRequest": "9", "usb.setup.wValue": "1",
              "usb.setup.wIndex": "0", "usb.setup.wLength": "0"})
    out.append(r)
    r = base(4, 1002.01, 124, "C")
    r.update({"usb.urb_status": "0"})
    out.append(r)
    return out


def main():
    with tempfile.TemporaryDirectory(prefix="usb-byte-report-test-") as td:
        temp = Path(td)
        campaign = temp / "campaign"
        traces = campaign / "traces"
        traces.mkdir(parents=True)
        profile_source = ROOT / "profiles/valid/minimal-device.json"
        profile_path = campaign / "case-00001.json"
        shutil.copyfile(profile_source, profile_path)
        profile = json.loads(profile_path.read_text())
        expected = verifier.build_expected_descriptors(profile)[(1, 0, 0)]
        trace_path = traces / "case-00001.device.jsonl"
        trace_events = [
            {"sequence": 1, "event": "CONTROL_REQUEST", "request": {"bmRequestType": 128, "bRequest": 6, "wValue": 256, "wIndex": 0, "wLength": 64}},
            {"sequence": 2, "event": "CONTROL_RESPONSE_COMPLETE", "request": {"bmRequestType": 128, "bRequest": 6, "wValue": 256, "wIndex": 0, "wLength": 64}, "payload_hex": expected.hex(), "actual_length": len(expected)},
            {"sequence": 3, "event": "SET_CONFIGURATION", "configuration_value": 1},
        ]
        trace_path.write_text("\n".join(json.dumps(x) for x in trace_events) + "\n")
        (campaign / "campaign.jsonl").write_text(json.dumps({
            "case": 1, "status": "COMPLETED", "started_epoch": 1000.0, "ended_epoch": 1010.0,
            "duration_seconds": 10.0, "profile": str(profile_path), "trace": str(trace_path),
            "profile_sha256": "test-sha", "changes": ["$.device.idProduct: 1 -> 2"]
        }) + "\n")

        fake_tshark = temp / "fake-tshark"
        fake_tshark.write_text("""#!/usr/bin/env python3
import csv, json, sys
from pathlib import Path
FIELDS = %r
if '-G' in sys.argv:
    for f in FIELDS:
        print('F\\t' + f + '\\t' + f + '\\tFT_STRING\\tusb\\t0x0')
    raise SystemExit(0)
pcap = Path(sys.argv[sys.argv.index('-r') + 1])
rows = json.loads(pcap.read_text())
chosen = [sys.argv[i+1] for i,x in enumerate(sys.argv[:-1]) if x == '-e']
w = csv.writer(sys.stdout, delimiter='\\t', lineterminator='\\n', quoting=csv.QUOTE_MINIMAL)
w.writerow(chosen)
for r in rows:
    w.writerow([r.get(f, '') for f in chosen])
""" % FIELDS, encoding="utf-8")
        fake_tshark.chmod(0o755)
        good_pcap = temp / "good.pcapng"
        good_pcap.write_text(json.dumps(rows_for_descriptor(":".join(f"{x:02x}" for x in expected))))
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(good_pcap), "--tshark", str(fake_tshark)],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\n" + run.stderr
        data = json.loads((campaign / "protocol-report.json").read_text())
        assert data["cases"][0]["verdict"] == "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED", data["cases"][0]["verdict"]
        assert data["cases"][0]["descriptor_transactions"][0]["result"] == "MATCH"
        assert (campaign / "protocol-report.txt").is_file()
        html = (campaign / "protocol-report.html").read_text()
        assert "СЛЕВА — ОЖИДАЕМЫЕ БАЙТЫ ПРОФИЛЯ" in html
        assert "СПРАВА — НАБЛЮДЕНИЕ USBPcap" in html

        bad_bytes = bytearray(expected)
        bad_bytes[8] ^= 0x01
        bad_pcap = temp / "bad.pcapng"
        bad_pcap.write_text(json.dumps(rows_for_descriptor(":".join(f"{x:02x}" for x in bad_bytes))))
        run = subprocess.run([sys.executable, str(SCRIPT), "--campaign-dir", str(campaign),
                              "--host-pcap", str(bad_pcap), "--tshark", str(fake_tshark),
                              "--out-prefix", str(campaign / "mismatch-report")],
                             text=True, capture_output=True)
        assert run.returncode == 0, run.stdout + "\n" + run.stderr
        bad = json.loads((campaign / "mismatch-report.json").read_text())
        assert bad["cases"][0]["verdict"] == "HOST_DESCRIPTOR_BYTES_MISMATCH"
        assert bad["cases"][0]["descriptor_transactions"][0]["first_diff_offset"] == 8
    print("test_campaign_byte_report: PASS")


if __name__ == "__main__":
    main()
