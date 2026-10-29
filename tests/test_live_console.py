#!/usr/bin/env python3
import importlib.util
import sys
from pathlib import Path

script = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("usb_campaign_live_test", script)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(mod)

assert mod.describe_control_request({"bRequest": 6, "wValue": 0x0100, "wIndex": 0, "wLength": 64}) == "GET_DESCRIPTOR(Device, index=0, wLength=64, wIndex=0x0000)"
assert "GET_DESCRIPTOR(Configuration" in mod.describe_control_request({"bRequest": 6, "wValue": 0x0200, "wIndex": 0, "wLength": 255})
assert mod.describe_control_request({"bRequest": 9, "wValue": 1, "wIndex": 0, "wLength": 0}) == "SET_CONFIGURATION(value=1)"

import tempfile, json, contextlib, io, time
with tempfile.TemporaryDirectory() as td:
    trace = Path(td) / "trace.jsonl"
    watcher = mod.LiveTraceProgress(trace)
    events = [
        {"event":"BACKEND_RUNNING", "state":"BACKEND_READY"},
        {"event":"CONTROL_REQUEST", "request":{"bRequest":6,"wValue":0x0100,"wIndex":0,"wLength":64}},
        {"event":"CONTROL_RESPONSE_COMPLETE", "actual_length":18, "request":{"bRequest":6,"wValue":0x0100,"wIndex":0,"wLength":64}},
        {"event":"SET_CONFIGURATION", "configuration_value":1},
    ]
    trace.write_text("".join(json.dumps(e)+"\n" for e in events))
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf): watcher.poll()
    summary=watcher.summary()
    assert summary["host_control_requests"] == 1
    assert summary["control_responses_complete"] == 1
    assert summary["configured_observed"] is True
    output=buf.getvalue()
    assert "GET_DESCRIPTOR(Device" in output and "SET_CONFIGURATION" in output
print("live console tests passed")

# End-to-end smoke test for streaming events from a mock usb-connect process.
import argparse, os
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    fake = td / "fake-usb-connect"
    fake.write_text('''#!/usr/bin/env python3
import json, signal, sys, time
from pathlib import Path
trace = Path(sys.argv[sys.argv.index("--trace") + 1])
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
events = [
  {"event":"BACKEND_RUNNING","state":"BACKEND_READY"},
  {"event":"UDC_BOUND","state":"BACKEND_READY"},
  {"event":"CONTROL_REQUEST","request":{"bRequest":6,"wValue":0x0100,"wIndex":0,"wLength":64}},
  {"event":"CONTROL_RESPONSE_COMPLETE","actual_length":18,"request":{"bRequest":6,"wValue":0x0100,"wIndex":0,"wLength":64}},
  {"event":"SET_CONFIGURATION","configuration_value":1},
]
with trace.open("w", encoding="utf-8") as f:
  for e in events:
    f.write(json.dumps(e) + "\\n")
    f.flush()
    time.sleep(0.12)
while True:
  time.sleep(0.1)
''', encoding="utf-8")
    fake.chmod(0o755)
    profile = Path(mod.__file__).resolve().parents[1] / "profiles/templates/hid-mouse.json"
    out = td / "out"
    args = argparse.Namespace(
        run_id="live-test", udc_driver="fake-driver", udc_device="fake-udc",
        speed="high", allow_research=True, startup_grace=0.15,
        dwell_seconds=1.2, live_progress_interval=0.3, stop_grace=1.0,
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        row = mod.run_case(fake, profile, 1, args, out, None, ["$.device.idProduct: 4608 -> 7"])
    assert row["status"] == "COMPLETED", row
    assert row["trace_summary"]["host_contact_observed"] is True
    assert row["trace_summary"]["configured_observed"] is True
    live_output = buf.getvalue()
    assert "ХОСТ → GET_DESCRIPTOR(Device" in live_output
    assert "SET_CONFIGURATION" in live_output
print("live runner integration test passed")
