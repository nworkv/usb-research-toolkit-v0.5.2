#!/usr/bin/env python3
import json
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

script = Path(sys.argv[1]).resolve()
root = script.parents[1]
base = root / "profiles" / "templates" / "hid-mouse.json"
with tempfile.TemporaryDirectory() as td:
    out = Path(td) / "dry-run"
    cmd = [sys.executable, str(script), "--base", str(base), "--count", "3",
           "--seed", "20261028", "--mutations", "1", "--udc-driver", "fake-driver",
           "--udc-device", "fake-udc", "--out-dir", str(out), "--dry-run"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "USB Gadget не запускался" in result.stdout
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "DRY_RUN_ONLY"
    assert summary["generated"] == 3 and summary["executed"] == 0
    rows = [json.loads(line) for line in (out / "campaign.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3 and all(x["status"] == "DRY_RUN_ONLY" for x in rows)
    assert all((out / f"case-{i:05d}.json").exists() for i in range(1, 4))

    # Never silently overwrite the results of an earlier campaign.
    repeated = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert repeated.returncode != 0
    assert "--out-dir уже существует и не пуст" in repeated.stderr

    # Empty UDC strings usually come from forgotten exports in a new shell;
    # reject them before creating a dozen uninformative START_FAILED cases.
    empty_udc_out = Path(td) / "empty-udc"
    empty_udc_cmd = [sys.executable, str(script), "--base", str(base), "--count", "1",
                     "--seed", "1", "--mutations", "1", "--udc-driver", "",
                     "--udc-device", "fake-udc", "--out-dir", str(empty_udc_out), "--dry-run"]
    empty_udc = subprocess.run(empty_udc_cmd, capture_output=True, text=True, check=False)
    assert empty_udc.returncode != 0
    assert "--udc-driver пустой" in empty_udc.stderr
    assert not empty_udc_out.exists()

    replay_out = Path(td) / "replay-dry-run"
    replay_cmd = [sys.executable, str(script), "--base", str(base),
                  "--replay-from", str(out), "--replay-case", "2",
                  "--udc-driver", "fake-driver", "--udc-device", "fake-udc",
                  "--out-dir", str(replay_out), "--dry-run"]
    replay = subprocess.run(replay_cmd, capture_output=True, text=True, check=False)
    assert replay.returncode == 0, replay.stderr
    replay_rows = [json.loads(line) for line in
                   (replay_out / "campaign.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(replay_rows) == 1 and replay_rows[0]["case"] == 2
    assert replay_rows[0]["profile"] == str((out / "case-00002.json").resolve())
# Exercise the conservative Wireshark review queue with a deterministic fake tshark.
spec = importlib.util.spec_from_file_location("usb_gadget_campaign", script)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as td:
    capture_dir = Path(td) / "captures"
    capture_dir.mkdir()
    (capture_dir / "host.pcapng").write_bytes(b"fake capture")
    fake_tshark = Path(td) / "fake-tshark"
    fake_tshark.write_text("#!/bin/sh\nprintf '1\\t1700000001.0\\tUSB\\tDevice reset detected\\n'\n", encoding="utf-8")
    fake_tshark.chmod(0o755)
    rows = [{"case": 7, "profile": "/tmp/case-00007.json", "profile_sha256": "abc",
             "run_id": "test-case-7", "status": "COMPLETED",
             "started_epoch": 1700000000.0, "ended_epoch": 1700000002.0}]
    rows.append({"case": 8, "profile": "/tmp/case-00008.json", "profile_sha256": "def",
                 "run_id": "test-case-8", "status": "START_FAILED",
                 "stderr_tail": "profile validation failed"})
    queue = module.analyze_campaign_captures(capture_dir, rows, str(fake_tshark), Path(td))
    assert len(queue) == 2 and queue[0]["case"] == 7
    assert "WIRESHARK_ANOMALY_TEXT" in queue[0]["reasons"]
    failed = next(x for x in queue if x["case"] == 8)
    assert "GADGET_START_FAILED" in failed["reasons"]
    assert "profile validation failed" in failed["stderr_excerpt"]
print("usb-gadget-campaign tests passed")
