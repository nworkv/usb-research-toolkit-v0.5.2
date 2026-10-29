#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile

GEN, CONFIG, ROOT = sys.argv[1:4]

def run(args, expect=0):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expect:
        raise AssertionError(
            f"command failed ({result.returncode}, expected {expect}): {' '.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result

with tempfile.TemporaryDirectory(prefix="usb-profile-generator-test-") as td:
    td = pathlib.Path(td)
    listed = run([GEN, "list", "--templates-dir", str(pathlib.Path(ROOT) / "profiles/templates")])
    for expected in ("vendor-bulk", "cdc-acm-serial", "hid-mouse", "msc-bot-descriptor-only"):
        assert expected in listed.stdout, expected

    out1, out2 = td / "a", td / "b"
    common = [GEN, "generate", "--template", "cdc-acm-serial", "--count", "3", "--seed", "123456",
              "--templates-dir", str(pathlib.Path(ROOT) / "profiles/templates")]
    run(common + ["--out-dir", str(out1)])
    run(common + ["--out-dir", str(out2)])
    files1 = sorted(p for p in out1.glob("*.json") if p.name != "manifest.json")
    files2 = sorted(p for p in out2.glob("*.json") if p.name != "manifest.json")
    assert len(files1) == len(files2) == 3
    ids = set()
    for f1, f2 in zip(files1, files2):
        p1, p2 = json.loads(f1.read_text()), json.loads(f2.read_text())
        assert p1 == p2, "same seed should reproduce identical generated profile"
        pid = p1["device"]["idProduct"]
        assert pid not in ids
        ids.add(pid)
        assert p1["validation"]["mode"] == "strict"
        run([CONFIG, "validate", str(f1), "--mode", "strict"])
        # Every configured IN payload should be associated with an IN endpoint after address remapping.
        in_addresses = set()
        for config in p1["configurations"]:
            for iface in config["interfaces"]:
                for ep in iface["endpoints"]:
                    if ep["bEndpointAddress"] & 0x80:
                        in_addresses.add(str(ep["bEndpointAddress"]))
        payloads = p1.get("endpoint_io", {}).get("in_payloads", {})
        assert set(payloads).issubset(in_addresses)

    # Extended mutation set can vary class/protocol and configuration/endpoint fields
    # while keeping descriptor structure parsable and strict-validator-clean.
    all_out = td / "all-fields"
    run([GEN, "generate", "--template", "cdc-acm-serial", "--count", "3", "--seed", "987",
         "--mode", "safe", "--fields", "all", "--out-dir", str(all_out), "--templates-dir",
         str(pathlib.Path(ROOT) / "profiles/templates")])
    all_files = sorted(p for p in all_out.glob("*.json") if p.name != "manifest.json")
    assert len(all_files) == 3
    for f in all_files:
        run([CONFIG, "validate", str(f), "--mode", "strict"])

    research = td / "research"
    run([GEN, "generate", "--template", "vendor-bulk", "--count", "4", "--seed", "10",
         "--mode", "research", "--out-dir", str(research), "--templates-dir",
         str(pathlib.Path(ROOT) / "profiles/templates")])
    rfiles = sorted(p for p in research.glob("*.json") if p.name != "manifest.json")
    assert len(rfiles) == 4
    for f in rfiles:
        run([CONFIG, "validate", str(f), "--mode", "research"])

print("Profile generator tests passed")
