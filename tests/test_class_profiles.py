#!/usr/bin/env python3
"""Static checks for built-in USB class and composite profiles."""
from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> None:
    raise SystemExit("FAIL: " + msg)


def report_for(profile: dict, config_value: int, interface_number: int) -> bytes | None:
    m = profile.get("interface_descriptors", {})
    key = f"{config_value}:{interface_number}"
    if key in m:
        return bytes.fromhex(m[key])
    key2 = str(interface_number)
    if key2 in m:
        return bytes.fromhex(m[key2])
    raw = profile.get("raw_descriptors", {}).get("34:0")
    return bytes.fromhex(raw) if raw else None


def main() -> int:
    binary = Path(sys.argv[1])
    templates = Path(sys.argv[2])
    files = sorted(templates.glob("*.json"))
    if not files:
        fail("no profile templates found")
    validated = []
    for path in files:
        result = subprocess.run([str(binary), "validate", str(path), "--mode", "strict"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            fail(f"{path.name} failed strict profile validation:\n{result.stdout}\n{result.stderr}")
        p = json.loads(path.read_text())
        validated.append(path.name)
        for cfg in p.get("configurations", []):
            cv = cfg.get("bConfigurationValue", 1)
            for iface in cfg.get("interfaces", []):
                extra = bytes.fromhex(iface.get("extra_descriptors_hex", ""))
                off = 0
                while off + 2 <= len(extra):
                    length = extra[off]
                    if length < 2 or off + length > len(extra):
                        fail(f"{path.name}: malformed interface extra descriptor framing")
                    dtype = extra[off + 1]
                    if dtype == 0x21:
                        if length < 9:
                            fail(f"{path.name}: HID descriptor shorter than 9 bytes")
                        report_len = extra[off + 7] | (extra[off + 8] << 8)
                        report = report_for(p, cv, iface.get("bInterfaceNumber", 0))
                        if report is None:
                            fail(f"{path.name}: HID interface {iface.get('bInterfaceNumber')} has no report descriptor")
                        if len(report) != report_len:
                            fail(f"{path.name}: HID interface report descriptor length is {len(report)}, descriptor says {report_len}")
                    off += length
        runtime=p.get("runtime", {})
        if runtime.get("mass_storage", {}).get("enabled"):
            if not any(i.get("bInterfaceClass")==8 and any((e.get("bEndpointAddress",0)&0x80) for e in i.get("endpoints",[])) and any(not (e.get("bEndpointAddress",0)&0x80) for e in i.get("endpoints",[])) for c in p.get("configurations",[]) for i in c.get("interfaces",[])):
                fail(f"{path.name}: enabled MSC BOT runtime has no bulk IN/OUT interface")
    print(f"Validated {len(validated)} profile templates and HID report descriptor lengths.")
    print("Profiles:")
    for name in validated:
        print("  " + name)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
