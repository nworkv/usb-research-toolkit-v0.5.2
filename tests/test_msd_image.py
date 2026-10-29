#!/usr/bin/env python3
"""Smoke-test backing-image creation without requiring mkfs.vfat."""
from __future__ import annotations
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

script = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="usb-msd-test-") as temp:
    image = Path(temp) / "test.img"
    first = subprocess.run([sys.executable, str(script), "--path", str(image), "--size-mib", "8"],
                           text=True, capture_output=True)
    if first.returncode != 0:
        raise SystemExit(f"image creation failed:\n{first.stdout}\n{first.stderr}")
    data = image.read_bytes()[:512]
    if data[510:512] != b"\x55\xaa":
        raise SystemExit("MBR signature is missing")
    entry = data[446:462]
    if entry[4] != 0x06:
        raise SystemExit(f"unexpected partition type: {entry[4]:#x}")
    start, size = struct.unpack_from("<II", entry, 8)
    total_sectors = (8 * 1024 * 1024) // 512
    if start != 2048 or size != total_sectors - 2048:
        raise SystemExit(f"unexpected partition geometry: start={start}, size={size}")
    if image.stat().st_size != 8 * 1024 * 1024:
        raise SystemExit("image size is incorrect")
    duplicate = subprocess.run([sys.executable, str(script), "--path", str(image), "--size-mib", "8"],
                               text=True, capture_output=True)
    if duplicate.returncode != 2:
        raise SystemExit("existing image must not be overwritten without --force")
print("msd image tests passed")
