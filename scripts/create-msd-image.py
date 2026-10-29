#!/usr/bin/env python3
"""Create a partitioned file-backed block image for the USB MSC BOT test profile."""
from __future__ import annotations
import argparse
import shutil
import struct
import subprocess
import sys
from pathlib import Path

SECTOR_SIZE = 512
FIRST_PARTITION_SECTOR = 2048  # 1 MiB alignment


def create_mbr(path: Path, total_sectors: int) -> None:
    if total_sectors <= FIRST_PARTITION_SECTOR + 4096:
        raise ValueError("image is too small for the aligned partition and FAT16 volume")
    partition_sectors = total_sectors - FIRST_PARTITION_SECTOR
    if partition_sectors > 0xFFFFFFFF:
        raise ValueError("image is too large for an MBR partition")
    mbr = bytearray(SECTOR_SIZE)
    entry_offset = 446
    # LBA values are authoritative. Saturated CHS values are used for compatibility.
    mbr[entry_offset + 0] = 0x00  # non-bootable
    mbr[entry_offset + 1:entry_offset + 4] = b"\xfe\xff\xff"
    mbr[entry_offset + 4] = 0x06  # FAT16 partition type
    mbr[entry_offset + 5:entry_offset + 8] = b"\xfe\xff\xff"
    struct.pack_into("<II", mbr, entry_offset + 8, FIRST_PARTITION_SECTOR, partition_sectors)
    mbr[510:512] = b"\x55\xaa"
    with path.open("r+b") as f:
        f.seek(0)
        f.write(mbr)
        f.flush()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default="runs/storage/usb-lab.img", help="backing file path")
    ap.add_argument("--size-mib", type=int, default=64, help="whole image size in MiB (default: 64)")
    ap.add_argument("--format-vfat", action="store_true", help="format the MBR partition as FAT16 (requires dosfstools with --offset support)")
    ap.add_argument("--force", action="store_true", help="replace an existing image file")
    args = ap.parse_args()
    if args.size_mib < 8 or args.size_mib > 2048:
        ap.error("--size-mib must be between 8 and 2048 MiB")
    path = Path(args.path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not args.force:
        print(f"ERROR: {path} already exists; use --force to replace it", file=sys.stderr)
        return 2

    mkfs = None
    if args.format_vfat:
        mkfs = shutil.which("mkfs.vfat") or shutil.which("mkfs.fat") or shutil.which("mkdosfs")
        if not mkfs:
            print("ERROR: mkfs.vfat not found. Install dosfstools or omit --format-vfat.", file=sys.stderr)
            return 2

    total_sectors = args.size_mib * 1024 * 1024 // SECTOR_SIZE
    created = False
    try:
        with path.open("wb") as f:
            f.truncate(args.size_mib * 1024 * 1024)
        created = True
        create_mbr(path, total_sectors)
        if args.format_vfat:
            # Format the partition starting at LBA 2048; the MBR remains at LBA 0.
            subprocess.run([mkfs, "-F", "16", "-n", "USBLAB", f"--offset={FIRST_PARTITION_SECTOR}", str(path)], check=True)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        if created:
            print(f"ERROR: image creation/formatting failed; partial file remains at {path}: {exc}", file=sys.stderr)
        else:
            print(f"ERROR: cannot create image: {exc}", file=sys.stderr)
        return 1

    print(f"Created image: {path}")
    print(f"Whole image size: {args.size_mib} MiB; sector size: 512 bytes; sectors: {total_sectors}")
    print(f"MBR partition: start LBA {FIRST_PARTITION_SECTOR}, sectors {total_sectors - FIRST_PARTITION_SECTOR}, type FAT16 (0x06)")
    if args.format_vfat:
        print("Filesystem: FAT16, label USBLAB")
    else:
        print("Filesystem is not formatted. The host may ask to format it; for a FAT16 filesystem, install dosfstools and use --format-vfat.")
    print("Do not mount/edit this backing file on Linux while the USB host has the disk connected.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
