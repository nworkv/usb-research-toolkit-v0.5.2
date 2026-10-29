#!/usr/bin/env python3
"""Watch the Raspberry Pi Wireshark SMB share and index completed capture files.

No software/agent is required on the test host beyond Wireshark/USBPcap.
This script runs on the Raspberry Pi and invokes tshark installed there.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

CAPTURE_SUFFIXES = {".pcapng", ".pcap"}
EVENT_PATTERNS = re.compile(r"\b(reset|disconnect(?:ed)?|stall|timed?\s*out|timeout|error|failed|not responding|enumerat(?:ion|e))\b", re.I)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_tshark_output(text: str) -> dict:
    """Summarize tab-separated frame number, epoch, protocol and info fields."""
    frame_count = 0
    first_epoch = None
    last_epoch = None
    notable = []
    for line in text.splitlines():
        parts = line.split("\t", 3)
        if not parts or not parts[0].strip().isdigit():
            continue
        frame_count += 1
        if len(parts) > 1 and parts[1].strip():
            try:
                epoch = float(parts[1])
                first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
                last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
            except ValueError:
                pass
        protocol = parts[2].strip() if len(parts) > 2 else ""
        info = parts[3].strip() if len(parts) > 3 else ""
        if EVENT_PATTERNS.search(f"{protocol} {info}") and len(notable) < 500:
            notable.append({"frame": int(parts[0]), "protocol": protocol, "info": info[:1000]})
    return {"frame_count": frame_count, "first_frame_epoch": first_epoch,
            "last_frame_epoch": last_epoch, "notable_usb_or_transport_lines": notable}


def analyze_capture(path: Path, tshark: str) -> dict:
    result = {"capture": path.name, "processed_at": datetime.now(timezone.utc).isoformat(),
              "file_size": path.stat().st_size, "sha256": sha256_file(path),
              "classification": "CAPTURE_ANALYZED_NOT_OS_CRASH_PROOF"}
    command = [tshark, "-r", str(path), "-T", "fields", "-E", "separator=/t",
               "-E", "quote=n", "-e", "frame.number", "-e", "frame.time_epoch",
               "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"]
    try:
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=180, check=False)
        result.update(parse_tshark_output(proc.stdout))
        result["tshark_returncode"] = proc.returncode
        if proc.stderr.strip(): result["tshark_stderr"] = proc.stderr[-4000:]
        if proc.returncode != 0:
            result["analysis_warning"] = "tshark reported an error; capture may be incomplete or unsupported"
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["analysis_error"] = str(exc)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Индексирует Wireshark PCAP/PCAPNG на Raspberry Pi")
    ap.add_argument("--watch-dir", required=True, help="каталог SMB share на Raspberry Pi")
    ap.add_argument("--out-dir", default="runs/wireshark-analysis")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--poll-seconds", type=float, default=2.0)
    ap.add_argument("--stable-seconds", type=float, default=15.0,
                    help="сколько секунд размер файла должен быть неизменным перед анализом")
    ap.add_argument("--once", action="store_true", help="обработать стабильные файлы и выйти")
    args = ap.parse_args()
    watch_dir = Path(args.watch_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    if not watch_dir.is_dir():
        ap.error(f"watch directory does not exist: {watch_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    index_path = out_dir / "capture-index.jsonl"
    seen = set()
    if index_path.exists():
        for line in index_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try: seen.add(json.loads(line)["sha256"])
            except (ValueError, KeyError): pass
    observed = {}
    print(f"Watching {watch_dir}; output={out_dir}; Ctrl+C to stop", flush=True)
    while True:
        candidates = sorted(p for p in watch_dir.iterdir() if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES)
        now = time.monotonic()
        for path in candidates:
            try:
                stat = path.stat()
                previous = observed.get(str(path))
                if previous is None:
                    # In one-shot mode, files already older than the settle interval
                    # are treated as stable; in watch mode begin observing them now.
                    if args.once and (time.time() - stat.st_mtime) >= args.stable_seconds:
                        observed[str(path)] = (stat.st_size, stat.st_mtime_ns, now - args.stable_seconds)
                        previous = observed[str(path)]
                    else:
                        observed[str(path)] = (stat.st_size, stat.st_mtime_ns, now)
                        continue
                if previous[0] != stat.st_size or previous[1] != stat.st_mtime_ns:
                    observed[str(path)] = (stat.st_size, stat.st_mtime_ns, now)
                    continue
                if now - previous[2] < args.stable_seconds or stat.st_size == 0:
                    continue
                digest = sha256_file(path)
                if digest in seen:
                    continue
                # Re-stat after hashing to avoid analyzing a file that changed during the read.
                after = path.stat()
                if after.st_size != stat.st_size or after.st_mtime_ns != stat.st_mtime_ns:
                    observed[str(path)] = (after.st_size, after.st_mtime_ns, now)
                    continue
                result = analyze_capture(path, args.tshark)
                result["sha256"] = digest
                result["source_path"] = str(path)
                result["warning"] = "USB capture symptoms are not proof of an operating-system crash. Wireshark capture alone cannot read Windows Event Log or prove BSOD/kernel panic."
                out_name = path.name + ".analysis.json"
                (out_dir / out_name).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                with index_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(result, ensure_ascii=False) + "\n")
                seen.add(digest)
                print(f"Analyzed {path.name}: frames={result.get('frame_count', '?')} sha256={digest[:12]}", flush=True)
            except (OSError, PermissionError) as exc:
                print(f"Waiting for {path.name}: {exc}", file=sys.stderr, flush=True)
        if args.once:
            return 0
        time.sleep(max(0.5, args.poll_seconds))

if __name__ == "__main__":
    raise SystemExit(main())
