#!/usr/bin/env python3
"""Sequential, bounded Raw Gadget USB profile fuzz campaign runner.

Runs on the Raspberry Pi only. Each profile is attached for a bounded dwell
period, then SIGINT is sent so Raw Gadget can detach and flush its trace.
The Windows host is expected to run Wireshark/USBPcap separately.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REVIEW_PATTERN = re.compile(
    r"\b(reset|disconnect|stall|timed?\s*out|timeout|error|failed|malformed|invalid|not responding|enumeration failed|urb status)\b",
    re.IGNORECASE,
)

ROOT = Path(__file__).resolve().parents[1]
FUZZ_SCRIPT = ROOT / "scripts" / "usb-fuzz.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_fuzzer():
    spec = importlib.util.spec_from_file_location("usb_fuzz_module", FUZZ_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load mutator: {FUZZ_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_usb_connect() -> Path:
    candidates = [
        ROOT / "build" / "usb-connect",
        ROOT / "build" / "Release" / "usb-connect",
        ROOT / "build" / "Debug" / "usb-connect",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("usb-connect")
    if found:
        return Path(found)
    raise RuntimeError(
        "не найден usb-connect. Сначала выполните: "
        "sudo python3 scripts/usb-lab.py build"
    )


def capture_snapshot(directory: Path | None) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    if directory is None or not directory.is_dir():
        return snapshot
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng"):
            try:
                st = path.stat()
                snapshot[str(path.resolve())] = {
                    "size_bytes": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                }
            except OSError:
                continue
    return snapshot


def capture_delta(before: dict[str, dict[str, Any]],
                  after: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    changed = []
    for path, current in after.items():
        previous = before.get(path)
        if previous != current:
            changed.append({
                "path": path,
                "size_before": previous["size_bytes"] if previous else None,
                "size_after": current["size_bytes"],
                "mtime_ns": current["mtime_ns"],
                "new_file": previous is None,
            })
    return changed


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def terminate_process(proc: subprocess.Popen[str], grace: float) -> tuple[str, int | None]:
    """Ask usb-connect to detach cleanly; escalate only if it ignores SIGINT."""
    if proc.poll() is not None:
        return "already_exited", proc.returncode
    try:
        proc.send_signal(signal.SIGINT)
    except ProcessLookupError:
        return "already_exited", proc.poll()
    try:
        return "sigint", proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            return "sigterm", proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
            return "sigkill", proc.wait(timeout=grace)



DESCRIPTOR_NAMES = {
    1: "Device", 2: "Configuration", 3: "String", 4: "Interface",
    5: "Endpoint", 6: "Device Qualifier", 7: "Other-speed Configuration",
    15: "BOS", 33: "HID", 34: "HID Report", 35: "Physical",
    48: "SuperSpeed Endpoint Companion",
}
REQUEST_NAMES = {
    0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE",
    5: "SET_ADDRESS", 6: "GET_DESCRIPTOR", 8: "GET_CONFIGURATION",
    9: "SET_CONFIGURATION", 10: "GET_INTERFACE", 11: "SET_INTERFACE",
}

def describe_control_request(request: dict[str, Any]) -> str:
    req = int(request.get("bRequest", -1))
    name = REQUEST_NAMES.get(req, f"bRequest={req}")
    value = int(request.get("wValue", 0))
    length = int(request.get("wLength", 0))
    index = int(request.get("wIndex", 0))
    if req == 6:
        dtype, dindex = (value >> 8) & 0xff, value & 0xff
        desc = DESCRIPTOR_NAMES.get(dtype, f"type 0x{dtype:02x}")
        return f"GET_DESCRIPTOR({desc}, index={dindex}, wLength={length}, wIndex=0x{index:04x})"
    if req == 9:
        return f"SET_CONFIGURATION(value={value & 0xff})"
    if req == 5:
        return f"SET_ADDRESS(value={value & 0x7f})"
    if req == 11:
        return f"SET_INTERFACE(interface={index}, alternate={value})"
    return f"{name}(wValue=0x{value:04x}, wIndex=0x{index:04x}, wLength={length})"

class LiveTraceProgress:
    """Incrementally read Raw Gadget JSONL events and explain them to the operator."""
    def __init__(self, trace_path: Path):
        self.path = trace_path
        self.offset = 0
        self.pending = b""
        self.started = time.monotonic()
        self.events: dict[str, int] = {}
        self.host_requests = 0
        self.responses = 0
        self.stalls = 0
        self.configurations = 0
        self.configuration_value = 0
        self.resets = 0
        self.suspends = 0
        self.disconnects = 0
        self.errors = 0
        self.udc_connect_event = False

    def poll(self) -> None:
        try:
            with self.path.open("rb") as stream:
                stream.seek(self.offset)
                chunk = stream.read()
                self.offset = stream.tell()
        except OSError:
            return
        if not chunk:
            return
        self.pending += chunk
        lines = self.pending.split(b"\n")
        self.pending = lines.pop()
        for raw in lines:
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8", errors="replace"))
            except (ValueError, UnicodeDecodeError):
                continue
            self.consume(event)

    def consume(self, event: dict[str, Any]) -> None:
        name = str(event.get("event", "UNKNOWN"))
        self.events[name] = self.events.get(name, 0) + 1
        elapsed = time.monotonic() - self.started
        detail = ""
        if name == "BACKEND_STARTING":
            detail = "подготовка Raw Gadget"
        elif name == "BACKEND_RUNNING":
            detail = "Raw Gadget запущен; ожидаю запросы USB-хоста"
        elif name == "UDC_BOUND":
            self.udc_connect_event = True
            detail = "UDC сообщил событие CONNECT (это ещё не означает, что хост завершил enumeration)"
        elif name == "ENDPOINT_CAPABILITIES":
            endpoints = event.get("endpoints", [])
            detail = f"обнаружены возможности endpoint: {len(endpoints) if isinstance(endpoints, list) else '?'}"
        elif name == "CONTROL_REQUEST":
            self.host_requests += 1
            request = event.get("request") or {}
            detail = "ХОСТ → " + describe_control_request(request)
        elif name == "CONTROL_RESPONSE_COMPLETE":
            self.responses += 1
            request = event.get("request") or {}
            length = event.get("actual_length", "?")
            detail = f"ответ EP0 завершён, длина={length} байт; " + describe_control_request(request)
        elif name == "CONTROL_OUT_COMPLETE":
            request = event.get("request") or {}
            detail = "управляющая передача OUT завершена: " + describe_control_request(request)
        elif name == "SET_CONFIGURATION":
            self.configuration_value = int(event.get("configuration_value", 0) or 0)
            if self.configuration_value:
                self.configurations += 1
                detail = f"SET_CONFIGURATION: хост установил конфигурацию {self.configuration_value}; enumeration дошёл до CONFIGURED"
            else:
                detail = "хост сбросил конфигурацию (value=0)"
        elif name == "SET_ADDRESS_OBSERVED":
            detail = f"хост назначил USB-адрес {event.get('address', '?')}"
        elif name == "CONTROL_STALL":
            self.stalls += 1
            req = event.get("request") or {}
            detail = "STALL: устройство не предоставило ответ на " + describe_control_request(req)
        elif name in ("USB_RESET", "USB_RESET_OR_DISCONNECT"):
            self.resets += 1
            detail = "USB reset или неоднозначное reset/disconnect; требуется оценка контекста"
        elif name == "USB_SUSPEND":
            self.suspends += 1
            detail = "USB вошёл в suspend (само по себе не ошибка)"
        elif name == "USB_RESUME":
            detail = "USB вышел из suspend"
        elif name == "BACKEND_STOPPED":
            detail = "Raw Gadget остановлен и отсоединён"
        elif "DISCONNECT" in name:
            self.disconnects += 1
            detail = "событие отключения от UDC; причина требует проверки"
        elif "ERROR" in name or "MALFORMED" in name:
            self.errors += 1
            detail = str(event.get("message") or event.get("error") or event.get("reason") or name)
        elif name == "DEVICE_IN_TRANSFER_COMPLETE":
            detail = f"IN-передача завершена: endpoint=0x{int(event.get('endpoint_address', 0)):02x}, bytes={event.get('actual_length', '?')}"
        elif name == "DEVICE_OUT_TRANSFER_RECEIVED":
            detail = f"OUT-передача получена: endpoint=0x{int(event.get('endpoint_address', 0)):02x}, bytes={event.get('actual_length', '?')}"
        elif name == "ENDPOINT_ENABLED":
            detail = f"endpoint включён: 0x{int(event.get('endpoint_address', 0)):02x}, max_packet={event.get('max_packet_size', '?')}"
        elif name == "ENDPOINT_IO_UNSUPPORTED":
            detail = str(event.get("reason", name))

        # Emit operator-relevant lifecycle / USB events only; every event still
        # remains available in the complete JSONL trace.
        if detail:
            label = "ОШИБКА" if ("ERROR" in name or "MALFORMED" in name or name == "CONTROL_STALL") else "USB"
            print(f"    [+{elapsed:6.2f}s] [{label}] {detail}", flush=True)

    def summary(self) -> dict[str, Any]:
        return {
            "events_by_type": dict(sorted(self.events.items())),
            "host_control_requests": self.host_requests,
            "control_responses_complete": self.responses,
            "control_stalls": self.stalls,
            "configuration_set_count": self.configurations,
            "configuration_value": self.configuration_value,
            "host_contact_observed": self.host_requests > 0,
            "udc_connect_event_observed": self.udc_connect_event,
            "configured_observed": self.configurations > 0 and self.configuration_value > 0,
            "usb_reset_events": self.resets,
            "usb_suspend_events": self.suspends,
            "usb_disconnect_events": self.disconnects,
            "backend_error_events": self.errors,
        }

def print_case_changes(case: dict[str, Any], profile: Path) -> None:
    try:
        data = json.loads(profile.read_text(encoding="utf-8"))
        name = data.get("profile_name", profile.stem) if isinstance(data, dict) else profile.stem
    except (OSError, json.JSONDecodeError):
        name = profile.stem
    print(f"  Устройство-профиль: {name}", flush=True)
    print(f"  JSON: {profile}", flush=True)
    digest = case.get("sha256")
    if digest:
        print(f"  SHA-256: {digest}", flush=True)
    changes = case.get("changes") or []
    if changes:
        print(f"  Изменённые параметры ({len(changes)}):", flush=True)
        for change in changes:
            print(f"    • {change}", flush=True)
    else:
        print("  Изменения: в манифесте не зарегистрированы (проверь manifest.json для replay/старой кампании).", flush=True)

def print_case_outcome(row: dict[str, Any]) -> None:
    stats = row.get("trace_summary", {})
    status = row.get("status", "UNKNOWN")
    if status == "COMPLETED":
        print("  ИТОГ: процесс Gadget отработал запрошенное время; это не означает, что Windows приняла устройство.", flush=True)
    elif status == "START_FAILED":
        print("  ИТОГ: START_FAILED — процесс быстро завершился; смотри stderr.log.", flush=True)
    elif status == "DEVICE_EXITED_EARLY":
        print("  ИТОГ: Gadget завершился раньше заданного времени.", flush=True)
    elif status == "STOP_ERROR":
        print("  ИТОГ: ошибка остановки процесса Gadget.", flush=True)
    elif status == "INTERRUPTED":
        print("  ИТОГ: запуск прерван пользователем.", flush=True)
    elif status == "LAUNCH_ERROR":
        print("  ИТОГ: не удалось запустить usb-connect.", flush=True)
    print(
        "  USB-сводка: "
        f"запросы хоста={stats.get('host_control_requests', 0)}, "
        f"завершённые ответы EP0={stats.get('control_responses_complete', 0)}, "
        f"SET_CONFIGURATION={('ДА' if stats.get('configured_observed') else 'НЕ ЗАФИКСИРОВАНО')}, "
        f"STALL={stats.get('control_stalls', 0)}, "
        f"reset={stats.get('usb_reset_events', 0)}, "
        f"backend errors={stats.get('backend_error_events', 0)}", flush=True
    )
    if stats.get("configured_observed"):
        print("  ПОДКЛЮЧЕНИЕ: в trace подтверждено состояние CONFIGURED (SET_CONFIGURATION с ненулевым значением).", flush=True)
    elif stats.get("host_contact_observed"):
        print("  ПОДКЛЮЧЕНИЕ: хост обменивался управляющими запросами, но CONFIGURED не зафиксирован; enumeration мог остановиться.", flush=True)
    elif stats.get("udc_connect_event_observed"):
        print("  ПОДКЛЮЧЕНИЕ: UDC сообщил CONNECT, но запросов USB-хоста в trace не обнаружено.", flush=True)
    else:
        print("  ПОДКЛЮЧЕНИЕ: контакт хоста не подтверждён trace.", flush=True)
    if stats.get("control_stalls") or stats.get("backend_error_events"):
        print("  ОШИБКИ/ОТКЛОНЕНИЯ: есть STALL и/или события ошибки; это не автоматически означает сбой Windows.", flush=True)
    else:
        print("  ОШИБКИ BACKEND: в trace не зафиксированы. Это не утверждение об отсутствии ошибок Windows.", flush=True)
    if row.get("capture_files_changed"):
        print("  Файлы PCAP изменялись во время этого случая:", flush=True)
        for item in row["capture_files_changed"]:
            print(f"    {item.get('path')} ({item.get('size_before')} -> {item.get('size_after')} байт)", flush=True)
    elif row.get("capture_dir"):
        print("  PCAP: изменения файлов во время случая не замечены; это не доказывает отсутствие трафика (Wireshark может обновить файл после Stop/Save).", flush=True)
    print(f"  Trace: {row.get('trace')}", flush=True)
    print(f"  stdout: {row.get('stdout_log')}", flush=True)
    print(f"  stderr: {row.get('stderr_log')}", flush=True)


def run_case(binary: Path, profile: Path, case_no: int, args: argparse.Namespace,
             out: Path, capture_dir: Path | None,
             changes: list[str] | None = None) -> dict[str, Any]:
    trace_dir = out / "traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"case-{case_no:05d}.device.jsonl"
    stdout_path = trace_dir / f"case-{case_no:05d}.stdout.log"
    stderr_path = trace_dir / f"case-{case_no:05d}.stderr.log"
    run_id = f"{args.run_id}-case-{case_no:05d}"
    command = [
        str(binary), "run", str(profile),
        "--backend", "raw-gadget",
        "--udc-driver", args.udc_driver,
        "--udc-device", args.udc_device,
        "--speed", args.speed,
        "--trace", str(trace_path),
        "--run-id", run_id,
    ]
    if args.allow_research:
        command.append("--allow-research")

    row: dict[str, Any] = {
        "case": case_no,
        "started_epoch": time.time(),
        "profile": str(profile.resolve()),
        "profile_sha256": sha256(profile),
        "run_id": run_id,
        "command": command,
        "started_at": utc_now(),
        "status": "STARTING",
        "dwell_seconds_requested": args.dwell_seconds,
        "trace": str(trace_path),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }
    row["changes"] = list(changes or [])
    row["capture_dir"] = str(capture_dir) if capture_dir else None
    progress = LiveTraceProgress(trace_path)
    before_capture = capture_snapshot(capture_dir)
    start = time.monotonic()

    with stdout_path.open("w", encoding="utf-8") as stdout, \
         stderr_path.open("w", encoding="utf-8") as stderr:
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(ROOT),
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            row.update(status="LAUNCH_ERROR", error=str(exc))
            row["ended_at"] = utc_now()
            row["duration_seconds"] = round(time.monotonic() - start, 3)
            row["capture_files_changed"] = capture_delta(before_capture, capture_snapshot(capture_dir))
            return row

        row["pid"] = proc.pid
        # Wait briefly to distinguish a failed validation/backend startup from a live device.
        startup_deadline = time.monotonic() + args.startup_grace
        try:
            while proc.poll() is None and time.monotonic() < startup_deadline:
                progress.poll()
                time.sleep(min(0.1, max(0.0, startup_deadline - time.monotonic())))
            progress.poll()
        except KeyboardInterrupt:
            row["interrupted_by_user"] = True
            stop_method, returncode = terminate_process(proc, args.stop_grace)
            row.update(status="INTERRUPTED", stop_method=stop_method, returncode=returncode)

        if row.get("status") == "INTERRUPTED":
            pass
        elif proc.poll() is not None:
            row.update(status="START_FAILED", returncode=proc.returncode)
        else:
            row["status"] = "RUNNING"
            row["device_started_at"] = utc_now()
            deadline = time.monotonic() + args.dwell_seconds
            next_live_status = (time.monotonic() + args.live_progress_interval
                                if args.live_progress_interval > 0 else float("inf"))
            try:
                while proc.poll() is None and time.monotonic() < deadline:
                    progress.poll()
                    now = time.monotonic()
                    if args.live_progress_interval > 0 and now >= next_live_status:
                        elapsed = args.dwell_seconds - max(0.0, deadline - now)
                        configured = "ДА" if progress.configurations > 0 and progress.configuration_value > 0 else "пока нет"
                        print(
                            f"    [LIVE] Gadget работает {min(args.dwell_seconds, elapsed):.1f}/{args.dwell_seconds:.1f} с; "
                            f"запросы хоста={progress.host_requests}; конфигурация={configured}", flush=True
                        )
                        next_live_status = now + args.live_progress_interval
                    time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            except KeyboardInterrupt:
                row["interrupted_by_user"] = True
            if proc.poll() is None:
                stop_method, returncode = terminate_process(proc, args.stop_grace)
                row["stop_method"] = stop_method
                row["returncode"] = returncode
                row["status"] = "INTERRUPTED" if row.get("interrupted_by_user") else ("COMPLETED" if returncode == 0 else "STOP_ERROR")
            else:
                row.update(status="DEVICE_EXITED_EARLY", returncode=proc.returncode)

    # Drain final trace events written immediately before process exit.
    for _ in range(3):
        progress.poll()
        time.sleep(0.02)
    row["trace_summary"] = progress.summary()
    row["ended_epoch"] = time.time()
    row["ended_at"] = utc_now()
    row["duration_seconds"] = round(time.monotonic() - start, 3)
    row["trace_exists"] = trace_path.exists()
    row["trace_bytes"] = trace_path.stat().st_size if trace_path.exists() else 0
    row["capture_files_changed"] = capture_delta(before_capture, capture_snapshot(capture_dir))
    if stderr_path.exists():
        try:
            row["stderr_tail"] = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            pass
    return row



def analyze_campaign_captures(capture_dir: Path | None, rows: list[dict[str, Any]],
                              tshark_name: str, out: Path) -> list[dict[str, Any]]:
    """Use tshark on Wireshark/USBPcap files and build a conservative manual-review queue.

    Timestamp correlation assumes Pi and Windows clocks are reasonably synchronized.
    It does not claim to prove that every transmitted byte matched the intended profile.
    """
    queue: list[dict[str, Any]] = []
    if capture_dir is None:
        for row in rows:
            if row.get("status") in ("COMPLETED", "STOP_ERROR", "DEVICE_EXITED_EARLY", "START_FAILED"):
                queue.append({"case": row.get("case"), "profile": row.get("profile"),
                              "profile_sha256": row.get("profile_sha256"),
                              "reasons": ["CAPTURE_DIR_NOT_CONFIGURED"],
                              "capture_files": [], "status": "REVIEW_REQUIRED"})
        return queue

    captures = sorted(p for p in capture_dir.iterdir()
                      if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng"))
    tshark = shutil.which(tshark_name) if not Path(tshark_name).is_file() else tshark_name
    frames: list[dict[str, Any]] = []
    tshark_error = None
    if not captures:
        tshark_error = "NO_PCAP_OR_PCAPNG_FOUND"
    elif not tshark:
        tshark_error = "TSHARK_NOT_FOUND"
    else:
        for cap in captures:
            cmd = [str(tshark), "-r", str(cap), "-T", "fields", "-E", "separator=/t",
                   "-E", "quote=n", "-e", "frame.number", "-e", "frame.time_epoch",
                   "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"]
            try:
                proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=300, check=False)
                if proc.returncode != 0:
                    tshark_error = f"TSHARK_FAILED:{cap.name}:{proc.stderr[-500:]}"
                for line in proc.stdout.splitlines():
                    parts = line.split("\t", 3)
                    if len(parts) < 2:
                        continue
                    try:
                        frame_no = int(parts[0]); epoch = float(parts[1])
                    except ValueError:
                        continue
                    frames.append({"capture": str(cap.resolve()), "frame": frame_no,
                                   "epoch": epoch, "protocol": parts[2] if len(parts) > 2 else "",
                                   "info": parts[3] if len(parts) > 3 else ""})
            except (OSError, subprocess.TimeoutExpired) as exc:
                tshark_error = f"TSHARK_ERROR:{cap.name}:{exc}"

    for row in rows:
        status = row.get("status")
        # Startup failures are not host findings, but must remain visible for triage.
        if status == "START_FAILED":
            queue.append({"case": row.get("case"), "profile": row.get("profile"),
                          "profile_sha256": row.get("profile_sha256"),
                          "run_id": row.get("run_id"),
                          "reasons": ["GADGET_START_FAILED", "NO_HOST_REACTION_OBSERVED"],
                          "capture_files": [], "matched_frame_count": 0,
                          "stderr_excerpt": str(row.get("stderr_tail", ""))[-2000:],
                          "status": "REVIEW_REQUIRED"})
            continue
        if status not in ("COMPLETED", "STOP_ERROR", "DEVICE_EXITED_EARLY"):
            continue
        start = row.get("started_epoch")
        end = row.get("ended_epoch")
        reasons: list[str] = []
        matched = []
        if tshark_error:
            reasons.append(tshark_error)
        elif isinstance(start, (int, float)) and isinstance(end, (int, float)):
            # Small margin compensates for scheduling and timestamp rounding, but clock skew
            # between Pi and Windows can still make this correlation inconclusive.
            matched = [f for f in frames if start - 1.0 <= f["epoch"] <= end + 1.0]
            if not matched:
                reasons.append("NO_CAPTURE_FRAMES_IN_CASE_WINDOW")
            for f in matched:
                label = f'{f["protocol"]} {f["info"]}'.strip()
                if re.search(r"malformed|invalid|undecoded", label, re.I):
                    reasons.append("POSSIBLE_DECODE_OR_DESCRIPTOR_MISMATCH")
                    break
                if REVIEW_PATTERN.search(label):
                    reasons.append("WIRESHARK_ANOMALY_TEXT")
                    break
            # If capture contains no USB-ish protocol/info lines, don't treat it as verified.
            if matched and not any(re.search(r"usb|urb|device descriptor|configuration descriptor|interface descriptor|endpoint descriptor", f'{f["protocol"]} {f["info"]}', re.I) for f in matched):
                reasons.append("USB_ACTIVITY_NOT_IDENTIFIED_IN_CAPTURE")
        else:
            reasons.append("CASE_TIMESTAMPS_UNAVAILABLE")
        if reasons:
            queue.append({"case": row.get("case"), "profile": row.get("profile"),
                          "profile_sha256": row.get("profile_sha256"),
                          "run_id": row.get("run_id"), "reasons": sorted(set(reasons)),
                          "capture_files": sorted(set(f["capture"] for f in matched)),
                          "matched_frame_count": len(matched),
                          "status": "REVIEW_REQUIRED"})
    return queue


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Последовательная кампания USB profile fuzzing для Raw Gadget на Raspberry Pi"
    )
    parser.add_argument("--base", required=True, help="базовый JSON-профиль")
    parser.add_argument("--count", type=int, default=5, help="число вариантов (1..1000)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--mutations", type=int, default=1)
    parser.add_argument("--out-dir", default="runs/fuzz/auto-campaign")
    parser.add_argument("--udc-driver", required=True)
    parser.add_argument("--udc-device", required=True)
    parser.add_argument("--speed", choices=("high", "full", "low"), default="high")
    parser.add_argument("--dwell-seconds", type=float, default=10.0,
                        help="сколько держать каждый профиль подключённым")
    parser.add_argument("--startup-grace", type=float, default=2.0,
                        help="сколько ждать, чтобы определить ошибку старта")
    parser.add_argument("--stop-grace", type=float, default=5.0,
                        help="тайм-аут чистой остановки после SIGINT")
    parser.add_argument("--settle-seconds", type=float, default=2.0,
                        help="пауза между случаями для USB/host стабилизации")
    parser.add_argument("--live-progress-interval", type=float, default=2.0,
                        help="частота строки LIVE-прогресса во время каждого случая; 0 отключает строки LIVE")
    parser.add_argument("--capture-dir", help="необязательно: каталог PCAPNG на Pi/SMB-шаре")
    parser.add_argument("--run-id", default="usb-fuzz")
    parser.add_argument("--allow-research", action="store_true",
                        help="разрешить профили validation.mode=research")
    parser.add_argument("--stop-on-error", action="store_true",
                        help="остановить кампанию после ошибки запуска (по умолчанию продолжать)" )
    parser.add_argument("--confirm-lab", action="store_true",
                        help="подтвердить, что подключён только собственный изолированный тестовый хост")
    parser.add_argument("--dry-run", action="store_true",
                        help="создать профили и план без запуска USB Gadget")
    parser.add_argument("--tshark", default="tshark", help="путь к tshark для анализа PCAPNG")
    parser.add_argument("--replay-from", help="каталог предыдущей кампании с case-NNNNN.json")
    parser.add_argument("--replay-case", type=int, help="повторить один case по номеру из --replay-from")
    args = parser.parse_args()

    if not args.udc_driver.strip():
        parser.error("--udc-driver пустой. Выполните `sudo build/usb-connect probe` и передайте имя драйвера, например 'fe980000.usb'; не используйте пустую shell-переменную.")
    if not args.udc_device.strip():
        parser.error("--udc-device пустой. Выполните `sudo build/usb-connect probe` и передайте имя UDC, например 'fe980000.usb'; не используйте пустую shell-переменную.")
    if bool(args.replay_from) != bool(args.replay_case):
        parser.error("--replay-from и --replay-case нужно указывать вместе")
    if args.replay_case is not None and args.replay_case < 1:
        parser.error("--replay-case должен быть >= 1")
    if not args.confirm_lab and not args.dry_run:
        parser.error("для реального запуска обязателен --confirm-lab")
    if not args.allow_research and not args.dry_run:
        parser.error("мутации помечены validation.mode=research; для запуска добавьте --allow-research только в изолированной лаборатории")
    if args.count < 1 or args.count > 1000:
        parser.error("--count должен быть в диапазоне 1..1000")
    if args.dwell_seconds <= 0 or args.dwell_seconds > 600:
        parser.error("--dwell-seconds должен быть в диапазоне (0, 600]")
    if not 0 <= args.startup_grace <= 30 or not 0.1 <= args.stop_grace <= 30:
        parser.error("недопустимое значение startup/stop grace")
    if not 0 <= args.settle_seconds <= 60:
        parser.error("--settle-seconds должен быть в диапазоне 0..60")
    if not 0 <= args.live_progress_interval <= 60:
        parser.error("--live-progress-interval должен быть в диапазоне 0..60")
    if args.mutations < 1 or args.mutations > 100:
        parser.error("--mutations должен быть в диапазоне 1..100")
    if not platform.system().lower() == "linux":
        parser.error("реальная кампания запускается только на Raspberry Pi/Linux")
    if not args.dry_run:
        if os.geteuid() != 0:
            parser.error("запустите через sudo: Raw Gadget требует root-доступа")
        if not Path("/dev/raw-gadget").exists():
            parser.error("/dev/raw-gadget не найден; проверьте ядро/модуль Raw Gadget")
        if not Path("/sys/class/udc").exists() or not any(Path("/sys/class/udc").glob("*")):
            parser.error("UDC не обнаружен в /sys/class/udc")

    base = Path(args.base).resolve()
    if not base.is_file():
        parser.error(f"базовый профиль не найден: {base}")
    out = Path(args.out_dir).expanduser().resolve()
    if out.exists():
        if not out.is_dir():
            parser.error(f"--out-dir существует, но это не каталог: {out}")
        try:
            is_nonempty = next(out.iterdir(), None) is not None
        except OSError as exc:
            parser.error(f"не удалось проверить --out-dir {out}: {exc}")
        if is_nonempty:
            parser.error(f"--out-dir уже существует и не пуст: {out}. Выберите новый каталог (например, с датой/временем), чтобы не затереть прошлую кампанию.")
    out.mkdir(parents=True, exist_ok=True)
    capture_dir = Path(args.capture_dir).resolve() if args.capture_dir else None
    if capture_dir is not None and not capture_dir.is_dir():
        parser.error(f"--capture-dir не существует или не каталог: {capture_dir}")

    fuzzer = load_fuzzer()
    if args.replay_case is not None:
        replay_root = Path(args.replay_from).resolve()
        replay_profile = replay_root / f"case-{args.replay_case:05d}.json"
        if not replay_profile.is_file():
            parser.error(f"профиль для повтора не найден: {replay_profile}")
        try:
            profile_data = json.loads(replay_profile.read_text(encoding="utf-8"))
            if not isinstance(profile_data, dict) or "device" not in profile_data:
                parser.error(f"некорректный профиль для повтора: {replay_profile}")
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"не удалось прочитать профиль для повтора: {exc}")
        replay_changes: list[str] = []
        replay_manifest = replay_root / "manifest.json"
        if replay_manifest.is_file():
            try:
                saved_manifest = json.loads(replay_manifest.read_text(encoding="utf-8"))
                for saved_case in saved_manifest.get("cases", []):
                    if int(saved_case.get("case", -1)) == args.replay_case:
                        replay_changes = list(saved_case.get("changes") or [])
                        break
            except (OSError, ValueError, TypeError):
                pass
        cases = [{"case": args.replay_case, "profile": str(replay_profile),
                  "sha256": sha256(replay_profile), "changes": replay_changes, "status": "REPLAY"}]
    else:
        cases = fuzzer.generate(base, args.count, args.seed, out, args.mutations)
    campaign_log = out / "campaign.jsonl"
    summary_path = out / "summary.json"
    campaign_log.write_text("", encoding="utf-8")
    (out / "runner-config.json").write_text(json.dumps({
        "base": str(base),
        "base_sha256": sha256(base),
        "seed": args.seed,
        "count": args.count,
        "mutations_per_case": args.mutations,
        "dwell_seconds": args.dwell_seconds,
        "udc_driver": args.udc_driver,
        "udc_device": args.udc_device,
        "speed": args.speed,
        "run_id": args.run_id,
        "capture_dir": str(capture_dir) if capture_dir else None,
        "dry_run": args.dry_run,
        "replay_from": str(Path(args.replay_from).resolve()) if args.replay_from else None,
        "replay_case": args.replay_case,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.dry_run:
        plan = []
        for case in cases:
            plan.append({
                "case": case["case"],
                "profile": case["profile"],
                "sha256": case["sha256"],
                "changes": case.get("changes", []),
                "status": "DRY_RUN_ONLY",
            })
        (out / "campaign.jsonl").write_text(
            "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in plan),
            encoding="utf-8",
        )
        (out / "summary.json").write_text(json.dumps({
            "status": "DRY_RUN_ONLY", "generated": len(cases), "executed": 0,
            "results": plan,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Dry run: сгенерировано {len(cases)} профилей; USB Gadget не запускался.")
        print(f"План: {campaign_log}")
        return 0

    binary = find_usb_connect()
    results: list[dict[str, Any]] = []
    interrupted = False
    print("\n=== USB FUZZ CAMPAIGN: LIVE CONSOLE ===", flush=True)
    print(f"Профили: {len(cases)} | seed={args.seed} | мутаций на профиль максимум={args.mutations} | speed={args.speed}", flush=True)
    print(f"UDC driver={args.udc_driver} | UDC device={args.udc_device}", flush=True)
    print(f"Результаты: {out} | захваты: {capture_dir if capture_dir else 'не указаны'}", flush=True)
    print("Важно: RUNNING означает, что процесс Gadget жив; контакт с хостом подтверждается CONTROL_REQUEST, CONFIGURED — событием SET_CONFIGURATION.", flush=True)
    for index, case in enumerate(cases, start=1):
        profile = Path(case["profile"])
        case_no = int(case["case"])
        print(f"\n[{index}/{len(cases)}] ===== CASE {case_no:05d} =====", flush=True)
        print_case_changes(case, profile)
        print("  Старт Raw Gadget; ожидаю события UDC и запросы хоста...", flush=True)
        row = run_case(binary, profile, case_no, args, out, capture_dir, list(case.get("changes") or []))
        results.append(row)
        append_jsonl(campaign_log, row)
        print(f"  -> Статус процесса: {row['status']} ({row.get('duration_seconds', 0)} s)", flush=True)
        print_case_outcome(row)
        if row["status"] == "INTERRUPTED":
            interrupted = True
            break
        if row["status"] in ("LAUNCH_ERROR", "START_FAILED", "DEVICE_EXITED_EARLY", "STOP_ERROR") and args.stop_on_error:
            print("Остановка: ошибка запуска/раннее завершение. Подробности в traces/*.stderr.log", file=sys.stderr)
            break
        if index < len(cases) and args.settle_seconds:
            try:
                time.sleep(args.settle_seconds)
            except KeyboardInterrupt:
                interrupted = True
                break

    review_queue = analyze_campaign_captures(capture_dir, results, args.tshark, out)
    review_path = out / "review-queue.json"
    review_path.write_text(json.dumps({
        "generated_at": utc_now(),
        "count": len(review_queue),
        "note": "Heuristic queue for manual review. Wireshark text/timestamp correlation is not proof of a host crash or byte-for-byte mismatch; synchronize Pi and Windows clocks for useful correlation.",
        "cases": review_queue,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {
        "status": "INTERRUPTED" if interrupted else "COMPLETED",
        "seed": args.seed,
        "generated": len(cases),
        "executed": len(results),
        "completed": sum(x["status"] == "COMPLETED" for x in results),
        "startup_errors": sum(x["status"] in ("LAUNCH_ERROR", "START_FAILED", "DEVICE_EXITED_EARLY", "STOP_ERROR") for x in results),
        "interrupted_cases": sum(x["status"] == "INTERRUPTED" for x in results),
        "results": results,
        "review_required": len(review_queue),
        "review_queue": str(review_path),
        "note": "Review queue is heuristic. Live console distinguishes process lifecycle, observed host control requests, and SET_CONFIGURATION. Wireshark captures alone cannot prove a Windows crash or guarantee byte-for-byte comparison against every intended descriptor.",
    }
    trace_summaries = [x.get("trace_summary", {}) for x in results]
    summary["cases_host_contact_observed"] = sum(bool(x.get("host_contact_observed")) for x in trace_summaries)
    summary["cases_configured_observed"] = sum(bool(x.get("configured_observed")) for x in trace_summaries)
    summary["cases_with_stall"] = sum(int(x.get("control_stalls", 0)) > 0 for x in trace_summaries)
    summary["cases_with_usb_reset"] = sum(int(x.get("usb_reset_events", 0)) > 0 for x in trace_summaries)
    summary["cases_with_backend_errors"] = sum(int(x.get("backend_error_events", 0)) > 0 for x in trace_summaries)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\n=== ИТОГ КАМПАНИИ ===", flush=True)
    print(f"Случаев: {len(results)} | Gadget completed: {summary['completed']} | ошибки старта/завершения: {summary['startup_errors']} | прервано: {summary['interrupted_cases']}", flush=True)
    print(f"Запросы хоста замечены: {summary['cases_host_contact_observed']}/{len(results)} | CONFIGURED замечен: {summary['cases_configured_observed']}/{len(results)}", flush=True)
    print(f"Случаи со STALL: {summary['cases_with_stall']} | USB reset: {summary['cases_with_usb_reset']} | backend errors: {summary['cases_with_backend_errors']}", flush=True)
    print(f"Очередь дополнительной проверки: {review_path} ({len(review_queue)} случаев)", flush=True)
    print(f"Итог: {summary_path}", flush=True)
    return 130 if interrupted else (1 if summary["startup_errors"] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
