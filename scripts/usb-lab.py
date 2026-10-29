#!/usr/bin/env python3
"""Удобная командная оболочка USB Research Toolkit. Python 3.10+."""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "profiles" / "templates"
BUILDS = [ROOT / "build", ROOT / "build" / "Release", ROOT / "build" / "Debug"]

ALIASES = {
    "vendor": "vendor-bulk",
    "vendor-bulk": "vendor-bulk",
    "bulk": "vendor-bulk",
    "cdc": "cdc-acm-serial",
    "cdc-acm": "cdc-acm-serial",
    "cdc-acm-serial": "cdc-acm-serial",
    "hid": "hid-mouse",
    "hid-mouse": "hid-mouse",
    "hid-keyboard": "hid-keyboard",
    "keyboard": "hid-keyboard",
    "hid-gamepad": "hid-gamepad",
    "gamepad": "hid-gamepad",
    "hid-joystick": "hid-joystick",
    "joystick": "hid-joystick",
    "hid-consumer-control": "hid-consumer-control",
    "consumer-control": "hid-consumer-control",
    "composite-cdc-hid-keyboard": "composite-cdc-hid-keyboard",
    "composite-msc-hid-gamepad": "composite-msc-hid-gamepad",
    "composite-hid-keyboard-mouse-consumer": "composite-hid-keyboard-mouse-consumer",
    "composite-hid": "composite-hid-keyboard-mouse-consumer",
    "composite-cdc-msc-hid-gamepad": "composite-cdc-msc-hid-gamepad",
    "multi-config-keyboard-mouse": "multi-config-keyboard-mouse",
    "mass-storage": "msc-bot-disk",
    "msc": "msc-bot-disk",
    "msc-bot": "msc-bot-disk",
    "msc-bot-disk": "msc-bot-disk",
    "msc-bot-descriptor-only": "msc-bot-descriptor-only",
}


def say_err(message: str) -> None:
    print(f"usb-lab: {message}", file=sys.stderr)


def executable(name: str, required: bool = True) -> str | None:
    exe_suffix = ".exe" if os.name == "nt" else ""
    candidates = []
    for directory in BUILDS:
        candidates.extend([directory / f"{name}{exe_suffix}", directory / name])
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    if required:
        raise RuntimeError(
            f"не найден исполняемый файл {name}. Сначала выполните: "
            f"python {'scripts\\usb-lab.py' if os.name == 'nt' else 'scripts/usb-lab.py'} build"
        )
    return None


def run_cmd(command: list[str], *, cwd: Path = ROOT, check: bool = True,
            capture: bool = False, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    printable = " ".join(f'"{x}"' if " " in x else x for x in command)
    if not capture:
        print(f"$ {printable}", flush=True)
    result = subprocess.run(
        command, cwd=str(cwd), text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
    )
    if check and result.returncode != 0:
        details = ""
        if capture:
            details = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"команда завершилась с кодом {result.returncode}" + (f":\n{details}" if details else ""))
    return result


def resolve_type(value: str) -> str:
    key = value.strip().lower()
    if key in ALIASES:
        return ALIASES[key]
    expected = ", ".join(sorted(ALIASES))
    raise RuntimeError(f"неизвестный тип '{value}'. Допустимые значения: {expected}")


def list_profiles(verbose: bool = True) -> list[dict[str, Any]]:
    items = []
    if not TEMPLATES.exists():
        raise RuntimeError(f"каталог шаблонов не найден: {TEMPLATES}")
    for path in sorted(TEMPLATES.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception as ex:
            say_err(f"не удалось прочитать {path.name}: {ex}")
            continue
        info = data.get("template_info", {})
        item = {
            "name": path.stem,
            "category": info.get("category", path.stem),
            "runtime_ready": info.get("runtime_ready", False),
            "notes": info.get("notes", ""),
            "path": str(path.relative_to(ROOT)),
        }
        items.append(item)
        if verbose:
            state = "эмуляция заявлена" if item["runtime_ready"] else "только дескрипторы / ограниченная реализация"
            print(f"\n{item['name']} — {item['category']}\n  Статус: {state}\n  Файл: {item['path']}")
            if item["notes"]:
                print(f"  Примечание: {item['notes']}")
    return items


def cmd_build(args: argparse.Namespace) -> int:
    cmake = shutil.which("cmake")
    if not cmake:
        raise RuntimeError("CMake не найден. Установите CMake 3.20 или новее.")
    build_dir = ROOT / "build"
    run_cmd([cmake, "-S", str(ROOT), "-B", str(build_dir), f"-DCMAKE_BUILD_TYPE={args.config}"])
    run_cmd([cmake, "--build", str(build_dir), "--config", args.config, "--parallel", str(args.jobs)])
    if not args.no_test:
        run_cmd([cmake, "-E", "env", "CTEST_OUTPUT_ON_FAILURE=1", "ctest", "--test-dir", str(build_dir), "-C", args.config])
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    print("USB Research Toolkit — проверка окружения")
    print(f"ОС: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    for prog in ("cmake", "ctest", "tshark", "git"):
        value = shutil.which(prog)
        print(f"{'OK' if value else 'НЕТ':>4}  {prog}: {value or 'не найден'}")
    for prog in ("usb-config", "usb-connect", "usb-trace", "usb-profile-gen"):
        value = executable(prog, required=False)
        print(f"{'OK' if value else 'НЕТ':>4}  {prog}: {value or 'сначала выполните build'}")
    if sys.platform.startswith("linux"):
        print(f"{'OK' if Path('/dev/raw-gadget').exists() else 'НЕТ':>4}  /dev/raw-gadget")
        udc = list(Path("/sys/class/udc").glob("*")) if Path("/sys/class/udc").exists() else []
        print(f"{'OK' if udc else 'НЕТ':>4}  /sys/class/udc: {', '.join(p.name for p in udc) or 'UDC не обнаружен'}")
    print("Примечание: утилиты usb-connect / Raw Gadget требуют Linux и подходящий USB Device Controller.")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    items = list_profiles(verbose=not args.json)
    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2))
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    tool = executable("usb-profile-gen")
    command = [tool, "generate"]
    if args.base:
        command += ["--base", str(Path(args.base).resolve())]
    else:
        command += ["--template", resolve_type(args.type)]
    command += ["--count", str(args.count), "--out-dir", str(Path(args.out_dir).resolve()),
                "--mode", args.mode, "--speed", args.speed]
    if args.seed is not None:
        command += ["--seed", str(args.seed)]
    if args.fields:
        command += ["--fields", args.fields]
    if args.vid:
        command += ["--vid", args.vid]
    if args.pid_start:
        command += ["--pid-start", args.pid_start]
    if args.print_profiles:
        command.append("--print")
    return run_cmd(command, check=False).returncode


def cmd_validate(args: argparse.Namespace) -> int:
    tool = executable("usb-config")
    return run_cmd([tool, "validate", str(Path(args.profile).resolve()), "--mode", args.mode], check=False).returncode


def cmd_show(args: argparse.Namespace) -> int:
    tool = executable("usb-profile-gen")
    target = resolve_type(args.type)
    return run_cmd([tool, "show", target], check=False).returncode


def cmd_probe(_: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("команда probe работает на Raspberry Pi/Linux, а не на хосте Windows")
    return run_cmd([executable("usb-connect"), "probe"], check=False).returncode


def cmd_device(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("устройство USB Gadget запускается на Raspberry Pi/Linux; на хосте запускают capture")
    command = [executable("usb-connect"), "run", str(Path(args.profile).resolve()),
               "--backend", "raw-gadget", "--trace", str(Path(args.trace).resolve()), "--speed", args.speed]
    if args.udc_driver:
        command += ["--udc-driver", args.udc_driver]
    if args.udc_device:
        command += ["--udc-device", args.udc_device]
    if args.run_id:
        command += ["--run-id", args.run_id]
    if args.allow_research:
        command.append("--allow-research")
    return run_cmd(command, check=False).returncode


def tshark_path() -> str:
    value = shutil.which("tshark")
    if not value:
        raise RuntimeError("tshark не найден. Установите Wireshark и добавьте tshark в PATH.")
    return value


def capture_interfaces(tshark: str) -> list[tuple[str, str]]:
    result = run_cmd([tshark, "-D"], check=False, capture=True)
    if result.returncode != 0:
        raise RuntimeError("не удалось получить интерфейсы tshark: " + (result.stderr or ""))
    interfaces = []
    for line in (result.stdout or "").splitlines():
        m = re.match(r"\s*(\d+)\.\s+(.*)", line)
        if m:
            interfaces.append((m.group(1), m.group(2).strip()))
    return interfaces


def choose_interface(tshark: str, requested: str | None) -> str:
    interfaces = capture_interfaces(tshark)
    if requested:
        return requested
    print("Доступные интерфейсы захвата:")
    for number, name in interfaces:
        print(f"  {number}. {name}")
    preferred = None
    if sys.platform.startswith("linux"):
        preferred = next((num for num, name in interfaces if "usbmon0" in name.lower()), None)
        if preferred:
            print(f"Найден usbmon0 (номер {preferred}). Для USB обычно подходит usbmon0 или интерфейс нужной шины.")
    try:
        prompt = f"Введите номер/имя USB-интерфейса [{preferred or 'выберите из списка'}]: "
        selected = input(prompt).strip()
        return selected or (preferred if preferred else "")
    except EOFError as ex:
        raise RuntimeError("задайте --interface; без интерактивного терминала интерфейс выбрать нельзя") from ex


def cmd_capture(args: argparse.Namespace) -> int:
    tshark = tshark_path()
    if sys.platform.startswith("linux"):
        udc_root = Path("/sys/class/udc")
        udcs = list(udc_root.glob("*") if udc_root.exists() else [])
        if udcs:
            print(
                "\nВНИМАНИЕ: эта машина имеет USB Device Controller (UDC). "
                "usbmon на ней наблюдает USB-трафик, инициированный её HOST-контроллерами, "
                "но обычно не захватывает линию, где сама машина работает USB-Gadget. "
                "Для PCAPNG запустите capture на отдельном тестовом HOST-компьютере "
                "и выберите usbmonN (Linux) или USBPcapN (Windows).\n",
                file=sys.stderr,
                flush=True,
            )
    output = Path(args.out).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not args.force:
        raise RuntimeError(f"файл уже существует: {output}. Используйте --force или другой путь.")
    iface = choose_interface(tshark, args.interface)
    command = [tshark, "-i", iface, "-w", str(output)]
    if args.duration:
        if args.duration < 1:
            raise RuntimeError("duration должна быть не меньше 1 секунды")
        command[1:1] = ["-a", f"duration:{args.duration}"]
    if sys.platform.startswith("linux") and os.geteuid() != 0 and not args.no_sudo:
        sudo = shutil.which("sudo")
        if sudo:
            command.insert(0, sudo)
        else:
            say_err("tshark может потребовать root/разрешение захвата; sudo не найден")
    print("\nЗапускаю захват USB host-stack в PCAPNG.")
    print("Остановите Ctrl+C после теста. Захват программный (URB/USB stack), не физический анализатор шины.")
    print("Файл:", output)
    try:
        return subprocess.call(command, cwd=str(ROOT))
    except KeyboardInterrupt:
        print("\nЗахват остановлен пользователем.")
        return 0


# Wireshark exposes bmRequestType as usb.bmRequestType in current builds.
# Some older/vendor builds exposed usb.setup.bmRequestType, so select the
# first field actually advertised by the installed tshark.
NORMALIZER_FIELDS = [
    "frame.time_epoch", "usb.device_address", "usb.endpoint_address",
    "usb.transfer_type", "usb.urb_type", "usb.data_len",
    "usb.setup.bRequest", "usb.setup.wValue", "usb.setup.wIndex",
    "usb.setup.wLength", "usb.capdata",
]
REQUEST_TYPE_FIELD_ALIASES = ["usb.bmRequestType", "usb.setup.bmRequestType"]
OPTIONAL_NORMALIZER_FIELDS = ["frame.number", "usb.bus_id", "usb.urb_id", "usb.urb_status", "usb.usbd_status", "usb.control.Response", "usb.getDescriptor.Response"]


def choose_request_type_field(available_fields: set[str]) -> str | None:
    """Select current Wireshark field spelling, with a legacy fallback."""
    return next((field for field in REQUEST_TYPE_FIELD_ALIASES if field in available_fields), None)


def normalize_pcap(input_pcap: Path, output_jsonl: Path, source: str) -> None:
    tshark = tshark_path()
    normalizer = ROOT / "scripts" / "normalize-tshark.py"
    if not input_pcap.is_file():
        raise RuntimeError(f"файл захвата не найден: {input_pcap}")
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    # Wireshark field availability varies by release/OS. Required fields define the
    # normalizer schema; optional USB status/URB identifiers are included only when
    # this installed tshark advertises them.
    available_fields = set()
    field_list = run_cmd([tshark, "-G", "fields"], check=False, capture=True)
    if field_list.returncode == 0:
        for line in (field_list.stdout or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0] == "F":
                available_fields.add(parts[2])
    request_type_field = choose_request_type_field(available_fields)
    if available_fields and request_type_field is None:
        raise RuntimeError(
            "в установленном TShark не найдено поле bmRequestType "
            "(ожидалось usb.bmRequestType; совместимый вариант: usb.setup.bmRequestType). "
            "Проверьте `tshark -G fields` и версию Wireshark."
        )
    fields = NORMALIZER_FIELDS.copy()
    if request_type_field is not None:
        # Keep the request-type column near the other setup fields; the Python
        # normalizer accepts both canonical and legacy header names.
        fields.insert(fields.index("usb.setup.bRequest"), request_type_field)
    else:
        # If the field registry could not be queried, use the current canonical
        # field; TShark will provide a useful error if the installation is broken.
        fields.insert(fields.index("usb.setup.bRequest"), "usb.bmRequestType")
    fields += [f for f in OPTIONAL_NORMALIZER_FIELDS if f in available_fields]
    command = [tshark, "-r", str(input_pcap), "-T", "fields", "-E", "header=y",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in fields:
        command += ["-e", field]
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as tshark_err:
        proc = subprocess.Popen(command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=tshark_err,
                                text=True, encoding="utf-8", errors="replace")
        assert proc.stdout is not None
        with output_jsonl.open("w", encoding="utf-8", newline="\n") as output:
            norm = subprocess.run([sys.executable, str(normalizer), "--source", source],
                                  stdin=proc.stdout, stdout=output, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
        proc.stdout.close()
        tshark_rc = proc.wait()
        tshark_err.seek(0)
        stderr_text = tshark_err.read().strip()
    if tshark_rc != 0:
        output_jsonl.unlink(missing_ok=True)
        raise RuntimeError("tshark не смог разобрать PCAPNG: " + (stderr_text or f"код {tshark_rc}"))
    if norm.returncode != 0:
        output_jsonl.unlink(missing_ok=True)
        raise RuntimeError("нормализация не удалась: " + (norm.stderr or "проверьте поля вашей версии Wireshark"))


def cmd_normalize(args: argparse.Namespace) -> int:
    source = args.source
    if source == "auto":
        source = "windows_host" if os.name == "nt" else "linux_host"
    normalize_pcap(Path(args.pcap).resolve(), Path(args.out).resolve(), source)
    print(f"События записаны в: {Path(args.out).resolve()}")
    return 0


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    if not path.exists():
        raise RuntimeError(f"JSONL не найден: {path}")
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as ex:
                raise RuntimeError(f"ошибка JSONL {path}:{line_no}: {ex}") from ex
            if isinstance(item, dict):
                events.append(item)
    return events


def status_report(device_events: list[dict[str, Any]], host_events: list[dict[str, Any]],
                  comparison: dict[str, Any], device_path: str, host_path: str) -> dict[str, Any]:
    device_counts = collections.Counter(str(e.get("event", "UNKNOWN")) for e in device_events)
    host_counts = collections.Counter(str(e.get("event", "UNKNOWN")) for e in host_events)
    # Raw Gadget's USB_RAW_EVENT_DISCONNECT is ambiguous on some UDCs:
    # DWC2 can report a bus reset as DISCONNECT. Do not label it as a proven
    # physical cable pull; keep it separate from an explicit physical event.
    reset_or_disconnects = [e for e in device_events if str(e.get("event", "")).upper() in
                            {"USB_DISCONNECT", "USB_RESET_OR_DISCONNECT"}]
    disconnects = [e for e in device_events if str(e.get("event", "")).upper() in
                   {"USB_PHYSICAL_DISCONNECT", "PHYSICAL_USB_DISCONNECT"}]
    errors = [e for e in device_events if any(word in str(e.get("event", "")).upper()
              for word in ("ERROR", "STALL", "TIMEOUT"))]
    host_errors = [e for e in host_events if any(word in str(e.get("status", "")).lower()
                   for word in ("error", "stall", "timeout", "failed"))]
    possible_disconnects = []
    for event in host_errors:
        raw = str(event.get("host_status_raw", "")).lower()
        code = event.get("host_status_code")
        if code in (-19, -108) or any(token in raw for token in ("device gone", "no device", "device removed", "shutdown")):
            possible_disconnects.append(event)
    matched = int(comparison.get("matched_control_requests", 0)) + int(comparison.get("matched_data_transfers", 0))
    unmatched_device = len(comparison.get("unmatched_device_events", []))
    unmatched_host = sum(int(x.get("unmatched_count", 0)) for x in comparison.get("unmatched_host_signatures", []))

    if disconnects:
        status = "DISCONNECT_OBSERVED"
        summary = "Явное событие физического отключения зарегистрировано источником трассы."
    elif reset_or_disconnects:
        status = "RESET_OR_DISCONNECT_OBSERVED"
        summary = ("Raw Gadget сообщил RESET/DISCONNECT. На DWC2 событие DISCONNECT может означать "
                   "сброс шины; по этому событию нельзя утверждать, что кабель физически отключили.")
    elif possible_disconnects:
        status = "POSSIBLE_DISCONNECT"
        summary = "Хостовый статус совместим с отключением/исчезновением устройства. Это признак возможного разрыва; сопоставьте время и проверьте физическое подключение."
    elif errors or host_errors:
        status = "ERROR_OR_STALL_OBSERVED"
        summary = "В журнале найдены события ошибки, STALL или тайм-аута; проверьте подробности и момент возникновения."
    elif not host_events:
        status = "NO_HOST_EVIDENCE"
        summary = "В нормализованном захвате нет событий. Это может означать неверный интерфейс захвата, фильтр, отсутствие enumeration или отключение; по одному пустому файлу различить их нельзя."
    elif matched > 0 and unmatched_device == 0 and unmatched_host == 0:
        status = "CORRELATED"
        summary = "Все найденные сопоставляемые сигнатуры совпали между журналами. Это программное подтверждение корреляции, не доказательство каждого физического USB-пакета."
    elif matched > 0:
        status = "PARTIAL_CORRELATION"
        summary = "Часть сигнатур совпала, часть осталась без пары. Проверьте список расхождений, фильтр захвата и повторяющиеся передачи."
    else:
        status = "NO_CORRELATION"
        summary = "Сопоставляемые события не найдены. Причина может быть в несовпадении профиля/endpoint, неполном захвате, разрыве или неподходящем источнике лога."

    return {
        "report_version": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "summary_ru": summary,
        "device_trace": device_path,
        "host_trace": host_path,
        "device_event_count": len(device_events),
        "host_event_count": len(host_events),
        "device_events_by_type": dict(sorted(device_counts.items())),
        "host_events_by_type": dict(sorted(host_counts.items())),
        "matched_control_requests": int(comparison.get("matched_control_requests", 0)),
        "matched_data_transfers": int(comparison.get("matched_data_transfers", 0)),
        "unmatched_device_observations": unmatched_device,
        "unmatched_host_signatures": unmatched_host,
        "disconnect_events": disconnects,
        "reset_or_disconnect_events": reset_or_disconnects,
        "possible_disconnect_events": possible_disconnects,
        "device_error_or_stall_events": errors,
        "host_error_status_events": host_errors,
        "comparison": comparison,
        "limitations": [
            "usbmon/USBPcap обычно фиксируют передачи на уровне USB host stack/URB, а не каждый физический токен/ACK/NAK/CRC.",
            "Несопоставленное наблюдение не доказывает потерю пакета: могли отличаться точка захвата, фильтрация, формат полей или повторяющиеся запросы.",
            "Захват на общей USB-шине может содержать события других устройств; при интерпретации учитывайте device_address и состав шины.",
            "Физическое подтверждение транзакций USB 2.0 требует аппаратного анализатора USB."
        ],
    }


def write_markdown_report(report: dict[str, Any], path: Path) -> None:
    label = {
        "DISCONNECT_OBSERVED": "Обнаружено явное физическое отключение",
        "RESET_OR_DISCONNECT_OBSERVED": "Raw Gadget сообщил RESET/DISCONNECT (событие неоднозначно)",
        "POSSIBLE_DISCONNECT": "Возможный разрыв по статусу хоста",
        "ERROR_OR_STALL_OBSERVED": "Обнаружена ошибка / STALL / тайм-аут",
        "NO_HOST_EVIDENCE": "Нет наблюдений на хосте",
        "CORRELATED": "События сопоставлены",
        "PARTIAL_CORRELATION": "Частичное совпадение",
        "NO_CORRELATION": "Сопоставление не найдено",
    }.get(report["status"], report["status"])
    lines = [
        "# Отчёт USB Research Toolkit", "",
        f"**Итог:** {label} (`{report['status']}`)", "",
        report["summary_ru"], "",
        "## Сводка", "",
        f"- Журнал Raspberry Pi: `{report['device_trace']}` ({report['device_event_count']} событий)",
        f"- Захват хоста: `{report['host_trace']}` ({report['host_event_count']} событий)",
        f"- Совпавшие control-запросы: {report['matched_control_requests']}",
        f"- Совпавшие передачи с доступной нагрузкой: {report['matched_data_transfers']}",
        f"- Непарные наблюдения устройства: {report['unmatched_device_observations']}",
        f"- Непарные сигнатуры хоста: {report['unmatched_host_signatures']}",
        "", "## События устройства", "",
    ]
    if report["disconnect_events"]:
        lines.append("### Явные события отключения")
        for event in report["disconnect_events"]:
            lines.append(f"- `{event.get('event')}` state=`{event.get('state')}` sequence=`{event.get('sequence')}`")
        lines.append("")
    if report.get("reset_or_disconnect_events"):
        lines.append("### RESET/DISCONNECT от Raw Gadget (не всегда физический обрыв)")
        for event in report["reset_or_disconnect_events"][:100]:
            lines.append(f"- `{event.get('event')}` state=`{event.get('state')}` sequence=`{event.get('sequence')}`: {event.get('note', 'На DWC2 это событие может обозначать сброс шины.')}")
        lines.append("")
    if report["possible_disconnect_events"]:
        lines.append("### Возможный разрыв по статусу USB-хоста")
        for event in report["possible_disconnect_events"][:100]:
            lines.append(f"- frame=`{event.get('frame_number')}` status=`{event.get('host_status_raw', event.get('host_status_code'))}`")
        lines.append("")
    if report["device_error_or_stall_events"]:
        lines.append("### Ошибки / STALL / тайм-ауты на стороне устройства")
        for event in report["device_error_or_stall_events"][:100]:
            lines.append(f"- `{event.get('event')}` state=`{event.get('state')}`: {event.get('message', event.get('reason', event.get('error', 'подробности см. в JSON')))}")
        lines.append("")
    if report["host_error_status_events"]:
        lines.append("### Ошибки в статусах хоста")
        for event in report["host_error_status_events"][:100]:
            lines.append(f"- `{event.get('event')}` status=`{event.get('status')}`")
        lines.append("")
    lines.extend(["## Частоты событий", "", "### Raspberry Pi", ""])
    if report["device_events_by_type"]:
        lines.extend(f"- `{k}`: {v}" for k, v in report["device_events_by_type"].items())
    else:
        lines.append("Событий нет.")
    lines += ["", "### Хост", ""]
    if report["host_events_by_type"]:
        lines.extend(f"- `{k}`: {v}" for k, v in report["host_events_by_type"].items())
    else:
        lines.append("Событий нет.")
    lines += ["", "## Ограничения интерпретации", ""]
    lines.extend(f"- {item}" for item in report["limitations"])
    lines += ["", "Подробные сигнатуры, пары и непарные события сохранены в JSON-отчёте.", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def cmd_compare(args: argparse.Namespace) -> int:
    tool = executable("usb-trace")
    device_path = Path(args.device_trace).resolve()
    host_path = Path(args.host).resolve()
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if host_path.suffix.lower() in (".pcap", ".pcapng", ".cap"):
        source = args.source
        if source == "auto":
            source = "windows_host" if os.name == "nt" else "linux_host"
        host_jsonl = out.parent / (out.stem + ".host-normalized.jsonl")
        normalize_pcap(host_path, host_jsonl, source)
        normalized_host = host_jsonl
    else:
        normalized_host = host_path
    device_events = load_jsonl(device_path)
    host_events = load_jsonl(normalized_host)
    command = [tool, "compare", str(device_path), str(normalized_host)]
    result = run_cmd(command, check=True, capture=True)
    try:
        comparison = json.loads(result.stdout)
    except json.JSONDecodeError as ex:
        raise RuntimeError(f"usb-trace вернул некорректный JSON: {ex}") from ex
    report = status_report(device_events, host_events, comparison, str(device_path), str(host_path))
    md_path = out.with_suffix(".md")
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown_report(report, md_path)
    labels = {
        "DISCONNECT_OBSERVED": "ОБНАРУЖЕНО ОТКЛЮЧЕНИЕ",
        "POSSIBLE_DISCONNECT": "ВОЗМОЖНЫЙ РАЗРЫВ ПО СТАТУСУ ХОСТА",
        "ERROR_OR_STALL_OBSERVED": "ОШИБКА / STALL / ТАЙМ-АУТ",
        "NO_HOST_EVIDENCE": "НЕТ ДАННЫХ ХОСТА",
        "CORRELATED": "СОБЫТИЯ СОПОСТАВЛЕНЫ",
        "PARTIAL_CORRELATION": "ЧАСТИЧНОЕ СОВПАДЕНИЕ",
        "NO_CORRELATION": "СОВПАДЕНИЯ НЕ НАЙДЕНЫ",
    }
    print("\n" + "=" * 68)
    print(labels.get(report["status"], report["status"]))
    print(report["summary_ru"])
    print(f"Совпадений: control={report['matched_control_requests']}, data={report['matched_data_transfers']}")
    print(f"Непарные: устройство={report['unmatched_device_observations']}, хост={report['unmatched_host_signatures']}")
    print(f"JSON: {out}\nMarkdown: {md_path}")
    print("=" * 68)
    return 0


def cmd_fuzz(args: argparse.Namespace) -> int:
    script = ROOT / "scripts" / "usb-fuzz.py"
    return run_cmd([sys.executable, str(script), *args.fuzz_args], check=False).returncode


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usb-lab.py",
        description="Единый интерфейс USB Research Toolkit: генерация профилей, запуск Gadget, PCAP-захват и сравнение.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("build", help="собрать C++-утилиты и запустить тесты")
    p.add_argument("--config", choices=["Debug", "Release"], default="Release")
    p.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 2))
    p.add_argument("--no-test", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("doctor", help="проверить инструменты и Raw Gadget")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("profiles", help="вывести встроенные шаблоны устройств")
    p.add_argument("--json", action="store_true", help="вывести машинно-читаемый JSON")
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("generate", help="генерировать варианты USB-профиля")
    p.add_argument("--type", default="vendor", help="vendor, cdc, hid, mass-storage или имя шаблона")
    p.add_argument("--base", help="исходный JSON-профиль вместо шаблона")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--mode", choices=["safe", "research"], default="safe")
    p.add_argument("--speed", choices=["high", "full"], default="high")
    p.add_argument("--fields", default="pid,revision,strings,power,endpoint-addresses,packet-size,interval")
    p.add_argument("--vid", help="переопределить VID (только разрешённый для вашей лаборатории)")
    p.add_argument("--pid-start", help="начальный PID")
    p.add_argument("--out-dir", default="profiles/generated/session")
    p.add_argument("--print", dest="print_profiles", action="store_true", help="также печатать варианты в консоль")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("fuzz", help="мутации профилей и лабораторная fuzz-кампания")
    p.add_argument("fuzz_args", nargs=argparse.REMAINDER, help="аргументы scripts/usb-fuzz.py; например: generate --base profiles/valid/minimal-device.json")
    p.set_defaults(func=cmd_fuzz)

    p = sub.add_parser("show", help="показать шаблон")
    p.add_argument("--type", default="vendor")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("validate", help="проверить JSON-профиль")
    p.add_argument("profile")
    p.add_argument("--mode", choices=["strict", "research"], default="strict")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("probe", help="проверить USB Gadget/UDC на Raspberry Pi")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("device", help="запустить профиль на Raspberry Pi (Linux only)")
    p.add_argument("--profile", required=True)
    p.add_argument("--trace", default="runs/latest/device.jsonl")
    p.add_argument("--speed", choices=["high", "full", "low"], default="high")
    p.add_argument("--udc-driver")
    p.add_argument("--udc-device")
    p.add_argument("--run-id", default="usb-lab-run")
    p.add_argument("--allow-research", action="store_true")
    p.set_defaults(func=cmd_device)

    p = sub.add_parser("capture", help="захватить USB host-stack в PCAPNG")
    p.add_argument("--out", required=True)
    p.add_argument("--interface", help="номер/имя из tshark -D; без аргумента откроется выбор")
    p.add_argument("--duration", type=int, help="остановить захват через N секунд")
    p.add_argument("--force", action="store_true", help="перезаписать файл, если он существует")
    p.add_argument("--no-sudo", action="store_true", help="не добавлять sudo на Linux")
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("normalize", help="преобразовать PCAP/PCAPNG в JSONL")
    p.add_argument("--pcap", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--source", choices=["auto", "linux_host", "windows_host"], default="auto")
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("compare", help="сравнить лог Raspberry Pi с PCAP или host JSONL")
    p.add_argument("--device-trace", required=True)
    p.add_argument("--host", required=True, help=".pcap/.pcapng или нормализованный .jsonl")
    p.add_argument("--source", choices=["auto", "linux_host", "windows_host"], default="auto")
    p.add_argument("--out", default="runs/latest/report.json", help="путь к JSON-отчёту; рядом создаётся .md")
    p.set_defaults(func=cmd_compare)
    return parser


def interactive_menu() -> int:
    print("\nUSB Research Toolkit — меню")
    print("1. Проверить окружение")
    print("2. Собрать проект и запустить тесты")
    print("3. Показать типы USB-профилей")
    print("4. Сгенерировать варианты профиля")
    print("5. Проверить профиль")
    print("6. Проверить Raw Gadget на Raspberry Pi")
    print("7. Захватить USB PCAPNG на хосте")
    print("8. Сравнить лог устройства и PCAP/JSONL")
    print("0. Выход")
    choice = input("Выберите действие: ").strip()
    parser = make_parser()
    calls = {
        "1": ["doctor"], "2": ["build"], "3": ["profiles"],
    }
    if choice in calls:
        return int(parser.parse_args(calls[choice]).func(parser.parse_args(calls[choice])) or 0)
    if choice == "4":
        print("Типы: vendor, cdc, hid, mass-storage")
        kind = input("Тип [vendor]: ").strip() or "vendor"
        count = input("Количество вариантов [10]: ").strip() or "10"
        seed = input("Seed для воспроизводимости [42]: ").strip() or "42"
        out = input("Каталог результата [profiles/generated/session]: ").strip() or "profiles/generated/session"
        argv = ["generate", "--type", kind, "--count", count, "--seed", seed, "--out-dir", out]
    elif choice == "5":
        prof = input("Путь к JSON-профилю: ").strip()
        argv = ["validate", prof]
    elif choice == "6":
        argv = ["probe"]
    elif choice == "7":
        out = input("Куда сохранить PCAPNG [runs/latest/host.pcapng]: ").strip() or "runs/latest/host.pcapng"
        argv = ["capture", "--out", out]
        iface = input("Номер/имя интерфейса (Enter — выбрать из списка): ").strip()
        if iface:
            argv += ["--interface", iface]
    elif choice == "8":
        device = input("Лог Raspberry Pi [runs/latest/device.jsonl]: ").strip() or "runs/latest/device.jsonl"
        host = input("Захват хоста PCAPNG или JSONL: ").strip()
        out = input("JSON-отчёт [runs/latest/report.json]: ").strip() or "runs/latest/report.json"
        argv = ["compare", "--device-trace", device, "--host", host, "--out", out]
    elif choice == "0":
        return 0
    else:
        print("Неизвестный пункт меню.")
        return 2
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


def main(argv: list[str] | None = None) -> int:
    try:
        parser = make_parser()
        if argv is None:
            argv = sys.argv[1:]
        if not argv:
            return interactive_menu()
        args = parser.parse_args(argv)
        if not hasattr(args, "func"):
            parser.print_help()
            return 2
        return int(args.func(args) or 0)
    except (RuntimeError, OSError, ValueError) as ex:
        say_err(str(ex))
        return 2
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
