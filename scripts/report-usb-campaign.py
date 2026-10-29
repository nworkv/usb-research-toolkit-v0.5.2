#!/usr/bin/env python3
"""Create byte-level TXT/HTML/JSON reports for a whole USB fuzz campaign.

Compares descriptor bytes expected from each case JSON profile against the
USBPcap/tshark observations assigned to that case by capture time. A single
PCAPNG may contain the whole campaign. PCAP is a host-stack observation, not
an electrical USB analyzer; timestamps must be reasonably synchronized.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "frame_number": ("frame.number",),
    "time_epoch": ("frame.time_epoch",),
    "bus_id": ("usb.bus_id",),
    "device_address": ("usb.device_address",),
    "urb_id": ("usb.urb_id",),
    "urb_type": ("usb.urb_type",),
    "endpoint_address": ("usb.endpoint_address",),
    "transfer_type": ("usb.transfer_type",),
    "urb_status": ("usb.urb_status", "usb.usbd_status"),
    "request_type": ("usb.bmRequestType", "usb.setup.bmRequestType"),
    "bRequest": ("usb.setup.bRequest",),
    "wValue": ("usb.setup.wValue",),
    "wIndex": ("usb.setup.wIndex",),
    "wLength": ("usb.setup.wLength",),
    "data_len": ("usb.data_len",),
    "capdata": ("usb.capdata",),
    "control_response": ("usb.control.Response",),
    "get_descriptor_response": ("usb.getDescriptor.Response",),
    "idVendor": ("usb.idVendor",),
    "idProduct": ("usb.idProduct",),
}
DESC_NAMES = {
    1: "Device", 2: "Configuration", 3: "String", 4: "Interface",
    5: "Endpoint", 6: "Device Qualifier", 7: "Other-speed Configuration",
    15: "BOS", 16: "Device Capability", 0x21: "HID", 0x22: "HID Report",
    0x23: "Physical", 0x30: "SuperSpeed Endpoint Companion",
}
REQ_NAMES = {0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE", 5: "SET_ADDRESS",
             6: "GET_DESCRIPTOR", 8: "GET_CONFIGURATION", 9: "SET_CONFIGURATION",
             10: "GET_INTERFACE", 11: "SET_INTERFACE"}


def import_verifier():
    path = ROOT / "scripts" / "verify-usb-case.py"
    if not path.is_file():
        raise RuntimeError(f"не найден компилятор ожидаемых дескрипторов: {path}")
    spec = importlib.util.spec_from_file_location("usb_case_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"не удалось загрузить {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        m = re.search(r"\(\s*(-?0x[0-9a-fA-F]+|-?\d+)\s*\)", text)
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                pass
        try:
            return int(text, 10)
        except ValueError:
            # A tshark enum may look like "GET DESCRIPTOR (6)".
            m = re.search(r"\((-?\d+)\)\s*$", text)
            return int(m.group(1)) if m else None


def parse_hex_field(value: Any) -> bytes | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s or s in ("<MISSING>", "N/A", "No data"):
        return None
    # tshark fields for USB byte arrays are usually colon-separated hex.
    if not re.fullmatch(r"[0-9a-fA-F\s:.,-]+", s):
        return None
    compact = re.sub(r"[\s:.,-]", "", s)
    if not compact or len(compact) % 2:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def load_campaign_rows(campaign_dir: Path) -> list[dict[str, Any]]:
    p = campaign_dir / "campaign.jsonl"
    rows = []
    if p.is_file():
        for line_no, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{p}:{line_no}: некорректный JSON: {exc}") from exc
            if isinstance(row, dict) and row.get("case") is not None:
                rows.append(row)
    return rows


def merge_manifest_cases(campaign_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Include generated-but-not-run profiles, so interrupted campaigns remain complete in reports."""
    existing = {int(r.get("case", -1)) for r in rows if r.get("case") is not None}
    manifest_path = campaign_dir / "manifest.json"
    if not manifest_path.is_file():
        return rows
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return rows
    for item in manifest.get("cases", []) if isinstance(manifest, dict) else []:
        try:
            number = int(item.get("case"))
        except (TypeError, ValueError):
            continue
        if number in existing:
            # Trace/run rows carry authoritative final status and timestamps; retain manifest changes if missing.
            prior = next(r for r in rows if int(r.get("case", -1)) == number)
            if not prior.get("changes") and item.get("changes"):
                prior["changes"] = item.get("changes")
            if not prior.get("profile") and item.get("profile"):
                prior["profile"] = item.get("profile")
            continue
        rows.append({**item, "case": number, "status": "NOT_RUN", "started_epoch": None,
                     "ended_epoch": None, "profile": item.get("profile"), "trace": None,
                     "note": "Профиль сгенерирован, но в campaign.jsonl нет записи о запуске."})
    return rows


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    if not path.is_file():
        return events
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: некорректный JSON: {exc}") from exc
        if isinstance(item, dict):
            events.append(item)
    return events


def available_tshark_fields(tshark: str) -> set[str]:
    result = subprocess.run([tshark, "-G", "fields"], text=True, capture_output=True, errors="replace", timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"tshark -G fields завершился с кодом {result.returncode}: {(result.stderr or '')[-2000:]}")
    fields = set()
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            fields.add(parts[2].strip())
    return fields


def select_field_map(available: set[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for logical, candidates in FIELD_CANDIDATES.items():
        match = next((f for f in candidates if f in available), None)
        if match:
            mapping[logical] = match
    for required in ("frame_number", "time_epoch"):
        if required not in mapping:
            raise RuntimeError(f"tshark не предоставляет обязательное поле {FIELD_CANDIDATES[required][0]}")
    for required in ("request_type", "bRequest", "wValue", "wIndex", "wLength"):
        if required not in mapping:
            rendered = ", ".join(FIELD_CANDIDATES[x][0] for x in ("request_type", "bRequest", "wValue", "wIndex", "wLength"))
            raise RuntimeError(f"tshark не предоставляет одно или несколько обязательных полей setup: {rendered}; проверь версию Wireshark и декодирование USBPcap")
    return mapping


def parse_request_code(value: Any) -> int | None:
    number = parse_int(value)
    if number is not None:
        return number
    names = {"GET STATUS": 0, "CLEAR FEATURE": 1, "SET FEATURE": 3, "SET ADDRESS": 5,
             "GET DESCRIPTOR": 6, "SET DESCRIPTOR": 7, "GET CONFIGURATION": 8,
             "SET CONFIGURATION": 9, "GET INTERFACE": 10, "SET INTERFACE": 11}
    text = re.sub(r"\s+", " ", str(value or "").strip().upper().replace("_", " "))
    return next((code for name, code in names.items() if text == name or text.startswith(name + " ")), None)


def normalize_field_row(raw: dict[str, str], mapping: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for logical, field in mapping.items():
        value = (raw.get(field) or "").strip()
        if logical in ("capdata", "control_response", "get_descriptor_response"):
            out[logical] = value or None
        elif logical == "time_epoch":
            try:
                out[logical] = float(value) if value else None
            except ValueError:
                out[logical] = None
        elif logical in ("urb_id",):
            out[logical] = value or None
        elif logical in ("urb_type", "transfer_type", "urb_status"):
            out[logical] = value or None
        elif logical == "bRequest":
            out[logical] = parse_request_code(value)
        else:
            out[logical] = parse_int(value)
    out["request"] = None
    if out.get("bRequest") is not None and out.get("wValue") is not None:
        out["request"] = {
            "bmRequestType": out.get("request_type") if out.get("request_type") is not None else 0,
            "bRequest": out.get("bRequest"),
            "wValue": out.get("wValue", 0),
            "wIndex": out.get("wIndex") or 0,
            "wLength": out.get("wLength") or 0,
        }
    return out


def read_tshark_rows(pcap: Path, tshark: str) -> tuple[list[dict[str, Any]], list[str]]:
    exe = shutil.which(tshark) or (tshark if Path(tshark).is_file() else None)
    if not exe:
        raise RuntimeError(f"tshark не найден: {tshark}. На Raspberry Pi установи: sudo apt install tshark")
    available = available_tshark_fields(exe)
    mapping = select_field_map(available)
    fields = list(mapping.values())
    cmd = [exe, "-r", str(pcap), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in fields:
        cmd.extend(["-e", field])
    result = subprocess.run(cmd, text=True, capture_output=True, errors="replace", timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"tshark не смог прочитать PCAPNG: {(result.stderr or result.stdout)[-4000:]}")
    reader = csv.DictReader(result.stdout.splitlines(), delimiter="\t", quotechar='"')
    rows = [normalize_field_row(row, mapping) for row in reader]
    rows.sort(key=lambda r: (r.get("frame_number") if r.get("frame_number") is not None else 0))
    return rows, fields


def urb_class(value: Any) -> str:
    s = str(value or "").strip().upper()
    if s in {"S", "SUBMIT"} or s.startswith("SUBMIT"):
        return "S"
    if s in {"C", "COMPLETE", "COMPLETED"} or s.startswith("COMPLETE"):
        return "C"
    if s in {"E", "ERROR"} or s.startswith("ERROR"):
        return "E"
    return "?"


def build_transfer_groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pair USBPcap URB submit/completion rows while respecting reused URB IDs."""
    groups: list[dict[str, Any]] = []
    pending: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)

    def make_group(row: dict[str, Any]) -> dict[str, Any]:
        g = {"rows": [row], "request": row.get("request"), "first_time": row.get("time_epoch"),
             "last_time": row.get("time_epoch"), "frame_numbers": [row.get("frame_number")],
             "bus_id": row.get("bus_id"), "device_address": row.get("device_address"),
             "urb_id": row.get("urb_id"), "urb_types": [urb_class(row.get("urb_type"))]}
        groups.append(g)
        return g

    for row in rows:
        urbid = row.get("urb_id")
        bus = str(row.get("bus_id") if row.get("bus_id") is not None else "?")
        key = (bus, str(urbid)) if urbid else None
        typ = urb_class(row.get("urb_type"))
        if key and typ == "S":
            g = make_group(row)
            pending[key].append(g)
            continue
        if key and typ in {"C", "E"}:
            queue = pending.get(key)
            if queue:
                g = queue.popleft()
                if not queue:
                    pending.pop(key, None)
                g["rows"].append(row)
                g["last_time"] = row.get("time_epoch")
                g["frame_numbers"].append(row.get("frame_number"))
                g["urb_types"].append(typ)
                if g.get("request") is None and row.get("request") is not None:
                    g["request"] = row.get("request")
                if g.get("device_address") is None:
                    g["device_address"] = row.get("device_address")
                continue
            make_group(row)
            continue
        if key and pending.get(key):
            g = pending[key][-1]
            g["rows"].append(row)
            g["last_time"] = row.get("time_epoch")
            g["frame_numbers"].append(row.get("frame_number"))
            g["urb_types"].append(typ)
            if g.get("request") is None and row.get("request") is not None:
                g["request"] = row.get("request")
            continue
        make_group(row)
    for g in groups:
        if g.get("request") is None:
            g["request"] = next((x.get("request") for x in g["rows"] if x.get("request") is not None), None)
        g["time_epoch"] = next((x.get("time_epoch") for x in g["rows"] if x.get("request") is not None and x.get("time_epoch") is not None), g.get("first_time"))
        g["payload"] = choose_payload(g["rows"])
        g["status"] = transfer_status(g["rows"])
        g["complete_seen"] = "C" in g.get("urb_types", [])
        g["is_urb_error"] = "E" in g.get("urb_types", [])
        g["frame_numbers"] = sorted({n for n in g.get("frame_numbers", []) if n is not None})
    groups.sort(key=lambda g: (g.get("time_epoch") if g.get("time_epoch") is not None else -1, g["frame_numbers"][0] if g["frame_numbers"] else -1))
    return groups


def choose_payload(rows: list[dict[str, Any]]) -> bytes | None:
    candidates: list[tuple[int, int, bytes]] = []
    for row in rows:
        for rank, key in enumerate(("get_descriptor_response", "control_response", "capdata")):
            value = row.get(key)
            parsed = parse_hex_field(value)
            if parsed is not None:
                complete_bonus = 1 if urb_class(row.get("urb_type")) in {"C", "E"} else 0
                candidates.append((rank, -len(parsed), parsed))
    if not candidates:
        return None
    # Prefer parsed descriptor/control-response fields, then the longest capture.
    candidates.sort(key=lambda x: (x[0], x[1]))
    return candidates[0][2]


def transfer_status(rows: list[dict[str, Any]]) -> str:
    saw_status = False
    for row in rows:
        raw = row.get("urb_status")
        if raw is None or raw == "":
            continue
        saw_status = True
        n = parse_int(raw)
        if n is not None and n != 0:
            return "ERROR"
        low = str(raw).lower()
        if any(s in low for s in ("stall", "error", "timeout", "failed", "cancelled", "canceled")):
            return "ERROR"
    if any(urb_class(r.get("urb_type")) == "E" for r in rows):
        return "ERROR"
    if any(urb_class(r.get("urb_type")) == "C" for r in rows):
        return "COMPLETED" if saw_status else "COMPLETION_FRAME_OBSERVED"
    return "SUBMITTED_ONLY"


def descriptor_name(dtype: int, index: int, lang: int = 0, iface: int | None = None) -> str:
    base = DESC_NAMES.get(dtype, f"Unknown type 0x{dtype:02x}")
    suffix = f"index={index}"
    if dtype == 3:
        suffix += f", lang=0x{lang:04x}"
    if dtype == 0x22 and iface is not None:
        suffix += f", interface={iface}"
    return f"{base} ({suffix})"


def case_expected(profile: dict[str, Any], verifier: Any) -> tuple[dict[tuple[int, int, int], bytes], list[dict[str, Any]]]:
    standard = verifier.build_expected_descriptors(profile)
    catalog: list[dict[str, Any]] = []
    seen = set()
    for (dtype, index, lang), data in standard.items():
        key = (dtype, index, lang)
        seen.add(key)
        catalog.append({"type": dtype, "index": index, "language_id": lang, "interface": None,
                        "configuration_value": None, "key": key, "name": descriptor_name(dtype, index, lang),
                        "bytes": data, "expected_hex": data.hex()})
    # Interface-specific HID report descriptors override the generic 34:0 descriptor.
    for key_text, value in (profile.get("interface_descriptors") or {}).items():
        try:
            config_text, interface_text = key_text.split(":", 1)
            config_index, interface = int(config_text, 0), int(interface_text, 0)
            raw = verifier.hexbytes(value)
        except Exception:
            continue
        catalog.append({"type": 0x22, "index": 0, "language_id": 0, "interface": interface,
                        "configuration_value": config_index,
                        "key": (0x22, 0, 0), "name": descriptor_name(0x22, 0, 0, interface),
                        "bytes": raw, "expected_hex": raw.hex()})
    catalog.sort(key=lambda x: (x["type"], x["index"], x.get("language_id") or 0,
                                x.get("configuration_value") if x.get("configuration_value") is not None else -1,
                                x.get("interface") if x.get("interface") is not None else -1))
    return standard, catalog


def resolve_expected(profile: dict[str, Any], standard: dict[tuple[int, int, int], bytes],
                     dtype: int, index: int, windex: int, active_config_value: int) -> tuple[bytes | None, str]:
    if dtype == 0x22:
        override = profile.get("interface_descriptors") or {}
        # The key is configuration-array index : interface number.
        key = f"{active_config_value}:{windex}"
        if key in override:
            try:
                return bytes.fromhex(re.sub(r"\s+", "", str(override[key]))), f"interface_descriptors[{key}]"
            except ValueError:
                return None, f"interface_descriptors[{key}] (invalid hex)"
    lang = windex if dtype == 3 else 0
    found = standard.get((dtype, index, lang))
    if found is None and dtype == 3:
        found = standard.get((dtype, index, 0))
    if found is not None:
        return found, f"descriptor type={dtype} index={index}"
    return None, "not defined in profile"


def bytes_diff(expected: bytes, actual: bytes | None) -> dict[str, Any]:
    if actual is None:
        return {"status": "HOST_BYTES_NOT_EXTRACTED", "first_diff_offset": None, "different_offsets": []}
    limit = min(len(expected), len(actual))
    different = [i for i in range(limit) if expected[i] != actual[i]]
    first = different[0] if different else None
    if len(expected) != len(actual):
        first = min(len(expected), len(actual)) if first is None else first
    if not different and len(expected) == len(actual):
        status = "MATCH"
    else:
        status = "MISMATCH"
    return {"status": status, "first_diff_offset": first, "different_offsets": different,
            "expected_length": len(expected), "actual_length": len(actual)}


def describe_descriptor(dtype: int, data: bytes) -> list[str]:
    """Decode common standard descriptor headers, preserving raw bytes elsewhere."""
    lines: list[str] = []
    if len(data) >= 2:
        lines.append(f"bLength={data[0]} (0x{data[0]:02x})")
        lines.append(f"bDescriptorType={data[1]} (0x{data[1]:02x})")
    if dtype == 1 and len(data) >= 18:
        bcdusb = data[2] | data[3] << 8
        bcddev = data[12] | data[13] << 8
        vid = data[8] | data[9] << 8
        pid = data[10] | data[11] << 8
        lines.extend([f"bcdUSB=0x{bcdusb:04x}", f"bDeviceClass=0x{data[4]:02x}",
                      f"bDeviceSubClass=0x{data[5]:02x}", f"bDeviceProtocol=0x{data[6]:02x}",
                      f"bMaxPacketSize0={data[7]} (0x{data[7]:02x})", f"idVendor=0x{vid:04x}",
                      f"idProduct=0x{pid:04x}", f"bcdDevice=0x{bcddev:04x}",
                      f"iManufacturer={data[14]}", f"iProduct={data[15]}", f"iSerialNumber={data[16]}",
                      f"bNumConfigurations={data[17]}"])
    elif dtype == 2 and len(data) >= 9:
        total = data[2] | data[3] << 8
        lines.extend([f"wTotalLength={total} (0x{total:04x})", f"bNumInterfaces={data[4]}",
                      f"bConfigurationValue={data[5]}", f"iConfiguration={data[6]}",
                      f"bmAttributes=0x{data[7]:02x}", f"bMaxPower={data[8]} (2 mA units for USB 2.0)"])
        off = 9
        while off + 2 <= len(data):
            length = data[off]
            stype = data[off + 1]
            if length < 2:
                lines.append(f"offset {off}: malformed bLength={length}; stop decoding")
                break
            if off + length > len(data):
                lines.append(f"offset {off}: descriptor type=0x{stype:02x}, bLength={length} exceeds captured bytes")
                break
            chunk = data[off:off+length]
            if stype == 4 and length >= 9:
                lines.append(f"offset {off}: Interface number={chunk[2]}, alternate={chunk[3]}, endpoints={chunk[4]}, class=0x{chunk[5]:02x}, subclass=0x{chunk[6]:02x}, protocol=0x{chunk[7]:02x}")
            elif stype == 5 and length >= 7:
                packet = chunk[4] | chunk[5] << 8
                lines.append(f"offset {off}: Endpoint address=0x{chunk[2]:02x}, attributes=0x{chunk[3]:02x}, max_packet={packet}, interval={chunk[6]}")
            elif stype == 0x21 and length >= 6:
                lines.append(f"offset {off}: HID bcdHID=0x{(chunk[2] | chunk[3]<<8):04x}, country={chunk[4]}, subordinate_count={chunk[5]}")
            else:
                lines.append(f"offset {off}: subdescriptor type=0x{stype:02x}, len={length}")
            off += length
    elif dtype == 3 and len(data) >= 2:
        try:
            text = data[2:].decode("utf-16le", errors="replace")
            lines.append(f"String={text!r}")
        except Exception:
            pass
    elif dtype == 4 and len(data) >= 9:
        lines.extend([f"bInterfaceNumber={data[2]}", f"bAlternateSetting={data[3]}",
                      f"bNumEndpoints={data[4]}", f"bInterfaceClass=0x{data[5]:02x}",
                      f"bInterfaceSubClass=0x{data[6]:02x}", f"bInterfaceProtocol=0x{data[7]:02x}", f"iInterface={data[8]}"])
    elif dtype == 5 and len(data) >= 7:
        lines.extend([f"bEndpointAddress=0x{data[2]:02x}", f"bmAttributes=0x{data[3]:02x}",
                      f"wMaxPacketSize={data[4] | data[5]<<8}", f"bInterval={data[6]}"])
    elif dtype == 0x22:
        lines.append("HID Report Descriptor: raw report-item bytes (no claim of semantic parsing)")
    return lines


def hex_lines(data: bytes | None, expected: bytes | None = None) -> list[dict[str, Any]]:
    if data is None:
        return []
    out = []
    for base in range(0, len(data), 16):
        row = []
        for offset in range(base, min(base + 16, len(data))):
            value = data[offset]
            exp_value = expected[offset] if expected is not None and offset < len(expected) else None
            row.append({"offset": offset, "hex": f"{value:02X}",
                        "different": exp_value is not None and exp_value != value,
                        "expected_missing": expected is not None and offset >= len(expected)})
        out.append({"offset": base, "bytes": row})
    return out


def byte_diff_text(expected: bytes, actual: bytes | None) -> str:
    if actual is None:
        return "Байты ответа не удалось извлечь из USBPcap."
    lines = ["offset | expected | USBPcap | result", "-------+----------+---------+-------"]
    max_len = max(len(expected), len(actual))
    for off in range(max_len):
        e = f"{expected[off]:02X}" if off < len(expected) else "--"
        a = f"{actual[off]:02X}" if off < len(actual) else "--"
        mark = "==" if off < len(expected) and off < len(actual) and expected[off] == actual[off] else "!!"
        lines.append(f"{off:04X}   | {e:>8} | {a:>7} | {mark}")
    return "\n".join(lines)


def case_profile_path(row: dict[str, Any], campaign_dir: Path) -> Path:
    raw = row.get("profile")
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = (ROOT / p).resolve()
        if p.is_file():
            return p
    num = int(row.get("case", 0))
    return campaign_dir / f"case-{num:05d}.json"


def case_trace_path(row: dict[str, Any], campaign_dir: Path) -> Path | None:
    raw = row.get("trace")
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = (ROOT / p).resolve()
        return p
    num = int(row.get("case", 0))
    p = campaign_dir / "traces" / f"case-{num:05d}.device.jsonl"
    return p


def event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(e.get("event", "UNKNOWN")) for e in events)
    config_values = [int(e.get("configuration_value") or 0) for e in events
                     if e.get("event") == "SET_CONFIGURATION" and e.get("configuration_value") is not None]
    return {
        "event_counts": dict(sorted(counts.items())),
        "get_descriptor_requests": [e.get("request") for e in events
                                     if e.get("event") == "CONTROL_REQUEST" and
                                     isinstance(e.get("request"), dict) and int(e["request"].get("bRequest", -1)) == 6],
        "control_request_count": counts["CONTROL_REQUEST"],
        "control_response_complete_count": counts["CONTROL_RESPONSE_COMPLETE"],
        "configuration_values": config_values,
        "configured_observed": any(v != 0 for v in config_values),
        "stall_count": counts["CONTROL_STALL"],
        "reset_count": counts["USB_RESET"] + counts["USB_RESET_OR_DISCONNECT"],
        "disconnect_count": sum(v for k, v in counts.items() if "DISCONNECT" in k),
        "error_count": sum(v for k, v in counts.items() if "ERROR" in k or "FAILED" in k or "MALFORMED" in k),
    }


def make_expected_display(profile: dict[str, Any], verifier: Any) -> tuple[dict, list[dict]]:
    standard, catalog = case_expected(profile, verifier)
    display = []
    for item in catalog:
        data = item["bytes"]
        display.append({k: v for k, v in item.items() if k != "bytes"} | {
            "expected_hex": data.hex(), "length": len(data),
            "decoded": describe_descriptor(item["type"], data),
            "hex_lines": hex_lines(data),
        })
    return standard, display


def device_trace_descriptor_summary(events: list[dict[str, Any]], profile: dict[str, Any] | None,
                                    standard: dict[tuple[int, int, int], bytes]) -> list[dict[str, Any]]:
    """List GET_DESCRIPTOR exchanges recorded by Raw Gadget; this is not host-PCAP evidence."""
    pending: dict[tuple[int, int, int, int, int], deque[dict[str, Any]]] = defaultdict(deque)
    result = []
    active_config_value = 0
    def key_of(event: dict[str, Any]) -> tuple[int, int, int, int, int] | None:
        req = event.get("request")
        if not isinstance(req, dict):
            return None
        try:
            return tuple(int(req[k]) for k in ("bmRequestType", "bRequest", "wValue", "wIndex", "wLength"))
        except (ValueError, TypeError, KeyError):
            return None
    for event in events:
        name = event.get("event")
        if name == "SET_CONFIGURATION":
            active_config_value = int(event.get("configuration_value") or 0)
        elif name in ("USB_RESET", "USB_RESET_OR_DISCONNECT", "USB_DISCONNECT"):
            active_config_value = 0
        key = key_of(event)
        if name == "CONTROL_REQUEST" and key and key[1] == 6 and key[0] & 0x80:
            pending[key].append({"sequence": event.get("sequence"), "request": event.get("request")})
        elif name == "CONTROL_RESPONSE_COMPLETE" and key and key[1] == 6 and key[0] & 0x80:
            req_item = pending[key].popleft() if pending.get(key) else {"sequence": None, "request": event.get("request")}
            req = event.get("request") or {}
            dtype, index = (int(req.get("wValue", 0)) >> 8) & 0xff, int(req.get("wValue", 0)) & 0xff
            windex, wlength = int(req.get("wIndex", 0)), int(req.get("wLength", 0))
            expected, source = resolve_expected(profile or {}, standard, dtype, index, windex, active_config_value)
            actual = parse_hex_field(event.get("payload_hex"))
            exp = expected[:wlength] if expected is not None else None
            diff = bytes_diff(exp, actual) if exp is not None else {"status": "NOT_DEFINED_IN_PROFILE"}
            result.append({"request_sequence": req_item.get("sequence"), "response_sequence": event.get("sequence"),
                           "name": descriptor_name(dtype, index, windex if dtype == 3 else 0, windex if dtype == 0x22 else None),
                           "expected_source": source, "expected_length": len(exp) if exp is not None else None,
                           "trace_length": len(actual) if actual is not None else None,
                           "result": diff.get("status"), "expected_hex": exp.hex() if exp is not None else None,
                           "trace_payload_hex": actual.hex() if actual is not None else None})
    return result


def render_case(row: dict[str, Any], profile_path: Path, trace_path: Path | None,
                profile: dict[str, Any] | None, device_events: list[dict[str, Any]],
                host_groups: list[dict[str, Any]], verifier: Any,
                time_tolerance: float, clock_offset: float) -> dict[str, Any]:
    case_no = int(row.get("case", 0))
    run_status = str(row.get("status", "NOT_RUN"))
    started = row.get("started_epoch")
    ended = row.get("ended_epoch")
    if started is not None:
        try: started = float(started)
        except (TypeError, ValueError): started = None
    if ended is not None:
        try: ended = float(ended)
        except (TypeError, ValueError): ended = None
    per_case_groups: list[dict[str, Any]] = []
    if started is not None:
        end = ended if ended is not None else started + float(row.get("dwell_seconds_requested", 10) or 10)
        # Clock offset means host-capture epoch minus Pi epoch; subtract to align to Pi.
        for g in host_groups:
            t = g.get("time_epoch")
            if t is not None and started - time_tolerance <= (t - clock_offset) <= end + time_tolerance:
                per_case_groups.append(g)
    if run_status in ("NOT_RUN", "DRY_RUN_ONLY", "GENERATED", "NO_CHANGE", "START_FAILED", "LAUNCH_ERROR"):
        # No reliable device emission window exists, so do not attach bus traffic to this profile.
        per_case_groups = []
    if profile is None:
        standard, catalog = {}, []
        profile_error = f"не удалось прочитать профиль: {profile_path}"
    else:
        try:
            standard, catalog = case_expected(profile, verifier)
            profile_error = None
        except Exception as exc:
            standard, catalog = {}, []
            profile_error = str(exc)

    config_values_expected = []
    if profile:
        for cfg in profile.get("configurations", []):
            try: config_values_expected.append(int(cfg.get("bConfigurationValue", 1)))
            except (ValueError, TypeError): pass

    descriptor_transactions = []
    active_config_value = 0
    host_set_configs = []
    host_errors = []
    host_control_requests = 0
    data_transfers = []
    for g in sorted(per_case_groups, key=lambda x: (x.get("time_epoch") or 0, x.get("frame_numbers", [0])[0] if x.get("frame_numbers") else 0)):
        req = g.get("request")
        if not isinstance(req, dict):
            if g.get("status") == "ERROR":
                host_errors.append({"frames": g.get("frame_numbers", []), "status": g.get("status"), "endpoint": g.get("endpoint_address")})
            continue
        brequest = req.get("bRequest")
        bm = req.get("bmRequestType", 0) or 0
        wvalue = req.get("wValue", 0) or 0
        windex = req.get("wIndex", 0) or 0
        wlength = req.get("wLength", 0) or 0
        host_control_requests += 1
        if g.get("status") == "ERROR":
            host_errors.append({"frames": g.get("frame_numbers", []), "status": g.get("status"), "request": req})
        if brequest == 9:
            value = wvalue & 0xff
            host_set_configs.append({"value": value, "frames": g.get("frame_numbers", []),
                                     "status": g.get("status"), "complete_seen": g.get("complete_seen", False),
                                     "error": g.get("is_urb_error", False) or g.get("status") == "ERROR"})
            active_config_value = value
            continue
        if brequest == 6 and (bm & 0x80):
            dtype, dindex = (wvalue >> 8) & 0xff, wvalue & 0xff
            expected, source = resolve_expected(profile or {}, standard, dtype, dindex, windex, active_config_value)
            actual = g.get("payload")
            expected_truncated = expected[:wlength] if expected is not None else None
            diff = bytes_diff(expected_truncated, actual) if expected_truncated is not None else {
                "status": "NOT_DEFINED_IN_PROFILE", "first_diff_offset": None, "different_offsets": []}
            status = diff["status"]
            if expected is None:
                status = "UNEXPECTED_OR_UNDEFINED_DESCRIPTOR"
            descriptor_transactions.append({
                "time_epoch": g.get("time_epoch"), "frames": g.get("frame_numbers", []),
                "bus_id": g.get("bus_id"), "device_address": g.get("device_address"),
                "urb_id": g.get("urb_id"), "urb_types": g.get("urb_types"),
                "request": req, "descriptor_type": dtype, "descriptor_index": dindex,
                "language_id": windex if dtype == 3 else 0,
                "interface": windex if dtype == 0x22 else None,
                "descriptor_name": descriptor_name(dtype, dindex, windex if dtype == 3 else 0, windex if dtype == 0x22 else None),
                "expected_source": source,
                "expected_hex": expected_truncated.hex() if expected_truncated is not None else None,
                "actual_hex": actual.hex() if actual is not None else None,
                "expected_length": len(expected_truncated) if expected_truncated is not None else None,
                "actual_length": len(actual) if actual is not None else None,
                "result": status, "first_diff_offset": diff.get("first_diff_offset"),
                "different_offsets": diff.get("different_offsets", []),
                "byte_table": byte_diff_text(expected_truncated, actual) if expected_truncated is not None else "В профиле нет ожидаемого ответа для этого запроса.",
                "expected_decoded": describe_descriptor(dtype, expected_truncated) if expected_truncated is not None else [],
                "actual_decoded": describe_descriptor(dtype, actual) if actual is not None else [],
                "expected_hex_lines": hex_lines(expected_truncated) if expected_truncated is not None else [],
                "actual_hex_lines": hex_lines(actual, expected_truncated) if actual is not None else [],
                "host_transfer_status": g.get("status"),
                "payload_available": actual is not None,
            })
        elif g.get("endpoint_address") is not None and g.get("payload") is not None:
            data_transfers.append({"frames": g.get("frame_numbers", []), "endpoint_address": g.get("endpoint_address"),
                                   "payload_hex": g["payload"].hex(), "status": g.get("status")})

    # A case must not inherit unrelated host frames as positive evidence when the gadget never started.
    if run_status in ("NOT_RUN", "DRY_RUN_ONLY", "GENERATED", "NO_CHANGE") and started is None:
        verdict = "NOT_RUN_NOT_CAPTURE_MATCHABLE"
    elif run_status in ("START_FAILED", "LAUNCH_ERROR"):
        verdict = "DEVICE_START_FAILED"
    elif profile_error:
        verdict = "PROFILE_BYTES_UNAVAILABLE"
    elif not per_case_groups or not any(g.get("request") for g in per_case_groups):
        verdict = "NO_HOST_EVIDENCE_FOR_CASE"
    elif any(t["result"] == "MISMATCH" for t in descriptor_transactions):
        verdict = "HOST_DESCRIPTOR_BYTES_MISMATCH"
    elif host_errors:
        verdict = "HOST_TRANSFER_ERROR_OBSERVED"
    elif any(t["result"] == "HOST_BYTES_NOT_EXTRACTED" for t in descriptor_transactions):
        verdict = "HOST_RESPONSE_BYTES_UNAVAILABLE"
    elif any(t["result"] == "UNEXPECTED_OR_UNDEFINED_DESCRIPTOR" for t in descriptor_transactions):
        verdict = "HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE"
    elif descriptor_transactions and all(t["result"] == "MATCH" for t in descriptor_transactions):
        host_cfg_ok = any(c["value"] != 0 and c["complete_seen"] and not c["error"] for c in host_set_configs)
        device_summary = event_summary(device_events)
        if host_cfg_ok and device_summary["configured_observed"]:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED"
        elif host_cfg_ok or device_summary["configured_observed"]:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL"
        else:
            verdict = "EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE"
    elif descriptor_transactions:
        verdict = "PARTIAL_DESCRIPTOR_CHECK"
    else:
        verdict = "HOST_CONTROL_TRAFFIC_OBSERVED_NO_DESCRIPTOR_RESPONSE"

    if profile is None:
        catalogue_display = []
        changed_fields = []
    else:
        _, catalogue_display = make_expected_display(profile, verifier)
        changed_fields = row.get("changes") or []
    device_sum = event_summary(device_events)
    trace_descriptor_transactions = device_trace_descriptor_summary(device_events, profile, standard) if profile else []
    requested_keys = {(x["descriptor_type"], x["descriptor_index"], x["language_id"], x.get("interface"))
                      for x in descriptor_transactions}
    for item in catalogue_display:
        key = (item["type"], item["index"], item.get("language_id", 0), item.get("interface"))
        item["observed_in_pcap"] = key in requested_keys
        item["capture_state"] = "OBSERVED_IN_PCAP" if key in requested_keys else "NOT_OBSERVED_IN_PCAP"
        if item["type"] == 0x22 and item.get("interface") is None and profile and profile.get("interface_descriptors"):
            item["capture_state"] = "GENERIC_REPORT_OVERRIDDEN_BY_INTERFACE_DESCRIPTOR"
            item["observed_in_pcap"] = any(t["descriptor_type"] == 0x22 for t in descriptor_transactions)
    return {
        "case": case_no, "profile": str(profile_path), "profile_name": profile.get("profile_name") if profile else None,
        "profile_sha256": row.get("profile_sha256") or row.get("sha256"), "run_status": run_status,
        "run_started_epoch": started, "run_ended_epoch": ended, "duration_seconds": row.get("duration_seconds"),
        "returncode": row.get("returncode"), "trace": str(trace_path) if trace_path else None,
        "profile_error": profile_error, "changes": changed_fields, "verdict": verdict,
        "time_window": {"start_epoch": started, "end_epoch": ended, "tolerance_seconds": time_tolerance,
                        "host_clock_offset_seconds": clock_offset},
        "device_trace_summary": device_sum,
        "host_groups_in_window": len(per_case_groups), "host_control_requests_in_window": host_control_requests,
        "host_set_configuration": host_set_configs, "host_errors": host_errors,
        "descriptor_transactions": descriptor_transactions,
        "device_trace_descriptor_transactions": trace_descriptor_transactions,
        "expected_descriptor_catalogue": catalogue_display,
        "non_control_payload_transfers": data_transfers,
        "note": "PCAP/USBPcap shows host-stack observations. A single campaign PCAP is partitioned by timestamps; synchronize clocks and review ambiguous frames. USBPcap is not an electrical USB analyzer."
    }


def human_verdict(code: str) -> str:
    return {
        "HOST_CORRELATION_AMBIGUOUS_SHARED_FRAMES": "КОРРЕЛЯЦИЯ НЕОДНОЗНАЧНА — кадры попали в несколько временных окон",
        "NOT_RUN_NOT_CAPTURE_MATCHABLE": "СЛУЧАЙ НЕ ЗАПУСКАЛСЯ — USBPcap не сопоставляется",
        "DEVICE_START_FAILED": "УСТРОЙСТВО НЕ СТАРТОВАЛО — трафик этому случаю не приписываем",
        "PROFILE_BYTES_UNAVAILABLE": "НЕ УДАЛОСЬ СОБРАТЬ ОЖИДАЕМЫЕ ДЕСКРИПТОРЫ ИЗ ПРОФИЛЯ",
        "NO_HOST_EVIDENCE_FOR_CASE": "НЕТ USB-НАБЛЮДЕНИЙ В ОКНЕ ЭТОГО СЛУЧАЯ",
        "HOST_DESCRIPTOR_BYTES_MISMATCH": "ОШИБКА: БАЙТЫ ДЕСКРИПТОРА В USBPcap НЕ СОВПАЛИ С ПРОФИЛЕМ",
        "HOST_TRANSFER_ERROR_OBSERVED": "НАБЛЮДАЛАСЬ ОШИБКА ПЕРЕДАЧИ ХОСТА — НУЖНА ПРОВЕРКА",
        "HOST_RESPONSE_BYTES_UNAVAILABLE": "ЗАПРОС ВИДЕН, НО БАЙТЫ ОТВЕТА НЕ ИЗВЛЕЧЕНЫ",
        "HOST_REQUESTED_DESCRIPTOR_NOT_DEFINED_IN_PROFILE": "ХОСТ ЗАПРОСИЛ ДЕСКРИПТОР, НЕ ОПИСАННЫЙ В ПРОФИЛЕ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED": "БАЙТЫ ДЕСКРИПТОРОВ СОВПАЛИ; CONFIGURED НАБЛЮДАЛСЯ НА ХОСТЕ И УСТРОЙСТВЕ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURATION_PARTIAL": "БАЙТЫ ДЕСКРИПТОРОВ СОВПАЛИ; CONFIGURED ПОДТВЕРЖДЁН ТОЛЬКО ОДНИМ ИСТОЧНИКОМ",
        "EXPECTED_DESCRIPTOR_BYTES_MATCH_ENUMERATION_INCOMPLETE": "БАЙТЫ ЗАПРОШЕННЫХ ДЕСКРИПТОРОВ СОВПАЛИ, НО CONFIGURED НЕ ПОДТВЕРЖДЁН",
        "PARTIAL_DESCRIPTOR_CHECK": "ЧАСТИЧНАЯ ПРОВЕРКА ДЕСКРИПТОРОВ",
        "HOST_CONTROL_TRAFFIC_OBSERVED_NO_DESCRIPTOR_RESPONSE": "УПРАВЛЯЮЩИЙ ТРАФИК ЕСТЬ, ОТВЕТЫ НА ДЕСКРИПТОРЫ НЕ НАЙДЕНЫ",
    }.get(code, code)


def build_txt(report: dict[str, Any]) -> str:
    lines = ["USB CAMPAIGN — ПОБАЙТОВЫЙ ОТЧЁТ", "=" * 96,
             f"Кампания: {report['campaign_dir']}", f"PCAP/PCAPNG: {report['host_pcap']}",
             f"Всего случаев: {len(report['cases'])}", "", "СВОДКА СТАТУСОВ:"]
    for status, count in sorted(report["status_counts"].items()):
        lines.append(f"  {status}: {count}")
    lines.extend(["", "ВАЖНО: хостовый захват сопоставляется со случаем по времени. Часы Windows и Pi должны быть синхронизированы.",
                  "USBPcap — наблюдение USB host stack, не анализатор электрической шины."])
    for case in report["cases"]:
        lines.extend(["", "=" * 96,
                      f"CASE {case['case']:05d} | run={case['run_status']} | verdict={case['verdict']}",
                      human_verdict(case['verdict']), f"Профиль: {case['profile']}",
                      f"SHA-256: {case.get('profile_sha256')}", f"Длительность: {case.get('duration_seconds')} s",
                      f"Trace: {case.get('trace')}", f"Host frames/groups in time window: {case['host_groups_in_window']}",
                      f"USB control requests in window: {case['host_control_requests_in_window']}"])
        if case.get("profile_error"):
            lines.append("ОШИБКА ПРОФИЛЯ: " + case["profile_error"])
        lines.append("Изменённые поля:")
        lines.extend("  " + str(x) for x in case.get("changes", [])) if case.get("changes") else lines.append("  (изменения не записаны в manifest)")
        ts = case["device_trace_summary"]
        lines.append(f"Trace: requests={ts['control_request_count']}, responses={ts['control_response_complete_count']}, configured={ts['configured_observed']}, STALL={ts['stall_count']}, reset={ts['reset_count']}, disconnect={ts['disconnect_count']}, errors={ts['error_count']}")
        lines.append("GET_DESCRIPTOR, записанные Raw Gadget (payload trace — отдельное наблюдение, не PCAP):")
        if case.get("device_trace_descriptor_transactions"):
            for item in case["device_trace_descriptor_transactions"]:
                lines.append(f"  {item['name']}: trace={item.get('result')}, request seq={item.get('request_sequence')}, response seq={item.get('response_sequence')}, trace_len={item.get('trace_length')}, expected_len={item.get('expected_length')}")
        else:
            lines.append("  в trace нет завершённых ответов GET_DESCRIPTOR")
        lines.append("SET_CONFIGURATION, замеченный USBPcap:")
        if case["host_set_configuration"]:
            lines.extend(f"  value={x['value']} frames={x['frames']} status={x['status']} complete={x['complete_seen']} error={x['error']}" for x in case["host_set_configuration"])
        else:
            lines.append("  не наблюдался")
        lines.extend(["", "ОТВЕТЫ НА GET_DESCRIPTOR (ОЖИДАЕМЫЕ БАЙТЫ ПРОФИЛЯ VS USBPcap):"])
        if not case["descriptor_transactions"]:
            lines.append("  Не найдено ни одного сопоставимого GET_DESCRIPTOR в окне этого случая.")
        for n, t in enumerate(case["descriptor_transactions"], 1):
            lines.extend(["", f"  [{n}] {t['descriptor_name']} | result={t['result']} | frames={t['frames']} | USB address={t.get('device_address')}",
                          f"      wLength={t['request'].get('wLength')} | expected_len={t.get('expected_length')} | host_len={t.get('actual_length')} | transfer={t.get('host_transfer_status')}",
                          "      " + (f"first diff offset: 0x{t['first_diff_offset']:04X}" if t.get("first_diff_offset") is not None and t['result'] == "MISMATCH" else "байтовое сравнение: " + t['result']),
                          "      PROFILЬ / EXPECTED (HEX):", "      " + (t.get("expected_hex") or "<не определено в профиле>"),
                          "      USBPcap / OBSERVED (HEX):", "      " + (t.get("actual_hex") or "<байты не извлечены>"),
                          "      ПОБАЙТОВО:"])
            lines.extend("      " + ln for ln in t.get("byte_table", "").splitlines())
            if t.get("expected_decoded"):
                lines.append("      Расшифровка expected:")
                lines.extend("        " + x for x in t["expected_decoded"])
            if t.get("actual_decoded"):
                lines.append("      Расшифровка USBPcap:")
                lines.extend("        " + x for x in t["actual_decoded"])
        lines.extend(["", "ДЕСКРИПТОРЫ ИЗ ПРОФИЛЯ, НЕ НАБЛЮДЁННЫЕ В PCAP:"])
        unseen = [x for x in case.get("expected_descriptor_catalogue", []) if x.get("capture_state") == "NOT_OBSERVED_IN_PCAP"]
        if unseen:
            for item in unseen:
                lines.append(f"  {item['name']}: {item['expected_hex']} (NOT_OBSERVED_IN_PCAP; это не доказывает, что хост не запрашивал его вне окна/захвата)")
        else:
            lines.append("  все каталогизированные ключи дескрипторов наблюдались (не обязательно все байты сравнивались)")
        if case.get("host_errors"):
            lines.extend(["", "ОШИБОЧНЫЕ HOST TRANSFERS:"])
            lines.extend(f"  frames={e.get('frames')} status={e.get('status')} request={e.get('request')}" for e in case["host_errors"])
        if case.get("non_control_payload_transfers"):
            lines.extend(["", "НЕ-КОНТРОЛЬНЫЕ ПЕРЕДАЧИ С ДАННЫМИ:"])
            for x in case["non_control_payload_transfers"]:
                lines.append(f"  frames={x['frames']} endpoint=0x{int(x['endpoint_address']):02x} bytes={len(bytes.fromhex(x['payload_hex']))} status={x['status']} hex={x['payload_hex']}")
    lines.append("")
    return "\n".join(lines)


def html_byte_dump(data: bytes | None, expected: bytes | None = None) -> str:
    if data is None:
        return '<p class="missing">Байты ответа не извлечены из PCAPNG.</p>'
    rows = []
    for base in range(0, len(data), 16):
        cells = []
        for offset in range(base, min(base + 16, len(data))):
            value = data[offset]
            mismatch = expected is not None and (offset >= len(expected) or expected[offset] != value)
            cells.append(f'<span class="byte {"bad" if mismatch else "good"}" title="offset 0x{offset:04X}">{value:02X}</span>')
        ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[base:base+16])
        rows.append(f'<div class="hexrow"><span class="offset">{base:04X}</span><code>{" ".join(cells)}</code><span class="ascii">{html.escape(ascii_text)}</span></div>')
    return '<div class="hexdump">' + ''.join(rows) + '</div>'


def descriptor_html(t: dict[str, Any], index: int) -> str:
    status_class = "match" if t["result"] == "MATCH" else ("mismatch" if t["result"] == "MISMATCH" else "warn")
    expected = bytes.fromhex(t["expected_hex"]) if t.get("expected_hex") else None
    actual = bytes.fromhex(t["actual_hex"]) if t.get("actual_hex") else None
    def fields(items: list[str]) -> str:
        return '<ul class="decoded">' + ''.join(f'<li>{html.escape(x)}</li>' for x in items) + '</ul>' if items else '<p class="muted">Нет декодированных полей.</p>'
    return f'''<details class="descriptor" open>
<summary><b>GET_DESCRIPTOR #{index}: {html.escape(t['descriptor_name'])}</b><span class="pill {status_class}">{html.escape(t['result'])}</span><span class="muted">frames {html.escape(str(t['frames']))}; host address {html.escape(str(t.get('device_address')))}</span></summary>
<div class="comparegrid">
<section class="pane expected"><h4>СЛЕВА — ОЖИДАЕМЫЕ БАЙТЫ ПРОФИЛЯ</h4><p>Источник: {html.escape(t.get('expected_source','profile'))}; длина: {t.get('expected_length')}</p>{html_byte_dump(expected)}<h5>Расшифровка полей</h5>{fields(t.get('expected_decoded',[]))}</section>
<section class="pane observed"><h4>СПРАВА — НАБЛЮДЕНИЕ USBPcap</h4><p>Длина: {t.get('actual_length')}; состояние передачи: {html.escape(str(t.get('host_transfer_status')))}</p>{html_byte_dump(actual, expected)}<h5>Расшифровка полей</h5>{fields(t.get('actual_decoded',[]))}</section>
</div>
<div class="diffline"><b>Результат:</b> {html.escape(t['result'])}. {('Первое отличие: offset 0x%04X' % t['first_diff_offset']) if t.get('first_diff_offset') is not None else 'Первое отличие не обнаружено.'}</div>
<details><summary>Побайтовая таблица</summary><pre>{html.escape(t.get('byte_table',''))}</pre></details>
</details>'''


def build_html(report: dict[str, Any]) -> str:
    cards = []
    for case in report["cases"]:
        case_class = "bad" if ("MISMATCH" in case["verdict"] or "ERROR" in case["verdict"] or "FAILED" in case["verdict"]) else ("good" if case["verdict"] == "EXPECTED_DESCRIPTOR_BYTES_MATCH_CONFIGURED_OBSERVED" else "warn")
        changes = ''.join(f'<li>{html.escape(str(x))}</li>' for x in case.get("changes", [])) or '<li class="muted">Нет записанных мутаций.</li>'
        descriptor_parts = ''.join(descriptor_html(t, i) for i, t in enumerate(case.get("descriptor_transactions", []), 1))
        if not descriptor_parts:
            descriptor_parts = '<p class="missing">Временное окно этого случая не содержит сопоставимых GET_DESCRIPTOR-запросов в захвате.</p>'
        unseen = [x for x in case.get("expected_descriptor_catalogue", []) if x.get("capture_state") == "NOT_OBSERVED_IN_PCAP"]
        unseen_html = ''.join(f'<details><summary>{html.escape(x["name"])} — ожидаемо, в PCAP не замечено</summary><pre>{html.escape(x["expected_hex"])}</pre>{html_byte_dump(bytes.fromhex(x["expected_hex"]))}</details>' for x in unseen)
        events = case["device_trace_summary"]
        setcfg = ''.join(f'<li>value={x["value"]}; frames={html.escape(str(x["frames"]))}; transfer={html.escape(str(x["status"]))}; complete={x["complete_seen"]}; error={x["error"]}</li>' for x in case["host_set_configuration"]) or '<li>SET_CONFIGURATION не наблюдался в PCAP.</li>'
        cards.append(f'''<details class="case {case_class}" open>
<summary><span class="case-title">CASE {case['case']:05d}</span><span class="pill {case_class}">{html.escape(case['verdict'])}</span><span class="muted">run={html.escape(case['run_status'])}; host groups={case['host_groups_in_window']}</span></summary>
<div class="meta"><p><b>Профиль:</b> {html.escape(case['profile'])}</p><p><b>SHA-256:</b> <code>{html.escape(str(case.get('profile_sha256')))}</code></p><p><b>Trace:</b> {html.escape(str(case.get('trace')))}</p><p><b>События на Pi:</b> control requests={events['control_request_count']}, completed EP0={events['control_response_complete_count']}, CONFIGURED={events['configured_observed']}, STALL={events['stall_count']}, reset={events['reset_count']}, disconnect={events['disconnect_count']}, errors={events['error_count']}</p>{''.join('<p class="missing">'+html.escape(str(w))+'</p>' for w in case.get('warnings', []))}</div>
<h3>Что изменено в этом профиле</h3><ul>{changes}</ul>
<h3>Что Raw Gadget записал в trace</h3><ul>{''.join(f'<li>{html.escape(str(x["name"]))}: trace={html.escape(str(x.get("result")))}, request seq={html.escape(str(x.get("request_sequence")))}, response seq={html.escape(str(x.get("response_sequence")))}, байт={html.escape(str(x.get("trace_length")))} / expected={html.escape(str(x.get("expected_length")))}</li>' for x in case.get("device_trace_descriptor_transactions", [])) or '<li>Нет завершённых ответов GET_DESCRIPTOR в trace.</li>'}</ul>
<h3>События SET_CONFIGURATION в хостовом захвате</h3><ul>{setcfg}</ul>
<h3>Побайтовая проверка дескрипторов</h3>{descriptor_parts}
<h3>Ожидаемые дескрипторы, не замеченные в PCAP</h3>{unseen_html or '<p>Все ожидаемые ключи дескрипторов были замечены в захвате (это не гарантирует наличие данных по каждому запросу).</p>'}
</details>''')
    counts = ''.join(f'<div class="summarybox"><b>{n}</b><span>{html.escape(s)}</span></div>' for s, n in sorted(report["status_counts"].items()))
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>USB campaign byte report</title>
<style>
:root{{color-scheme:light dark;--border:#7d8790;--bg:#12171c;--panel:#1c242c;--text:#e8edf2;--muted:#aeb8c2;--ok:#214d38;--bad:#6c252a;--warn:#5d4a1f;--byte:#313b45}}
body{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--bg);color:var(--text);margin:0;padding:22px;line-height:1.42}}h1,h2,h3,h4,h5{{font-family:system-ui,sans-serif}}h1{{margin:0 0 6px}}h2{{margin-top:26px}}.meta,.muted{{color:var(--muted);overflow-wrap:anywhere}}.summary{{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0}}.summarybox{{border:1px solid var(--border);border-radius:8px;padding:10px;min-width:130px;display:flex;flex-direction:column;gap:5px}}.summarybox b{{font-size:22px}}.case{{border:1px solid var(--border);border-radius:10px;margin:14px 0;padding:12px;background:var(--panel)}}summary{{cursor:pointer;display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:4px}}.case-title{{font-size:18px;font-weight:bold}}.pill{{padding:3px 8px;border-radius:5px;font-size:12px;overflow-wrap:anywhere}}.pill.match,.pill.good{{background:var(--ok)}}.pill.mismatch,.pill.bad{{background:var(--bad)}}.pill.warn{{background:var(--warn)}}.comparegrid{{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;margin:10px 0}}.pane{{min-width:0;border:1px solid var(--border);border-radius:8px;padding:10px}}.pane h4{{margin:0 0 10px}}.expected{{border-top:4px solid #3f9a64}}.observed{{border-top:4px solid #c18d41}}.hexdump{{overflow-x:auto;background:#0e1216;padding:8px;border-radius:5px}}.hexrow{{display:flex;gap:8px;white-space:nowrap}}.offset{{color:#8da0b3;min-width:42px}}.ascii{{color:#93a5b7;margin-left:8px}}.byte{{display:inline-block;padding:1px 2px;border-radius:2px;margin-right:1px;background:var(--byte)}}.byte.bad{{background:#a72f39;color:#fff;font-weight:bold}}.byte.good{{background:#254633}}.missing{{color:#ffbd8f;border:1px solid #9a653d;padding:10px;border-radius:5px}}.decoded{{margin-top:7px;padding-left:20px;overflow-wrap:anywhere}}.diffline{{margin:10px 0;padding:8px;background:#0e1216;border-radius:5px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1216;padding:10px;border-radius:5px}}.note{{border-left:4px solid #c18d41;padding:10px;margin:12px 0}}@media(max-width:850px){{.comparegrid{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>USB Research Toolkit — побайтовый отчёт кампании</h1><p class="meta">Кампания: {html.escape(report['campaign_dir'])}<br>PCAPNG: {html.escape(report['host_pcap'])}<br>Generated: {html.escape(report['created_utc'])}</p>
<div class="note">Левая панель — ожидаемые байты из конкретного JSON-профиля. Правая — данные ответа, извлечённые TShark из USBPcap. Это наблюдение на уровне host stack, не подтверждение электрических USB-пакетов. Обработка привязана ко времени записи кампании; при несинхронизированных часах сопоставление может быть неверным.</div>
<div class="summary">{counts}</div>
<h2>Случаи</h2>{''.join(cards)}
</body></html>'''


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Побайтовый отчёт всей USB-фаззинг-кампании: ожидаемые дескрипторы профиля слева, USBPcap справа (TXT + HTML + JSON).")
    ap.add_argument("--campaign-dir", required=True, help="каталог кампании с campaign.jsonl, case-*.json, traces/")
    ap.add_argument("--host-pcap", required=True, help="один PCAP/PCAPNG со всей кампанией")
    ap.add_argument("--out-prefix", help="префикс выходных файлов (по умолчанию <campaign-dir>/protocol-report)")
    ap.add_argument("--tshark", default="tshark", help="путь к tshark")
    ap.add_argument("--time-tolerance", type=float, default=0.75, help="допуск по границам временного окна случая, секунды")
    ap.add_argument("--host-clock-offset-seconds", type=float, default=0.0,
                    help="разница часов host minus Pi; это значение будет вычитаться из времени PCAP для сопоставления")
    args = ap.parse_args(argv)
    campaign_dir = Path(args.campaign_dir).resolve()
    pcap = Path(args.host_pcap).resolve()
    if not campaign_dir.is_dir():
        ap.error(f"каталог кампании не найден: {campaign_dir}")
    if not pcap.is_file():
        ap.error(f"PCAP/PCAPNG не найден: {pcap}")
    if args.time_tolerance < 0:
        ap.error("--time-tolerance должен быть >= 0")
    rows = load_campaign_rows(campaign_dir)
    if not rows:
        # Fallback for older campaign dirs: infer cases from files, but the time mapping cannot be trusted.
        rows = []
        for p in sorted(campaign_dir.glob("case-*.json")):
            m = re.search(r"case-(\d+)", p.name)
            if m:
                rows.append({"case": int(m.group(1)), "profile": str(p), "status": "NOT_RUN",
                             "trace": str(campaign_dir / "traces" / f"case-{int(m.group(1)):05d}.device.jsonl")})
    rows = merge_manifest_cases(campaign_dir, rows)
    if not rows:
        ap.error(f"в {campaign_dir} не найден campaign.jsonl/manifest.json с результатами или case-*.json")
    print(f"Читаю PCAPNG через tshark: {pcap}", flush=True)
    host_rows, fields = read_tshark_rows(pcap, args.tshark)
    host_groups = build_transfer_groups(host_rows)
    print(f"Host frames: {len(host_rows)}; USB transfer groups: {len(host_groups)}; fields: {len(fields)}", flush=True)
    verifier = import_verifier()
    cases = []
    for row in sorted(rows, key=lambda x: int(x.get("case", 0))):
        number = int(row.get("case", 0))
        profile_path = case_profile_path(row, campaign_dir)
        profile = None
        if profile_path.is_file():
            try: profile = json.loads(profile_path.read_text(encoding="utf-8-sig"))
            except Exception: profile = None
        trace_path = case_trace_path(row, campaign_dir)
        events = load_jsonl(trace_path) if trace_path and trace_path.is_file() else []
        cases.append(render_case(row, profile_path, trace_path, profile, events, host_groups, verifier,
                                 args.time_tolerance, args.host_clock_offset_seconds))
        c = cases[-1]
        match_count = sum(t["result"] == "MATCH" for t in c["descriptor_transactions"])
        mismatch_count = sum(t["result"] == "MISMATCH" for t in c["descriptor_transactions"])
        print(f"CASE {number:05d}: {c['verdict']} | descriptor responses={len(c['descriptor_transactions'])} match={match_count} mismatch={mismatch_count}", flush=True)
    frame_owners: dict[int, set[int]] = defaultdict(set)
    for c in cases:
        for transaction in c.get("descriptor_transactions", []):
            for frame in transaction.get("frames", []):
                if frame is not None:
                    frame_owners[int(frame)].add(int(c["case"]))
    ambiguous_frames = {frame: owners for frame, owners in frame_owners.items() if len(owners) > 1}
    if ambiguous_frames:
        for c in cases:
            owned = sorted({frame for t in c.get("descriptor_transactions", []) for frame in t.get("frames", [])
                            if frame in ambiguous_frames})
            if owned:
                c["ambiguous_shared_frames"] = owned
                if c["verdict"] not in ("DEVICE_START_FAILED", "NOT_RUN_NOT_CAPTURE_MATCHABLE"):
                    c["verdict"] = "HOST_CORRELATION_AMBIGUOUS_SHARED_FRAMES"
                c.setdefault("warnings", []).append("Один или несколько кадров PCAP попали во временные окна нескольких cases: " + ", ".join(map(str, owned)))
                print(f"CASE {c['case']:05d}: предупреждение — общие кадры PCAP с другими cases: {owned}", flush=True)
    status_counts = dict(Counter(c["verdict"] for c in cases))
    report = {"report_version": 1, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "campaign_dir": str(campaign_dir), "host_pcap": str(pcap), "tshark_fields": fields,
              "time_tolerance_seconds": args.time_tolerance, "host_clock_offset_seconds": args.host_clock_offset_seconds,
              "host_frame_count": len(host_rows), "host_transfer_group_count": len(host_groups),
              "status_counts": status_counts, "cases": cases,
              "limitations": [
                  "USBPcap records Windows USB host-stack/URB observations; it is not an electrical USB analyzer.",
                  "The single capture is split by campaign timestamps. Synchronize clocks; unrelated traffic on the same captured USB bus may still appear in a case window.",
                  "USB requests absent from the selected capture window may mean the host did not request them, the capture missed them, or the clocks/selected Root Hub are wrong.",
                  "A successful byte match proves only that the captured response bytes matched the expected compiled descriptor for that request; it does not prove driver/kernel stability or correct class operation beyond observed traffic.",
              ]}
    prefix = Path(args.out_prefix).resolve() if args.out_prefix else campaign_dir / "protocol-report"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix(".json")
    txt_path = prefix.with_suffix(".txt")
    html_path = prefix.with_suffix(".html")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    txt_path.write_text(build_txt(report), encoding="utf-8")
    html_path.write_text(build_html(report), encoding="utf-8")
    print("\n=== ОТЧЁТ СОЗДАН ===")
    print(f"TXT : {txt_path}")
    print(f"HTML: {html_path}")
    print(f"JSON: {json_path}")
    print("Сводка:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"report-usb-campaign: ошибка: {exc}", file=sys.stderr)
        raise SystemExit(2)
