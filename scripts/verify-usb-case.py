#!/usr/bin/env python3
"""Verify one USB case: profile -> Raw Gadget trace -> optional single-case USBPcap.

Important: host captures are host-stack observations, not an electrical USB analyzer.
"""
from __future__ import annotations
import argparse
import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def uint(obj: dict, key: str, default: int) -> int:
    value = obj.get(key, default)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    return int(value)


def u8(obj: dict, key: str, default: int, auto: bool = False, calculated: int | None = None) -> int:
    v = calculated if auto and calculated is not None else uint(obj, key, default)
    if not 0 <= v <= 255:
        raise ValueError(f"{key}={v} не помещается в 1 байт")
    return v


def u16(obj: dict, key: str, default: int) -> int:
    v = uint(obj, key, default)
    if not 0 <= v <= 65535:
        raise ValueError(f"{key}={v} не помещается в 2 байта")
    return v


def le16(buf: bytearray, value: int) -> None:
    if not 0 <= value <= 65535:
        raise ValueError(f"16-битное значение вне диапазона: {value}")
    buf.extend((value & 0xff, (value >> 8) & 0xff))


def hexbytes(text: str) -> bytes:
    s = ''.join(str(text).split()).replace(':', '').replace('-', '')
    if len(s) % 2:
        raise ValueError("hex-строка имеет нечётную длину")
    return bytes.fromhex(s)


def build_expected_descriptors(profile: dict) -> dict[tuple[int, int, int], bytes]:
    """Mirror src/profile.cpp's descriptor compiler for standard/raw descriptors.
    Keys are (descriptor_type, descriptor_index, language_id); language is ignored
    for non-string descriptors.
    """
    validation = profile.get('validation') or {}
    auto = validation.get('calculated_fields', 'auto') != 'manual'
    device = profile['device']
    configs = profile.get('configurations') or []
    expected: dict[tuple[int, int, int], bytes] = {}

    d = bytearray()
    d.append(u8(device, 'bLength', 18, auto, 18))
    d.append(u8(device, 'bDescriptorType', 1, auto, 1))
    le16(d, u16(device, 'bcdUSB', 0x0200))
    for field, default in [('bDeviceClass', 0), ('bDeviceSubClass', 0), ('bDeviceProtocol', 0), ('bMaxPacketSize0', 64)]:
        d.append(u8(device, field, default))
    le16(d, u16(device, 'idVendor', 0x1209))
    le16(d, u16(device, 'idProduct', 1))
    le16(d, u16(device, 'bcdDevice', 1))
    for field, default in [('iManufacturer', 1), ('iProduct', 2), ('iSerialNumber', 3)]:
        d.append(u8(device, field, default))
    d.append(u8(device, 'bNumConfigurations', len(configs), auto, len(configs)))
    expected[(1, 0, 0)] = bytes(d)

    raw = profile.get('raw_descriptors') or {}
    for key, value in raw.items():
        try:
            typ, idx = (int(x, 0) for x in key.split(':', 1))
            if not 0 <= typ <= 255 or not 0 <= idx <= 255:
                continue
            expected[(typ, idx, 0)] = hexbytes(value)
        except Exception:
            continue

    for ci, cfg in enumerate(configs):
        c = bytearray()
        c.append(u8(cfg, 'bLength', 9, auto, 9))
        c.append(u8(cfg, 'bDescriptorType', 2, auto, 2))
        total_pos = len(c)
        le16(c, 0)
        ifaces = cfg.get('interfaces') or []
        unique_interfaces = len({uint(i, 'bInterfaceNumber', 0) for i in ifaces})
        c.append(u8(cfg, 'bNumInterfaces', unique_interfaces, auto, unique_interfaces))
        for field, default in [('bConfigurationValue', 1), ('iConfiguration', 0), ('bmAttributes', 0x80), ('bMaxPower', 50)]:
            c.append(u8(cfg, field, default))
        c.extend(hexbytes(cfg.get('extra_descriptors_hex', '')))
        for iface in ifaces:
            endpoints = iface.get('endpoints') or []
            c.append(u8(iface, 'bLength', 9, auto, 9))
            c.append(u8(iface, 'bDescriptorType', 4, auto, 4))
            for field, default in [('bInterfaceNumber', 0), ('bAlternateSetting', 0)]:
                c.append(u8(iface, field, default))
            c.append(u8(iface, 'bNumEndpoints', len(endpoints), auto, len(endpoints)))
            for field, default in [('bInterfaceClass', 0xff), ('bInterfaceSubClass', 0), ('bInterfaceProtocol', 0), ('iInterface', 0)]:
                c.append(u8(iface, field, default))
            c.extend(hexbytes(iface.get('extra_descriptors_hex', '')))
            for ep in endpoints:
                c.append(u8(ep, 'bLength', 7, auto, 7))
                c.append(u8(ep, 'bDescriptorType', 5, auto, 5))
                c.append(u8(ep, 'bEndpointAddress', 0x81))
                c.append(u8(ep, 'bmAttributes', 2))
                le16(c, u16(ep, 'wMaxPacketSize', 64))
                c.append(u8(ep, 'bInterval', 0))
                c.extend(hexbytes(ep.get('extra_descriptors_hex', '')))
        total = len(c)
        advertised = total if auto or 'wTotalLength' not in cfg else u16(cfg, 'wTotalLength', total)
        c[total_pos:total_pos+2] = bytes((advertised & 0xff, advertised >> 8))
        expected[(2, ci, 0)] = bytes(c)

    strings = profile.get('strings') or {}
    lang_ids = []
    for lang in strings:
        try:
            lang_ids.append(int(lang, 0))
        except ValueError:
            continue
    lang_ids.sort()
    languages = bytearray((0, 3))
    for lid in lang_ids:
        le16(languages, lid)
    languages[0] = len(languages) & 0xff
    expected[(3, 0, 0)] = bytes(languages)
    for lang, entries in strings.items():
        try:
            lid = int(lang, 0)
        except ValueError:
            continue
        if not isinstance(entries, dict):
            continue
        for idx_text, text in entries.items():
            try:
                idx = int(idx_text, 0)
            except ValueError:
                continue
            if idx == 0 or not isinstance(text, str):
                continue
            data = text.encode('utf-16le')
            payload = bytes((len(data) + 2, 3)) + data
            expected[(3, idx, lid)] = payload
    return expected


def request_tuple(event: dict) -> tuple[int, int, int, int, int] | None:
    req = event.get('request')
    if not isinstance(req, dict):
        return None
    names = ('bmRequestType', 'bRequest', 'wValue', 'wIndex', 'wLength')
    try:
        return tuple(int(req[n]) for n in names)
    except (KeyError, TypeError, ValueError):
        return None


def profile_descriptor_checks(profile: dict, events: list[dict]) -> dict:
    expected = build_expected_descriptors(profile)
    pending: dict[tuple[int, int, int, int, int], deque[dict]] = defaultdict(deque)
    comparisons = []
    for e in events:
        name = e.get('event')
        key = request_tuple(e)
        if name == 'CONTROL_REQUEST' and key:
            pending[key].append(e)
            continue
        if name != 'CONTROL_RESPONSE_COMPLETE' or not key:
            continue
        bm, brequest, wvalue, windex, wlength = key
        if brequest != 6 or not (bm & 0x80):
            continue
        typ, idx = (wvalue >> 8) & 0xff, wvalue & 0xff
        lang = windex if typ == 3 else 0
        exp = expected.get((typ, idx, lang))
        if exp is None and typ == 3:
            exp = expected.get((typ, idx, 0))
        if exp is None:
            comparisons.append({
                'sequence': e.get('sequence'), 'descriptor_type': typ, 'descriptor_index': idx,
                'language_id': lang, 'result': 'UNEXPECTED_OR_UNDEFINED_DESCRIPTOR',
                'actual_hex': e.get('payload_hex'),
            })
            continue
        expect_wire = exp[:wlength]
        actual_text = e.get('payload_hex') or ''
        try:
            actual = hexbytes(actual_text)
        except ValueError:
            actual = b''
        result = 'MATCH' if actual == expect_wire else 'MISMATCH'
        first_diff = None
        if result == 'MISMATCH':
            limit = min(len(actual), len(expect_wire))
            first_diff = next((i for i in range(limit) if actual[i] != expect_wire[i]), limit)
        comparisons.append({
            'sequence': e.get('sequence'), 'descriptor_type': typ, 'descriptor_index': idx,
            'language_id': lang, 'requested_length': wlength,
            'expected_length': len(expect_wire), 'actual_length': len(actual),
            'result': result, 'first_difference_offset': first_diff,
            'expected_hex': expect_wire.hex(), 'actual_hex': actual.hex(),
        })
    matched = sum(x['result'] == 'MATCH' for x in comparisons)
    mismatched = sum(x['result'] == 'MISMATCH' for x in comparisons)
    unknown = sum(x['result'] == 'UNEXPECTED_OR_UNDEFINED_DESCRIPTOR' for x in comparisons)
    return {
        'expected_descriptor_kinds': len(expected),
        'descriptor_responses_checked': len(comparisons),
        'matches': matched, 'mismatches': mismatched, 'undefined_responses': unknown,
        'status': 'PASS' if comparisons and mismatched == 0 and unknown == 0 else ('FAIL' if mismatched or unknown else 'INCOMPLETE'),
        'responses': comparisons,
        'note': 'Compares descriptor bytes reported by the Raw Gadget trace against the bytes compiled from this exact profile. Host-side receipt is checked separately with a per-case PCAP/PCAPNG.',
    }


def load_jsonl(path: Path) -> list[dict]:
    rows=[]
    for n, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
        if not line.strip(): continue
        try: rows.append(json.loads(line))
        except json.JSONDecodeError as exc: raise ValueError(f'{path}:{n}: invalid JSON: {exc}')
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description='Проверка одного USB fuzz-case: профиль -> trace -> USBPcap.')
    ap.add_argument('--profile', required=True, help='точный case-NNNNN.json из кампании')
    ap.add_argument('--device-trace', required=True, help='case-NNNNN.device.jsonl')
    ap.add_argument('--host-pcap', help='PCAP/PCAPNG только этого одного тестового случая')
    ap.add_argument('--source', choices=['windows_host','linux_host'], default='windows_host')
    ap.add_argument('--out', help='путь отчёта JSON (по умолчанию рядом с profile)')
    ap.add_argument('--host-scope', choices=['single-case','whole-campaign'], default='single-case',
                    help='укажи whole-campaign, если PCAP содержит несколько случаев; тогда корреляция не будет считаться доказательством для одного случая')
    args = ap.parse_args()
    profile_path = Path(args.profile).resolve()
    trace_path = Path(args.device_trace).resolve()
    out_path = Path(args.out).resolve() if args.out else profile_path.with_suffix('.verification.json')
    if not profile_path.is_file(): ap.error(f'профиль не найден: {profile_path}')
    if not trace_path.is_file(): ap.error(f'trace не найден: {trace_path}')
    profile = json.loads(profile_path.read_text(encoding='utf-8-sig'))
    events = load_jsonl(trace_path)
    descriptor_report = profile_descriptor_checks(profile, events)
    event_counts = Counter(str(e.get('event','UNKNOWN')) for e in events)
    config_values = [int(e.get('configuration_value', 0)) for e in events
                     if e.get('event') == 'SET_CONFIGURATION' and e.get('configuration_value') is not None]
    configured_values = [x for x in config_values if x != 0]
    stalls = event_counts['CONTROL_STALL']
    errors = sum(n for k,n in event_counts.items() if 'ERROR' in k or 'MALFORMED' in k or k.endswith('_FAILED'))
    resets = event_counts['USB_RESET'] + event_counts['USB_RESET_OR_DISCONNECT']
    disconnects = event_counts['USB_DISCONNECT']
    host_requests = event_counts['CONTROL_REQUEST']

    expected_config_values = {uint(c,'bConfigurationValue',1) for c in profile.get('configurations',[])}
    unexpected_config_values = [x for x in configured_values if x not in expected_config_values]
    configured = bool(configured_values)

    expected_eps = set()
    for cfg in profile.get('configurations', []):
        value = uint(cfg, 'bConfigurationValue', 1)
        if value in configured_values:
            for iface in cfg.get('interfaces', []):
                for ep in iface.get('endpoints', []):
                    expected_eps.add(uint(ep, 'bEndpointAddress', 0x81))
    enabled_eps = {int(e.get('endpoint_address')) for e in events
                   if e.get('event') == 'ENDPOINT_ENABLED' and e.get('endpoint_address') is not None}
    missing_eps = sorted(expected_eps - enabled_eps) if configured else sorted(expected_eps)

    expected_payloads = {}
    for k, v in (profile.get('endpoint_io',{}).get('in_payloads',{}) or {}).items():
        try: expected_payloads[int(k,0)] = hexbytes(v).hex()
        except Exception: pass
    observed_in = [e for e in events if e.get('event') == 'DEVICE_IN_TRANSFER_COMPLETE']
    wrong_in_payloads = []
    for e in observed_in:
        ep = e.get('endpoint_address')
        if ep in expected_payloads and (e.get('payload_hex') or '').lower() != expected_payloads[ep]:
            wrong_in_payloads.append({'sequence':e.get('sequence'),'endpoint_address':ep,
                                      'expected_hex':expected_payloads[ep],'actual_hex':e.get('payload_hex')})

    strict_validation = None
    validator = ROOT / 'build' / 'usb-config'
    if validator.is_file():
        try:
            v = subprocess.run([str(validator), 'validate', str(profile_path), '--mode', 'strict'],
                               text=True, capture_output=True, timeout=15)
            strict_validation = {'valid': v.returncode == 0,
                                 'returncode': v.returncode,
                                 'output': (v.stdout + '\n' + v.stderr).strip()[-12000:]}
        except Exception as exc:
            strict_validation = {'valid': None, 'error': str(exc)}
    else:
        strict_validation = {'valid': None, 'note': 'build/usb-config not found; strict validation skipped'}

    host_result = {'status':'NO_HOST_CAPTURE', 'note':'Невозможно подтвердить, что Windows наблюдала те же байты, пока не предоставлен PCAPNG.'}
    compare_paths = {}
    if args.host_pcap:
        pcap = Path(args.host_pcap).resolve()
        if not pcap.is_file(): ap.error(f'PCAP/PCAPNG не найден: {pcap}')
        compare_out = out_path.with_name(out_path.stem + '.host-compare.json')
        command = [sys.executable, str(ROOT/'scripts'/'usb-lab.py'), 'compare',
                   '--device-trace', str(trace_path), '--host', str(pcap), '--source', args.source,
                   '--out', str(compare_out)]
        run = subprocess.run(command, cwd=str(ROOT), text=True, capture_output=True, timeout=120)
        compare_paths = {'command':command, 'stdout':run.stdout[-10000:], 'stderr':run.stderr[-10000:],
                         'report_path':str(compare_out)}
        if run.returncode == 0 and compare_out.is_file():
            host_result = json.loads(compare_out.read_text(encoding='utf-8'))
            host_result['pcap_path'] = str(pcap)
            host_result['scope'] = args.host_scope
            if args.host_scope == 'whole-campaign':
                host_result['warning'] = 'PCAP содержит несколько случаев: повторяющиеся USB-запросы/данные могут совпасть с другим случаем. Нельзя присваивать корреляцию этому case без временного выделения кадров.'
                host_result['status_for_this_case'] = 'INCONCLUSIVE_SHARED_CAPTURE'
            else:
                host_result['status_for_this_case'] = host_result.get('status', 'UNKNOWN')
        else:
            host_result = {'status':'HOST_ANALYSIS_FAILED','returncode':run.returncode,
                           'stderr':run.stderr[-10000:],'stdout':run.stdout[-10000:]}

    if descriptor_report['status'] == 'FAIL':
        verdict = 'FAIL_DEVICE_TRACE_BYTES_DIFFER_FROM_PROFILE'
    elif not configured:
        if strict_validation and strict_validation.get('valid') is False:
            verdict = 'EXPECTED_REJECTION_POSSIBLE_NOT_CONFIGURED'
        elif host_result.get('status') == 'NO_HOST_CAPTURE':
            verdict = 'INCONCLUSIVE_NO_HOST_CAPTURE_AND_NOT_CONFIGURED'
        else:
            verdict = 'ENUMERATION_NOT_CONFIGURED_REVIEW_HOST_CAPTURE'
    elif resets or disconnects or stalls or errors or missing_eps or wrong_in_payloads:
        verdict = 'REVIEW_PROTOCOL_ANOMALY'
    elif host_result.get('status_for_this_case') == 'CORRELATED' and descriptor_report['status'] == 'PASS':
        verdict = 'PASS_OBSERVED_CORRELATED'
    elif host_result.get('status') == 'NO_HOST_CAPTURE':
        verdict = 'INCOMPLETE_HOST_BYTES_NOT_VERIFIED'
    elif args.host_scope == 'whole-campaign':
        verdict = 'INCONCLUSIVE_SHARED_PCAP_NEEDS_PER_CASE_CAPTURE'
    else:
        verdict = 'REVIEW_HOST_DEVICE_CORRELATION'

    report = {
        'report_version':1,'created_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
        'verdict':verdict,
        'profile':str(profile_path),'profile_name':profile.get('profile_name'),
        'device_trace':str(trace_path),'host_capture':str(Path(args.host_pcap).resolve()) if args.host_pcap else None,
        'device_profile_descriptor_check':descriptor_report,
        'strict_profile_validation':strict_validation,
        'runtime_protocol':{
            'host_control_requests':host_requests,
            'control_responses_complete':event_counts['CONTROL_RESPONSE_COMPLETE'],
            'configuration_values_observed':config_values,
            'configured_observed':configured,
            'expected_configuration_values':sorted(expected_config_values),
            'unexpected_configuration_values':unexpected_config_values,
            'expected_endpoint_addresses_for_observed_config':[f'0x{x:02x}' for x in sorted(expected_eps)],
            'enabled_endpoint_addresses':[f'0x{x:02x}' for x in sorted(enabled_eps)],
            'missing_expected_endpoints':[f'0x{x:02x}' for x in missing_eps],
            'device_in_transfers_observed':len(observed_in),
            'wrong_device_in_payloads':wrong_in_payloads,
            'control_stalls':stalls,'reset_events':resets,'disconnect_events':disconnects,'backend_error_events':errors,
            'events_by_type':dict(sorted(event_counts.items())),
        },
        'host_capture_comparison':host_result,
        'comparison_command':compare_paths,
        'interpretation':[
            'PASS_OBSERVED_CORRELATED means profile descriptor replies matched the locally expected bytes, configured state was observed, no listed local anomaly was found, and the per-case host capture correlation was CORRELATED. This is not a physical electrical-layer proof.',
            'If profile is intentionally malformed, a host rejection/no SET_CONFIGURATION can be an expected result; compare it against the mutation intent.',
            'USBPcap/tshark sees host-stack URB observations, not every physical USB token/ACK/NAK/CRC. A hardware protocol analyzer is needed for electrical-layer certainty.',
            'Do not use a whole-campaign PCAP as per-case proof without splitting it by timestamps; repeated descriptors and requests may correlate to the wrong case.'
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

    labels={
        'FAIL_DEVICE_TRACE_BYTES_DIFFER_FROM_PROFILE':'FAIL: TRACE BYTES DO NOT MATCH PROFILE',
        'EXPECTED_REJECTION_POSSIBLE_NOT_CONFIGURED':'PROFILE INVALID IN STRICT MODE; HOST REJECTION POSSIBLE',
        'INCONCLUSIVE_NO_HOST_CAPTURE_AND_NOT_CONFIGURED':'INCONCLUSIVE: NO HOST PCAP AND NOT CONFIGURED',
        'ENUMERATION_NOT_CONFIGURED_REVIEW_HOST_CAPTURE':'ENUMERATION DID NOT REACH CONFIGURED: REVIEW',
        'REVIEW_PROTOCOL_ANOMALY':'REVIEW: RESET/STALL/ERROR/ENDPOINT MISMATCH OBSERVED',
        'PASS_OBSERVED_CORRELATED':'PASS (OBSERVED): PROFILE, TRACE AND HOST CAPTURE CORRELATED',
        'INCOMPLETE_HOST_BYTES_NOT_VERIFIED':'INCOMPLETE: HOST-RECEIVED BYTES NOT VERIFIED',
        'INCONCLUSIVE_SHARED_PCAP_NEEDS_PER_CASE_CAPTURE':'INCONCLUSIVE: SPLIT PCAP BY CASE FIRST',
        'REVIEW_HOST_DEVICE_CORRELATION':'REVIEW: HOST AND DEVICE TRACE NOT FULLY CORRELATED',
    }
    print('='*76)
    print(f'USB CASE VERIFICATION: {labels.get(verdict,verdict)}')
    print(f'Профиль: {profile_path}')
    print(f'Дескрипторы trace vs compiled profile: {descriptor_report["status"]} '
          f'(совпало {descriptor_report["matches"]}, mismatch {descriptor_report["mismatches"]}, '
          f'неопределённых {descriptor_report["undefined_responses"]})')
    print(f'Host requests={host_requests}; CONFIGURED={configured}; SET_CONFIGURATION={config_values}')
    print(f'Endpoints expected={len(expected_eps)}, enabled={len(enabled_eps)}, missing={len(missing_eps)}')
    print(f'STALL={stalls}; RESET={resets}; DISCONNECT={disconnects}; errors={errors}')
    print(f'Host capture status: {host_result.get("status_for_this_case",host_result.get("status"))}')
    print(f'Отчёт: {out_path}')
    print('Примечание: PASS означает наблюдаемое программное сопоставление, не гарантию корректности каждого физического USB-пакета.')
    return 1 if verdict.startswith('FAIL_') else 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'verify-usb-case: ошибка: {exc}', file=sys.stderr)
        raise SystemExit(2)
