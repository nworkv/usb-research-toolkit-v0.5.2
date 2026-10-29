#!/usr/bin/env python3
"""Show profile mutations and execution status for every case in a USB fuzz campaign."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

IGNORED_PATHS = {
    "$.profile_name",
    "$.validation.mode",
    "$.validation.calculated_fields",
}
CASE_FILE_RE = re.compile(r"^case-(\d+)\.json$")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Предупреждение: {path}:{line_no}: {exc}", file=sys.stderr)
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def case_number(value: Any) -> int | None:
    try:
        n = int(value)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def load_optional_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Предупреждение: не удалось прочитать {path}: {exc}", file=sys.stderr)
        return default


def find_existing_path(value: Any, campaign_dir: Path, case_no: int | None = None) -> Path | None:
    candidates: list[Path] = []
    if isinstance(value, str) and value.strip():
        raw = Path(value).expanduser()
        candidates.append(raw)
        if not raw.is_absolute():
            candidates.extend([campaign_dir / raw, Path.cwd() / raw])
    if case_no is not None:
        candidates.append(campaign_dir / f"case-{case_no:05d}.json")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def load_base(base_arg: str | None, campaign_dir: Path,
              config: Any, manifest: Any) -> tuple[Path | None, str]:
    choices: list[tuple[Any, str]] = []
    if base_arg:
        choices.append((base_arg, "--base"))
    if isinstance(config, dict):
        choices.append((config.get("base"), "runner-config.json"))
    if isinstance(manifest, dict):
        choices.append((manifest.get("base"), "manifest.json"))
    for value, source in choices:
        path = find_existing_path(value, campaign_dir)
        if path:
            return path, source
    return None, "not found"


def diff_json(a: Any, b: Any, path: str = "$") -> list[str]:
    out: list[str] = []

    def walk(left: Any, right: Any, current: str) -> None:
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                p = f"{current}.{key}"
                if p in IGNORED_PATHS:
                    continue
                if key not in left:
                    out.append(f"+ {p}: <отсутствует> -> {right[key]!r}")
                elif key not in right:
                    out.append(f"- {p}: {left[key]!r} -> <отсутствует>")
                else:
                    walk(left[key], right[key], p)
        elif isinstance(left, list) and isinstance(right, list):
            for index in range(max(len(left), len(right))):
                p = f"{current}[{index}]"
                if index >= len(left):
                    out.append(f"+ {p}: <отсутствует> -> {right[index]!r}")
                elif index >= len(right):
                    out.append(f"- {p}: {left[index]!r} -> <отсутствует>")
                else:
                    walk(left[index], right[index], p)
        elif left != right and current not in IGNORED_PATHS:
            out.append(f"~ {current}: {left!r} -> {right!r}")

    walk(a, b, path)
    return out


def load_trace_summary(row: dict[str, Any], campaign_dir: Path, case_no: int) -> dict[str, Any]:
    trace_value = row.get("trace")
    trace_path = find_existing_path(trace_value, campaign_dir)
    if trace_path is None:
        traces_dir = campaign_dir / "traces"
        candidates = sorted(traces_dir.glob(f"case-{case_no:05d}*.jsonl")) if traces_dir.is_dir() else []
        trace_path = candidates[0].resolve() if candidates else None
    counts: Counter[str] = Counter()
    if trace_path and trace_path.is_file():
        for event in read_jsonl(trace_path):
            name = event.get("event")
            if isinstance(name, str):
                counts[name] += 1
    return {
        "trace": str(trace_path) if trace_path else None,
        "event_counts": dict(counts),
        "host_requests": counts.get("CONTROL_REQUEST", 0),
        "ep0_responses": counts.get("CONTROL_RESPONSE_COMPLETE", 0),
        "stalls": sum(n for name, n in counts.items() if "STALL" in name.upper()),
        "reset_disconnect_events": sum(
            n for name, n in counts.items()
            if "RESET" in name.upper() or "DISCONNECT" in name.upper()
        ),
        "set_configuration_events": sum(
            n for name, n in counts.items()
            if "SET_CONFIGURATION" in name.upper() or name.upper() == "CONFIGURED"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Показывает изменения и результаты ВСЕХ случаев кампании, а не только review-queue."
    )
    parser.add_argument("--campaign-dir", required=True, help="каталог кампании с case-*.json и manifest.json")
    parser.add_argument("--base", help="исходный JSON-профиль; по умолчанию берётся из runner-config/manifest")
    parser.add_argument("--case", type=int, help="показать только один случай, например 18")
    parser.add_argument("--only-review", action="store_true", help="отфильтровать только случаи из review-queue.json")
    parser.add_argument("--json", action="store_true", help="вывести итоговый отчёт в JSON")
    parser.add_argument("--out", help="дополнительно сохранить JSON-отчёт в файл")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir).expanduser().resolve()
    if not campaign_dir.is_dir():
        parser.error(f"каталог кампании не найден: {campaign_dir}")

    manifest = load_optional_json(campaign_dir / "manifest.json", {})
    config = load_optional_json(campaign_dir / "runner-config.json", {})
    summary = load_optional_json(campaign_dir / "summary.json", {})
    queue = load_optional_json(campaign_dir / "review-queue.json", {})

    manifest_rows = manifest.get("cases", []) if isinstance(manifest, dict) else []
    manifest_cases = {
        case_number(item.get("case")): item
        for item in manifest_rows if isinstance(item, dict) and case_number(item.get("case")) is not None
    }
    campaign_rows = {
        case_number(item.get("case")): item
        for item in read_jsonl(campaign_dir / "campaign.jsonl")
        if case_number(item.get("case")) is not None
    }
    queue_rows = queue.get("cases", []) if isinstance(queue, dict) else []
    queue_cases = {
        case_number(item.get("case")): item
        for item in queue_rows if isinstance(item, dict) and case_number(item.get("case")) is not None
    }

    # Union of all available records: manifest, execution log, and case files on disk.
    case_numbers = set(manifest_cases) | set(campaign_rows)
    for path in campaign_dir.glob("case-*.json"):
        match = CASE_FILE_RE.match(path.name)
        if match:
            case_numbers.add(int(match.group(1)))
    if args.case is not None:
        case_numbers = {n for n in case_numbers if n == args.case}
    if args.only_review:
        case_numbers &= set(queue_cases)
    if not case_numbers:
        if args.case is not None:
            parser.error(f"case-{args.case:05d} не найден в манифесте, журнале или каталоге {campaign_dir}")
        parser.error(f"в {campaign_dir} не найдено ни одного случая")

    base_path, base_source = load_base(args.base, campaign_dir, config, manifest)
    results: list[dict[str, Any]] = []

    for number in sorted(case_numbers):
        mrow = manifest_cases.get(number, {})
        crow = campaign_rows.get(number, {})
        qrow = queue_cases.get(number, {})
        profile_path = find_existing_path(
            crow.get("profile") or mrow.get("profile"), campaign_dir, number
        )
        if profile_path is None:
            profile_path = find_existing_path(None, campaign_dir, number)

        changes_val = mrow.get("changes")
        if changes_val is None:
            changes_val = crow.get("changes")
        changes = [str(x) for x in changes_val if str(x).strip()] if isinstance(changes_val, list) else []
        changes_source = "manifest/campaign.jsonl" if changes else "JSON diff fallback"
        if not changes and profile_path and base_path:
            try:
                changes = diff_json(read_json(base_path), read_json(profile_path))
            except (OSError, json.JSONDecodeError) as exc:
                changes = [f"Не удалось сравнить профиль с исходным: {exc}"]
        if not changes:
            changes = ["Изменений относительно исходного профиля не найдено (или исходный профиль недоступен)."]

        campaign_status = crow.get("status") or mrow.get("status") or "NOT_RUN"
        review_status = qrow.get("status") or "NOT_IN_REVIEW_QUEUE"
        trace = load_trace_summary(crow, campaign_dir, number)
        results.append({
            "case": number,
            "profile": str(profile_path) if profile_path else mrow.get("profile") or crow.get("profile"),
            "sha256": crow.get("profile_sha256") or crow.get("sha256") or mrow.get("sha256"),
            "campaign_status": campaign_status,
            "review_status": review_status,
            "review_reasons": qrow.get("reasons", []),
            "changes_source": changes_source,
            "changes": changes,
            "capture_files_changed": crow.get("capture_files_changed", []),
            "trace_summary": trace,
            "duration_seconds": crow.get("duration_seconds"),
            "returncode": crow.get("returncode"),
            "stderr_log": crow.get("stderr_log"),
        })

    statuses = Counter(item["campaign_status"] for item in results)
    report = {
        "campaign_dir": str(campaign_dir),
        "base_profile": str(base_path) if base_path else None,
        "base_source": base_source,
        "case_count": len(results),
        "in_review_queue": sum(1 for item in results if item["review_status"] != "NOT_IN_REVIEW_QUEUE"),
        "status_counts": dict(statuses),
        "cases": results,
    }

    if args.out:
        out_path = Path(args.out).expanduser()
        if not out_path.is_absolute():
            out_path = Path.cwd() / out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print(f"Кампания: {campaign_dir}")
    print(f"Исходный профиль: {base_path or 'не найден (передай --base)'}")
    print(f"Случаев показано: {len(results)} | в очереди доп. проверки: {report['in_review_queue']}")
    print("Статусы: " + (", ".join(f"{k}={v}" for k, v in sorted(statuses.items())) if statuses else "нет данных"))
    if args.out:
        print(f"JSON-отчёт сохранён: {out_path}")
    for item in results:
        print("\n" + "=" * 88)
        print(f"CASE {item['case']:05d} | запуск: {item['campaign_status']} | доп. проверка: {item['review_status']}")
        print(f"Профиль: {item['profile'] or '(путь не найден)'}")
        if item["sha256"]:
            print(f"SHA-256: {item['sha256']}")
        if item["duration_seconds"] is not None:
            print(f"Длительность: {item['duration_seconds']} s | return code: {item['returncode']}")
        print("Изменения:")
        for change in item["changes"]:
            print(f"  {change}")
        ts = item["trace_summary"]
        if ts["trace"]:
            print(f"Trace: {ts['trace']}")
            print(
                "USB-события: "
                f"CONTROL_REQUEST={ts['host_requests']}, "
                f"CONTROL_RESPONSE_COMPLETE={ts['ep0_responses']}, "
                f"STALL={ts['stalls']}, "
                f"RESET/DISCONNECT={ts['reset_disconnect_events']}, "
                f"SET_CONFIGURATION/CONFIGURED={ts['set_configuration_events']}"
            )
        if item["review_reasons"]:
            print("Причины доп. проверки: " + ", ".join(map(str, item["review_reasons"])))
        captures = item["capture_files_changed"]
        if captures:
            print("Файлы захвата, изменившиеся во время случая:")
            for capture in captures:
                if isinstance(capture, dict):
                    print(f"  {capture.get('path', capture)}")
                else:
                    print(f"  {capture}")
        if item["stderr_log"]:
            print(f"Журнал stderr: {item['stderr_log']}")

    print("\nПримечание: COMPLETED означает завершение процесса Gadget, а не подтверждение успешного подключения Windows.")
    print("Очередь дополнительной проверки эвристическая; её отсутствие не доказывает отсутствие проблем хоста.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
