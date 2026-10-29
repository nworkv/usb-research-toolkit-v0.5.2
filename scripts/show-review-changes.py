#!/usr/bin/env python3
"""Print profile mutations for cases listed in review-queue.json."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

METADATA_PATHS = {"$.profile_name", "$.validation.mode", "$.validation.calculated_fields"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"Предупреждение: пропускаю {path}:{n}: {exc}", file=sys.stderr)
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def norm_case(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def resolve_profile(value: Any, campaign_dir: Path, case_no: int) -> Path | None:
    candidates: list[Path] = []
    if isinstance(value, str) and value.strip():
        p = Path(value).expanduser()
        candidates.append(p)
        if not p.is_absolute():
            candidates.append(campaign_dir / p)
    candidates.append(campaign_dir / f"case-{case_no:05d}.json")
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.resolve()
        except OSError:
            pass
    return None


def json_diff(a: Any, b: Any, path: str = "$", out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            next_path = f"{path}.{key}"
            if key not in a:
                if next_path not in METADATA_PATHS:
                    out.append(f"+ {next_path}: <отсутствует> -> {b[key]!r}")
            elif key not in b:
                if next_path not in METADATA_PATHS:
                    out.append(f"- {next_path}: {a[key]!r} -> <отсутствует>")
            else:
                json_diff(a[key], b[key], next_path, out)
    elif isinstance(a, list) and isinstance(b, list):
        for i in range(max(len(a), len(b))):
            next_path = f"{path}[{i}]"
            if i >= len(a):
                out.append(f"+ {next_path}: <отсутствует> -> {b[i]!r}")
            elif i >= len(b):
                out.append(f"- {next_path}: {a[i]!r} -> <отсутствует>")
            else:
                json_diff(a[i], b[i], next_path, out)
    elif a != b and path not in METADATA_PATHS:
        out.append(f"~ {path}: {a!r} -> {b!r}")
    return out


def load_base(args_base: str | None, campaign_dir: Path) -> Path | None:
    if args_base:
        candidate = Path(args_base).expanduser()
        if candidate.is_file():
            return candidate.resolve()
    cfg_path = campaign_dir / "runner-config.json"
    if cfg_path.is_file():
        try:
            base_value = read_json(cfg_path).get("base")
            if isinstance(base_value, str):
                candidate = Path(base_value).expanduser()
                if candidate.is_file():
                    return candidate.resolve()
        except (OSError, json.JSONDecodeError):
            pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Показывает изменения профилей, попавших в review-queue.json"
    )
    parser.add_argument("--campaign-dir", required=True, help="каталог кампании с review-queue.json")
    parser.add_argument("--case", type=int, help="показать только один номер, например 18")
    parser.add_argument("--base", help="исходный профиль для резервного сравнения, если манифест не содержит changes")
    parser.add_argument("--json", action="store_true", help="вывести отчёт как JSON")
    args = parser.parse_args()

    campaign_dir = Path(args.campaign_dir).expanduser().resolve()
    queue_path = campaign_dir / "review-queue.json"
    manifest_path = campaign_dir / "manifest.json"
    if not queue_path.is_file():
        parser.error(f"не найден файл очереди: {queue_path}; сначала выполните scripts/review-usb-campaign.py")
    try:
        queue_obj = read_json(queue_path)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"не удалось прочитать {queue_path}: {exc}")
    queue_cases = queue_obj.get("cases", []) if isinstance(queue_obj, dict) else []
    if not isinstance(queue_cases, list):
        parser.error(f"неверный формат {queue_path}: поле cases должно быть списком")

    manifest_cases: dict[int, dict[str, Any]] = {}
    if manifest_path.is_file():
        try:
            manifest = read_json(manifest_path)
            for item in manifest.get("cases", []):
                if isinstance(item, dict) and norm_case(item.get("case")) is not None:
                    manifest_cases[norm_case(item.get("case"))] = item  # type: ignore[index]
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            print(f"Предупреждение: не удалось прочитать манифест: {exc}", file=sys.stderr)

    campaign_rows = {
        norm_case(row.get("case")): row
        for row in read_jsonl(campaign_dir / "campaign.jsonl")
        if norm_case(row.get("case")) is not None
    }
    base_path = load_base(args.base, campaign_dir)

    selected = []
    for qcase in queue_cases:
        if not isinstance(qcase, dict):
            continue
        case_no = norm_case(qcase.get("case"))
        if case_no is None or (args.case is not None and case_no != args.case):
            continue
        mcase = manifest_cases.get(case_no, {})
        row = campaign_rows.get(case_no, {})
        profile_path = resolve_profile(
            qcase.get("profile") or row.get("profile") or mcase.get("profile"), campaign_dir, case_no
        )
        raw_changes = mcase.get("changes")
        if raw_changes is None:
            raw_changes = row.get("changes")
        changes = [str(x) for x in raw_changes if str(x).strip()] if isinstance(raw_changes, list) else []
        source = "manifest/campaign log" if changes else "JSON diff fallback"
        if not changes and profile_path and base_path:
            try:
                base_obj = read_json(base_path)
                profile_obj = read_json(profile_path)
                changes = json_diff(base_obj, profile_obj)
            except (OSError, json.JSONDecodeError) as exc:
                changes = [f"Не удалось сравнить профиль с базовым: {exc}"]
        if not changes:
            changes = ["Изменения не найдены или манифест их не сохранил."]
        item = {
            "case": case_no,
            "review_status": qcase.get("status", "REVIEW_REQUIRED"),
            "reasons": qcase.get("reasons", []),
            "campaign_status": row.get("status", "UNKNOWN"),
            "profile": str(profile_path) if profile_path else qcase.get("profile") or row.get("profile") or mcase.get("profile"),
            "sha256": qcase.get("profile_sha256") or qcase.get("sha256") or row.get("profile_sha256") or mcase.get("sha256"),
            "capture_files": qcase.get("capture_files", []),
            "matched_frame_count": qcase.get("matched_frame_count"),
            "changes_source": source,
            "changes": changes,
        }
        selected.append(item)

    if args.case is not None and not selected:
        print(f"Случай case-{args.case:05d} не найден в очереди дополнительной проверки {queue_path}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"campaign_dir": str(campaign_dir), "review_count": len(selected), "cases": selected}, ensure_ascii=False, indent=2))
        return 0

    print(f"Кампания: {campaign_dir}")
    print(f"Случаев в очереди, показано: {len(selected)}")
    if not selected:
        print("Очередь пуста. Сначала сохраните PCAPNG и запустите scripts/review-usb-campaign.py.")
        return 0
    for item in selected:
        print("\n" + "=" * 76)
        print(f"CASE {item['case']:05d} | очередь: {item['review_status']} | запуск: {item['campaign_status']}")
        print(f"Профиль: {item['profile'] or '(не найден)'}")
        if item["sha256"]:
            print(f"SHA-256: {item['sha256']}")
        reasons = item["reasons"]
        print("Причины доп. проверки:")
        for reason in reasons if isinstance(reasons, list) else [reasons]:
            print(f"  - {reason}")
        if item["matched_frame_count"] is not None:
            print(f"Совпавших кадров в PCAP/PCAPNG: {item['matched_frame_count']}")
        print(f"Источник сведений об изменениях: {item['changes_source']}")
        print("Изменения профиля относительно исходного:")
        for change in item["changes"]:
            print(f"  {change}")
        captures = item["capture_files"]
        if captures:
            print("Файлы захвата:")
            for capture in captures:
                print(f"  - {capture}")
        else:
            print("Файлы захвата: не привязаны к этому случаю в очереди")
    print("\nПримечание: очередь эвристическая; попадание в неё не означает, что Windows аварийно завершилась.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
