#!/usr/bin/env python3
"""Re-analyze a completed USB campaign after the Wireshark capture has been saved."""
from __future__ import annotations
import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "usb-gadget-campaign.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("usb_gadget_campaign", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load campaign runner: {RUNNER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    ap = argparse.ArgumentParser(description="Повторно анализирует Wireshark PCAPNG после сохранения захвата")
    ap.add_argument("--campaign-dir", required=True, help="каталог с campaign.jsonl и summary.json")
    ap.add_argument("--capture-dir", required=True, help="каталог с сохранёнными PCAP/PCAPNG")
    ap.add_argument("--tshark", default="tshark", help="путь к tshark")
    args = ap.parse_args()
    campaign_dir = Path(args.campaign_dir).resolve()
    capture_dir = Path(args.capture_dir).resolve()
    log_path = campaign_dir / "campaign.jsonl"
    if not log_path.is_file():
        ap.error(f"не найден журнал кампании: {log_path}")
    if not capture_dir.is_dir():
        ap.error(f"каталог захватов не найден: {capture_dir}")
    rows = []
    for line_no, line in enumerate(log_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            ap.error(f"ошибка JSON в {log_path}:{line_no}: {exc}")
    runner = load_runner()
    queue = runner.analyze_campaign_captures(capture_dir, rows, args.tshark, campaign_dir)
    queue_path = campaign_dir / "review-queue.json"
    try:
        queue_path.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "count": len(queue),
            "note": "Эвристическая очередь для ручной проверки; отсутствие аномалий не доказывает отсутствие сбоя и не является полным побайтовым сравнением дескрипторов.",
            "cases": queue,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except PermissionError:
        print(f"Нет прав на запись в {queue_path}. Кампания запускалась через sudo? Выполните: sudo chown -R \"$USER\":\"$(id -gn)\" {campaign_dir}", file=sys.stderr)
        return 2
    summary_path = campaign_dir / "summary.json"
    if summary_path.is_file():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["review_required"] = len(queue)
            summary["review_queue"] = str(queue_path)
            summary["review_generated_at"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass
    print(f"Очередь дополнительной проверки: {queue_path} ({len(queue)} случаев)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
