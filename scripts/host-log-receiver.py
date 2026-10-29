#!/usr/bin/env python3
"""Authenticated newline-JSON receiver for lab host health/event logs.

Run on the Raspberry Pi. Bind only to a trusted lab interface and use a long
random token; this intentionally does not expose a general remote shell.
"""
from __future__ import annotations
import argparse, json, os, re, socketserver, threading, time
from pathlib import Path

SAFE = re.compile(r"[^A-Za-z0-9_.-]+")
MAX_LINE = 1024 * 1024

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        self.request.settimeout(10)
        try:
            raw = self.rfile.readline(MAX_LINE + 1)
            if not raw or len(raw) > MAX_LINE:
                return
            hello = json.loads(raw.decode("utf-8"))
            if hello.get("type") != "hello" or not secrets_compare(str(hello.get("token", "")), server.token):
                self.wfile.write(b'{"ok":false,"error":"unauthorized"}\n'); return
            host = SAFE.sub("_", str(hello.get("hostname", "unknown")))[:80] or "unknown"
            platform = str(hello.get("platform", "unknown"))[:100]
            self.wfile.write((json.dumps({"ok": True, "host": host}) + "\n").encode())
            log_path = server.out_dir / f"host-{host}.log"
            jsonl_path = server.out_dir / f"host-{host}.jsonl"
            with server.lock_for(host):
                server.last_seen[host] = time.time()
                server.missing_reported.discard(host)
                append_event(server, host, log_path, jsonl_path, {
                    "type": "agent_connected", "timestamp": time.time(), "hostname": host,
                    "platform": platform, "boot_id": str(hello.get("boot_id", ""))[:128],
                    "message": f"HOST_AGENT_CONNECTED platform={platform}"
                })
            while True:
                raw = self.rfile.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    break
                try:
                    event = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(event, dict):
                    continue
                event = {"type": str(event.get("type", "event"))[:40],
                         "timestamp": event.get("timestamp", time.time()),
                         "hostname": host,
                         "platform": platform,
                         "event_id": str(event.get("event_id", ""))[:128],
                         "severity": str(event.get("severity", "info"))[:30],
                         "source": str(event.get("source", "host-agent"))[:100],
                         "message": str(event.get("message", ""))[:20000]}
                with server.lock_for(host):
                    server.last_seen[host] = time.time()
                    if event.get('type') == 'heartbeat': server.missing_reported.discard(host)
                    append_event(server, host, log_path, jsonl_path, event)
        except (OSError, ValueError, json.JSONDecodeError, socketserver.socket.timeout):
            return

def secrets_compare(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())

def append_event(server, host, log_path, jsonl_path, event):
    # The plain-text mirror is compatible with usb-fuzz.py --host-log signature scanning.
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(event.get("timestamp", time.time()))))
    message = str(event.get("message", "")).replace("\r", " ").replace("\n", " ")
    if event.get('type') != 'heartbeat':
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"[{stamp}] [{event.get('severity','info')}] [{event.get('source','host-agent')}] {message}\n")
            f.flush()
            os.fsync(f.fileno())
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
        f.flush()

def main():
    p = argparse.ArgumentParser(description="Приём журналов лабораторных хостов на Raspberry Pi")
    p.add_argument("--listen", default="127.0.0.1", help="IP интерфейса лабораторной сети; по умолчанию только localhost")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--token-file", required=True, help="файл с секретом; права доступа 600")
    p.add_argument("--out-dir", default="runs/host-logs")
    p.add_argument("--heartbeat-timeout", type=float, default=15.0, help="секунд без heartbeat до записи HOST_AGENT_HEARTBEAT_MISSED")
    a = p.parse_args()
    if not (3 <= a.heartbeat_timeout <= 3600): p.error("heartbeat-timeout must be in 3..3600 seconds")
    token = Path(a.token_file).read_text(encoding="utf-8").strip()
    if len(token) < 24:
        p.error("token must be at least 24 characters; use a random secret")
    out = Path(a.out_dir).resolve(); out.mkdir(parents=True, exist_ok=True)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        def __init__(self, addr, handler):
            self.token, self.out_dir = token, out
            self._locks, self._locks_guard = {}, threading.Lock()
            self.last_seen, self.missing_reported = {}, set()
            super().__init__(addr, handler)
        def lock_for(self, host):
            with self._locks_guard:
                return self._locks.setdefault(host, threading.Lock())
    def heartbeat_watchdog(srv):
        while True:
            time.sleep(1)
            now = time.time()
            for host, last in list(srv.last_seen.items()):
                if now - last <= a.heartbeat_timeout or host in srv.missing_reported: continue
                with srv.lock_for(host):
                    if host in srv.missing_reported or now - srv.last_seen.get(host, now) <= a.heartbeat_timeout: continue
                    srv.missing_reported.add(host)
                    msg = f"HOST_AGENT_HEARTBEAT_MISSED host={host} silence_seconds={int(now - srv.last_seen[host])}; host/network unavailable, not proof of OS crash"
                    append_event(srv, host, out / f"host-{host}.log", out / f"host-{host}.jsonl", {"type":"heartbeat_missed","timestamp":now,"hostname":host,"platform":"receiver-watchdog","severity":"warning","source":"receiver-watchdog","message":msg})
    with Server((a.listen, a.port), Handler) as srv:
        threading.Thread(target=heartbeat_watchdog, args=(srv,), daemon=True).start()
        print(f"Receiving host logs on {a.listen}:{a.port}; output: {out}; heartbeat timeout: {a.heartbeat_timeout}s", flush=True)
        try: srv.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt: print("\nReceiver stopped")
if __name__ == "__main__": main()
