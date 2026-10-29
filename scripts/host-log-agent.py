#!/usr/bin/env python3
"""Host-side log collector/forwarder for an isolated USB test lab.

Windows: polls System event log for bugcheck/unexpected reboot/power events.
Linux: follows warning-and-higher system journal entries. Every collected event
is appended locally before being forwarded to the Raspberry Pi receiver.
"""
from __future__ import annotations
import argparse, json, os, platform, socket, subprocess, sys, time, uuid, threading, datetime
from pathlib import Path

WINDOWS_PS = r'''
$ids = @(41,1001,6008,6005,6006)
try {
  Get-WinEvent -FilterHashtable @{LogName='System'; Id=$ids} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object RecordId,Id,ProviderName,LevelDisplayName,@{N='TimeCreatedUtc';E={$_.TimeCreated.ToUniversalTime().ToString('o')}},Message |
    ConvertTo-Json -Compress -Depth 3
} catch { '[]' }
'''

def send_line(sock, obj):
    sock.sendall((json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))

def event_obj(message, source="host-agent", severity="info", event_id="", kind="event"):
    return {"type":kind,"timestamp":time.time(),"source":source,"severity":severity,"event_id":str(event_id),"message":str(message)[:20000]}

class Agent:
    def __init__(self, args):
        self.args=args; self.hostname=socket.gethostname(); self.platform=f"{platform.system()} {platform.release()}"; self.boot_id=self.get_boot_id()
        self.local=Path(args.local_log).resolve(); self.local.parent.mkdir(parents=True,exist_ok=True)
        self.seen=set(); self.sock=None; self.send_lock=threading.Lock(); self.local_lock=threading.Lock(); self.started_at=time.time()
    def get_boot_id(self):
        try:
            p=Path('/proc/sys/kernel/random/boot_id')
            if p.exists(): return p.read_text().strip()
        except OSError: pass
        return str(uuid.getnode()) + "-" + str(int(time.time() - time.monotonic()))
    def local_write(self, ev):
        with self.local_lock:
            with self.local.open('a',encoding='utf-8') as f:
                f.write(json.dumps(ev,ensure_ascii=False)+"\n"); f.flush(); os.fsync(f.fileno())
    def connect(self):
        while True:
            try:
                s=socket.create_connection((self.args.server,self.args.port),timeout=5); s.settimeout(10)
                send_line(s,{"type":"hello","token":self.args.token,"hostname":self.hostname,"platform":self.platform,"boot_id":self.boot_id})
                reply=s.makefile('rb').readline(4096)
                if not reply or not json.loads(reply).get('ok'): raise RuntimeError('receiver rejected agent authentication')
                self.sock=s
                self.emit(event_obj(f"HOST_AGENT_CONNECTED platform={self.platform}","host-agent","info",kind="agent_connected"))
                print(f"Connected to receiver {self.args.server}:{self.args.port}; local log: {self.local}",flush=True)
                return
            except Exception as e:
                print(f"receiver unavailable ({e}); retrying in {self.args.reconnect}s",file=sys.stderr,flush=True)
                time.sleep(self.args.reconnect)
    def emit(self, ev):
        self.local_write(ev)
        if self.sock:
            try:
                with self.send_lock: send_line(self.sock,ev)
            except OSError:
                try: self.sock.close()
                except OSError: pass
                self.sock=None
    def heartbeat(self):
        self.emit(event_obj("HOST_AGENT_HEARTBEAT","host-agent","info",kind="heartbeat"))
    def run_windows(self):
        print("Collecting Windows System events: IDs 41, 1001, 6008, 6005, 6006",flush=True)
        while True:
            try:
                cp=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",WINDOWS_PS],capture_output=True,text=True,timeout=20,check=False)
                if cp.returncode==0 and cp.stdout.strip():
                    try: rows=json.loads(cp.stdout)
                    except json.JSONDecodeError: rows=[]
                    if isinstance(rows,dict): rows=[rows]
                    for row in rows if isinstance(rows,list) else []:
                        rid=str(row.get('RecordId',''))
                        if not rid or rid in self.seen: continue
                        self.seen.add(rid)
                        # Mark old events as baseline; do not attribute pre-campaign history to a new profile.
                        created = str(row.get('TimeCreatedUtc', ''))
                        try:
                            created_ts = datetime.datetime.fromisoformat(created.replace('Z', '+00:00')).timestamp()
                        except (ValueError, TypeError): created_ts = self.started_at
                        if created_ts < self.started_at - 2: continue
                        msg=f"WINDOWS_EVENT id={row.get('Id')} record={rid} provider={row.get('ProviderName')} level={row.get('LevelDisplayName')} time={row.get('TimeCreatedUtc')} message={row.get('Message','')}"
                        severity='error' if str(row.get('Id')) in ('41','1001','6008') else 'info'
                        self.emit(event_obj(msg,'Windows-System',severity,f"{row.get('Id')}:{rid}"))
                    if len(self.seen)>5000: self.seen=set(list(self.seen)[-1000:])
                elif cp.stderr.strip(): self.emit(event_obj(f"WINDOWS_EVENT_QUERY_ERROR {cp.stderr.strip()}",'host-agent','warning'))
            except (OSError,subprocess.TimeoutExpired) as e: self.emit(event_obj(f"WINDOWS_EVENT_QUERY_ERROR {e}",'host-agent','warning'))
            time.sleep(self.args.poll)
    def run_linux(self):
        print("Following Linux journal entries with priority warning or higher",flush=True)
        while True:
            try:
                proc=subprocess.Popen(['journalctl','-f','-n','0','-p','warning','-o','json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
                self.emit(event_obj("LINUX_JOURNAL_FOLLOW_STARTED","host-agent","info"))
                assert proc.stdout is not None
                while True:
                    line=proc.stdout.readline()
                    if line:
                        try: row=json.loads(line)
                        except json.JSONDecodeError: continue
                        msg=row.get('MESSAGE','')
                        source=row.get('SYSLOG_IDENTIFIER',row.get('_COMM','system-journal'))
                        pr=str(row.get('PRIORITY','4'))
                        sev='error' if pr in ('0','1','2','3') else 'warning'
                        event_id=row.get('__CURSOR','')
                        self.emit(event_obj(msg,source,sev,event_id))
                    elif proc.poll() is not None: break
                err=proc.stderr.read() if proc.stderr else ''
                self.emit(event_obj(f"LINUX_JOURNAL_RESTART returncode={proc.returncode} {err}",'host-agent','warning'))
            except FileNotFoundError:
                self.emit(event_obj("journalctl not found; install systemd-journal utilities or configure a supported collector",'host-agent','error'))
                raise
            except OSError as e: self.emit(event_obj(f"LINUX_JOURNAL_ERROR {e}",'host-agent','error'))
            time.sleep(self.args.reconnect)
    def heartbeat_loop(self):
        while True:
            time.sleep(self.args.heartbeat)
            try:
                if self.sock is None: self.connect()
                self.emit(event_obj("HOST_AGENT_HEARTBEAT","host-agent","info",kind="heartbeat"))
            except (OSError, RuntimeError, ValueError): pass
    def run(self):
        self.connect()
        threading.Thread(target=self.heartbeat_loop,daemon=True).start()
        if platform.system().lower()=='windows': self.run_windows()
        elif platform.system().lower()=='linux': self.run_linux()
        else: raise SystemExit(f"Unsupported platform: {platform.system()}; Windows and Linux are supported")

def main():
    p=argparse.ArgumentParser(description="Непрерывный сбор системных событий хоста и передача на Raspberry Pi")
    p.add_argument('--server',required=True,help='IP Raspberry Pi в лабораторной сети')
    p.add_argument('--port',type=int,default=8765)
    auth=p.add_mutually_exclusive_group(required=True)
    auth.add_argument('--token',help='секрет (будет виден в списке процессов; предпочтительнее --token-file)')
    auth.add_argument('--token-file',help='файл с тем же секретом, что у host-log-receiver.py')
    p.add_argument('--local-log',default='runs/host-agent/host-events.jsonl',help='локальный журнал на тестируемом хосте')
    p.add_argument('--poll',type=float,default=5.0,help='интервал опроса Windows Event Log, секунды')
    p.add_argument('--heartbeat',type=float,default=5.0,help='интервал heartbeat Linux, секунды')
    p.add_argument('--reconnect',type=float,default=3.0)
    a=p.parse_args()
    if a.token_file:
        try: a.token=Path(a.token_file).read_text(encoding='utf-8').strip()
        except OSError as e: p.error(f'cannot read token file: {e}')
    if len(a.token)<24: p.error('token must be at least 24 characters')
    if not (0.2<=a.poll<=300 and 0.2<=a.heartbeat<=300 and 0.2<=a.reconnect<=60): p.error('poll/heartbeat/reconnect interval out of range')
    Agent(a).run()
if __name__=='__main__': main()
