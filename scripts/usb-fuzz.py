#!/usr/bin/env python3
"""Bounded USB profile mutation/campaign runner for isolated lab systems.

This tool mutates JSON profiles and optionally runs an explicitly supplied test
command. It does not claim to detect an OS crash unless the configured host log
contains a recognized crash signature.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, os, random, re, shlex, signal, subprocess, sys, time
from pathlib import Path
from typing import Any

NUMERIC_FIELDS = {
    "bcdUSB": (0, 65535), "bDeviceClass": (0, 255), "bDeviceSubClass": (0, 255),
    "bDeviceProtocol": (0, 255), "bMaxPacketSize0": (0, 255), "idVendor": (0, 65535),
    "idProduct": (0, 65535), "bcdDevice": (0, 65535), "bNumConfigurations": (0, 255),
    "bLength": (0, 255), "bDescriptorType": (0, 255), "wTotalLength": (0, 65535),
    "bNumInterfaces": (0, 255), "bConfigurationValue": (0, 255), "bmAttributes": (0, 255),
    "bMaxPower": (0, 255), "bInterfaceNumber": (0, 255), "bAlternateSetting": (0, 255),
    "bNumEndpoints": (0, 255), "bInterfaceClass": (0, 255), "bInterfaceSubClass": (0, 255),
    "bInterfaceProtocol": (0, 255), "bEndpointAddress": (0, 255), "bmAttributes": (0, 255),
    "wMaxPacketSize": (0, 65535), "bInterval": (0, 255),
}
CRASH_PATTERNS = re.compile(r"kernel panic|BUG: unable to handle|Oops:|general protection fault|bugcheck|blue screen|SYSTEM_THREAD_EXCEPTION|KMODE_EXCEPTION|IRQL_NOT_LESS_OR_EQUAL|kernel-power.*41|41.*kernel-power|windows_event id=(?:41|1001|6008)\b|HOST_AGENT_HEARTBEAT_MISSED", re.I)

def sha256(path: Path) -> str:
    h=hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()

def mutate_tree(node: Any, rng: random.Random, changed: list[str], path: str="$", budget: int=2, max_changes: int | None = None) -> Any:
    """Mutate at most max_changes fields during this traversal (None means no limit)."""
    if budget <= 0 or (max_changes is not None and len(changed) >= max_changes):
        return node
    if isinstance(node, dict):
        keys=list(node.keys())
        rng.shuffle(keys)
        for key in keys:
            if max_changes is not None and len(changed) >= max_changes:
                break
            val=node[key]; p=f"{path}.{key}"
            if key in NUMERIC_FIELDS and isinstance(val, int) and not isinstance(val, bool) and rng.random() < 0.42:
                lo,hi=NUMERIC_FIELDS[key]
                choices=[0,1,lo,hi,max(lo,val-1),min(hi,val+1),rng.randint(lo,hi)]
                # Keep values representable in their descriptor field. Research-mode
                # semantic violations are useful; over-width integers cannot be emitted.
                choices=[x for x in choices if lo <= x <= hi and x != val]
                if choices:
                    new=rng.choice(choices)
                    node[key]=new
                    changed.append(f"{p}: {val} -> {new}")
                    if max_changes is not None and len(changed) >= max_changes:
                        return node
            elif key in ("manufacturer", "product", "serial") and isinstance(val,str) and rng.random()<0.3:
                new=val[:rng.randint(0,len(val))] if val else "LAB"
                if new == val: new=val+"-M"
                node[key]=new; changed.append(f"{p}: string changed")
                if max_changes is not None and len(changed) >= max_changes: return node
            elif key.endswith("_hex") and isinstance(val,str) and len(val)>=2 and rng.random()<0.45:
                try: b=bytearray.fromhex(val)
                except ValueError: b=bytearray()
                if b:
                    i=rng.randrange(len(b)); old=b[i]
                    options=[x for x in (0,255,old ^ (1 << rng.randrange(8))) if x != old]
                    if options:
                        b[i]=rng.choice(options); node[key]=b.hex(); changed.append(f"{p}[{i}]: {old:02x} -> {b[i]:02x}")
                        if max_changes is not None and len(changed) >= max_changes: return node
            elif key in ("34:0", "33:0", "32:0") and isinstance(val,str) and len(val)>=2 and rng.random()<0.6:
                try: b=bytearray.fromhex(val)
                except ValueError: b=bytearray()
                if b:
                    i=rng.randrange(len(b)); old=b[i]
                    options=[x for x in (0,255,old ^ (1 << rng.randrange(8))) if x != old]
                    if options:
                        b[i]=rng.choice(options); node[key]=b.hex(); changed.append(f"{p}[{i}]: {old:02x} -> {b[i]:02x}")
                        if max_changes is not None and len(changed) >= max_changes: return node
            elif key == "in_payloads" and isinstance(val,dict):
                eps=list(val.keys()); rng.shuffle(eps)
                for ep in eps:
                    if max_changes is not None and len(changed) >= max_changes: return node
                    payload=val[ep]
                    if isinstance(payload,str) and len(payload)>=2 and rng.random()<0.3:
                        try: b=bytearray.fromhex(payload)
                        except ValueError: continue
                        if b:
                            i=rng.randrange(len(b)); old=b[i]; new=old ^ (1 << rng.randrange(8))
                            b[i]=new; val[ep]=b.hex(); changed.append(f"{p}.{ep}[{i}]: {old:02x} -> {new:02x}")
                            if max_changes is not None and len(changed) >= max_changes: return node
            else:
                mutate_tree(val,rng,changed,p,budget-1,max_changes)
                if max_changes is not None and len(changed) >= max_changes: return node
    elif isinstance(node,list):
        indices=list(range(len(node))); rng.shuffle(indices)
        for i in indices:
            if max_changes is not None and len(changed) >= max_changes: break
            mutate_tree(node[i],rng,changed,f"{path}[{i}]",budget-1,max_changes)
    return node

def load_profile(path: Path) -> dict:
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data,dict) or "device" not in data: raise ValueError("base profile must be a JSON object with a 'device' section")
    return data

def generate(base: Path, count: int, seed: int, out_dir: Path, mutations: int) -> list[dict]:
    if count < 1 or count > 10000: raise ValueError("count must be in 1..10000")
    if mutations < 1 or mutations > 100: raise ValueError("mutations must be in 1..100")
    original=load_profile(base); rng=random.Random(seed); out_dir.mkdir(parents=True,exist_ok=True); cases=[]
    for n in range(1,count+1):
        profile=copy.deepcopy(original); changes=[]
        for _ in range(mutations): mutate_tree(profile,rng,changes,budget=5,max_changes=len(changes)+1)
        profile["profile_name"]=f"fuzz-{base.stem}-{n:05d}"
        profile.setdefault("validation",{})["mode"]="research"
        profile["validation"]["calculated_fields"]="manual"
        target=out_dir/f"case-{n:05d}.json"
        target.write_text(json.dumps(profile,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        cases.append({"case":n,"profile":str(target.resolve()),"sha256":sha256(target),"changes":changes,"status":"GENERATED" if changes else "NO_CHANGE"})
    (out_dir/"manifest.json").write_text(json.dumps({"tool":"usb-fuzz.py","seed":seed,"base":str(base.resolve()),"base_sha256":sha256(base),"count":count,"mutations_per_case":mutations,"cases":cases},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    return cases

def run_campaign(args: argparse.Namespace) -> int:
    out=Path(args.out_dir).resolve(); cases=generate(Path(args.base).resolve(),args.count,args.seed,out,args.mutations)
    hostlog=Path(args.host_log).resolve() if args.host_log else None
    offset=hostlog.stat().st_size if hostlog and hostlog.exists() else 0
    results=[]; (out/"campaign.jsonl").write_text("",encoding="utf-8"); command=shlex.split(args.runner) if args.runner else None
    if command and not args.confirm_lab:
        print("Refusing to execute runner without --confirm-lab; generated profiles only.",file=sys.stderr); command=None
    for case in cases:
        row={"case":case["case"],"profile":case["profile"],"sha256":case["sha256"],"status":"GENERATED_ONLY","returncode":None,"timeout":False,"host_crash_signature":False}
        if command:
            argv=[part.replace("{profile}",case["profile"]).replace("{case}",str(case["case"])) for part in command]
            start=time.time()
            try:
                proc=subprocess.run(argv,capture_output=True,text=True,timeout=args.timeout,check=False)
                row.update(status="COMPLETED" if proc.returncode==0 else "RUNNER_ERROR",returncode=proc.returncode,stdout=proc.stdout[-12000:],stderr=proc.stderr[-12000:])
            except subprocess.TimeoutExpired as e:
                row.update(status="TIMEOUT",timeout=True,stdout=(e.stdout or b"").decode(errors="replace")[-12000:] if isinstance(e.stdout,bytes) else str(e.stdout or "")[-12000:],stderr=(e.stderr or b"").decode(errors="replace")[-12000:] if isinstance(e.stderr,bytes) else str(e.stderr or "")[-12000:])
            row["duration_seconds"]=round(time.time()-start,3)
            if hostlog and args.host_log_settle > 0:
                time.sleep(args.host_log_settle)
            if hostlog and hostlog.exists():
                try:
                    with hostlog.open("rb") as f: f.seek(offset); added=f.read().decode(errors="replace")
                    offset=hostlog.stat().st_size
                    row["host_log_excerpt"]=added[-8000:]
                    row["host_crash_signature"]=bool(CRASH_PATTERNS.search(added))
                except OSError as e: row["host_log_error"]=str(e)
            if row["host_crash_signature"] or row["timeout"] or (row["returncode"] not in (0,None)):
                row["status"]="SUSPECTED_FAILURE"
                # Preserve an exact reproducer package for every suspicious run.
                repro=out/"reproducers"/f"case-{case['case']:05d}"; repro.mkdir(parents=True,exist_ok=True)
                import shutil; shutil.copy2(case["profile"],repro/"profile.json")
                (repro/"result.json").write_text(json.dumps(row,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
                (repro/"README.txt").write_text(f"Reproducer case {case['case']}\nSeed: {args.seed}\nProfile SHA-256: {case['sha256']}\nRunner: {args.runner}\nStatus is a suspicion, not proof of an OS crash. Re-run only in an isolated lab.\n",encoding="utf-8")
        results.append(row)
        with (out/"campaign.jsonl").open("a",encoding="utf-8") as f: f.write(json.dumps(row,ensure_ascii=False)+"\n")
        print(f"[{case['case']}/{len(cases)}] {row['status']} {case['profile']}")
        if row["status"]=="SUSPECTED_FAILURE" and args.stop_on_crash: break
    summary={"seed":args.seed,"generated":len(cases),"executed":sum(r["status"] not in ("GENERATED_ONLY",) for r in results),"suspected_failures":sum(r["status"]=="SUSPECTED_FAILURE" for r in results),"host_crash_signatures":sum(bool(r["host_crash_signature"]) for r in results),"results":results}
    (out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(f"Summary: {out/'summary.json'}")
    return 1 if summary["suspected_failures"] else 0

def main() -> int:
    p=argparse.ArgumentParser(description="Воспроизводимые мутации USB-профилей и ограниченная лабораторная кампания")
    sub=p.add_subparsers(dest="cmd",required=True)
    g=sub.add_parser("generate",help="только создать профили, без подключения к хосту")
    g.add_argument("--base",required=True); g.add_argument("--count",type=int,default=100); g.add_argument("--seed",type=int,default=42); g.add_argument("--mutations",type=int,default=3); g.add_argument("--out-dir",default="runs/fuzz/generated")
    c=sub.add_parser("campaign",help="генерация и последовательный запуск пользовательского тестового runner")
    c.add_argument("--base",required=True); c.add_argument("--count",type=int,default=100); c.add_argument("--seed",type=int,default=42); c.add_argument("--mutations",type=int,default=3); c.add_argument("--out-dir",default="runs/fuzz/campaign"); c.add_argument("--runner",help="команда с плейсхолдером {profile}; без неё только генерация"); c.add_argument("--timeout",type=float,default=30.0); c.add_argument("--host-log",help="файл host log, куда добавляются новые строки с kernel panic/bugcheck signatures"); c.add_argument("--host-log-settle",type=float,default=6.0,help="секунды ожидания новых удалённых событий перед чтением host log (по умолчанию 6)"); c.add_argument("--confirm-lab",action="store_true",help="подтвердить, что runner подключён только к изолированному тестовому хосту"); c.add_argument("--stop-on-crash",action="store_true")
    args=p.parse_args()
    try:
        if args.cmd=="generate":
            cases=generate(Path(args.base).resolve(),args.count,args.seed,Path(args.out_dir).resolve(),args.mutations)
            print(f"Generated {len(cases)} profiles; manifest: {Path(args.out_dir).resolve()/'manifest.json'}"); return 0
        if args.timeout<=0 or args.timeout>3600: raise ValueError("timeout must be in (0, 3600]")
        if args.cmd=="campaign" and (args.host_log_settle<0 or args.host_log_settle>60): raise ValueError("host-log-settle must be in 0..60 seconds")
        return run_campaign(args)
    except (OSError,ValueError,json.JSONDecodeError) as e:
        print(f"error: {e}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
