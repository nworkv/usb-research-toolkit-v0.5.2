#!/usr/bin/env python3
import importlib.util, json, tempfile, threading
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('host_receiver',root/'scripts'/'host-log-receiver.py')
mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)
class FakeServer:
    def __init__(self, out): self.out_dir=out
with tempfile.TemporaryDirectory() as td:
    out=Path(td); server=FakeServer(out)
    mod.append_event(server,'host-a',out/'host-host-a.log',out/'host-host-a.jsonl',{
        'type':'event','timestamp':1770000000,'severity':'error','source':'Windows-System',
        'message':'WINDOWS_EVENT id=1001 BugCheck'
    })
    assert 'BugCheck' in (out/'host-host-a.log').read_text()
    rows=[json.loads(x) for x in (out/'host-host-a.jsonl').read_text().splitlines()]
    assert len(rows)==1 and rows[0]['message'].endswith('BugCheck')
    mod.append_event(server,'host-a',out/'host-host-a.log',out/'host-host-a.jsonl',{
        'type':'heartbeat','timestamp':1770000001,'severity':'info','source':'host-agent',
        'message':'HOST_AGENT_HEARTBEAT'
    })
    assert 'HEARTBEAT' not in (out/'host-host-a.log').read_text()
    assert len((out/'host-host-a.jsonl').read_text().splitlines())==2
assert mod.secrets_compare('a'*32, 'a'*32)
assert not mod.secrets_compare('a'*32, 'b'*32)
fuzz_spec=importlib.util.spec_from_file_location('usb_fuzz',root/'scripts'/'usb-fuzz.py')
fuzz=importlib.util.module_from_spec(fuzz_spec); assert fuzz_spec and fuzz_spec.loader; fuzz_spec.loader.exec_module(fuzz)
assert fuzz.CRASH_PATTERNS.search('HOST_AGENT_HEARTBEAT_MISSED host=test')
assert fuzz.CRASH_PATTERNS.search('WINDOWS_EVENT id=41 provider=Microsoft-Windows-Kernel-Power')
print('host-log transport tests passed')
