#!/usr/bin/env python3
import importlib.util
import json
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify_usb_case', root/'scripts'/'verify-usb-case.py')
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

profile = json.loads((root/'profiles'/'templates'/'hid-mouse.json').read_text())
expected = mod.build_expected_descriptors(profile)
assert expected[(1,0,0)][0] == 18
assert expected[(1,0,0)][1] == 1
assert expected[(1,0,0)][7] == 64
assert int.from_bytes(expected[(1,0,0)][10:12], 'little') == profile['device']['idProduct']
assert len(expected[(2,0,0)]) == 34
assert expected[(34,0,0)] == bytes.fromhex(profile['raw_descriptors']['34:0'])

trace = [
 {'event':'CONTROL_REQUEST','sequence':1,'request':{'bmRequestType':128,'bRequest':6,'wValue':256,'wIndex':0,'wLength':64}},
 {'event':'CONTROL_RESPONSE_COMPLETE','sequence':2,'request':{'bmRequestType':128,'bRequest':6,'wValue':256,'wIndex':0,'wLength':64},'actual_length':18,'payload_hex':expected[(1,0,0)].hex()},
]
r = mod.profile_descriptor_checks(profile, trace)
assert r['status'] == 'PASS', r
trace[1]['payload_hex'] = '00'*18
r = mod.profile_descriptor_checks(profile, trace)
assert r['status'] == 'FAIL', r
print('verify-usb-case descriptor checks: PASS')
