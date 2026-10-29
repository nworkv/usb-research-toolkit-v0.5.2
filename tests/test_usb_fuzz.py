#!/usr/bin/env python3
import importlib.util, json, tempfile
from pathlib import Path
import sys
script=Path(sys.argv[1]).resolve()
spec=importlib.util.spec_from_file_location("usb_fuzz",script)
mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(mod)
root=script.parents[1]
base=root/"profiles"/"templates"/"hid-mouse.json"
with tempfile.TemporaryDirectory() as td:
    out=Path(td)/"a"
    cases=mod.generate(base,8,1234,out,3)
    assert len(cases)==8
    manifest=json.loads((out/"manifest.json").read_text())
    assert manifest["seed"]==1234 and len(manifest["cases"])==8
    assert all(Path(c["profile"]).exists() for c in cases)
    assert all(len(c["changes"]) <= 3 for c in cases)
    one_mutation = mod.generate(base, 5, 20261028, Path(td)/"one", 1)
    assert all(len(c["changes"]) <= 1 for c in one_mutation)
    assert any(len(c["changes"]) == 1 for c in one_mutation)
    # Fixed seed yields byte-for-byte identical profiles in another directory.
    out2=Path(td)/"b"; mod.generate(base,8,1234,out2,3)
    for i in range(1,9):
        a=json.loads((out/f"case-{i:05d}.json").read_text())
        b=json.loads((out2/f"case-{i:05d}.json").read_text())
        assert a==b
    # Every generated profile explicitly records research/manual descriptor mode.
    for c in cases:
        d=json.loads(Path(c["profile"]).read_text())
        assert d["validation"]["mode"]=="research"
        assert d["validation"]["calculated_fields"]=="manual"
print("usb-fuzz tests passed")
