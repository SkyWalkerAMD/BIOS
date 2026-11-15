"""Copy only selected, SHA-256 bound original modules for local REA analysis."""
from pathlib import Path
import hashlib, json, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
EXTRACT = ROOT / "analysis/workstation_20261008"
INV = EXTRACT / "W890_SAGE_0603/inventory.json"
inventory = json.loads(INV.read_text(encoding="utf-8"))
selected = {"3370A4BD-8C23-4565-A2A2-065FEEDE6080": "SecSMIFlash",
            "3FEEC852-F14C-4E7F-97FD-4C3A8C5BBECC": "FWkey"}
out = HERE / "native_inputs"
out.mkdir(exist_ok=True)
result = []
for module in inventory["modules"]:
    if module["guid"] not in selected:
        continue
    name = selected[module["guid"]]
    section = next(s for s in module["sections"] if s["type"] == ("Raw" if name == "FWkey" else "PE32 image"))
    source = EXTRACT / section["path"]
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == section["sha256"]
    target = out / (name + (".bin" if name == "FWkey" else ".efi"))
    if target.exists():
        assert target.read_bytes() == data
    else:
        target.write_bytes(data)
    result.append(dict(guid=module["guid"], name=name, source=str(source.resolve()),
                       copy=str(target.resolve()), sha256=digest, size=len(data)))
assert len(result) == len(selected)
(out / "derivation.json").write_text(json.dumps(dict(source_inventory_sha256=hashlib.sha256(INV.read_bytes()).hexdigest(),
    script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), modules=result), indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
