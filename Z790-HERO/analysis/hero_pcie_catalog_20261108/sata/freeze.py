from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((OUT/'build.json').read_text());tests=json.loads((OUT/'verification.json').read_text());assert tests['all_passed'] and tests['dll_sha256']==sha(OUT/'sata.dll')==build['dll_sha256']
for name,origin in [('hero_pcie_catalog.h',ROOT/'analysis/hero_pcie_catalog_20261108/source/hero_pcie_catalog.h'),('hero_hardware_source.h',ROOT/'analysis/hero_hardware_source_20261108/source/hero_hardware_source.h')]:assert sha(OUT/'source'/name)==sha(origin)
files=[p for p in (OUT/'source').glob('*') if p.is_file()]+[OUT/n for n in ('build.py','test_sata.py','build.json','verification.json','hero71-sata-proposal.json','hero_sata_catalog.su','接入与证据说明.txt','freeze.py')]
result=dict(version='HSC1',frozen=True,hardware_operations=0,network_operations=0,tests=tests['count'],files=[dict(path=str(p.relative_to(OUT)),bytes=p.stat().st_size,sha256=sha(p)) for p in files],dll_sha256=sha(OUT/'sata.dll'),input_sha256=tests['current_host_source_sha256'])
(OUT/'handoff.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))
