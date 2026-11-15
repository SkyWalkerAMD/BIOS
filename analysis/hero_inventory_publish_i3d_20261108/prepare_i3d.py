"""Create the independent I3D shell once; never alter the frozen I3B input."""
from pathlib import Path
import hashlib
import json
import shutil

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
BASE=ROOT/'analysis/hero_inventory_publish_i3b_20261108'
assert not (OUT/'source').exists(), 'One-time preparation refuses existing source tree'
manifest=json.loads((BASE/'build.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for relative,digest in manifest['sources'].items():
    assert sha(BASE/'source'/relative)==digest, relative
for folder in ('source','staged-drivers'):
    shutil.copytree(BASE/folder,OUT/folder,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
names=('build.py','decode_captures.py','identity-source.json','test_network.c','test_network.py',
       'test_tcp.c','test_tcp.py','test_tls_client.c','test_tls_client.py','test_qr_bounds.py',
       'verify_i3b_pe.py','run_vm.py')
for name in names:
    dest=OUT/name.replace('i3b','i3d')
    shutil.copy2(BASE/name,dest)
for path in [p for p in OUT.rglob('*') if p.is_file() and p.suffix in ('.c','.h','.py') and p.name!='prepare_i3d.py']:
    text=path.read_text(encoding='utf-8')
    text=text.replace('I3B','I3D').replace('I3b','I3d').replace('i3b','i3d')
    text=text.replace('LEGACY-INVENTORY','CONTINUATION').replace('I3D-LEGACY.iso','I3D-CONTINUATION.iso')
    text=text.replace('I3d-legacy-inventory','I3d-continuation').replace('INTERNAL INVENTORY VERIFICATION','INVENTORY CONTINUATION')
    path.write_text(text,encoding='utf-8',newline='\n')
input_files=[BASE/'build.json',BASE/'USB/EFI/BOOT/BOOTX64.EFI',BASE/'HERO-INVENTORY-I3B-LEGACY.iso']
report={'scope':'Independent I3D copy; frozen I3B is read-only input.',
        'inputs':{p.relative_to(ROOT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in input_files},
        'base_source_hashes':manifest['sources'],
        'continuation_engine':'Awaiting reviewed handoff from analysis/hero_inventory_20261108/native_i3d; no package frozen yet.'}
(OUT/'base-provenance.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('I3D independent shell prepared; continuation engine handoff pending.')
