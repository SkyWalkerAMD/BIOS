"""Prepare independent INV04 sources from pinned INV03; no old output changes."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;OLD=HERE.with_name('spi_inventory_candidate03')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(OLD/'source/inventory.c')=='2f6856531adbb98403aeb4e455531c6d03149e0d426c10c62b1932bde97a442a'
assert sha(OLD/'build/BOOTX64.EFI')=='ffff289eb6e2b52ba8a53c66ffd70ff4e181443b23a1ef0b5ba60c445c50efba'
assert sha(OLD/'build/SAGE1904-SPI-INVENTORY03.iso')=='cafd2b99a276897afa9bff0d330e2fecc58fecb5554c546e07fbdf7ef78f34e3'
for p in (OLD/'source').rglob('*'):
    if p.is_file():
        dest=HERE/'source'/p.relative_to(OLD/'source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
for name in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','sources.json','layout_evidence.json','root_bridge_evidence.json']:
    shutil.copyfile(OLD/name,HERE/name)
for name in ['source/inventory.c','build_candidate.py','verify_ovmf.py']:
    path=HERE/name;s=path.read_text(encoding='utf8')
    for a,b in [('SPI-INVENTORY03','SPI-INVENTORY04'),('SPI-INVENTORY-03','SPI-INVENTORY-04'),('SPIINV03','SPIINV04'),('SPI INVENTORY 03','SPI INVENTORY 04'),('SPI inventory 03','SPI inventory 04')]:s=s.replace(a,b)
    path.write_text(s,encoding='utf8')
(HERE/'baseline_binding.json').write_text(json.dumps({'inv03_source_sha256':sha(OLD/'source/inventory.c'),'inv03_efi_sha256':sha(OLD/'build/BOOTX64.EFI'),'inv03_iso_sha256':sha(OLD/'build/SAGE1904-SPI-INVENTORY03.iso')},indent=2)+'\n',encoding='utf8')
print('INV04 independent sources prepared')
