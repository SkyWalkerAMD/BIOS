"""Copy pinned INV02 into an independent INV03 work area, excluding outputs."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;OLD=HERE.with_name('spi_inventory_candidate02')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(OLD/'source/inventory.c')=='20747e5fa983c34993059e052aafaae100be57a6fe7b534f3fddcd4da874a403'
assert sha(OLD/'build/BOOTX64.EFI')=='9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e'
assert sha(OLD/'build/SAGE1904-SPI-INVENTORY02.iso')=='e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9'
for p in (OLD/'source').rglob('*'):
    if p.is_file():
        target=HERE/'source'/p.relative_to(OLD/'source');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
for name in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','finalize_report.py','sources.json','layout_evidence.json']:
    shutil.copyfile(OLD/name,HERE/name)
for name in ['source/inventory.c','build_candidate.py','verify_ovmf.py','finalize_report.py']:
    path=HERE/name;s=path.read_text(encoding='utf8')
    for a,b in [('SPI-INVENTORY02','SPI-INVENTORY03'),('SPI-INVENTORY-02','SPI-INVENTORY-03'),('SPIINV02','SPIINV03'),('SPI INVENTORY 02','SPI INVENTORY 03'),('SPI inventory 02','SPI inventory 03')]:s=s.replace(a,b)
    path.write_text(s,encoding='utf8')
(HERE/'baseline_binding.json').write_text(json.dumps({'inv02_source_sha256':sha(OLD/'source/inventory.c'),'inv02_efi_sha256':sha(OLD/'build/BOOTX64.EFI'),'inv02_iso_sha256':sha(OLD/'build/SAGE1904-SPI-INVENTORY02.iso')},indent=2)+'\n',encoding='utf8')
print('INV03 isolated sources prepared; INV02 unchanged')
