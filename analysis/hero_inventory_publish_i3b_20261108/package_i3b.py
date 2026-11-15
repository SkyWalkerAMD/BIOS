from pathlib import Path
import hashlib,json,zipfile
O=Path(__file__).resolve().parent;R=O.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((O/'build.json').read_text());app=O/'USB/EFI/BOOT/BOOTX64.EFI';iso=O/'HERO-INVENTORY-I3B-LEGACY.iso'
assert b['artifacts']['BOOTX64.EFI']['sha256']==sha(app) and b['iso_sha256']==sha(iso)
for name in ('pe-verification.json','vm-verification.json'):
 t=json.loads((O/name).read_text());assert t.get('passed',t.get('all_passed')) and t['app_sha256']==sha(app)
for name in ('tls-client-tests.json','qr-boundary-tests.json'):
 assert json.loads((O/name).read_text())['passed']
handoff=json.loads((R/'analysis/hero_inventory_20261108/native/handoff.json').read_text())
native=R/'analysis/hero_inventory_20261108/native'
for name in ('inventory_legacy71.c','inventory_legacy71.h','legacy71_json.h','catalog71.h'):
 assert (O/'source'/name).read_bytes()==(native/name).read_bytes()
provenance={'mode':'Explicit .71 initial legacy inventory publication trial','base_iso':str(R/'analysis/hero_inventory_publish_20261108/HERO-INVENTORY-I3-READONLY.iso'),
 'base_iso_sha256':sha(R/'analysis/hero_inventory_publish_20261108/HERO-INVENTORY-I3-READONLY.iso'),
 'smbios_source':json.loads((O/'identity-source.json').read_text()),'inventory_module_handoff':handoff,
 'limits':['No live .71 connection was made by this build task.','Internal InventoryData capability is 200; this explicitly tests the extracted legacy compatibility requests first.','Stop on the first rejected or uncertain write; never automatic replay or route switch.'],
 'guards':['same exact .71 UUID and HERO3107','current Type0/1/2/4/17 bytes equal captured source before each write','successful UEFI app watchdog disable','exact pinned public leaf plus TLS1.2 cryptographic verification','fixed internal USB NIC and fixed method/path allowlist','fresh identity and ETag/no overwrite of different meaningful identity','one attempted write per item, bounded readback','2 MiB retained audit, 60k/request and 960k before write'],
 'iso_sha256':sha(iso),'app_sha256':sha(app)}
(O/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
names=['HERO-INVENTORY-I3B-LEGACY.iso','使用说明-I3b.txt','build.json','identity-source.json','provenance.json','pe-verification.json','vm-verification.json','tls-client-tests.json','qr-boundary-tests.json','network-tests.json','tcp-tests.json','decode_captures.py']
files=[O/n for n in names if (O/n).is_file()]+[p for folder in ('USB','source') for p in (O/folder).rglob('*') if p.is_file()]
manifest={p.relative_to(O).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}
(O/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
z=O/'HERO-INVENTORY-I3B-LEGACY.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as f:
 for p in files+[O/'package-manifest.json']:f.write(p,p.relative_to(O).as_posix())
print(json.dumps({'iso':str(iso),'iso_sha256':sha(iso),'iso_bytes':iso.stat().st_size,'app_sha256':sha(app),'zip_sha256':sha(z),'zip_bytes':z.stat().st_size}))
