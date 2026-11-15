"""Freeze an independently verified I3D package, without touching I3B."""
from pathlib import Path
import hashlib,json,zipfile
O=Path(__file__).resolve().parent;R=O.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(n):return json.loads((O/n).read_text(encoding='utf-8'))
b=read('build.json');app=O/'USB/EFI/BOOT/BOOTX64.EFI';iso=O/'HERO-INVENTORY-I3D-CONTINUATION.iso'
assert b['artifacts']['BOOTX64.EFI']['sha256']==sha(app) and b['iso_sha256']==sha(iso)
for name,digest in b['sources'].items():assert sha(O/'source'/name)==digest,name
for name in ('pe-verification.json','continuation-pe-tests.json','vm-verification.json'):
 t=read(name);assert t.get('passed',t.get('all_passed')) and t['app_sha256']==sha(app),name
for name in ('tls-client-tests.json','qr-boundary-tests.json','network-tests.json','tcp-tests.json'):
 assert read(name)['passed'],name
h=read('handoff-integration.json')
for name,meta in h['native_sources'].items():assert sha(O/'source'/name)==meta['sha256']
for name,digest in h['dxe_sources'].items():assert sha(O/'source'/name)==digest
base=read('base-provenance.json')
for name,meta in base['inputs'].items():assert sha(R/name)==meta['sha256'],'Frozen I3B input changed: '+name
for name,digest in base['base_source_hashes'].items():assert sha(R/'analysis/hero_inventory_publish_i3b_20261108/source'/name)==digest,name
provenance={'mode':'Explicit .71 continuation of verified I3B System and CPU objects',
 'base_provenance':base,'handoff_integration':h,'smbios_source':read('identity-source.json'),
 'guards':['exact .71 HERO3107 UUID and current Type0/1/2/4/17 bytes','UEFI app watchdog disabled successfully','fixed public leaf pin plus TLS1.2 cryptographic verification','CPU POST and System identity PATCH denied by transport','only four frozen DIMM bodies and 71-byte ProcessorSummary body accepted','fresh direct URI GET404 required before a DIMM POST','fresh System ETag for summary PATCH','at most one write per confirmed W/W or S/S; uncertain results stop writes','2 MiB retained audit and 960000-byte post-write reserve','D diagnostics are read-only and cannot gate/open publication'],
 'limits':['No live .71 operations were made by this build task.','Object readback and collection membership are separate outcomes; state4 is not complete Redfish success.','No BIOS configuration/SPI writes or OEM initialization.','No reboot persistence or collection repair is claimed.'],
 'app_sha256':sha(app),'iso_sha256':sha(iso),'frozen_i3b_unchanged_verified':True}
(O/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
names=['HERO-INVENTORY-I3D-CONTINUATION.iso','使用说明-I3d.txt','build.json','identity-source.json','provenance.json',
       'base-provenance.json','handoff-integration.json','pe-verification.json','continuation-pe-tests.json','vm-verification.json',
       'tls-client-tests.json','qr-boundary-tests.json','network-tests.json','tcp-tests.json','decode_captures.py',
       'verify_i3d_pe.py','verify_continuation_pe.py','test_tls_client.c','test_tls_client.py','test_qr_bounds.py','run_vm.py','build.py']
files=[O/n for n in names]+[p for folder in ('USB','source','review') for p in (O/folder).rglob('*') if p.is_file()]
manifest={p.relative_to(O).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}
(O/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
z=O/'HERO-INVENTORY-I3D-CONTINUATION.zip'
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as f:
 for p in files+[O/'package-manifest.json']:f.write(p,p.relative_to(O).as_posix())
report={'iso':str(iso),'iso_sha256':sha(iso),'iso_bytes':iso.stat().st_size,'app_sha256':sha(app),'app_bytes':app.stat().st_size,
        'zip':str(z),'zip_sha256':sha(z),'zip_bytes':z.stat().st_size,'frozen':True}
(O/'release.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
