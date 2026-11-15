"""Parent review: frozen loader, ISO contents and final two boot screenshots."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,importlib.util,io,json,sys
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
LC=HERE.parent/'linux_capacity_candidate01'; LD=LC/'loader'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
mp=LD/'loader_manifest.json'
assert sha(mp)=='03749d2e36d203e6af459b93621579721443ac0aca5aaa90b849460cc2ff2247'
m=read(mp);assert len(m['files'])==m['artifact_count']==437
seen=set()
for r in m['files']:
 p=(LD/r['path']).resolve();assert p.is_relative_to(LD.resolve()) and p not in seen;seen.add(p)
 assert p.stat().st_size==r['bytes'] and sha(p)==r['sha256'],str(p)
media=read(LD/'candidate/media_manifest.json'); verification=read(LD/'candidate/verification.json')
assert media['iso_sha256']==verification['iso_sha256']==m['iso_sha256']=='4e70bb0abfc285849301a6829b1ac51cae914d65025e135b971b06dd47d25d18'
assert media['contract']['cmdline']==read(LC/'payload_review.json')['commandline']
assert media['contract']['payload_manifest_sha256']==sha(LC/'payload_manifest.json')
for key in ['kernel','initrd']:
 r=media['contract'][key];p=Path(r['path']);assert p.is_relative_to(LC) and p.stat().st_size==r['bytes'] and sha(p)==r['sha256']
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'));sys.path.insert(0,str(ROOT/'tools/vm-pydeps'))
import pycdlib
from pyfatfs.PyFatFS import PyFatFS
iso=Path(media['iso']);assert sha(iso)==m['iso_sha256']
cd=pycdlib.PyCdlib();cd.open(str(iso));data=io.BytesIO();cd.get_file_from_iso_fp(data,iso_path='/EFIBOOT.IMG;1');cd.close()
img=LD/'candidate/media/eltorito.img';assert data.getvalue()==img.read_bytes()
files={}
with PyFatFS(str(img),read_only=True,utc=True) as fat:
 for name in fat.walk.files():
  b=fat.readbytes(name);files[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
assert files==media['fat_files'] and len(files)==3
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image,assemble
spec=importlib.util.spec_from_file_location('lc_parent_iso',LC/'decode_linux_log.py')
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
screens=[]
for t in verification['production_iso_tests']:
 folder=LD/t['folder'];result=read(folder/'result.json')
 assert sha(folder/'result.json')==t['result_sha256'] and result['passed'] and result['iso_sha256']==m['iso_sha256']
 png=folder/'terminal-qr.png';assert sha(png)==t['screenshot_sha256']
 log,transport=assemble([read_image(png)],require_inventory=False);semantic=decoder.decode(log)
 assert semantic==t['semantic'] and semantic['complete'] and semantic['stage']==3 and semantic['modules']==semantic['userspace_rc10_calls']==0
 screens.append({'transport':t['transport'],'screenshot_sha256':sha(png),'log':semantic})
assert {x['transport'] for x in screens}=={'sata','usb'}
record={'status':'PASS_PARENT_LINUX_ISO_CONTENT_AND_BOOT_REVIEW','utc':datetime.now(timezone.utc).isoformat(),
 'loader_manifest_sha256':sha(mp),'verified_loader_bindings':437,
 'payload_parent_review_sha256':sha(HERE/'linux_payload_parent_review.json'),
 'iso_sha256':sha(iso),'efi_sha256':m['efi_sha256'],'only_three_expected_files':files,
 'production_parameters_unchanged':True,'final_boot_screens':screens,
 'manual_bootstrap_review':'Pinned same-device files loaded READ-only, complete SHA verification in owned RAM, exact two RandomSeed size-only absence gates, LoadFile2 delivery, stopped error/return path and no fallback.',
 'hardware_scope_reviewed':'User-authorized no-flash maintenance boot on172.20.2.162, exact SAGE1904 DMI gate and pinned disposable virtual HD only. No BIOS image upload or flash.',
 'not_proven':['Physical Linux boot/USB capacity/display','Full SPI backup','Native password UI acceptance','Firmware update acceptance or recovery'],
 'simulation_limit':verification['simulation_limit']}
(HERE/'linux_loader_parent_review.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':record['status'],'bindings':437,'iso_sha256':sha(iso),'screens':len(screens)}))
