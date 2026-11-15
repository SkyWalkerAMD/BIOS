"""Retain immutable vendor sources and exact existing evidence, no device IO."""
from pathlib import Path
import hashlib,json,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[1];D=P/'sources';D.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'));sys.path.insert(0,str(ROOT/'analysis'))
from PySquashfsImage import SquashFsImage
from bmc_arm_inspect import Elf32
sha=lambda b:hashlib.sha256(b).hexdigest();rows=[]
def retain(name,b,origin):
 p=D/name
 if p.exists():assert p.read_bytes()==b
 else:p.write_bytes(b)
 rows.append(dict(file=name,bytes=len(b),sha256=sha(b),origin=origin));return p
for name in ('libipmipdkcmds.so.13.0.0','libipmipdk.so.13.8.0'):
 p=ROOT/'analysis/bmc_1_3_13_official/selected-rootfs/usr/local/lib'/name;retain(name,p.read_bytes(),p.relative_to(ROOT).as_posix())
p=ROOT/'analysis/bmc_1_3_13_official/selected-rootfs/usr/local/lib/ipmi/ast2600evb_ami/libipmipar.so.13.16.0';retain(p.name,p.read_bytes(),p.relative_to(ROOT).as_posix())
image=ROOT/'analysis/bmc_1_3_13_official/KODO1313.ima'
with SquashFsImage.from_file(str(image),offset=0x520000) as fs:
 for name in ('/usr/local/lib/libipmipdkapi.so.13.1.0',):
  x=fs.root.select(name);assert x.is_file and x.size<100000;retain(Path(name).name,x.read_bytes(),dict(image=image.relative_to(ROOT).as_posix(),offset='0x520000',member=name))
j=json.loads((ROOT/'analysis/hero_sensor_r1/manifest.json').read_text())
for m in j['modules']:
 if m['guid'] not in ('68A0D4CA-9022-474C-BA22-483480DC9A0A','6372357A-06D7-43EF-B55C-1964F3DD6916'):continue
 paths=list((ROOT/m['source_path']).rglob('*PE32 image section/body.bin'));assert len(paths)==1
 b=paths[0].read_bytes();assert sha(b)==m['original_pe_sha256'];retain('donor-'+m['guid']+'.efi',b,paths[0].relative_to(ROOT).as_posix())
p=ROOT/'analysis/hero_3107_official/selected/062A6204-8C80-4A27-9D09-96654C965894/image.efi';retain('HERO-3107-HWM.efi',p.read_bytes(),p.relative_to(ROOT).as_posix())
(P/'source-manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
(P/'disassembly').mkdir(exist_ok=True)
for f in D.glob('*.so.*'):
 e=Elf32(f)
 names=['OemEnDisSensor','OemMBFanControl','ASUS_API_GetSensorEnable','ASUS_API_SetSensorEnable','dev_virtualminusfan_32_0_32_read_device','dev_virtualminusfan_30_0_32_read_device']
 for n in names:
  if n in e.byname and e.byname[n]['value']:
   (P/'disassembly'/(f.name+'-'+n+'.txt')).write_text(e.disasm(n));print(f.name,n,hex(e.byname[n]['value']))
print('retained',len(rows))
