"""Offline vendor boot/scanner inspection; no network or hardware access."""
from pathlib import Path
import hashlib,json,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(ROOT/'analysis'))
sys.path.insert(0,str(ROOT/'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage
from bmc_arm_inspect import Elf32
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
D=P/'sources';D.mkdir(exist_ok=True);A=P/'disassembly';A.mkdir(exist_ok=True)
rows=[]
def retain(name,b,origin):
 p=D/name
 if p.exists():assert p.read_bytes()==b
 else:p.write_bytes(b)
 rows.append(dict(file=name,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),origin=origin));return p
j=json.loads((ROOT/'analysis/hero_sensor_r1/manifest.json').read_text())
for m in j['modules']:
 paths=list((ROOT/m['source_path']).rglob('*PE32 image section/body.bin'));assert len(paths)==1
 b=paths[0].read_bytes();assert hashlib.sha256(b).hexdigest()==m['original_pe_sha256']
 retain('donor-'+m['guid']+'.efi',b,paths[0].relative_to(ROOT).as_posix())
j=json.loads((ROOT/'analysis/hero_3107_official/ec_consumers.json').read_text())
for m in j:
 if m['guid'] not in ('C54FE9C8-EFC8-44DB-8EAA-E6755DC89E46','062A6204-8C80-4A27-9D09-96654C965894','DE9ABB5C-2F92-4352-9C56-F51BC9D5E55A','C0A2EC40-7CA9-4FF7-A17C-08B81D70DE80'):continue
 b=(ROOT/m['source']).read_bytes();assert hashlib.sha256(b).hexdigest()==m['sha256']
 retain('hero-'+m['guid']+'.efi',b,m['source'])
image=ROOT/'analysis/bmc_1_3_13_official/KODO1313.ima'
with SquashFsImage.from_file(str(image),offset=0x520000) as fs:
 for name in ('/usr/local/lib/libipmimsghndlr.so.13.22.0','/usr/local/bin/IPMIMain'):
  x=fs.root.select(name);assert x.is_file and x.size<1000000
  retain(Path(name).name,x.read_bytes(),dict(image=image.relative_to(ROOT).as_posix(),member=name,offset='0x520000'))
for name in ('libipmipdkcmds.so.13.0.0','libipmipdkapi.so.13.1.0','libipmipar.so.13.16.0'):
 path=ROOT/'analysis/hero_fan_mapping_20261108/sources'/name;retain(name,path.read_bytes(),path.relative_to(ROOT).as_posix())
for p in D.glob('*.efi'):
 b=p.read_bytes();pe=pefile.PE(data=b,fast_load=True);lines=[]
 for s in pe.sections:
  if s.Characteristics&0x20000000:
   for i in Cs(CS_ARCH_X86,CS_MODE_64).disasm(s.get_data(),s.VirtualAddress):
    lines.append(f'{i.address:08x}: {i.bytes.hex():30s} {i.mnemonic:10s} {i.op_str}')
 (A/(p.name+'.txt')).write_text('\n'.join(lines)+'\n')
symbols={}
for p in D.iterdir():
 if not p.name.startswith('lib') and p.name!='IPMIMain':continue
 e=Elf32(p);names=[n for n,s in e.byname.items() if s['value'] and any(x.lower() in n.lower() for x in ('SensorEnable','SensorEvent','SensorReading','ScanTask','ScanSensor','SensorScan','HideSDR','ReArmSensor','BiosFinish'))]
 symbols[p.name]=[dict(name=n,va=hex(e.byname[n]['value']),bytes=e.byname[n]['size']) for n in names]
 for n in names:
  if e.byname[n]['type']==2 and e.byname[n]['size']<30000:(A/(p.name+'-'+n+'.txt')).write_text(e.disasm(n))
(P/'source-manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
(P/'scanner-symbols.json').write_text(json.dumps(symbols,indent=2)+'\n')
print(json.dumps(symbols,indent=2))
