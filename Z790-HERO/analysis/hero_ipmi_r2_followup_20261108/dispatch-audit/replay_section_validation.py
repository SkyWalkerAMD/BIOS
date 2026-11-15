"""Execute exact HERO DxeCore stream validation basic block in Unicorn.
No hardware or firmware service emulation is necessary: stop before calls.
"""
from pathlib import Path
import sys,hashlib,json
P=Path(__file__).resolve().parent;ROOT=P.parents[2];sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
pepath=P/'DxeCore.efi';data=pepath.read_bytes();assert hashlib.sha256(data).hexdigest()=='5a4a8d96f7de6f714fd4d91e5579d701e4e4a6394b7dc46968d6cb1f07f8efcf'
image=pefile.PE(data=data).get_memory_mapped_image();BASE=0x100000;STACK=0x200000;BODY=0x300000
def execute(body):
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(BASE,0x20000);u.mem_write(BASE,image);u.mem_map(STACK,0x2000);u.mem_map(BODY,(len(body)+4095)//4096*4096+4096);u.mem_write(BODY,body)
 rsp=STACK+0x1000;u.reg_write(UC_X86_REG_RSP,rsp);u.mem_write(rsp+0x48,len(body).to_bytes(8,'little'));u.reg_write(UC_X86_REG_R11,BODY)
 verdict=[];trace=[]
 def hook(uc,addr,size,unused):
  trace.append(addr-BASE)
  if addr==BASE+0xe636:verdict.append(True);uc.emu_stop()
  if addr==BASE+0xe62a:verdict.append(False);uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(BASE+0xe5c4,BASE+0xe63a,count=100000)
 assert verdict,'bounded validator did not finish'
 return dict(valid=verdict[0],instructions=len(trace),end_rva=hex(trace[-1]),bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
targets=json.loads((P/'container-targets.json').read_text());rows=[]
for item in targets:
 if 'pe' not in item:continue
 root=ROOT/item['path'];body=(root/'body.bin').read_bytes();assert body[-2:]==b'\0\0'
 for label,value in [('original',body),('trim_final_two',body[:-2])]:
  row=execute(value);row.update(name=root.name,case=label);rows.append(row);assert row['valid']==(label=='trim_final_two')
p5=ROOT/'analysis/hero_ipmi_p5/HeroIpmiNativeP5.ffs';p5raw=p5.read_bytes();row=execute(p5raw[24:]);row.update(name='Current local P5 FFS (not assumed working control)',case='additional_observation');rows.append(row)
rc2=ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP.dump';p5body=next(rc2.rglob('534 HeroIpmiNativeP5/body.bin')).read_bytes();row=execute(p5body);row.update(name='Archived RC2 P5',case='additional_observation');rows.append(row)
peers=json.loads((P/'peer-pe-comparison.json').read_text())
for x in peers[:3]:
 body=(Path(x['path']).parent.parent/'body.bin').read_bytes();row=execute(body);row.update(name=x['name'],case='original_stock_control');rows.append(row);assert row['valid']
result=dict(passed=True,source_pe_sha256=hashlib.sha256(data).hexdigest(),entry_rva='0xe5c4',valid_exit='0xe636',invalid_exit='0xe62a',invalid_exit_status='EFI_INVALID_PARAMETER at 0xe62a',scope='Actual original machine code, no firmware/device callbacks; no image loading',cases=rows)
(P/'section-validation-machine-code.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
