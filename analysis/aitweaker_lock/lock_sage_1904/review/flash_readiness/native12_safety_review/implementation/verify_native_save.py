"""Actual original Setup RouteConfig and HiiDatabase ConfigToBlock execution.

Boot service allocation, device-path ownership and variable storage are explicit
in-memory fixtures. OEM parsing, comparison/commit code and guard are real bytes.
"""
from pathlib import Path
import json,uuid
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
HII_BASE=0x30000000;SETVAR=STOP+0x4100;DEVICE=STOP+0x4110
SETUP_GUID=uuid.UUID('ec87d643-eba4-4bb5-a1e5-3f3e36b20da9').bytes_le
class SaveVM(GateVM):
 def __init__(self):
  super().__init__();self.pool=HEAP+0x250000;self.allocated={};self.set_calls=[];self.native_block_calls=0;self.native_setup_calls=0;self.device_calls=0
  self.variables['Setup']=bytes(604);self.variable_guids={OC:OC_GUID,MEM:MEM_GUID,'Setup':SETUP_GUID}
  p=ns['pefile'].PE(str(HERE/'build/OriginalHiiDatabase.efi'));p.relocate_image(HII_BASE);data=p.get_memory_mapped_image();self.map(HII_BASE,(len(data)+4095)&~4095);self.u.mem_write(HII_BASE,data)
  self.routing=HII_BASE+0x16940;self.u.mem_write(HII_BASE+0x17220,q(self.bs));self.u.mem_write(self.rt+0x58,q(SETVAR));self.u.mem_write(self.bs+0xb8,q(DEVICE))
  for a in [SETVAR,DEVICE,HII_BASE+0x5fb8]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
 def hook(self,u,a,n,data):
  if a==SETUP+0x2568:self.native_setup_calls+=1;return
  if a==HII_BASE+0x5fb8:self.native_block_calls+=1;return
  if a==DEVICE:self.device_calls+=1;u.mem_write(self.arg(2),q(0xa001));self.ret(0);return
  if a==ALLOC:
   self.alloc_calls+=1
   if self.alloc_fail:self.ret(ERR(9));return
   size=self.arg(1);assert size<=0x100000 and self.pool+size<HEAP+0x400000
   out=self.pool;self.pool=(self.pool+size+31)&~31;self.allocated[out]=size;u.mem_write(out,bytes(size));u.mem_write(self.arg(2),q(out));self.ret(0);return
  if a==FREE:
   self.free_calls+=1;assert self.arg(0)in self.allocated,hex(self.arg(0));del self.allocated[self.arg(0)];self.ret(0);return
  if a==GETVAR:
   name=self.c16(self.arg(0));self.getvar_calls.append(name)
   if self.getvar_fail:self.ret(ERR(7));return
   assert name in self.variables,name;assert bytes(u.mem_read(self.arg(1),16))==self.variable_guids[name],(name,bytes(u.mem_read(self.arg(1),16)).hex())
   value=self.variables[name];size=self.getq(self.arg(3));u.mem_write(self.arg(3),q(len(value)))
   if self.arg(2):u.mem_write(self.arg(2),d(7))
   if size<len(value):self.ret(ERR(5));return
   assert self.argn(4);u.mem_write(self.argn(4),value);self.ret(0);return
  if a==SETVAR:
   name=self.c16(self.arg(0));assert bytes(u.mem_read(self.arg(1),16))==self.variable_guids[name]
   data=bytes(u.mem_read(self.argn(4),self.arg(3)));self.set_calls.append({'name':name,'size':len(data),'attrs':self.arg(2),'sha256':hashlib.sha256(data).hexdigest()});self.variables[name]=data;self.ret(0);return
  super().hook(u,a,n,data)
 def route_text(self,name,offset,value):
  guid=self.variable_guids[name];return 'GUID='+guid.hex()+'&NAME='+''.join(f'{ord(c):04x}'for c in name)+'&PATH=7fff0400&OFFSET='+f'{offset:x}'+'&WIDTH='+f'{len(value):x}'+'&VALUE='+bytes(reversed(value)).hex()
 def save(self,name,offset,value):return self.route(custom=self.route_text(name,offset,value))

checks=[];v=SaveVM()
check('native Setup unrelated save reaches in-memory SetVariable',v.save('Setup',8,b'\x2a')==0 and v.variables['Setup'][8]==42 and v.set_calls[-1]['name']=='Setup')
check('native Setup parsed real name/GUID/path',v.device_calls==1 and v.native_setup_calls==1)
check('unrelated save used actual original ConfigToBlock once',v.native_block_calls==1)
check('unrelated save no outstanding pool allocation',not v.allocated)
before=len(v.set_calls);check('native no-op OC submission succeeds without provider',v.save(OC,0,b'\0')==0 and len(v.set_calls)==before+1)
check('native no-op OC retains full original 26681-byte variable',v.variables[OC]==bytes(26681) and v.set_calls[-1]['size']==26681)
before=len(v.set_calls);check('native changed OC submission denied before original Setup commit',v.save(OC,4,b'\1')==ERR(15) and len(v.set_calls)==before and v.variables[OC][4]==0)
check('native unaffected memory byte can commit',v.save(MEM,0x11,b'\x5a')==0 and v.variables[MEM][0x11]==0x5a)
for offset in [0x10,0xbd,0xbe]:
 before=len(v.set_calls);check('native protected memory offset denied '+hex(offset),v.save(MEM,offset,b'\1')==ERR(15) and len(v.set_calls)==before and v.variables[MEM][offset]==0)
check('actual original parser multi-byte ordering validated',v.save('Setup',9,b'\x12\x34')==0 and v.variables['Setup'][9:11]==b'\x12\x34')
text=v.route_text(OC,0,b'\0')+'&OFFSET=4&WIDTH=1&VALUE=01';before=len(v.set_calls)
check('actual parser duplicate range changed protected bytes denied',v.route(custom=text)==ERR(15) and len(v.set_calls)==before)
text=v.route_text(OC,0,b'\0')+'&OFFSET=4&WIDTH=1&VALUE=00'
check('actual parser multiple no-op ranges accepted',v.route(custom=text)==0)
text=v.route_text(OC,26681,b'\0');before=len(v.set_calls)
check('actual parser out of bounds rejected without original commit',v.route(custom=text)==ERR(15) and len(v.set_calls)==before)
check('all native parser comparison/commit allocations freed',not v.allocated and v.alloc_calls==v.free_calls)
report={'status':'PASS_NATIVE_SETUP_AND_HII_CONFIG_PARSING_WITH_MEMORY_IO_FIXTURES','checks':len(checks),'check_names':checks,'modules_sha256':{n:r['sha256']for n,r in manifest['modules'].items()},'hii_database_sha256':sha(HERE/'build/OriginalHiiDatabase.efi'),'hii_binding':json.loads((HERE/'build/OriginalHiiDatabase.json').read_text()),'ConfigToBlock_registration':{'GUID_rva':'0x16740','registration_call':'0x49b','interface_rva':'0x16940','method_offset':'0x20','method_rva':'0x5fb8'},'native_Setup_route_entry':'0x152c -> 0x2568','native_variable_commit':'0x27ec','native_setup_calls':v.native_setup_calls,'native_ConfigToBlock_calls':v.native_block_calls,'memory_only_SetVariable_calls':v.set_calls,'test_source_sha256':sha(Path(__file__)),'limits':['BootServices allocation/free, LocateDevicePath and RuntimeServices GetVariable/SetVariable are explicit fixtures; no real persistent firmware storage.','This executes original Setup routing/parser/commit and original HiiDatabase block parser; it does not yet execute the entire F10 save iterator or establish the live AMITSE variable-record flags/direct-SetVariable branch.','No full ASUS graphical BIOS, hardware boot, new CAP or firmware write.']}
(HERE/'build/native_save_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'checks':len(checks),'native_setup_calls':v.native_setup_calls,'native_parser_calls':v.native_block_calls}))
