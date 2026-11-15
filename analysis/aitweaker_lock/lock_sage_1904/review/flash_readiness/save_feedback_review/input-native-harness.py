"""Frozen NATIVE11 native initializer/save replay, explicit memory IO fixtures.

This module never writes frozen evidence, firmware, variables or device state.
"""
from pathlib import Path
import sys,json,struct,hashlib,uuid
sys.dont_write_bytecode=True
DEST=Path(__file__).resolve().parent
OLD=DEST.parent/'cold_entry_candidate/implementation'
prefix=(OLD/'verify_native_commit.py').read_text().split('\nchecks=[];v=CommitVM(True)',1)[0]
__file__=str(OLD/'verify_native_commit.py')
exec(compile(prefix,__file__,'exec'),globals())
__file__=str(DEST/'native_harness.py')
COPY=STOP+0x4200;SETMEM=STOP+0x4210

class InitializationVM(CommitVM):
 def __init__(self,baseline=False):
  super().__init__(baseline)
  self.native_trace=[];self.fixture_calls=[];self.commit_status=[];self.missing=set();self.fail_get={}
  self.effects=[];self.skip_defaults=True;self.save_results=[]
  self.cache=HEAP+0x170000;self.defaults=HEAP+0x174000
  self.u.mem_write(TSE+0x83490,q(self.cache));self.u.mem_write(TSE+0x834a0,q(self.defaults))
  self.u.mem_write(TSE+0x83588,q(0));self.u.mem_write(TSE+0x83468,q(0))
  self.u.mem_write(TSE+0x8357a,b'\0');self.u.mem_write(TSE+0x83580,b'\0')
  self.u.mem_write(TSE+0x83900,b'\1') # OEM initializer already-populated short-return branch
  self.u.mem_write(self.bs+0x160,q(COPY));self.u.mem_write(self.bs+0x168,q(SETMEM))
  self.variable_guids.update({r['name']:uuid.UUID(r['guid']).bytes_le for r in records})
  targets=[0x5f688,0x5d4cc,0x5d547,0x5f6c2,0x5f6c9,0x1425c,0x1484a,0x1484f,0x148a2,
   0x36c34,0x5d44c,0x3ce14,0x32434,0x32264,0x6494,0x5a68,0x29cc4,0x12ec8]
  for r in targets:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+r,end=TSE+r)
  for a in [COPY,SETMEM]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
  self.original=(CASE/'analysis/modules/AMITSE.efi').read_bytes()
  if baseline:
   self.u.mem_write(TSE+0x5abc,self.original[0x5abc:0x5ac7])
   self.u.mem_write(SETUP+0x2bdd8,q(SETUP+0x152c))
  # The entire original 117-record variable table is retained; only firmware's
  # runtime pointer/length cache is a fixture. Protected records are unmodified.
  for idx in [7,23]:self.set_cache(idx,bytes())

 def set_cache(self,index,value,default=None):
  at=HEAP+0x280000+index*0x7000
  # Separate large sparse backing from allocation range.
  if not any(lo<=at and at+0x7000<=hi for lo,hi in self.ranges):self.map(at&~4095,0x7000)
  self.u.mem_write(at,bytes(value)or b'\0');self.u.mem_write(self.cache+index*16,q(at)+q(len(value)))
  if default is not None:
   da=at+0x6000
   assert len(default)<=0x1000
   self.u.mem_write(da,bytes(default));self.u.mem_write(self.defaults+index*16,q(da)+q(len(default)))
  return at

 def hook(self,u,a,n,data):
  if a in [COPY,SETMEM]:
   dst=self.arg(0);length=self.arg(2) if a==COPY else self.arg(1)
   if length:u.mem_write(dst,bytes(u.mem_read(self.arg(1),length)) if a==COPY else bytes([self.arg(2)&255])*length)
   self.ret(dst);return
  if a==GETVAR:
   name=self.c16(self.arg(0));self.getvar_calls.append(name)
   if name in self.fail_get:self.ret(self.fail_get[name]);return
   if name in self.missing or name not in self.variables:self.ret(ERR(14));return
   self.getvar_calls.pop()
  if a==SETVAR:
   name=self.c16(self.arg(0));guid=bytes(u.mem_read(self.arg(1),16));value=bytes(u.mem_read(self.argn(4),self.arg(3)))if self.arg(3) else b''
   self.set_calls.append({'name':name,'size':len(value),'attrs':self.arg(2),'sha256':hashlib.sha256(value).hexdigest()});self.variables[name]=value;self.variable_guids[name]=guid;self.missing.discard(name);self.ret(0);return
  if a==ALLOC and self.arg(1)==0:
   self.alloc_calls+=1;out=self.pool;self.pool+=32;self.allocated[out]=0;u.mem_write(self.arg(2),q(out));self.ret(0);return
  if a in [TSE+r for r in [0x36c34,0x5d44c,0x3ce14]]:
   self.effects.append(hex(a-TSE))
   if self.skip_defaults or a!=TSE+0x36c34:self.ret(0);return
  if a in [TSE+r for r in [0x32434,0x32264,0x6494,0x5a68,0x29cc4,0x12ec8]]:
   self.fixture_calls.append(hex(a-TSE));self.ret(0);return
  if a==TSE+0x1484a:self.native_trace.append({'rva':'0x1484a','index':self.arg(0),'size':self.arg(2)})
  elif a==TSE+0x1484f:self.commit_status.append({'index':u.reg_read(R.UC_X86_REG_R14),'status':hex(u.reg_read(R.UC_X86_REG_RAX))})
  elif a==TSE+0x148a2:self.save_results.append(u.reg_read(R.UC_X86_REG_RAX)&255)
  elif a in [TSE+r for r in [0x5f688,0x5d4cc,0x5d547,0x5f6c2,0x5f6c9,0x1425c]]:self.native_trace.append({'rva':hex(a-TSE)})
  super().hook(u,a,n,data)

 def vendor(self):return self.call(TSE+0x5f688)
 def direct_save(self):return self.call(TSE+0x1425c,0)

class ProtocolDefaultsVM(InitializationVM):
 def __init__(self,baseline=False):
  super().__init__(baseline)
  self.skip_defaults=False
  ud=lambda at:struct.unpack_from('<I',original_data,at)[0]
  pages=ud(0x2c);controls=ud(0x30)
  self.u.mem_write(TSE+0x930b0,q(DATA+pages));self.u.mem_write(TSE+0x930c8,q(DATA+controls));self.u.mem_write(TSE+0x93948,q(DATA))
  self.runtime_fixups=[];self.control_evidence=[]
  forms=json.loads((CASE/'analysis/modules/Setup_IFR.json').read_text())[0]
  seen=set()
  for i in range(ud(pages)):
   page=ud(pages+4+i*4)
   self.u.mem_write(DATA+page,q(self.handle if i==17 else 0))
   for j in range(ud(page+0x1c)):
    control=controls+ud(page+0x20+j*4)
    if control in seen:continue
    seen.add(control)
    self.u.mem_write(DATA+control+0x28,q(0))
    if i==17 and ud(control+8)==92:
     delta=struct.unpack_from('<Q',original_data,control+0x28)[0]
     ifr=SETUP+forms['offset']+delta
     self.u.mem_write(DATA+control,q(self.handle));self.u.mem_write(DATA+control+0x28,q(ifr))
     self.control_evidence.append({'control_offset':hex(control),'question_id':hex(struct.unpack_from('<H',original_data,control+12)[0]),'original_record_hex':original_data[control:control+64].hex(),'runtime_ifr_RVA':hex(ifr-SETUP)})
  assert len(self.control_evidence)==3
  self.runtime_fixups=['All page HII fields cleared except original DRAM Timing page17/form2E96 assigned runtime Setup handle.',
   'All native control runtime IFR pointers cleared except the three original memory controls on that page; their original index/flags/question fields and IFR bytes are unchanged.',
   'Runtime variable cache/default buffers supplied explicitly; 13B9C copies original question widths/offsets using original IFR accessor bytes.']

 def direct_defaults(self):return self.call(TSE+0x6286c)
