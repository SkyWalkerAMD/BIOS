"""Actual complete-app globals collector; CPU/UEFI map endpoints modeled.

The firmware inventory is deliberately seeded, as in verify_platform. This
checks exact collector instructions and terminal service boundaries, not ASUS.
"""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import verify_platform as T
U,S=T.U,T.S
RVAS=[0x83588,0x83468,0x930b0,0x93948,0x93028,0x83580]
class VM(T.VM):
 def __init__(self):
  self.map_error=False;self.map_variant=None;self.module_reads=set()
  super().__init__();self.label=T.DATA+0x9000;self.u.mem_write(self.label,b'TEST_NATIVE_GLOBALS\r\n\0')
  # Deliberately unmapped pointer-looking values must be logged, never followed.
  self.values=[0xdead123456789abc,7,0xabc123456789abcd,0x123456789abcdef0,0xfedcba9876543210,1]
  for i,rva in enumerate(RVAS):self.u.mem_write(self.bases[0]+rva,T.q(self.values[i])if i<5 else bytes([self.values[i]]))
  self.module_before=bytes(self.u.mem_read(self.bases[0],len(self.original[0])))
  self.u.hook_add(U.UC_HOOK_MEM_READ,self.record_read,begin=self.bases[0],end=self.bases[0]+len(self.original[0])-1)
 def record_read(self,u,access,address,size,value,data):self.module_reads.update(range(address-self.bases[0],address-self.bases[0]+size))
 def records(self):
  raw=bytearray(super().records())
  if self.map_variant=='duplicate':raw+=raw[:40]
  if self.map_variant in ['module_read_protected','loaded_metadata_read_protected']:
   target=self.bases[0]if self.map_variant=='module_read_protected'else T.DATA
   for at in range(0,len(raw),40):
    if struct.unpack_from('<Q',raw,at+8)[0]==target:struct.pack_into('<Q',raw,at+32,0x2000)
  return bytes(raw)
 def hook(self,u,a,n,data):
  if a==T.SERV['map']and self.map_error:self.finish_service('map',T.ERR(7));return
  super().hook(u,a,n,data)
 def collect(self):return self.call('platform_native_globals',self.label)
 def journal(self):return bytes(self.u.mem_read(S['journal'],22016)).split(b'\0',1)[0]
def main():
 checks=[]
 def check(label,ok):assert ok,label;checks.append(label)
 v=VM();check('actual collector accepts mapped original header and six fixed globals',v.collect()==1)
 check('collector only calls RaiseTPL RestoreTPL GetMemoryMap at application TPL',v.calls==[('raise',31),('restore',4),('map',4)])
 check('raw pointer-looking values are logged without dereference or idle inference',all(f'{x:016X}'.encode()in v.journal()for x in v.values)and b'NATIVE_GLOBALS_OBSERVATION_NOT_IDLE_PROOF'in v.journal())
 peoff=struct.unpack_from('<I',v.module_before,0x3c)[0]
 allowed=set(range(64))|set(range(peoff,peoff+0x108))
 for i,rva in enumerate(RVAS):allowed.update(range(rva,rva+(1 if i==5 else 8)))
 check('actual original-module read addresses limited to fixed header and fixed globals',v.module_reads<=allowed)
 check('collector made no original-module writes',bytes(v.u.mem_read(v.bases[0],len(v.original[0])))==v.module_before and not v.foreign_writes)
 for mode in ['duplicate','module_read_protected','loaded_metadata_read_protected']:
  x=VM();x.map_variant=mode
  if mode=='loaded_metadata_read_protected':x.u.mem_protect(x.lis[0]&~4095,4096,U.UC_PROT_NONE)
  check(mode+' fails before any native global read',x.collect()==0 and not any(r in x.module_reads for r in RVAS))
 for label,change in [
  ('not inventoried',lambda x:x.put('inventory_ready',T.d(0))),
  ('wrong loaded size',lambda x:x.u.mem_write(x.lis[0]+0x48,T.q(0xa2000))),
  ('wrong original header',lambda x:x.u.mem_write(x.bases[0]+0x3c,T.d(0x900))),
  ('changed loaded base',lambda x:x.u.mem_write(x.lis[0]+0x40,T.q(0))),
  ('CPU environment changed',lambda x:setattr(x,'env',T.q(0)+x.env[8:])),
  ('map ordinary failure',lambda x:setattr(x,'map_error',True))]:
  x=VM();change(x);check(label+' returns false with no native global read',x.collect()==0 and not any(r in x.module_reads for r in RVAS))
 for page in sorted(set(r&~4095 for r in RVAS)):
  x=VM();entry=x.pte(x.bases[0]+page);x.u.mem_write(entry,T.q((x.bases[0]+page)))
  check('nonpresent native global page '+hex(page)+' refuses safely',x.collect()==0 and not any(page<=r<page+4096 for r in x.module_reads))
 for prior in [8,31]:
  x=VM();x.tpl=prior;check('wrong entry TPL '+str(prior)+' holds before map/RestoreTPL',x.collect()=='HOLD'and len(x.calls)==1 and x.calls[0][0]=='raise'and x.tpl==31)
 for at in [1,2,3]:
  x=VM();x.fault=at;check('ending at collector service '+str(at)+' has zero later services',x.collect()=='HOLD'and x.fired and len(x.calls)==at)
 x=VM();x.map_error=True;x.fault=3;check('map error plus ending still holds without ordinary failure return',x.collect()=='HOLD'and len(x.calls)==3)
 x=VM();x.put('app_ended',T.d(1));check('already ended performs no service',x.collect()=='HOLD'and not x.calls)
 r={'status':'PASS_ACTUAL_TX09_NATIVE_GLOBALS_WITH_MODELED_MAP_CPU_AND_SEEDED_INVENTORY','checks':len(checks),'check_names':checks,'efi_sha256':T.sha(T.FILE),'build_sha256':T.sha(T.BUILD/'app_build.json'),'source_sha256':T.sha(Path(__file__)),'limits':['No hardware or native browser execution; inventory and standard firmware service contracts explicitly modeled.','Only the six original global values and original header are read. Values are observations, never an idle or safe-exit proof.','SendForm suppression after a failed pre-collector and post-return credential observation are checked by the separate UI suite.']}
 (T.BUILD/'globals_verification.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'checks':len(checks)}))
if __name__=='__main__':main()
