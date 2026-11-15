"""Original AMITSESetupData + real F10 commit instruction/direct store branch.

No disk image or firmware variables are written. Only Unicorn memory changes.
"""
from pathlib import Path
import struct,json,hashlib
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_native_save.py').read_text().split('\nchecks=[];v=SaveVM()',1)[0]
exec(compile(prefix,str(HERE/'verify_native_save.py'),'exec'),globals())
DATA=0x40000000
original_data=(HERE/'build/OriginalAMITSESetupData.bin').read_bytes();table_off=struct.unpack_from('<I',original_data,0x34)[0];count=struct.unpack_from('<I',original_data,table_off)[0]
records=[]
for i in range(count):
 at=table_off+struct.unpack_from('<I',original_data,table_off+4+i*4)[0]
 raw=original_data[at:at+0x7c];name=raw[16:0x60].decode('utf-16le').split('\0')[0]
 records.append({'index':i,'offset':at,'name':name,'guid':str(uuid.UUID(bytes_le=raw[:16])),'flags':struct.unpack_from('<I',raw,0x68)[0],'record_hex':raw.hex()})
oc=next(r for r in records if r['name']==OC);memory=next(r for r in records if r['name']==MEM)
assert oc['index']==88 and oc['flags']==0 and memory['index']==92 and memory['flags']==0x1000
class CommitVM(SaveVM):
 def __init__(self,baseline=False):
  super().__init__();self.map(DATA,(len(original_data)+4095)&~4095);self.u.mem_write(DATA,original_data);self.u.mem_write(TSE+0x930b8,q(DATA+table_off));self.cleaned=[];self.route_bridge_calls=0
  for a in [TSE+0x11d3c,TSE+0x1d8d8]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
  if baseline:
   b=(CASE/'analysis/modules/AMITSE.efi').read_bytes();self.u.mem_write(TSE+0x11164,b[0x11164:0x1116e])
 def hook(self,u,a,n,data):
  if a==TSE+0x11d3c:self.cleaned.append(self.arg(0));self.ret(0);return # cache refresh fixture
  if a==TSE+0x1d8d8:
   self.route_bridge_calls+=1;record=self.arg(0);name=self.c16(record+16);value=bytes(u.mem_read(self.arg(1),self.arg(3)))
   text=self.route_text(name,0,value);at=HEAP+0x230000;u.mem_write(at,text.encode('utf-16le')+b'\0\0')
   # Explicit formatter/dispatch bridge, then execute actual Setup guard, OEM
   # routing and OEM HiiDatabase block parser. Not a claim of AMITSE formatter.
   u.reg_write(R.UC_X86_REG_RCX,SETUP+0x2bdd0);u.reg_write(R.UC_X86_REG_RDX,at);u.reg_write(R.UC_X86_REG_R8,at-8)
   u.reg_write(R.UC_X86_REG_RIP,self.getq(SETUP+0x2bdd8));return
  super().hook(u,a,n,data)
 def commit(self,index,value,f10=False):
  at=HEAP+0x1c0000;self.u.mem_write(at,bytes(value))
  return self.native_site(0x1484a,0x1484f,index,at,len(value))if f10 else self.call(TSE+0x11164,index,at,len(value))

checks=[];v=CommitVM(True);fresh=bytearray(v.variables[MEM]);fresh[0x10]=1
check('unpatched original memory commit bypasses Setup guard',v.commit(92,fresh,f10=True)==0 and v.variables[MEM][0x10]==1 and v.native_setup_calls==0 and v.route_bridge_calls==0)
v=CommitVM();fresh=bytearray(v.variables[MEM]);fresh[0x10]=1
check('10th static gate rejects real memory direct branch from F10 call',v.commit(92,fresh,f10=True)==ERR(15) and not v.set_calls and not v.cleaned)
for at in [0xbd,0xbe]:
 fresh=bytearray(v.variables[MEM]);fresh[at]=1
 check('direct branch protected byte denied '+hex(at),v.commit(92,fresh)==ERR(15) and not v.set_calls)
check('direct branch unchanged memory commit preserves original path',v.commit(92,v.variables[MEM])==0 and v.set_calls[-1]['name']==MEM and v.cleaned[-1]==92 and v.native_setup_calls==0)
fresh=bytearray(v.variables[MEM]);fresh[0x11]=0x5a
check('direct branch unrelated memory byte remains savable',v.commit(92,fresh)==0 and v.variables[MEM][0x11]==0x5a)
before=len(v.set_calls);fresh=bytearray(v.variables[OC]);fresh[4]=1
check('generic OC commit changed bytes denied before formatter',v.commit(88,fresh)==ERR(15) and v.route_bridge_calls==0 and len(v.set_calls)==before)
check('generic OC no-op chains to native Setup/HII via declared formatter bridge',v.commit(88,v.variables[OC])==0 and v.route_bridge_calls==1 and v.native_setup_calls==1 and v.set_calls[-1]['name']==OC)
check('short protected variable rejected',v.commit(92,bytes(0x100))==ERR(15))
v.getvar_fail=True;before=len(v.set_calls);check('read failure denies direct protected commit',v.commit(92,v.variables[MEM])==ERR(15) and len(v.set_calls)==before);v.getvar_fail=False
v.alloc_fail=True;check('allocation failure denies direct protected commit',v.commit(92,v.variables[MEM])==ERR(15));v.alloc_fail=False
check('invalid variable index rejected without native call',v.commit(count,bytes(8))==ERR(15))
check('native original data table remains byte identical',bytes(v.u.mem_read(DATA,len(original_data)))==original_data)
check('all actual parser/gate temporary allocations freed',not v.allocated and v.alloc_calls-v.free_calls==1) # one intentionally failed AllocatePool
# Execute the real save iterator immediately after its commit call. It neither
# branches on RAX nor aggregates errors before the next variable iteration.
v.u.reg_write(R.UC_X86_REG_R14,92);v.u.reg_write(R.UC_X86_REG_R13,1);v.u.reg_write(R.UC_X86_REG_R15,HEAP+0x1d0000);v.u.reg_write(R.UC_X86_REG_RAX,ERR(15))
h=v.u.hook_add(U.UC_HOOK_CODE,lambda u,a,n,d:u.emu_stop(),begin=TSE+0x1438b,end=TSE+0x1438b)
v.u.emu_start(TSE+0x1484f,0,count=1000);v.u.hook_del(h)
check('native F10 iterator advances after EFI_ACCESS_DENIED',v.u.reg_read(R.UC_X86_REG_RIP)==TSE+0x1438b and v.u.reg_read(R.UC_X86_REG_R14)==93)
r={'status':'PASS_NATIVE_MEMORY_DIRECT_COMMIT_GUARD_WITH_ORIGINAL_DATA','checks':len(checks),'check_names':checks,'module_sha256':manifest['modules']['AMITSE']['sha256'],'setup_sha256':manifest['modules']['Setup']['sha256'],'guard_points':sum(len(row['patches'])for row in manifest['modules'].values()),'original_setup_data_sha256':sha(HERE/'build/OriginalAMITSESetupData.bin'),'original_setup_data_binding':json.loads((HERE/'build/OriginalAMITSESetupData.json').read_text()),'native_variable_records':[oc,memory],'F10_commit_call':'0x1484a -> 0x11164','direct_RT_SetVariable_call':'0x111e8','native_Setup_route_call':'0x111c7 -> 0x1d8d8','test_source_sha256':sha(Path(__file__)),'new_gate':'AMITSE11164 first10B detour, exact original10B trampoline to1116E; no RuntimeServices table replacement.','limits':['RuntimeServices variable storage and BS allocation are explicit Unicorn fixtures.','AMITSE1d8d8 formatter/ConfigRouting dispatch is a declared bridge into original Setup/HiiDatabase; original cache-refresh11d3c is stubbed.','The real F10 iterator ignores EFI_ACCESS_DENIED and advances, so a denied protected change may coexist with unrelated values saved and the OEM UI may still report/exit as success. No complete graphical F10 UX acceptance.','F5/default/profile transformations and any direct writes outside this generic function require separate coverage; this is not a global SetVariable guard.']}
(HERE/'build/native_commit_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks),'guard_points':sum(len(row['patches'])for row in manifest['modules'].values())}))
