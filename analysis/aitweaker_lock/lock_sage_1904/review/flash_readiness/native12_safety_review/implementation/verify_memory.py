"""Execute actual gate_memory machine code with explicit synthetic page tables."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
class WalkVM(GateVM):
 def hook(self,u,a,n,data):
  if a in [S[x]['gate_memory']for x in S]:return
  super().hook(u,a,n,data)
 def walk(self,address,size=1,write=0,levels=4,readonly_level=0,missing_level=0,large_level=0):
  root=HEAP+0x300000
  self.u.mem_write(root,bytes(0x6000));self.u.reg_write(R.UC_X86_REG_CR3,root)
  self.u.reg_write(R.UC_X86_REG_CR4,0x600|(0x1000 if levels==5 else 0))
  for level in range(levels,0,-1):
   table=root+(levels-level)*4096;index=(address>>(12+9*(level-1)))&511
   flags=(0 if missing_level==level else 1)|(0 if readonly_level==level else 2)
   value=(table+4096)|flags
   if large_level==level:value=flags|128
   self.u.mem_write(table+index*8,q(value))
   if large_level==level:break
  return self.call(S['AMITSE']['gate_memory'],address,size,write)
v=WalkVM();checks=[]
for levels in (4,5):
 limit=1<<(47 if levels==4 else 56)
 check(f'{levels}level ordinary readable page',v.walk(0x12345000,levels=levels)==1)
 check(f'{levels}level canonical last byte accepted',v.walk(limit-1,levels=levels)==1)
 check(f'{levels}level noncanonical first byte rejected',v.walk(limit,levels=levels)==0)
 check(f'{levels}level crossing canonical boundary rejected',v.walk(limit-1,size=2,levels=levels)==0)
 check(f'{levels}level high half deliberately unsupported',v.walk(0xffff800000000000,levels=levels)==0)
 for level in range(1,levels+1):
  check(f'{levels}level missing PTE level{level}',v.walk(0x12345000,levels=levels,missing_level=level)==0)
  check(f'{levels}level read-only PTE write rejected level{level}',v.walk(0x12345000,write=1,levels=levels,readonly_level=level)==0)
  check(f'{levels}level read-only PTE read accepted level{level}',v.walk(0x12345000,levels=levels,readonly_level=level)==1)
 for level in (2,3):check(f'{levels}level large page level{level}',v.walk(0x12345000,levels=levels,large_level=level)==1)
check('zero size rejected',v.walk(0x12345000,size=0)==0)
check('low null page rejected',v.walk(4095)==0)
check('overflow length rejected',v.walk(0x12345000,size=0xffffffffffffffff)==0)
report={'status':'PASS_ACTUAL_MACHINE_CODE_WITH_SYNTHETIC_PAGE_TABLES','checks':len(checks),'check_names':checks,'module_sha256':manifest['modules']['AMITSE']['sha256'],'source_sha256':manifest['source_sha256'],'test_source_sha256':sha(Path(__file__)),'limits':['CR3 page-table pages are explicit mapped synthetic RAM, not arbitrary physical RAM discovered on ASUS.','Firmware precondition remains: page table physical pages are identity-mapped readable RAM. This does not prove all physical or malformed paging configurations safe.','No guest paging or arbitrary target address dereference follows the permission query in this fixture.']}
(HERE/'build/memory_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'checks':len(checks)}))
