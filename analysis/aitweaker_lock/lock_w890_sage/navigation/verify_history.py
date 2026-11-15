"""Original W890 history routines with a constructed Main redirection fixture.

This does not implement a production redirect. It establishes which native
history fields a future verified, exclusive transaction must keep consistent.
"""
from native_replay import *
APP=DATA+0x2000;ARRAY=DATA+0x3000;HISTORY=DATA+0x4000;OUT=DATA+0x5000;HII=DATA+0x6000
def make():
 m=Machine();m.w64(BASE+0xafdd0,APP);m.w32(APP+0x2c,4);m.w64(APP+0x30,ARRAY)
 m.w64(BASE+0xafde8,HISTORY);m.w32(BASE+0xafde0,16);m.w32(BASE+0xafe00,0);m.w32(BASE+0xafddc,2)
 for i,form in enumerate([0,0x2712,0x2713,0x271d]):
  p=DATA+0x7000+i*0x100;m.w64(ARRAY+i*8,p);m.w64(p+0x20,HII);m.w16(p+0x2a,form);m.w16(p+0x30,i);m.w16(p+0x32,1 if i==3 else 0)
 def memset_fixture():
  ptr=m.reg(UC_X86_REG_RCX);n=m.reg(UC_X86_REG_RDX);value=m.reg(UC_X86_REG_R8)&255
  assert HISTORY<=ptr and ptr+n<=HISTORY+16*32
  m.uc.mem_write(ptr,bytes([value])*n);m.reg(UC_X86_REG_RAX,ptr)
  sp=m.reg(UC_X86_REG_RSP);m.reg(UC_X86_REG_RIP,m.r64(sp));m.reg(UC_X86_REG_RSP,sp+8)
 m.callbacks[BASE+0x1600]=memset_fixture
 return m
def call(m,rva,*args):
 m.setup()
 for reg,arg in zip(ARGS,args):m.reg(reg,arg)
 m.run(rva);return m.reg(UC_X86_REG_RAX)
def lookup(m,index):
 m.uc.mem_write(OUT,b'\xff'*16);r=call(m,0x1b814,index,OUT,OUT+8)
 return {'status':hex(r),'parent_index':int.from_bytes(m.uc.mem_read(OUT,2),'little'),'record_index':m.r32(OUT+8)}
def fixture_reset(m,index,root=True,clear=True):
 # This is a test fixture write, not an authorization to write these locations
 # on hardware. Scope includes all buffer bytes/capacity, root, count and page.
 if clear:m.uc.mem_write(HISTORY,bytes(16*32))
 m.w64(HISTORY,HII);m.w32(HISTORY+8,int.from_bytes(m.uc.mem_read(DATA+0x7000+index*0x100+0x2a,2),'little'))
 if root:m.w32(BASE+0xafddc,index)
 m.w32(BASE+0xafe00,1);m.w32(APP+0x28,index)
def case(fix):
 m=make();m.w32(APP+0x28,2);call(m,0x1b928,0,2);assert m.r32(BASE+0xafe00)==1
 m.w32(APP+0x28,1)
 if fix:fixture_reset(m,1)
 m.w32(APP+0x28,3);call(m,0x1b928,1,3);p=lookup(m,3)
 assert p['status']=='0x0' and p['parent_index']==(1 if fix else 2)
 return {'name':'redirect_with_history'if fix else'redirect_page_only_counterexample','passed':True,'security_parent':p,'history_count':m.r32(BASE+0xafe00)}
def stale_root():
 m=make();call(m,0x1b928,0,2);fixture_reset(m,1,root=False);call(m,0x1b928,1,3);p=lookup(m,3)
 assert p['status']=='0x800000000000000e'
 return {'name':'stale_search_root_counterexample','passed':True,'security_parent':p}
def repeated():
 m=make();call(m,0x1b928,0,2);parents=[]
 for _ in range(4):
  fixture_reset(m,1);m.w32(APP+0x28,3);call(m,0x1b928,1,3);p=lookup(m,3)
  assert p['status']=='0x0'and p['parent_index']==1;parents.append(p)
  m.w32(APP+0x28,1);call(m,0x1b928,3,1);p=lookup(m,1)
  assert p['status']=='0x800000000000000e' and m.r32(BASE+0xafe00)==1
 return {'name':'four_redirect_security_main_cycles','passed':True,'security_parents':parents}
def null_page():
 m=make();m.w64(ARRAY+3*8,0);p=lookup(m,3);assert p['status']=='0x8000000000000015'
 return {'name':'null_page_native_abort','passed':True,'result':p}
def main():
 cases=[case(False),case(True),stale_root(),repeated(),null_page()]
 out={'status':'PASS','scope':__doc__,'case_count':len(cases),'cases':cases,'module_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'source_sha256':sha(Path(__file__).read_bytes()),'required_root_form':'0x2712','required_native_fields':{'history_buffer':'0xAFDE8','capacity':'0xAFDE0','search_root':'0xAFDDC','used':'0xAFE00','record_bytes':32},'production_redirect_implemented':False,'limits':['Only constructed page/UEFI-memory fixtures; memset is modeled at its exact function entry.','No native browser whole-loop unwind, native reset flags or HII ownership validity established.','Any future redirect must atomically hold exclusive live context across its writes and reject overlap/unwritable/unstable extents before touching anything.']}
 (HERE/'history_replay.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
