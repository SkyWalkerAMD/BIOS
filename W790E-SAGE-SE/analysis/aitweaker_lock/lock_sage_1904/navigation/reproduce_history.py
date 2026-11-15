"""Original SAGE AMITSE parent-history routines under Unicorn.

No OEM code executes on the host. Only page objects/UEFI allocation are fixtures.
This demonstrates the missing history-root update independently of the live UI.
"""
from pathlib import Path
import json,sys,struct
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'lab'))
from native_hooks import Machine,BASE,DATA,END,UC_X86_REG_CR4

APP=DATA+0x2000;ARRAY=DATA+0x4000;HISTORY=DATA+0x5000;OUT=DATA+0x7000;HII=0x12345678
def w16(m,p,v):m.uc.mem_write(p,struct.pack('<H',v))
def make():
 m=Machine();m.uc.reg_write(UC_X86_REG_CR4,0x600)
 m.w64(BASE+0x83588,APP);m.w32(APP+0x2c,4);m.w64(APP+0x30,ARRAY)
 m.w64(BASE+0x835a0,HISTORY);m.w32(BASE+0x83598,16);m.w32(BASE+0x835b8,0);m.w32(BASE+0x83594,2)
 for i,form in [(0,0),(1,0x2713),(2,0x2714),(3,0x271e)]:
  page=DATA+0x8000+i*0x100;m.w64(ARRAY+i*8,page);m.w64(page+0x20,HII);w16(m,page+0x2a,form);w16(m,page+0x30,i);w16(m,page+0x32,1 if i==3 else 0)
 return m
def call(m,fn,*args):
 m.setup(fn)
 from native_hooks import ARGS
 for reg,arg in zip(ARGS,args):m.reg(reg,arg)
 m.run(fn);from native_hooks import UC_X86_REG_RAX
 return m.reg(UC_X86_REG_RAX)
def parent(m,i):
 m.uc.mem_write(OUT,b'\xff'*16);status=call(m,0x1012c,i,OUT,OUT+8)
 return {'status':hex(status),'parent_page_index':int.from_bytes(m.uc.mem_read(OUT,2),'little'),'record_index':m.r32(OUT+8)}
def root_reset(m,i,update_search=True):
 # Candidate minimal state repair: retain native buffer/capacity, replace its
 # used history by one validated root and reset the native search lower bound.
 page=DATA+0x8000+i*0x100
 m.uc.mem_write(HISTORY,b'\0'*(16*32))
 m.w64(HISTORY,HII);m.w32(HISTORY+8,int.from_bytes(m.uc.mem_read(page+0x2a,2),'little'))
 if update_search:m.w32(BASE+0x83594,i)
 m.w32(BASE+0x835b8,1)
def run(fix):
 m=make();m.w32(APP+0x28,2);initial=call(m,0x10220,0,2)
 assert m.r32(BASE+0x835b8)==1
 m.w32(APP+0x28,1) # Production redirect currently only does this + redraw.
 if fix:root_reset(m,1)
 m.w32(APP+0x28,3);entered=call(m,0x10220,1,3);p=parent(m,3)
 assert p['status']=='0x0' and p['parent_page_index']==(1 if fix else 2)
 count=m.r32(BASE+0x835b8);before=bytes(m.uc.mem_read(HISTORY,16*32))
 again=parent(m,3);assert again==p and bytes(m.uc.mem_read(HISTORY,16*32))==before
 # Validate returning to Main follows native truncation semantics after repair.
 returned=None
 if fix:
  m.w32(APP+0x28,1);ret=call(m,0x10220,3,1);returned=parent(m,1)
  assert m.r32(BASE+0x835b8)==1 and returned['status']=='0x800000000000000e'
 return {'repair':fix,'initial_history_update_status':hex(initial),'security_update_status':hex(entered),'security_parent':p,'history_count':count,'lookup_is_readonly':True,'return_main_parent':returned}
def incomplete_repairs():
 m=make();call(m,0x10220,0,2);m.w32(APP+0x28,1)
 call(m,0x10220,2,1);main_parent=parent(m,1)
 m.w32(APP+0x28,3);call(m,0x10220,1,3);security_parent=parent(m,3)
 assert main_parent['status']=='0x0' and main_parent['parent_page_index']==2
 assert security_parent['status']=='0x800000000000000e'
 m=make();call(m,0x10220,0,2);root_reset(m,1,False)
 m.w32(APP+0x28,3);call(m,0x10220,1,3);stale_start=parent(m,3)
 assert stale_start['status']=='0x800000000000000e'
 return [{'repair':'OEM update only','main_parent':main_parent,'security_parent':security_parent},
         {'repair':'root record only, search bound stale','security_parent':stale_start}]
def repeated_repair():
 m=make();call(m,0x10220,0,2);parents=[]
 for _ in range(3):
  root_reset(m,1);m.w32(APP+0x28,3);call(m,0x10220,1,3)
  p=parent(m,3);assert p['status']=='0x0' and p['parent_page_index']==1
  parents.append(p);m.w32(APP+0x28,1);call(m,0x10220,3,1)
  assert m.r32(BASE+0x835b8)==1
 return {'repetitions':3,'security_parents':parents,'final_count':m.r32(BASE+0x835b8)}
def main():
 cases=[run(False),run(True)]
 out={'status':'REPRODUCED_AND_REPAIR_MODEL_PASS','original_amitse_sha256':'531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1','cases':cases,'incomplete_repairs':incomplete_repairs(),'repeated_repair':repeated_repair(),'functions':['0x1012c','0x10220'],'history_layout':{'records_ptr':'0x835a0','record_count':'0x835b8','capacity':'0x83598','page_search_start':'0x83594','stride':32,'key_hii':0,'key_page_id':8,'parent_hii':16,'parent_page_id':24},'limits':'Tests original native helper behavior with constructed pages. Does not yet prove a compiled driver repair or actual header renderer behavior. No production artifact modified.'}
 (HERE/'history_regression.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
