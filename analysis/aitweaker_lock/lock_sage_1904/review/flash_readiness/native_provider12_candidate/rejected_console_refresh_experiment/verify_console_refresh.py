"""Actual EFI console-refresh size/error/scrolling contracts, synthetic I/O."""
from pathlib import Path
import hashlib,json
from verify_ebs_boundaries import UiVM
from verify_native_owner import HERE,OUT,EFI,SY,HEAP,ERR,STUB,u32,u64,UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX
class ConsoleVM(UiVM):
 def __init__(self):
    self.position=(0,0);self.positions=[];self.writes=[];self.error_at=None;self.seen={};self.failed=False;self.after_failure=[];super().__init__()
    self.fn(self.output+0x38,'text_cursor',self.cursor)
    self.fn(self.output+8,'text_output',self.output_text)
 def cursor(self):self.position=(self.arg(1),self.arg(2));self.positions.append(self.position);return 0
 def output_text(self):
    p=self.arg(1);text=[]
    for i in range(1025):
        ch=int.from_bytes(self.r(p+2*i,2),'little')
        if not ch:break
        text.append(ch)
    else:raise AssertionError('Unbounded console string')
    self.writes.append((self.position,text));return 0
 def hook(self,u,address,size,unused):
    if address==self.stop:u.emu_stop();return
    if address not in self.callbacks:return
    name,cb=self.callbacks[address];self.calls.append(name);self.seen[name]=self.seen.get(name,0)+1
    if self.failed:self.after_failure.append(name)
    if self.error_at==(name,self.seen[name]):result=ERR(7);self.failed=True
    else:result=cb()
    u.reg_write(UC_X86_REG_RAX,result);sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
def main():
 rows=[]
 def check(name,v,result,expected):
    assert result==expected,(name,result,expected)
    rows.append({'case':name,'passed':True,'result':result,'output_calls':len(v.writes),'cursor_calls':len(v.positions)})
 for columns,lines in [(2,1),(80,25),(100,31),(512,256)]:
    v=ConsoleVM();v.columns=columns;v.rows=lines;r=v.call('clear_console')
    assert len(v.writes)==lines and v.positions==[(0,row)for row in range(lines)]+[(0,0)]
    assert all(text==[32]*(columns-(1 if row+1==lines else 0))and pos==(0,row)for row,(pos,text)in enumerate(v.writes))
    assert len(v.writes[-1][1])==columns-1 # Never writes the scrolling corner.
    check('bounded refresh '+str(columns)+'x'+str(lines),v,r,1)
 for columns,lines in [(0,25),(1,25),(80,0),(513,25),(80,257),(0xffffffffffffffff,25),(80,0xffffffffffffffff)]:
    v=ConsoleVM();v.columns=columns;v.rows=lines;r=v.call('clear_console');assert not v.positions and not v.writes
    check('invalid dimensions '+str(columns)+'x'+str(lines),v,r,0)
 for name,prepare in [('QueryMode error',lambda v:setattr(v,'query_error',True)),
                       ('negative current mode',lambda v:v.w(v.outmode+4,u32(0xffffffff))),
                       ('missing QueryMode',lambda v:v.w(v.output+0x18,u64(0))),
                       ('missing mode descriptor',lambda v:v.w(v.output+0x48,u64(0)))]:
    v=ConsoleVM();prepare(v);r=v.call('clear_console');assert not v.positions and not v.writes;check(name,v,r,0)
 for target,nth in [('text_cursor',1),('text_cursor',2),('text_cursor',4),('text_output',1),('text_output',3)]:
    v=ConsoleVM();v.error_at=(target,nth);r=v.call('clear_console');assert v.failed and not v.after_failure
    check('stop immediately after '+target+str(nth)+' failure',v,r,0)
 for target in ['text_attribute','text_clear','text_enable_cursor']:
    v=ConsoleVM();v.error_at=(target,1);r=v.call('save_screen',[HEAP+0xd000]);assert v.failed and not v.after_failure
    check('screen preparation refuses '+target+' failure',v,r,0)
 report={'status':'PASS_ACTUAL_EFI_CONSOLE_REFRESH_CONTRACTS','case_count':len(rows),'cases':rows,'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),
  'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'fixture_source_hashes':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest()for name in ['verify_native_owner.py','verify_ebs_boundaries.py']},
  'scope':'Actual compiled refresh/save-screen code. Console modes and failures are synthetic. Real OVMF rendering/restoration is a separate two-process test.'}
 (OUT/'console_refresh_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(rows)}))
if __name__=='__main__':main()
