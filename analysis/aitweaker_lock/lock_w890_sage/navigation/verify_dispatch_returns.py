"""Original W890 control -> FrameInput -> PageInput return semantics.

The original code executes; control callbacks and key-translation services are
fixtures. This is a counterexample suite, not an installed input interceptor.
"""
from native_replay import *
FRAME=DATA+0x2000;CONTROLS=DATA+0x3000;EVENT=DATA+0x4000;PAGE=DATA+0x5000;VIRTUAL=DATA+0x6000
ABORT=0x8000000000000015;UNSUPPORTED=0x8000000000000003

def make(statuses,kind):
 m=Machine();m.w32(FRAME+0x3c,len(statuses));m.w32(FRAME+0x44,0 if kind==1 else 0xffffffff);m.w64(FRAME+0x48,CONTROLS);m.w16(EVENT+8,kind)
 seen=[];translations=[]
 for i,status in enumerate(statuses):
  control=DATA+0x7000+i*0x100;table=VIRTUAL+i*0x100;method=STUB+i*0x100
  m.w64(CONTROLS+i*8,control);m.w64(control,table);m.w64(table+0x20,method);m.w32(control+0x3c,1)
  def invoke(i=i,status=status):seen.append(i);m.reg(UC_X86_REG_RAX,status)
  m.callbacks[method]=invoke
 def returning_native(rva,value):
  def callback():
   translations.append(rva);sp=m.reg(UC_X86_REG_RSP);m.reg(UC_X86_REG_RAX,value);m.reg(UC_X86_REG_RIP,m.r64(sp));m.reg(UC_X86_REG_RSP,sp+8)
  m.callbacks[BASE+rva]=callback
 returning_native(0xff10,0);returning_native(0x21e68,0)
 return m,seen,translations

def keyboard(status):
 m,seen,keys=make([status],1);sp=m.setup();m.reg(UC_X86_REG_RCX,FRAME);m.reg(UC_X86_REG_RDX,EVENT);m.run(0x21ef4)
 result=m.reg(UC_X86_REG_RAX);want=status if status in [0,ABORT]else UNSUPPORTED
 assert result==want and seen==[0]and bool(keys)==(status not in [0,ABORT])
 assert m.reg(UC_X86_REG_RSP)==sp+8
 return {'name':'keyboard_control_'+hex(status),'passed':True,'control_status':hex(status),'frame_return':hex(result),'native_key_translation_calls':len(keys)}

def broadcast(statuses):
 m,seen,keys=make(statuses,2);sp=m.setup();m.reg(UC_X86_REG_RCX,FRAME);m.reg(UC_X86_REG_RDX,EVENT);m.run(0x21ef4)
 result=m.reg(UC_X86_REG_RAX);want=0 if 0 in statuses else UNSUPPORTED
 assert result==want and seen==list(range(len(statuses)))and not keys and m.reg(UC_X86_REG_RSP)==sp+8
 return {'name':'event2_broadcast_'+','.join(hex(x)for x in statuses),'passed':True,'control_returns':[hex(x)for x in statuses],'visited_all_controls':seen,'frame_return':hex(result)}

def page_caller(status):
 m,seen,keys=make([status],1);m.setup();sp=STACK+0x1fe000;m.reg(UC_X86_REG_RSP,sp);m.reg(UC_X86_REG_RBP,sp+0x100)
 m.reg(UC_X86_REG_RCX,FRAME);m.reg(UC_X86_REG_RDX,EVENT);m.reg(UC_X86_REG_RBX,PAGE);m.reg(UC_X86_REG_RSI,EVENT);m.reg(UC_X86_REG_R14,0);m.reg(UC_X86_REG_R13,0);m.w32(PAGE+0x4c,1)
 assert m.r64(BASE+0x93da8)==BASE+0x21ef4
 m.stops={BASE+0x23b05,BASE+0x23ac1};m.run(0x23aa8)
 stop=m.reg(UC_X86_REG_RIP)-BASE;assert stop==(0x23b05 if status==0 else 0x23ac1)
 assert seen==[0]and m.reg(UC_X86_REG_RSP)==sp
 return {'name':'page_frame_chain_'+hex(status),'passed':True,'control_return':hex(status),'stop_rva':hex(stop),'page_treats_input_as_consumed':stop==0x23b05,'next_native_stage':'pending-update tail'if stop==0x23b05 else'page descriptor / extra hotkeys / general key handling'}

def main():
 cases=[keyboard(x)for x in [0,DENY,ABORT]]+[broadcast(x)for x in [[DENY,ABORT,DENY],[0,DENY,ABORT],[ABORT,ABORT,ABORT]]]+[page_caller(x)for x in [0,DENY,ABORT]]
 report={'status':'PASS_RETURN_SEMANTICS_COUNTEREXAMPLES','case_count':len(cases),'cases':cases,'original_amitse_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'source_sha256':sha(Path(__file__).read_bytes()),'scope':__doc__,'conclusions':['EFI_ACCESS_DENIED from selected ControlInput continues native frame key handling.','EFI_ABORTED stops that FrameInput but PageInput treats it as unhandled and continues other routes.','Control return zero consumes keyboard handling at both layers; pending HII tail is still a separate sink.','Event kind2 visits every control even after one returns zero or abort; selected-control-only policy is incomplete.'],'hardware_validation':False}
 (HERE/'dispatch_return_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'case_count':len(cases)}))

if __name__=='__main__':main()
