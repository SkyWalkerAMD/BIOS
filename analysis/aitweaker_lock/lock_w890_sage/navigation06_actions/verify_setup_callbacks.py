"""Execute original Setup2250 action3/4 for every static handler-table QID.

Dynamic list is explicitly EMPTY. No UEFI methods or handler side effects are
mocked as successful: first external call/write aborts the case as UNKNOWN.
These are bounded observations, never callback authorization for live HII.
"""
from pathlib import Path
import sys,json,hashlib,struct,collections,time
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent
sys.path[:0]=[str(R/'tools/pydeps'),str(R/'tools/vm-pydeps')]
import pefile,capstone
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID,UcError
from unicorn.x86_const import *
P=B/'navigation/modules/Setup.efi';p=pefile.PE(str(P));BASE=0x4000000;p.relocate_image(BASE);im=p.get_memory_mapped_image();SIZE=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
STACK=0x8000000;DATA=0x9000000;STOP=DATA+0x1000
entries=json.loads((H/'setup_handler_table.json').read_text())['entries'];QIDS=sorted({e['qid']for e in entries})
u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(BASE,SIZE);u.mem_write(BASE,im);u.mem_map(STACK,0x20000);u.mem_map(DATA,0x2000)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
current={};steps=0
def stop(reason,**more):current.update(status='UNKNOWN_NOT_AUTHORIZED',reason=reason,**more);u.emu_stop()
def code(u,a,n,_):
 global steps
 steps+=1
 if a==STOP:u.emu_stop();return
 if not BASE+0x1000<=a<BASE+0x2b7f9:stop('outside original Setup text',pc=hex(a));return
 raw=bytes(u.mem_read(a,n));ins=next(md.disasm(raw,a))
 if ins.mnemonic in ['out','in','rdmsr','wrmsr','syscall','vmcall']:
  stop('hardware instruction boundary',pc=hex(a-BASE),instruction=ins.mnemonic);return
 if ins.mnemonic=='call':
  ret=a+n
  # Only the exact static dispatcher CALL may enter a QID handler. Calls
  # below any handler are an unclosed effect even if memory is mapped.
  if a!=BASE+0x22f6:stop('helper/protocol call boundary',pc=hex(a-BASE),instruction=ins.op_str);return
def write(u,access,a,n,value,_):
 if STACK<=a and a+n<=STACK+0x20000:return
 if DATA<=a and a+n<=DATA+0x2000:return
 if BASE+0x48180<=a and a+n<=BASE+0x48181:return
 if BASE+0x48190<=a and a+n<=BASE+0x48198:return
 stop('other module/global write',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),write_rva=hex(a-BASE),bytes=n)
def invalid(u,access,a,n,value,_):stop('unmapped service/data boundary',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),address=hex(a));return False
u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_MEM_INVALID,invalid)
def run(qid,action):
 global current,steps
 u.mem_write(BASE,im);u.mem_write(BASE+0x55180,struct.pack('<QQ',BASE+0x55180,BASE+0x55180));u.mem_write(BASE+0x2fd60,struct.pack('<Q',0x555100))
 sp=STACK+0x1f008;u.mem_write(sp,bytes(0x400));u.mem_write(sp,struct.pack('<Q',STOP));u.mem_write(DATA,bytes(0x1000));u.mem_write(sp+40,struct.pack('<QQ',DATA+0x100,DATA+0x200))
 for r,v in [(UC_X86_REG_RCX,BASE+0x2fd40),(UC_X86_REG_RDX,action),(UC_X86_REG_R8,qid),(UC_X86_REG_R9,9),(UC_X86_REG_RSP,sp)]:u.reg_write(r,v)
 current={'qid':qid,'action':action,'handlers':[e['handler']for e in entries if e['qid']==qid]};steps=0
 try:u.emu_start(BASE+0x2250,0,count=30000)
 except UcError as e:
  if 'status'not in current:stop('cpu boundary',error=str(e))
 if u.reg_read(UC_X86_REG_RIP)==STOP:
  current.update(status='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING',result=hex(u.reg_read(UC_X86_REG_RAX)),action_request=int.from_bytes(u.mem_read(DATA+0x200,8),'little'))
 elif 'status'not in current:current.update(status='UNKNOWN_NOT_AUTHORIZED',reason='instruction budget',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE))
 current['instructions']=steps;return dict(current)
def main():
 begin=time.time();rows=[]
 for action in [3,4]:
  for i,qid in enumerate(QIDS):
   rows.append(run(qid,action))
   if i%100==0:print(action,i,flush=True)
 out={'original_setup_sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'entries':len(entries),'unique_qids':len(QIDS),'actual_machine_code_cases':len(rows),'seconds':round(time.time()-begin,3),'summary':dict(collections.Counter(x['status']for x in rows)),'cases':rows,'authority':False,'limitations':['Dynamic Setup handler list modeled empty; actual runtime list not established','No original AMITSE 3E700 or ActionRequest consumer execution in this test','All secondary calls/writes remain UNKNOWN; no successful-return substitute','No hardware services or variables used']}
 (H/'setup_callback_action_tests.json').write_text(json.dumps(out,indent=2)+'\n');print(out['summary'])
if __name__=='__main__':main()
