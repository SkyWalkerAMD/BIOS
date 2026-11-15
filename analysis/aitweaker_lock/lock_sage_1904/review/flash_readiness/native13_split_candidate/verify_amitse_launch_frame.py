"""Original AMITSE prologue/callsite + Core StartImage + actual EP2 entry.

Intervening boot-policy body is not executed. Its complete disassembly is
audited for stack-register writes; no native full-browser test is claimed.
"""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;EP2=HERE/'entry_probe02'
sys.dont_write_bytecode=True;sys.path.insert(0,str(EP2));import verify_context_probe as e
from unicorn import UC_HOOK_CODE,UC_PROT_READ,UC_PROT_EXEC
from unicorn.x86_const import *
import capstone
f=e.f;path=HERE/'boot_context/AMITSE.original.efi';pe=f.pefile.PE(str(path));start,end,call=0x9f78,0xaada,0xa8e0;raw=pe.get_data(start,end-start)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;ins=list(md.disasm(raw,start));assert len(ins)==693 and ins[-1].address==0xaad9 and ins[-1].mnemonic=='ret'
stack=[]
for x in ins:
 _,writes=x.regs_access()
 if x.mnemonic!='call'and(capstone.x86.X86_REG_RSP in writes or capstone.x86.X86_REG_RBP in writes):stack.append({'rva':hex(x.address),'mnemonic':x.mnemonic,'operands':x.op_str})
assert not any(0x9f9e<=int(x['rva'],16)<=call for x in stack)
assert not any(x.mnemonic=='jmp'and not x.op_str.startswith('0x')for x in ins)
returns=[0x2d7d,0x9025,0x960c,0x9754,0x97c9]
for ret in returns:assert pe.get_data(ret-5,1)==b'\xe8'and ret+int.from_bytes(pe.get_data(ret-4,4),'little',signed=True)==start
v=e.VM();v.u.mem_protect(f.TSE,0xb0000,UC_PROT_READ|UC_PROT_EXEC);p=f.STACK+0xd0008;upper_rbp=0x3141592653589793;upper_return=f.TSE+0x9025
v.w(p,f.q(upper_return));v.u.reg_write(UC_X86_REG_RSP,p);v.u.reg_write(UC_X86_REG_RBP,upper_rbp);v.u.reg_write(UC_X86_REG_RCX,0x123);v.u.reg_write(UC_X86_REG_RDX,0);v.u.reg_write(UC_X86_REG_R8,0);v.u.reg_write(UC_X86_REG_R9,0)
h=v.u.hook_add(UC_HOOK_CODE,lambda u,a,n,d:u.emu_stop(),begin=f.TSE+0x9f9e,end=f.TSE+0x9f9e);v.u.emu_start(f.TSE+start,0,count=1000);v.u.hook_del(h)
assert v.u.reg_read(UC_X86_REG_RSP)==p-0x128 and v.u.reg_read(UC_X86_REG_RBP)==p-0x5f
v.w(f.TSE+0x83308,f.q(v.bs));v.w(p-0x5f-0x79,f.q(v.entry_image));priv=f.HEAP+0xa000;jump=f.HEAP+0xb000
v.w(priv+0x20,f.q(f.sy['efi_main']));v.w(priv+0x38,f.q(v.st));v.w(priv+0xd0,(0x8664).to_bytes(2,'little'));v.w(v.extra_lis[3]+0x48,f.q(0x21000));reached=[]
def hook(u,a,n,data):
 if a==f.sy['probe_main']:reached.append(a);u.emu_stop();return
 result={e.CORE+0x7e50:priv,e.CORE+0x10808:jump,e.CORE+0x280:0,e.CORE+0x11258:0}[a];sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RAX,result);u.reg_write(UC_X86_REG_RIP,v.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
for a in [e.CORE+0x7e50,e.CORE+0x10808,e.CORE+0x280,e.CORE+0x11258,f.sy['probe_main']]:v.u.hook_add(UC_HOOK_CODE,hook,begin=a,end=a)
v.u.emu_start(f.TSE+0xa8d0,0,count=100000);assert reached;s=v.q(f.sy['captured_entry'])
checks={'raw_entry_rsp_equals_launch_entry_minus190':s==p-0x190,'core_return_is88af':v.q(s)==e.CORE+0x88af,'native_return_isa8e6':v.q(s+0x60)==f.TSE+0xa8e6,'saved_native_rbp_equals_raw_plus131':v.q(s+0x78)==s+0x131,'next_return_slot_plus190':v.q(s+0x190)==upper_return,'saved_upper_rbp_slot_plus188':v.q(s+0x188)==upper_rbp,'original_function_stack_pointer_no_body_write':not any(0x9f9e<=int(x['rva'],16)<=call for x in stack),'five_known_outer_call_instructions_match':True}
assert all(checks.values())
report={'status':'PASS_ORIGINAL_AMITSE_LAUNCH_FIXED_FRAME_REPLAY_NOT_OUTER_CHAIN_PROOF','checks':checks,'function_start':start,'function_end_exclusive':end,'function_sha256':hashlib.sha256(raw).hexdigest(),'instruction_count':len(ins),'stack_register_instructions':stack,'known_outer_return_rvas':returns,'observed_fixture_raw_rsp':hex(s),'core_sha256':hashlib.sha256((HERE/'boot_context/DxeCore.original.efi').read_bytes()).hexdigest(),'amitse_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'entry_probe_efi_sha256':hashlib.sha256(f.EFI.read_bytes()).hexdigest(),'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Actual original AMITSE prologue and StartImage callsite, actual original Core normal entry path and actual compiled EP2 assembly entry executed. Boot-policy body skipped after static stack-write audit; upper return/address are synthetic. No real next frame or UI-absence proof.'}
(HERE/'amitse_launch_frame_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'function_sha256':report['function_sha256']}))
