"""Execute original DXE Core StartImage bytes up to its real EFI entry call.

Only internal service/report/SetJump dependencies are synthetic. This proves
the local frame offsets at the exact callsite; it does not prove boot ancestry.
"""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
BASE=0x10000000;HEAP=0x20000000;STACK=0x30000000;ENTRY=0x40000000;SIZE=0x100000
path=HERE/'boot_context/DxeCore.original.efi';raw=path.read_bytes();pe=pefile.PE(data=raw);pe.relocate_image(BASE)
u64=lambda v:struct.pack('<Q',v)
u=Uc(UC_ARCH_X86,UC_MODE_64)
for a,n in [(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095),(HEAP,SIZE),(STACK,SIZE),(ENTRY,4096)]:u.mem_map(a,n)
u.mem_write(BASE,pe.get_memory_mapped_image());image=HEAP+0x1000;handle=0x55667788;system=HEAP+0x2000;jump=HEAP+0x3000
u.mem_write(image+0x20,u64(ENTRY));u.mem_write(image+0x38,u64(system));u.mem_write(image+0xd0,struct.pack('<H',0x8664))
parent_rbp=0x3141592653589793;parent_rbx=0x1122334455667788;parent_ret=0x5000a8e6;sp=STACK+SIZE-0x108
u.mem_write(sp,u64(parent_ret));u.reg_write(UC_X86_REG_RSP,sp);u.reg_write(UC_X86_REG_RBP,parent_rbp);u.reg_write(UC_X86_REG_RBX,parent_rbx)
u.reg_write(UC_X86_REG_RCX,handle);u.reg_write(UC_X86_REG_RDX,0);u.reg_write(UC_X86_REG_R8,0)
captures={};calls=[]
def q(a):return int.from_bytes(u.mem_read(a,8),'little')
def hook(uc,a,n,data):
    if a==ENTRY:
        s=uc.reg_read(UC_X86_REG_RSP);captures.update(entry_rsp=s,entry_return=q(s),parent_return=q(s+0x60),saved_handle=q(s+0x68),saved_rbx=q(s+0x70),saved_rbp=q(s+0x78),entry_rcx=uc.reg_read(UC_X86_REG_RCX),entry_rdx=uc.reg_read(UC_X86_REG_RDX));uc.emu_stop();return
    off=a-BASE
    result={0x7e50:image,0x10808:jump,0x280:0,0x11258:0}.get(off)
    if result is not None:
        calls.append(hex(off));s=uc.reg_read(UC_X86_REG_RSP);uc.reg_write(UC_X86_REG_RAX,result);uc.reg_write(UC_X86_REG_RIP,q(s));uc.reg_write(UC_X86_REG_RSP,s+8)
for off in [0x7e50,0x10808,0x280,0x11258]:u.hook_add(UC_HOOK_CODE,hook,begin=BASE+off,end=BASE+off)
u.hook_add(UC_HOOK_CODE,hook,begin=ENTRY,end=ENTRY)
u.emu_start(BASE+0x8720,0,count=50000)
checks={'entry_stack_delta_0x60':captures['entry_rsp']==sp-0x60,'exact_entry_return_88af':captures['entry_return']==BASE+0x88af,'caller_return_at_plus60':captures['parent_return']==parent_ret,'image_handle_at_plus68':captures['saved_handle']==handle,'original_rbx_at_plus70':captures['saved_rbx']==parent_rbx,'original_rbp_at_plus78':captures['saved_rbp']==parent_rbp,'entry_abi_handle':captures['entry_rcx']==handle,'entry_abi_system_table':captures['entry_rdx']==system}
assert all(checks.values()),captures
report={'status':'PASS_ORIGINAL_STARTIMAGE_BYTES_FIXED_FRAME_ONLY','checks':checks,'captures':{k:hex(v)for k,v in captures.items()},'synthetic_dependencies':calls,'core_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'prologue_hex':pe.get_data(0x8720,0x17).hex(),'entry_call_hex':pe.get_data(0x88ac,3).hex(),'startimage_rva':'0x8720','entry_return_rva':'0x88af','scope':'Actual original DXE Core prologue, normal StartImage path, and indirect EFI entry CALL executed. Does not establish actual hardware caller chain, absence of native browser frames, or installer safety.'}
(HERE/'startimage_frame_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks)}))
