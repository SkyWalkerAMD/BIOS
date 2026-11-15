"""Actual compiled test-app cleanup/denial callbacks in Unicorn; no host EFI calls.
ResetSystem, firmware CRC service and memory-patch service are explicit stubs.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'ram_test'
sys.path[:0]=[str(ROOT/'tools/pydeps')]
import pefile,unicorn as U
from unicorn import x86_const as R
symbols={name:int(value,16) for name,value in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(OUT/'ram_test.map').read_text(encoding='utf8'),re.M)}
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
def q(v):return struct.pack('<Q',v)
def d(v):return struct.pack('<I',v)
def vm():
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);pe=pefile.PE(str(OUT/'BOOTX64.EFI'));pe.relocate_image(BASE);data=pe.get_memory_mapped_image()
    u.mem_map(BASE,(len(data)+4095)&~4095);u.mem_write(BASE,data)
    for start,n in [(HEAP,0x10000),(STACK,0x10000),(STOP,0x1000)]:u.mem_map(start,n)
    u.mem_write(symbols['system_table'],q(HEAP));u.mem_write(HEAP+0x58,q(HEAP+0x1000));u.mem_write(HEAP+0x60,q(HEAP+0x2000))
    u.mem_write(HEAP+0x1000+12,d(0x88));u.mem_write(HEAP+0x1000+0x68,q(STOP+0x100));u.mem_write(HEAP+0x2000+0x158,q(STOP+0x200))
    u.reg_write(R.UC_X86_REG_CR4,0x600)
    return u
def call(u,address,*args):
    sp=STACK+0x8008;u.mem_write(sp,q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    for reg,arg in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],args):u.reg_write(reg,arg)
    u.emu_start(address,STOP,count=100000);return u.reg_read(R.UC_X86_REG_RAX)
cases=[]
for kind in [0,2]:
    u=vm();u.mem_write(symbols['ram_record'],b'\xa5'*128);u.mem_write(symbols['ram_size'],q(128));u.mem_write(symbols['password_core'],b'\xa5'*208)
    seen=[]
    def reset_hook(u,address,size,unused):
        seen.append([u.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]])
        assert bytes(u.mem_read(symbols['ram_record'],128))==b'\0'*128
        assert bytes(u.mem_read(symbols['ram_size'],8))==b'\0'*8
        assert bytes(u.mem_read(symbols['password_core'],208))==b'\0'*208
        u.emu_stop()
    u.hook_add(U.UC_HOOK_CODE,reset_hook,begin=STOP+0x100,end=STOP+0x100)
    call(u,symbols['reset'],kind);assert seen==[[kind,0,0,0]]
    cases.append({'case':'cold reset' if kind==0 else 'shutdown','passed':True,'reset_type':kind,'credential_and_core_erased_before_reset':True})
u=vm();calls=[]
def services(u,address,size,unused):
    a,b,c=[u.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8]]
    if address==STOP+0x200:u.mem_write(c,d(zlib.crc32(bytes(u.mem_read(a,b)))));ret=0;calls.append('crc')
    else:assert a==HEAP+0x1000 and c==0x88;u.mem_write(a,bytes(u.mem_read(b,c)));ret=1;calls.append('patch')
    sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,ret);u.reg_write(R.UC_X86_REG_RIP,struct.unpack('<Q',u.mem_read(sp,8))[0]);u.reg_write(R.UC_X86_REG_RSP,sp+8)
u.hook_add(U.UC_HOOK_CODE,services,begin=STOP+0x200,end=STOP+0x200)
u.hook_add(U.UC_HOOK_CODE,services,begin=symbols['patch_memory'],end=symbols['patch_memory'])
assert call(u,symbols['block_variable_table'])==1 and calls==['crc','patch']
assert bytes(u.mem_read(HEAP+0x1000+0x58,8))==q(symbols['deny_variable'])
assert bytes(u.mem_read(symbols['original_set_variable'],8))==q(symbols['deny_variable'])
rt=bytearray(u.mem_read(HEAP+0x1000,0x88));crc=struct.unpack_from('<I',rt,16)[0];rt[16:20]=b'\0'*4;assert crc==zlib.crc32(rt)
cases.append({'case':'runtime table and saved original chain both deny; CRC updated','passed':True})
before=bytes(u.mem_read(HEAP,0x10000));result=call(u,symbols['deny_variable'],0,0,7,32768)
assert result==0x8000000000000008 and before==bytes(u.mem_read(HEAP,0x10000))
cases.append({'case':'denial callback returns EFI_WRITE_PROTECTED without touching caller data','passed':True})
report={'passed':True,'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((HERE/'ram_lock_test.c').read_bytes()).hexdigest(),'cases':cases,'scope':__doc__}
(OUT/'safety_validation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps(report,indent=2))
