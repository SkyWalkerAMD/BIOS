"""Execute exact original W890 IA32 GUID extraction handlers in Unicorn.

Firmware, input and output exist only in this local emulator. No device services
are supplied and no CAP/ROM is emitted. Only a bounded JSON report is written.
"""
from pathlib import Path
import hashlib,json,struct,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
for name in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/name))
import pefile,unicorn
from unicorn.x86_const import *
from validate_layout import main as layout_main

def sha(b):return hashlib.sha256(b).hexdigest()
def align(n):return (n+4095)&~4095
MODULE=HERE/'native_inputs/DxeIplW890Normal.efi'
original=MODULE.read_bytes()
assert sha(original)=='87f73cdbb246b2457e687a41711673359bdc62c869de1398e3d932c02e07461f'
pe=pefile.PE(data=original);assert pe.FILE_HEADER.Machine==0x14c
IMAGE=pe.OPTIONAL_HEADER.ImageBase;GET_INFO=IMAGE+0x2a43;DECODE=IMAGE+0x2ac1
S=0x01000000;O=0x03000000;H=0x07000000;STACK=0x08000000;R=0x09000000;STOP=0x09001000

def execute(section,expected,case):
    start=time.monotonic();mu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
    image=pe.get_memory_mapped_image()
    mb=IMAGE&~4095;ms=align(IMAGE-mb+pe.OPTIONAL_HEADER.SizeOfImage)
    mu.mem_map(mb,ms);mu.mem_write(IMAGE,image);mu.mem_protect(mb,ms,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    mu.mem_map(S,align(len(section)));mu.mem_write(S,section);mu.mem_protect(S,align(len(section)),unicorn.UC_PROT_READ)
    mu.mem_map(STACK,0x100000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.mem_map(R,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.mem_map(STOP,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
    faults=[]
    def bad(uc,access,address,size,value,context):
        faults.append(dict(access=access,address=hex(address),bytes=size));return False
    mu.hook_add(unicorn.UC_HOOK_MEM_INVALID,bad)
    def call(entry,args):
        sp=STACK+0x100000-0x100
        mu.reg_write(UC_X86_REG_ESP,sp);mu.reg_write(UC_X86_REG_EBP,0)
        mu.reg_write(UC_X86_REG_EFLAGS,2)
        mu.mem_write(sp,struct.pack('<'+'I'*(1+len(args)),STOP,*args))
        pc=entry;rounds=0;begin=time.monotonic()
        while pc!=STOP:
            # No per-instruction Python hooks; unknown addresses remain unmapped.
            mu.emu_start(pc,STOP,timeout=20_000_000,count=250_000_000)
            pc=mu.reg_read(UC_X86_REG_EIP);rounds+=1
            if pc!=STOP:print(json.dumps(dict(case=case,phase='native_decode_active',seconds=round(time.monotonic()-begin,1))),flush=True)
            if rounds>=12 or time.monotonic()-begin>180:raise RuntimeError('Bounded native execution did not return')
        return mu.reg_read(UC_X86_REG_EAX)
    mu.mem_write(R,b'\xa5'*64)
    info_status=call(GET_INFO,[S,R,R+4,R+8])
    if case=='wrong_guid':
        assert info_status==0x80000002 and bytes(mu.mem_read(R,16))==b'\xa5'*16 and not faults
        return dict(case=case,passed=True,get_info_status=hex(info_status),no_output_fields_written=True)
    assert info_status==0 and not faults
    output_size,scratch_size=struct.unpack('<II',mu.mem_read(R,8));attrs=struct.unpack('<H',mu.mem_read(R+8,2))[0]
    assert output_size==len(expected) and scratch_size==0x10000 and attrs==1
    mu.mem_map(O,align(output_size+128),unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.mem_map(H,align(scratch_size+128),unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
    mu.mem_write(O,b'\xa5'*64);mu.mem_write(O+64+output_size,b'\x5a'*64)
    mu.mem_write(H,b'\xc3'*64);mu.mem_write(H+64+scratch_size,b'\x3c'*64)
    mu.mem_write(R+16,struct.pack('<I',O+64));mu.mem_write(R+20,b'\xa5'*4)
    status=call(DECODE,[S,R+16,H+64,R+20])
    decoded=bytes(mu.mem_read(O+64,output_size))
    assert status==0 and decoded==expected and not faults
    assert bytes(mu.mem_read(R+20,4))==bytes(4)
    assert bytes(mu.mem_read(O,64))==b'\xa5'*64 and bytes(mu.mem_read(O+64+output_size,64))==b'\x5a'*64
    assert bytes(mu.mem_read(H,64))==b'\xc3'*64 and bytes(mu.mem_read(H+64+scratch_size,64))==b'\x3c'*64
    assert bytes(mu.mem_read(S,len(section)))==section and bytes(mu.mem_read(IMAGE,len(image)))==image
    return dict(case=case,passed=True,get_info_status=hex(info_status),decode_status=hex(status),attributes=attrs,
        scratch_bytes=scratch_size,output_bytes=output_size,output_sha256=sha(decoded),input_sha256=sha(section),
        original_module_unchanged=True,input_unchanged=True,output_and_scratch_guards_unchanged=True,
        invalid_memory_events=faults,seconds=round(time.monotonic()-start,3))

def main():
    cases=[]
    def memory(values):
        bad=bytearray(values['original_section']);bad[4]^=1
        for name,section,expected in [('wrong_guid',bytes(bad),b''),
            ('original_factory_stream',values['original_section'],values['original_output']),
            ('proposed_disabled_provider_stream',values['proposed_section'],values['proposed_output'])]:
            print(json.dumps(dict(case=name,phase='starting')),flush=True)
            result=execute(section,expected,name);cases.append(result);print(json.dumps(result),flush=True)
    layout_main(['--efi',str(HERE.parent/'password/provider/build/W890PasswordProvider01.UNBOUND.TESTONLY.efi'),
        '--sha256','971ae6208bb75bdbe15a859adf46b1e68ca2e232bb618cca5f476994d6465a9e',
        '--file-guid','1a643cc0-cc83-45e5-bb2d-c59d02659514','--output',str(HERE/'provider01_layout_experiment.json')],
        observe_memory=memory)
    result=dict(status='PASS_EXACT_ORIGINAL_GUID_DECODER_LOCAL_EMULATION',release_ready=False,
        module=dict(path=str(MODULE),sha256=sha(original),architecture='IA32',image_base=hex(IMAGE)),
        functions=dict(get_info=hex(GET_INFO),decode=hex(DECODE)),unicorn_version=unicorn.__version__,
        no_uefi_or_bmc_services_supplied=True,cases=cases,script_sha256=sha(Path(__file__).read_bytes()),
        limitations=['Actual original extraction handlers executed locally; actual platform selection/dispatch of this PEIM is not observed.',
            'Full FFS scanner behavior for the additional RAW padding section and expanded FV dispatch is not emulated here.',
            'No CAP/ROM or compressed firmware artifact written. Input and proposed output are reconstructed and kept in memory only.',
            'Does not prove password interception, signature acceptance, boot-integrity enforcement or recovery.'])
    (HERE/'native_lzma_replay.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=result['status'],cases=len(cases),report_sha256=sha((HERE/'native_lzma_replay.json').read_bytes()))),flush=True)

if __name__=='__main__':main()
