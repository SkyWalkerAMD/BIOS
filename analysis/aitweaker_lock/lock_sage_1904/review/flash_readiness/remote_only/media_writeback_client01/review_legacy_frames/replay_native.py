"""Pure emulation of shipped image dispatch bytes; never load DLL into Windows.
All memory is Unicorn-owned. Every imported API traps except a synthetic
GetFileSizeEx returning the chosen scalar. No actual file/device handle exists.
"""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[7]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
DLL=HERE.parent.parent/'media_writeback_review/javaharddiskwrapper-win64.dll'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
BASE=0x180000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
Q=lambda x:struct.pack('<Q',x)
D=lambda x:struct.pack('<I',x)
pe=pefile.PE(str(DLL));image=pe.get_memory_mapped_image()

def run(name,opcode=0,legacy=True,size_ok=True,opened=True):
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,pe.OPTIONAL_HEADER.SizeOfImage),(HEAP,0x20000),(STACK,0x20000),(STOP,0x2000)]:u.mem_map(a,n)
    u.mem_write(BASE,image)
    imports={}
    for group in pe.DIRECTORY_ENTRY_IMPORT:
        for item in group.imports:
            stub=STOP+0x100+16*len(imports)
            imports[stub]=(item.name or b'ordinal').decode()
            u.mem_write(item.address,Q(stub))
    inp,outp,outlen,state=HEAP,HEAP+0x1000,HEAP+0x2000,HEAP+0x3000
    frame=bytearray(108);frame[:8]=b'IUSB    ';struct.pack_into('<I',frame,12,76);frame[41]=opcode;frame[62]=1
    if not legacy:frame[8:11]=b'\x01\0\x20';frame[17:19]=b'\x05\x01'
    u.mem_write(inp,bytes(frame));u.mem_write(outp,b'\xa5'*256)
    u.mem_write(state+0x108,Q(0x12345678))
    u.mem_write(state+0x121,bytes([int(opened)]))
    calls=[]
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v)
        u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def code(uc,a,n,_):
        if a==STOP:uc.emu_stop();return
        assert a in imports,(name,'unknown stub',hex(a))
        fn=imports[a];calls.append(fn)
        assert fn=='GetFileSizeEx',(name,'forbidden native OS call',fn)
        handle=u.reg_read(R.UC_X86_REG_RCX);ptr=u.reg_read(R.UC_X86_REG_RDX)
        assert handle==0x12345678
        if size_ok:u.mem_write(ptr,Q(16777216))
        ret(1 if size_ok else 0)
    u.hook_add(U.UC_HOOK_CODE,code,begin=STOP,end=STOP+0x1fff)
    sp=STACK+0x1ff00-8;u.mem_write(sp,Q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    for reg,val in [(R.UC_X86_REG_RCX,inp),(R.UC_X86_REG_RDX,outp),(R.UC_X86_REG_R8,outlen),(R.UC_X86_REG_R9,state)]:u.reg_write(reg,val)
    u.emu_start(BASE+0x38a0,STOP+0x1fff,count=50000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP
    response=bytes(u.mem_read(outp,128))
    n=struct.unpack('<I',u.mem_read(outlen,4))[0]
    status=struct.unpack_from('<I',response,53)[0]
    assert response[:32]==frame[:32]
    assert response[32:53]==frame[32:53]
    assert struct.unpack_from('<I',response,57)[0]==n
    assert response[62+n:128]==b'\xa5'*(66-n)
    if opcode in [0,0x25]:assert status==0 and calls==['GetFileSizeEx']
    else:assert status==0x200501 and calls==[]
    if opcode==0x25:assert n==8 and response[61:69]==struct.pack('>II',32767,512)
    else:assert n==0
    return dict(name=name,opcode=f'{opcode:02X}',native_return_hex=f'{u.reg_read(R.UC_X86_REG_RAX):016X}',
                header_first32_preserved=True,header_length=response[10],native_data_bytes=n,
                status_hex=f'{status:08X}',JNI_returned_length=61+n,
                output_prefix_hex=response[:max(62,61+n)].hex(),imported_API_calls=calls,
                synthetic_file_size_ok=size_ok,untouched_tail_remains_seed=True)

if __name__=='__main__':
    cases=[run('legacy_TUR_auth_tail'),run('canonical_TUR_auth_tail',legacy=False),
           run('legacy_TUR_size_API_failure',size_ok=False),run('legacy_capacity8',opcode=0x25),
           run('legacy_F3_not_image_ready_command',opcode=0xf3)]
    report=dict(status='PASS_NATIVE_BYTES_SYNTHETIC_MEMORY_ONLY',DLL_sha256=sha(DLL),test_sha256=sha(Path(__file__)),
                entry_RVA='0x38a0',cases=cases,
                scope='No native DLL loading, no host ReadFile/WriteFile/GetFileSizeEx; all imported calls trap except synthetic scalar GetFileSizeEx in Unicorn.',
                limitations=['JNI add61 proven by decompile and bytecode analysis; this replay calls native image dispatch directly.',
                             'TUR readiness function returns success even if its GetFileSizeEx fails and sets fallback geometry; TUR success alone does not validate persistence.',
                             'No hardware, BMC traffic or server acceptance of a response is established.'])
    (HERE/'native_replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'cases':len(cases),'DLL_sha256':report['DLL_sha256']},indent=2))
