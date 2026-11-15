"""Actual vendor dispatch bytecode in Unicorn. No Windows DLL loading.
GetFileSizeEx and read/write helper boundaries are synthetic scalar/memory
fixtures; imported file/device methods always trap. No host file is touched.
"""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
DLL=HERE.parent.parent/'media_writeback_review/javaharddiskwrapper-win64.dll'
pe=pefile.PE(str(DLL));BASE=0x180000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
Q=lambda x:struct.pack('<Q',x);D=lambda x:struct.pack('<I',x)

def run(op,count=0,alloc=0,opaque=0):
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,pe.OPTIONAL_HEADER.SizeOfImage),(HEAP,0x100000),(STACK,0x20000),(STOP,0x2000)]:u.mem_map(a,n)
    u.mem_write(BASE,pe.get_memory_mapped_image());imports={}
    for g in pe.DIRECTORY_ENTRY_IMPORT:
        for i in g.imports:
            f=STOP+0x100+16*len(imports);imports[f]=(i.name or b'ordinal').decode();u.mem_write(i.address,Q(f))
    inp,outp,outlen,state=HEAP,HEAP+0x30000,HEAP+0x60000,HEAP+0x61000
    b=bytearray(108 if op!=0x2a else 61+count*512);b[:8]=b'IUSB    ';struct.pack_into('<I',b,12,len(b)-32);b[40]=opaque;b[41]=op
    if op in (0x28,0x2a,0xa8):
        b[43:47]=(1).to_bytes(4,'big')
        if op==0xa8:b[47:51]=count.to_bytes(4,'big')
        else:b[48:50]=count.to_bytes(2,'big')
    if op==0x1a:b[45]=alloc
    if op==0x2a:struct.pack_into('<I',b,57,count*512);b[61:]=bytes((i^0x5a)&255 for i in range(count*512))
    else:b[62]=1
    u.mem_write(inp,bytes(b));u.mem_write(outp,b'\xa5'*0x21000)
    u.mem_write(state+0x108,Q(0x12345678));u.mem_write(state+0x118,D(512)+D(32768));u.mem_write(state+0x121,b'\1')
    calls=[]
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v);u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def code(uc,a,n,_):
        if a==STOP:uc.emu_stop();return
        x,y,z,w=[u.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        if a==BASE+0x3520:
            assert x==state and y==1 and z<=256
            p=rq(u.reg_read(R.UC_X86_REG_RSP)+0x28);data=bytes((i^0x5a)&255 for i in range(z*512))
            if data:u.mem_write(p,data)
            u.mem_write(w,D(len(data)));calls.append(dict(helper='synthetic_read_boundary',lba=y,count=z));ret(0);return
        if a==BASE+0x3620:
            assert x==state and y==1 and z<=256
            assert bytes(u.mem_read(w,z*512))==bytes((i^0x5a)&255 for i in range(z*512))
            calls.append(dict(helper='synthetic_write_boundary',lba=y,count=z));ret(0);return
        assert a in imports and imports[a]=='GetFileSizeEx',('forbidden OS call',imports.get(a),hex(a))
        assert x==0x12345678;u.mem_write(y,Q(16777216));calls.append(dict(helper='synthetic_GetFileSizeEx'));ret(1)
    u.hook_add(U.UC_HOOK_CODE,code,begin=STOP,end=STOP+0x1fff)
    for addr in [BASE+0x3520,BASE+0x3620]:u.hook_add(U.UC_HOOK_CODE,code,begin=addr,end=addr)
    sp=STACK+0x1ff00-8;u.mem_write(sp,Q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    for r,v in [(R.UC_X86_REG_RCX,inp),(R.UC_X86_REG_RDX,outp),(R.UC_X86_REG_R8,outlen),(R.UC_X86_REG_R9,state)]:u.reg_write(r,v)
    u.emu_start(BASE+0x38a0,STOP+0x1fff,count=80000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP
    n=struct.unpack('<I',u.mem_read(outlen,4))[0];out=bytes(u.mem_read(outp,61+n));status=struct.unpack_from('<I',out,53)[0]
    if op in (0xf3,0xf4,0xf6,0xf7,0x35):assert status==0x200501 and n==0
    else:assert status==0
    if op==0x1a:assert out[61:]==b'\x03\0\0\0' and n==4
    if op==0x25:assert out[61:]==struct.pack('>II',32767,512)
    if op in (0x28,0x2a):assert calls[-1]['count']==count
    if op==0xa8:assert calls[-1]['count']==(count>>16)  # Vendor truncation, not reproduced by adapter.
    assert out[:32]==bytes(b[:32]) and out[40]==opaque
    return dict(opcode=f'{op:02X}',CDB_count=count,allocation=alloc,opaque_direction=opaque,status_hex=f'{status:08X}',native_data_bytes=n,helper_calls=calls,output_header_preserved=True)

if __name__=='__main__':
    cases=[run(op) for op in (0,0x1a,0x25,0x1b,0x1e,0x35,0xf3,0xf4,0xf6,0xf7)]
    cases += [run(0x1a,alloc=255),run(0x28,count=1),run(0x28,count=255),run(0x28,count=256),run(0x2a,count=1),run(0x2a,count=256),run(0xa8,count=2),run(0xa8,count=65536),run(0x28,count=1,opaque=255),run(0x2a,count=1,opaque=255)]
    report=dict(status='PASS_NATIVE_DISPATCH_SYNTHETIC_IO_BOUNDARIES_ONLY',DLL_sha256=hashlib.sha256(DLL.read_bytes()).hexdigest(),test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,
                limitations=['Read/write helper routines0x3520/0x3620 are explicit memory stubs; actual CDB branch/field extraction/status/header copy runs vendor bytes.',
                             'No native image path or real OS file/device API was invoked.',
                             'Vendor READ12 extracts the high16 bits of the32-bit count, a demonstrated defect; adapter instead follows standard32-bit CDB semantics and its255-sector bound.',
                             'Vendor0x35 falls into unsupported; adapter preserves existing verified backend flush semantics rather than claiming native equivalence.'])
    (HERE/'native_dispatch.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':report['status'],'cases':len(cases)}))
