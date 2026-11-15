"""Execute complete FD02 EFI + original ASUS CPU_IO2 instructions in Unicorn.

UEFI/PCI services and SPI registers are synthetic. Real native Mem.Read and
Mem.Write operate only on an emulated page; nothing executes on the target.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
from verify_core import FLASH,REGS
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=lambda x:struct.pack('<Q',x)
d=lambda x:struct.pack('<I',x)
ERR=lambda n:(1<<63)|n
BASE=0x140000000;NATIVE=0x30000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000;MMIO=0xfe010000
efi=HERE/'build/BOOTX64.EFI'
pe=pefile.PE(str(efi));pe.relocate_image(BASE);binary=pe.get_memory_mapped_image()
native=HERE.parent/'cpuio2_native/OriginalCpuIo2.efi'
assert sha(native)=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
np=pefile.PE(str(native));np.relocate_image(NATIVE);native_image=np.get_memory_mapped_image()
symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/inventory.map').read_text(),re.M)}
def smrecord(kind,length,text):
    b=bytearray(length);b[0]=kind;b[1]=length
    if text:b[5]=1
    return bytes(b)+(text.encode()+b'\0' if text else b'\0')+b'\0'

def execute(name,**opt):
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,(len(binary)+4095)&~4095),(NATIVE,0x10000),(HEAP,0x20000),(STACK,0x20000),(STOP,0x1000),(MMIO,0x1000)]:u.mem_map(a,n)
    u.mem_write(BASE,binary);u.mem_write(NATIVE,native_image)
    if 'native_damage' in opt:u.mem_write(NATIVE+opt['native_damage'],b'\xcc')
    st=HEAP;bs=HEAP+0x1000;ct=HEAP+0x2000;ep=HEAP+0x3000;sm=HEAP+0x4000
    pci=HEAP+0x8000;cpu=HEAP+0x9000;ph=HEAP+0x7000;ch=HEAP+0x7100
    raw=smrecord(0,24,opt.get('version','1904'))+smrecord(2,15,opt.get('board','Pro WS W790E-SAGE SE'))+smrecord(127,4,'')
    if opt.get('duplicate_smbios'):raw=smrecord(0,24,'1904')+raw
    epbytes=bytearray(24);epbytes[:5]=b'_SM3_';epbytes[6]=24;struct.pack_into('<IQ',epbytes,12,len(raw),sm);epbytes[5]=(-sum(epbytes))&255
    if opt.get('bad_checksum'):epbytes[5]^=1
    u.mem_write(sm,raw);u.mem_write(ep,bytes(epbytes));u.mem_write(ct,uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+q(ep))
    u.mem_write(st+0x58,q(STOP+0x900)+q(bs)+q(1)+q(ct))
    for off in range(0x18,0x178,8):u.mem_write(bs+off,q(STOP+0x900))
    for off,fn in {0x38:0x100,0x48:0x130,0x98:0x120,0xf8:0x180,0x100:0x170,0x138:0x110,0x140:0x190}.items():u.mem_write(bs+off,q(STOP+fn))
    for off in range(0,0xb0,8):u.mem_write(pci+off,q(STOP+0x900))
    u.mem_write(pci+0x30,q(STOP+0x140));u.mem_write(pci+0x70,q(STOP+0x150))
    u.mem_write(cpu,q(opt.get('read_method',NATIVE+0x3d4))+q(opt.get('write_method',NATIVE+0x484))+q(STOP+0x900)*2)
    u.mem_write(ph,q(pci)+q(pci));u.mem_write(ch,q(cpu)+q(cpu))
    model={'status':opt.get('status',0x0010e800),'address':0x03ffffc0,'go':0,'poll':0,'waiting':False}
    regs=dict(REGS);regs.update(opt.get('registers',{}));reads=[];writes=[];logs=[];calls=[];maps=0;cfgs=0
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v);u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def mmread(uc,access,a,n,value,_):
        assert n==4 and u.reg_read(R.UC_X86_REG_RIP)==NATIVE+0x44c,(name,hex(a),n)
        off=a-MMIO;reads.append(off)
        assert off in regs or off in [4,8] or (0x10<=off<=0x4c and off%4==0)
        if off==4:
            if model['waiting']:
                model['poll']+=1
                if model['poll']>=opt.get('polls',2):model['waiting']=False;model['status']=opt.get('completion_status',0x3f00e801)
            val=model['status']
            if opt.get('hardware_error') and model['go']:val|=2
        elif off==8:val=model['address']
        elif off in regs:val=regs[off]
        else:
            assert model['go'] and not model['waiting'] and model['status']&1
            pos=model['address']+off-0x10;assert 0<=pos<=4092
            val=struct.unpack_from('<I',FLASH,pos)[0]
        u.mem_write(a,d(val))
    def mmwrite(uc,access,a,n,value,_):
        assert n==4 and u.reg_read(R.UC_X86_REG_RIP)==NATIVE+0x4fe,(name,hex(a),n)
        off=a-MMIO;writes.append([off,value]);assert off in [4,8]
        assert not model['waiting']
        if off==8:
            assert value==0x03ffffc0 or (value<4096 and value%64==0)
            model['address']=value
        elif value&0x10000:
            assert value==0x3f01e800 and not model['status']&7
            assert 0<=model['address']<4096 and model['address']%64==0
            model.update(status=opt.get('busy_status',0x3f00e820),waiting=True,poll=0,go=model['go']+1)
        else:
            assert value&0xf800==model['status']&0xf800==0xe800
            assert value&0xc0e00000==0 and ((value>>17)&15)<=8
            model['status']=(value&0xffff0000)|(model['status']&0xfff8)|((model['status']&7)&~(value&7))
    u.hook_add(U.UC_HOOK_MEM_READ,mmread,begin=MMIO,end=MMIO+0xfff)
    u.hook_add(U.UC_HOOK_MEM_WRITE,mmwrite,begin=MMIO,end=MMIO+0xfff)
    def code(uc,a,n,_):
        nonlocal maps,cfgs
        if a==STOP:uc.emu_stop();return
        if a==symbols['kvm_present']:
            text=bytes(u.mem_read(u.reg_read(R.UC_X86_REG_RDX),u.reg_read(R.UC_X86_REG_R8)))
            logs.append(text);ret(0);return
        assert STOP+0x100<=a<=STOP+0x190,(name,hex(a))
        x,y,z,w=[u.reg_read(reg) for reg in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        fifth=rq(u.reg_read(R.UC_X86_REG_RSP)+0x28)
        if a==STOP+0x100:
            maps+=1;calls.append('GetMemoryMap')
            if maps==opt.get('map_fail_at'):ret(ERR(5));return
            desc=[]
            def md(typ,start,pages,attr=0):desc.append(struct.pack('<IIQQQQ',typ,0,start,0,pages,attr))
            md(4,HEAP,0x20);md(3,STOP,1);md(opt.get('native_memory_type',3),NATIVE,0x10)
            if not opt.get('no_mmio_map'):md(opt.get('mmio_type',11),MMIO,opt.get('mmio_pages',1),opt.get('mmio_attributes',0x8000000000000001))
            if opt.get('duplicate_mmio_map'):md(11,MMIO,1,0x8000000000000001)
            blob=b''.join(desc);u.mem_write(y,blob);u.mem_write(x,q(len(blob)));u.mem_write(z,q(1));u.mem_write(w,q(opt.get('map_stride',40)));u.mem_write(fifth,d(opt.get('map_version',1)));ret(0)
        elif a==STOP+0x110:
            assert x==2;guid=bytes(u.mem_read(y,16))
            if guid==uuid.UUID('4cf5b200-68b8-4ca5-9eec-b23e3f50029a').bytes_le:
                calls.append('EnumeratePCI');u.mem_write(w,q(opt.get('pci_count',1)));u.mem_write(fifth,q(ph));ret(0)
            else:
                assert guid==uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le
                calls.append('EnumerateCPU');u.mem_write(w,q(opt.get('cpu_count',1)));u.mem_write(fifth,q(ch));ret(0)
        elif a==STOP+0x120:
            assert x in [pci,cpu];u.mem_write(z,q(x));ret(0)
        elif a==STOP+0x130:assert x in [ph,ch];ret(0)
        elif a==STOP+0x140:
            cfgs+=1;assert x==pci and y==2 and w==1 and z in [0,4,8,0x10,0xdc]
            values={0:opt.get('id',0x7aa48086),4:2,8:opt.get('revclass',0x0c800011),0x10:opt.get('bar',MMIO),0xdc:opt.get('bc',0x100008aa)}
            if opt.get('binding_changes_after_GO') and model['go'] and z==0xdc:values[z]^=1
            u.mem_write(fifth,d(values[z]));ret(0)
        elif a==STOP+0x150:
            assert x==pci
            for ptr,val in zip([y,z,w,fifth],[0,0,31,5]):u.mem_write(ptr,q(val))
            ret(0)
        elif a==STOP+0x170:assert x==y==z==w==0;ret(ERR(3) if opt.get('watchdog_fail') else 0)
        elif a==STOP+0x180:assert x==10;ret(0)
        else:raise AssertionError(('Unapproved Boot Service',hex(a)))
    u.hook_add(U.UC_HOOK_CODE,code,begin=STOP,end=STOP+0xfff)
    u.hook_add(U.UC_HOOK_CODE,code,begin=symbols['kvm_present'],end=symbols['kvm_present'])
    sp=STACK+0x10008;u.mem_write(sp,q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    u.reg_write(R.UC_X86_REG_RCX,1);u.reg_write(R.UC_X86_REG_RDX,st)
    u.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,STOP+1,count=8000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP,name
    assert len(logs)==1,name
    text=logs[0].decode('ascii');status=u.reg_read(R.UC_X86_REG_RAX)
    if opt.get('pass_capture'):
        assert status==0 and model['go']==128
        chunks=re.findall(r'^([0-9A-F]{4}):([0-9A-F]{64})\r?$',text,re.M)
        assert [int(a,16) for a,b in chunks]==list(range(0,4096,32))
        assert b''.join(bytes.fromhex(b) for a,b in chunks)==FLASH
        assert model['address']==0x03ffffc0 and model['status']==0x0010e800
        assert 'DESCRIPTOR_TWO_PASSES_MATCH=YES' in text and 'PROTECTION_SNAPSHOT_UNCHANGED=0x1' in text
    else:
        assert status!=0 and 'DESCRIPTOR_HEX_BEGIN' not in text
        if not opt.get('allow_reads'):assert not reads
        if not opt.get('allow_writes'):assert not writes
        if opt.get('allow_writes'):assert model['go']==1
    assert len(logs[0])<16384
    folder=HERE/'frontend_logs';folder.mkdir(exist_ok=True)
    file=folder/(name+'.txt');file.write_bytes(logs[0])
    return {'name':name,'passed':True,'efi_status':hex(status),'mmio_reads':len(reads),'mmio_writes':len(writes),
            'read_cycles':model['go'],'native_read_instruction':'0x44c','native_write_instruction':'0x4fe',
            'log':str(file),'log_sha256':sha(file),'log_bytes':len(logs[0]),'hardware_access':False}

def main():
    cases=[]
    def add(name,**kw):cases.append(execute(name,**kw))
    add('complete_original_CPU_IO2_path',pass_capture=True)
    add('captured_busy_FGO_native_CPU_IO2',busy_status=0x3f01e820,pass_capture=True)
    add('busy_FGO_native_timeout',busy_status=0x3f01e820,polls=10001,allow_reads=True,allow_writes=True)
    add('native_FGO_idle_refused',completion_status=0x3f01e801,allow_reads=True,allow_writes=True)
    add('native_busy_FGO_error_refused',busy_status=0x3f01e822,allow_reads=True,allow_writes=True)
    for name,kw in [
        ('wrong_board',{'board':'Pro WS W790-ACE'}),('wrong_version',{'version':'2003'}),
        ('duplicate_smbios',{'duplicate_smbios':True}),('bad_checksum',{'bad_checksum':True}),
        ('wrong_did',{'id':0x7a248086}),('wrong_revision',{'revclass':0x0c800012}),('wrong_bar',{'bar':0xfe020000}),
        ('changed_BIOS_CNTL',{'bc':0x100008ab}),('two_PCI_targets',{'pci_count':2}),('two_CPU_protocols',{'cpu_count':2}),
        ('absent_CPU_protocol',{'cpu_count':0}),('null_read_method',{'read_method':0}),('null_write_method',{'write_method':0}),
        ('wrong_write_method',{'write_method':NATIVE+0x534}),('changed_validator',{'native_damage':0x30c}),
        ('changed_read_body',{'native_damage':0x44c}),('changed_write_body',{'native_damage':0x4fe}),('changed_stride_table',{'native_damage':0x750}),
        ('code_in_data',{'native_memory_type':4}),('missing_MMIO_map',{'no_mmio_map':True}),
        ('wrong_MMIO_type',{'mmio_type':4}),('wrong_MMIO_size',{'mmio_pages':2}),('wrong_MMIO_attributes',{'mmio_attributes':1}),
        ('ambiguous_MMIO_map',{'duplicate_mmio_map':True}),('invalid_map_stride',{'map_stride':39}),('invalid_map_version',{'map_version':2}),
        ('initial_map_failure',{'map_fail_at':1}),('CPU_map_failure',{'map_fail_at':2}),('CPU_final_map_failure',{'map_fail_at':3}),
        ('watchdog_failed',{'watchdog_fail':True}),
    ]:add(name,**kw)
    add('global_read_protection_set',registers={0x98:0x8000},allow_reads=True)
    add('preexisting_SPI_error',status=0x0010e802,allow_reads=True)
    add('error_after_actual_GO',hardware_error=True,allow_reads=True,allow_writes=True)
    add('BIOS_control_changes_mid_capture',binding_changes_after_GO=True,allow_reads=True,allow_writes=True)
    report={'status':'PASS_COMPLETE_EFI_AND_ORIGINAL_CPU_IO2_SYNTHETIC_ONLY','case_count':len(cases),'cases':cases,
            'efi_sha256':sha(efi),'native_cpuio2_sha256':sha(native),'verification_source_sha256':sha(Path(__file__)),
            'actual_native_CPU_IO2_DWORD_read_write_executed':True,'physical_hardware_or_host_privileged_execution':False,
            'limits':['UEFI/PCI publication and SPI register states are modeled; no physical pass is inferred.',
                      'KVM display is intercepted after the full ASCII log is produced; QR codec/display requires its separate fixture.']}
    (HERE/'frontend_regression.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['status','case_count','efi_sha256']}))
if __name__=='__main__':main()
