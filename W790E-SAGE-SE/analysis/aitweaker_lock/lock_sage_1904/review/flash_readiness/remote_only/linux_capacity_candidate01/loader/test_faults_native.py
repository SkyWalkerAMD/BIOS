"""Execute compiled bootstrap x64 instructions with synthetic EFI failures.

Complements real OVMF tests. No target firmware/host kernel is executed.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
from build_loader import OUT,ROOT,sha
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
B=0x1000000;S=0x2000000;D=0x3000000;T=0x4000000;H=0x5000000
ERR=lambda n:0x8000000000000000|n
G=lambda s:uuid.UUID(s).bytes_le
LI=G('5b1b31a1-9562-11d2-8e3f-00a0c969723b');FS=G('964e5b22-6459-11d2-8e39-00a0c969723b');DP=G('09576e91-6d3f-11d2-8e39-00a0c969723b')
SEED=G('1ce1e5bc-7ceb-42f2-81e5-8aadf180f57b');FI=G('09576e92-6d3f-11d2-8e39-00a0c969723b');FSI=G('09576e93-6d3f-11d2-8e39-00a0c969723b')
def filepath(s):
    b=(s+'\0').encode('utf-16-le');return bytes([4,4])+(4+len(b)).to_bytes(2,'little')+b+b'\x7f\xff\x04\0'
class Machine:
    def __init__(self,case):
        self.case=case;self.calls=[];self.output='';self.heap=H;self.allocs=[];self.starts=0;self.reads=0;self.queries=0;self.stopped=False
        fixture=OUT/'tests/fixture';self.binary=fixture/'loader/BOOTX64.EFI'
        pe=pefile.PE(str(self.binary));pe.relocate_image(B);image=pe.get_memory_mapped_image();self.entry=B+pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.uc=Uc(UC_ARCH_X86,UC_MODE_64);self.uc.mem_map(B,(len(image)+4095)&~4095);self.uc.mem_write(B,image)
        for a,n in [(S,0x10000),(D,0x20000),(T,0x200000),(H,0x2000000)]:self.uc.mem_map(a,n)
        self.callbacks={};self.uc.hook_add(UC_HOOK_CODE,self.hook)
        self.files={D+0x6000:(fixture/'VMFIXTURE.EFI').read_bytes(),D+0x7000:(fixture/'NOT-AN-INITRAMFS.fixture').read_bytes()};self.pos={p:0 for p in self.files}
        self.w64(D+0x40,D+0x3000);self.w64(D+0x58,D+0xa000);self.w64(D+0x60,D+0x1000)
        self.w64(D+0x3010,0);self.w64(D+0x3008,self.stub('OutputString',self.out))
        for off,name,fn in [(0x40,'AllocatePool',self.alloc),(0x48,'FreePool',lambda a:0),(0x98,'HandleProtocol',self.handle),(0xb8,'LocateDevicePath',self.locate),(0x80,'InstallProtocolInterface',self.install),(0xc8,'LoadImage',self.load),(0xd0,'StartImage',self.start),(0xf8,'Stall',self.stall),(0x100,'SetWatchdogTimer',self.watchdog)]:self.w64(D+0x1000+off,self.stub(name,fn))
        # Every unused boot-service and every write-capable runtime entry traps.
        for off in range(0x18,0x178,8):
            if not self.r64(D+0x1000+off):self.w64(D+0x1000+off,self.stub('FORBIDDEN_BS_'+hex(off),self.forbidden))
        self.w64(D+0xa048,self.stub('GetVariable',self.getvar));self.w64(D+0xa058,self.stub('FORBIDDEN_SetVariable',self.forbidden))
        self.w64(D+0x2018,0x222);self.w64(D+0x2020,D+0x8000)
        self.uc.mem_write(D+0x8000,filepath('\\EFI\\BOOT\\BOOTX64.EFI' if case!='bad_loader_path' else '\\OTHER.EFI'))
        self.uc.mem_write(D+0x8100,filepath('\\LINUX\\VMLINUX.EFI' if case!='bad_child_path' else '\\OTHER.EFI'))
        self.uc.mem_write(D+0x8200,bytes.fromhex('01010600001f7fff0400') if case!='malformed_device_path' else bytes.fromhex('01010000001f7fff0400'))
        self.w64(D+0x4008,self.stub('OpenVolume',self.volume))
        for p in [D+0x5000,D+0x6000,D+0x7000]:
            self.w64(p+8,self.stub('FileOpen',self.open));self.w64(p+0x10,self.stub('FileClose',self.close));self.w64(p+0x20,self.stub('FileRead',self.read));self.w64(p+0x40,self.stub('FileGetInfo',self.info))
            for off in [0x18,0x28,0x48,0x50]:self.w64(p+off,self.stub('FORBIDDEN_FILE_'+hex(off),self.forbidden))
        self.w64(D+0x9008,0x111);self.w64(D+0x9018,0x555 if case=='child_device_mismatch' else 0x222);self.w64(D+0x9020,D+0x8100)
        sp=T+0x1fe008;self.w64(sp,S+0xff00);self.uc.reg_write(UC_X86_REG_RSP,sp);self.uc.reg_write(UC_X86_REG_RCX,0x111);self.uc.reg_write(UC_X86_REG_RDX,D)
    def w64(self,a,v):self.uc.mem_write(a,struct.pack('<Q',v))
    def r64(self,a):return struct.unpack('<Q',self.uc.mem_read(a,8))[0]
    def c16(self,a):
        out=[]
        for i in range(2048):
            v=struct.unpack('<H',self.uc.mem_read(a+2*i,2))[0]
            if not v:return ''.join(out)
            out.append(chr(v))
        raise AssertionError('unterminated string')
    def args(self):return [self.uc.reg_read(r) for r in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]]+[self.r64(self.uc.reg_read(UC_X86_REG_RSP)+40),self.r64(self.uc.reg_read(UC_X86_REG_RSP)+48)]
    def stub(self,name,fn):
        p=S+0x100+len(self.callbacks)*16;self.callbacks[p]=(name,fn);self.uc.mem_write(p,b'\xc3');return p
    def hook(self,uc,p,n,_):
        if p in self.callbacks:
            name,fn=self.callbacks[p];assert uc.reg_read(UC_X86_REG_RSP)%16==8,(name,'ABI stack alignment');self.calls.append(name);value=fn(self.args());uc.reg_write(UC_X86_REG_RAX,value or 0)
    def forbidden(self,a):raise AssertionError('forbidden service called: '+self.calls[-1])
    def out(self,a):self.output+=self.c16(a[1]);return 0
    def watchdog(self,a):assert a[:4]==[0,0,0,0];return ERR(7) if self.case=='watchdog_error' else 0
    def getvar(self,a):
        assert self.c16(a[0])=='RandomSeed' and bytes(self.uc.mem_read(a[1],16))==SEED and a[2]==0 and self.r64(a[3])==0 and a[4]==0
        self.queries+=1;return ERR(14)
    def handle(self,a):
        guid=bytes(self.uc.mem_read(a[1],16));key=(a[0],guid)
        values={(0x111,LI):D+0x2000,(0x222,FS):D+0x4000,(0x222,DP):D+0x8200,(0x333,LI):D+0x9000}
        if self.case=='no_own_fs' and key==(0x222,FS):return ERR(14)
        if key not in values:raise AssertionError(('unexpected device/protocol',key))
        self.w64(a[2],values[key]);return 0
    def volume(self,a):
        assert a[0]==D+0x4000
        if self.case=='open_volume_error':return ERR(7)
        self.w64(a[1],D+0x5000);return 0
    def open(self,a):
        assert a[0]==D+0x5000 and a[3]==1 and a[4]==0,'non-read open'
        names={'\\LINUX\\VMLINUX.EFI':D+0x6000,'\\LINUX\\CAPACITY01.IMG':D+0x7000};name=self.c16(a[2]);assert name in names
        self.w64(a[1],names[name]);return 0
    def close(self,a):return ERR(7) if self.case=='file_close_error' and a[0]==D+0x6000 else 0
    def info(self,a):
        p,guid,n,buf=a[:4];g=bytes(self.uc.mem_read(guid,16));size=96
        if p==D+0x5000:
            assert g==FSI
            if self.case=='filesystem_info_error':return ERR(7)
            data=bytearray(40);struct.pack_into('<Q',data,0,40);data[8]=1;size=40
        else:
            assert g==FI
            if self.case=='payload_info_error':return ERR(7)
            data=bytearray(size);struct.pack_into('<QQ',data,0,size,len(self.files[p]));struct.pack_into('<Q',data,72,16 if self.case=='payload_is_directory' else 0)
            if self.case=='payload_info_corrupt':struct.pack_into('<Q',data,0,0xffff)
        assert self.r64(n)>=size;self.w64(n,size);self.uc.mem_write(buf,bytes(data));return 0
    def read(self,a):
        p,n,buf=a[:3];want=self.r64(n);self.reads+=1
        if self.case=='payload_read_error':return ERR(7)
        data=self.files[p][self.pos[p]:self.pos[p]+want]
        if self.case=='payload_read_short' and data:data=data[:-1]
        if self.case=='unexpected_extra_byte' and not data:data=b'!'
        self.uc.mem_write(buf,data);self.pos[p]+=len(data);self.w64(n,len(data));return 0
    def alloc(self,a):
        assert a[0]==2 and 0<a[1]<=64*1024*1024
        if self.case=='allocation_error':return ERR(9)
        p=self.heap+16;self.heap+=((a[1]+32+4095)//4096)*4096;self.uc.mem_write(p-16,b'A'*16);self.uc.mem_write(p+a[1],b'Z'*16);self.allocs.append((p,a[1]));self.w64(a[2],p);return 0
    def locate(self,a):
        if self.case=='initrd_provider_collision':self.w64(a[2],0x444);return 0
        return ERR(14)
    def install(self,a):
        assert a[2]==0
        if self.case=='install_protocol_error':return ERR(9)
        if not self.r64(a[0]):self.w64(a[0],0x444)
        return 0
    def load(self,a):
        assert a[0]==0 and a[1]==0x111 and a[4]==len(self.files[D+0x6000])
        assert bytes(self.uc.mem_read(a[3],a[4]))==self.files[D+0x6000],'kernel buffer changed'
        if self.case=='kernel_load_failure':return ERR(26)
        self.w64(a[5],0x333);return 0
    def start(self,a):
        assert a[0]==0x333;self.starts+=1
        opts=self.r64(D+0x9038);n=struct.unpack('<I',self.uc.mem_read(D+0x9030,4))[0]
        assert bytes(self.uc.mem_read(opts,n))==('fixture_exact_commandline=LC01 no_fallback=1\0').encode('utf-16-le')
        return ERR(7) if self.case=='kernel_start_failure' else 0
    def stall(self,a):
        assert a[0]==100000 and 'LC01_BOOT_STOP' in self.output and 'Use BMC power off' in self.output
        self.stopped=True;self.uc.emu_stop();return 0
    def run(self):
        self.uc.emu_start(self.entry,S+0xff00,count=20000000)
        assert self.stopped,'entry returned or instruction limit reached'
        for p,n in self.allocs:assert bytes(self.uc.mem_read(p-16,16))==b'A'*16 and bytes(self.uc.mem_read(p+n,16))==b'Z'*16
        assert self.starts==(1 if self.case in ['kernel_returned','kernel_start_failure'] else 0)
        return {'case':self.case,'passed':True,'stop':self.output.split('LC01_BOOT_STOP ')[1].split('\r\n')[0],'StartImage_calls':self.starts,'RandomSeed_size_queries':self.queries,'read_only_file_open_enforced':True,'allocation_canaries_intact':True,'forbidden_service_calls':0,'services_executed':len(self.calls)}
def main():
    cases=['watchdog_error','bad_loader_path','no_own_fs','open_volume_error','filesystem_info_error','payload_info_error','payload_info_corrupt','payload_is_directory','allocation_error','payload_read_error','payload_read_short','unexpected_extra_byte','file_close_error','malformed_device_path','initrd_provider_collision','install_protocol_error','kernel_load_failure','child_device_mismatch','bad_child_path','kernel_start_failure','kernel_returned']
    results=[]
    for c in cases:results.append(Machine(c).run());print(c,'PASS',flush=True)
    report={'scope':'Compiled fixture-contract bootstrap x64 under Unicorn with controlled EFI services; not full firmware or target hardware','bootstrap_sha256':sha(OUT/'tests/fixture/loader/BOOTX64.EFI'),'cases':results,'all_passed':True};(OUT/'tests/latest_native_fault_results.json').write_text(json.dumps(report,indent=2),encoding='utf8')
if __name__=='__main__':main()
