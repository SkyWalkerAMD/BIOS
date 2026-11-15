"""Execute compiled transport service boundaries with explicit UEFI/QR models."""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7];BUILD=HERE/'transport_boundary_build'
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,unicorn as U
from unicorn import x86_const as R
BASE=0x140000000;DATA=0x60000000;PIXELS=0x61000000;STACK=0x70000000;STOP=0x50000000
q=lambda n:struct.pack('<Q',n);d=lambda n:struct.pack('<I',n);ERR=lambda n:(1<<63)|n
pe=pefile.PE(str(BUILD/'TransportBoundary.TESTONLY.efi'))
symbols={name:int(addr,16)-pe.OPTIONAL_HEADER.ImageBase+BASE for name,addr in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',(BUILD/'transport.map').read_text(),re.M)}
NAMES=['out','query','handle','locate','allocate','visible','blt','read','wait','stall','free','attribute','clear']
services={STOP+0x100+i*16:name for i,name in enumerate(NAMES)};service={v:k for k,v in services.items()}

class VM:
 def __init__(self,route='normal',ending=None,latch='ended',return_error=False,qr_model=True):
    self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);self.calls=[];self.cause=None;self.route=route;self.ending=ending;self.latch=latch;self.return_error=return_error;self.reads=0
    for a,n in [(DATA,0x10000),(PIXELS,0x200000),(STACK,0x100000),(STOP,0x2000)]:self.u.mem_map(a,n)
    p=pefile.PE(str(BUILD/'TransportBoundary.TESTONLY.efi'));p.relocate_image(BASE);raw=p.get_memory_mapped_image();self.u.mem_map(BASE,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(BASE,raw)
    for s in p.sections:self.u.mem_protect(BASE+s.VirtualAddress,(max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095,U.UC_PROT_READ|(U.UC_PROT_EXEC if s.Characteristics&0x20000000 else 0)|(U.UC_PROT_WRITE if s.Characteristics&0x80000000 else 0))
    self.bs=DATA+0x1000;self.text=DATA+0x2000;self.input=DATA+0x3000;self.gop=DATA+0x4000;self.mode=DATA+0x5000;self.info=DATA+0x6000
    for off,v in [(0x30,self.input),(0x40,self.text),(0x60,self.bs)]:self.u.mem_write(DATA+off,q(v))
    for off,name in [(0x40,'allocate'),(0x48,'free'),(0x60,'wait'),(0x98,'handle'),(0xf8,'stall'),(0x140,'locate')]:self.u.mem_write(self.bs+off,q(service[name]))
    for off,name in [(8,'out'),(24,'query'),(40,'attribute'),(48,'clear'),(64,'visible')]:self.u.mem_write(self.text+off,q(service[name]))
    self.u.mem_write(self.text+72,q(self.mode+0x100));self.u.mem_write(self.mode+0x100,struct.pack('<5iB',1,0,7,0,0,1))
    self.u.mem_write(self.input+8,q(service['read']));self.u.mem_write(self.input+16,q(0x1234))
    if route=='stall':self.u.mem_write(self.bs+0x60,q(0))
    self.u.mem_write(self.gop+16,q(service['blt']));self.u.mem_write(self.gop+24,q(self.mode));self.u.mem_write(self.mode+8,q(self.info));self.u.mem_write(self.mode+16,q(36));self.u.mem_write(self.info,struct.pack('<9I',0,640,480,0,0,0,0,0,640))
    self.u.hook_add(U.UC_HOOK_CODE,self.external,begin=STOP,end=STOP+0x1fff)
    self.u.hook_add(U.UC_HOOK_CODE,self.hold,begin=symbols['boundary_hold'],end=symbols['boundary_hold'])
    if qr_model:self.u.hook_add(U.UC_HOOK_CODE,self.encode,begin=symbols['kvm_encode_frame'],end=symbols['kvm_encode_frame'])
 def arg(self,n):return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][n])
 def ret(self,value):
    sp=self.u.reg_read(R.UC_X86_REG_RSP);target=struct.unpack('<Q',self.u.mem_read(sp,8))[0];self.u.reg_write(R.UC_X86_REG_RAX,value);self.u.reg_write(R.UC_X86_REG_RIP,target);self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def hold(self,*_):self.cause='hold';self.u.emu_stop()
 def encode(self,*_):self.u.mem_write(self.arg(3),bytes([21])+bytes(60));self.ret(1)
 def external(self,u,a,n,data):
    if a==STOP:self.cause='returned';u.emu_stop();return
    name=services.get(a)
    if not name:raise AssertionError(('unexpected external entry',hex(a)))
    self.calls.append(name);status=0
    if name=='query':u.mem_write(self.arg(2),q(80));u.mem_write(self.arg(3),q(25))
    elif name in ['handle','locate']:
        if name=='handle' and self.route=='locate':status=ERR(14)
        else:u.mem_write(self.arg(2),q(self.gop))
    elif name=='allocate':
        assert self.arg(0)==4 and self.arg(1)==640*480*4
        if self.route=='allocation_failure':status=ERR(9)
        else:u.mem_write(self.arg(2),q(PIXELS))
    elif name=='read':
        self.reads+=1
        if self.route in ['wait','stall'] and self.reads==1:status=ERR(6)
        else:u.mem_write(self.arg(1),struct.pack('<HH',0x17,0))
    elif name=='wait':u.mem_write(self.arg(2),q(0))
    elif name=='free':assert self.arg(0)==PIXELS
    if self.ending==len(self.calls):
        u.mem_write(symbols['boundary_'+self.latch],d(1))
        if self.return_error:status=ERR(7)
    self.ret(status)
 def run(self):
    payload=b'AITWK-P3-KVM\r\nSAGE_NATIVE13_RAM_TEST05\r\nSNAPSHOT_ID=0000000000000001\r\nLOCAL_FIXTURE_ONLY=YES\r\nLOG_COMPLETE=YES\r\nLOG_OVERFLOW=NO\r\nSAGE_NATIVE13_RAM_TEST05_END\r\n'
    self.u.mem_write(DATA+0x8000,payload);sp=STACK+0xffe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
    for reg,value in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],[DATA,DATA+0x8000,len(payload),0]):self.u.reg_write(reg,value)
    self.u.emu_start(symbols['kvm_present'],0,count=100000000)
    assert self.cause in ['hold','returned'],'instruction bound exceeded'
    return self.u.reg_read(R.UC_X86_REG_RAX)

def main():
 checks=[];routes={}
 for route in ['normal','locate','allocation_failure','wait','stall']:
    vm=VM(route);assert vm.run()==0 and vm.cause=='returned';routes[route]=list(vm.calls);checks.append(route+' ordinary return')
    for index,name in enumerate(vm.calls,1):
        x=VM(route,ending=index,return_error=index%2==0);x.run();assert x.cause=='hold' and len(x.calls)==index
        checks.append(f'{route} boundary {index} {name}: ending stops before another firmware call')
 for latch in ['ended','held']:
    vm=VM();vm.u.mem_write(symbols['boundary_'+latch],d(1));vm.run();assert vm.cause=='hold' and not vm.calls;checks.append(latch+' preexisting latch stops before first service')
    vm=VM(ending=1,latch=latch);vm.run();assert vm.cause=='hold' and vm.calls==['out'];checks.append(latch+' set at service stops before next output chunk')
 vm=VM(qr_model=False);assert vm.run()==0 and vm.cause=='returned';checks.append('actual compiled QR encoder path also returns normally through all guarded services')
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 report={'status':'PASS_ACTUAL_TRANSPORT_PE_ENDING_BOUNDARIES_WITH_SERVICE_MODELS','checks':len(checks),'labels':checks,'routes':routes,'source_sha256':sha(HERE.parent/'ram_transaction05/source/transport/kvm.c'),'test_efi_sha256':sha(BUILD/'TransportBoundary.TESTONLY.efi'),'test_source_sha256':sha(Path(__file__)),'build_sha256':sha(BUILD/'build.json'),'substitutions':['UEFI service implementations and ending/held latch are explicit fixtures.','Boundary matrix replaces only QR encoder result to accelerate repeated pixel rendering; one normal case executes actual compiled encoder.','No ASUS native GUI, KVM network, physical device or firmware flash is exercised.'],'post_ending_firmware_calls':0}
 (HERE/'transport_boundary_result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'source_sha256':report['source_sha256']}))

if __name__=='__main__':main()
