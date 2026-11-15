"""Run the shipped P3 EFI with the three original BIOS module sets in Unicorn.
UEFI services here are synthetic; QEMU tests cover the real display/keyboard path.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
spec=importlib.util.spec_from_file_location('p2_reference_verify',OUT.parent/'probe_p2/verify.py')
ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RAX,UC_X86_REG_RSP,UC_X86_REG_RIP
import pefile
class Machine(ref.Machine):
    def __init__(self,tag,case):
        super().__init__(tag,case)
        image=pefile.PE(str(OUT/'BOOTX64.EFI'));image.relocate_image(0x100000)
        assert image.OPTIONAL_HEADER.SizeOfImage<=0x100000
        self.u.mem_write(0x100000,image.get_memory_mapped_image());self.entry=0x100000+image.OPTIONAL_HEADER.AddressOfEntryPoint
        self.stub(self.bs+0x100,'Watchdog');self.keys=[ord('n'),ord('p'),27]
        self.input=0x710000;self.mode=0x711000
        self.w64(self.st+0x30,0 if case=='no_keyboard' else self.input)
        self.stub(self.input+8,'ReadKey')
        self.u.mem_write(self.mode,struct.pack('<iiiiiB',1,0,7,0,0,1));self.w64(self.console+72,self.mode)
        for off,name in ((24,'QueryText'),(40,'TextAttribute'),(48,'ClearText'),(64,'VisibleText')):self.stub(self.console+off,name)
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        assert name not in ('OpenVolume','OpenFile','ReadMarker','WriteLog','FlushLog','CloseFile'),name
        if name not in ('Watchdog','ReadKey','QueryText','TextAttribute','ClearText','VisibleText'):
            return super().hook(u,addr,size,user)
        self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);assert sp%16==8
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];ret=0
        if name=='Watchdog':
            assert (a,b,c,d)==(0,0,0,0)
            if self.case=='watchdog_error':ret=ref.ERR(3)
        elif name=='ReadKey':
            if self.case=='keyboard_error':ret=ref.ERR(7)
            else:
                assert self.keys,'Unexpected endless UI loop'
                self.u.mem_write(b,struct.pack('<HH',0,self.keys.pop(0)))
        elif name=='QueryText':self.w64(c,80);self.w64(d,25)
        u.reg_write(UC_X86_REG_RAX,ret)
    def check(self):
        self.u.reg_write(UC_X86_REG_RSP,0xefff08);self.w64(0xefff08,0x8ff000)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        self.u.emu_start(self.entry,0x8ff000,count=250000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'execution limit'
        ret=self.u.reg_read(UC_X86_REG_RAX)
        assert ret==({'no_keyboard':ref.ERR(3),'keyboard_error':ref.ERR(7)}.get(self.case,0)),hex(ret)
        for base,data in self.module_images.values():assert bytes(self.u.mem_read(base,len(data)))==data
        for a,n in self.allocations.items():
            assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16 and bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        assert not self.created and not self.log
        log=b''
        if self.case!='no_keyboard':
            log=self.output.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode('ascii')
            assert log.startswith(b'AITWEAKER-PROBE-P3-KVM\r\n') and log.endswith(b'PROBE_COMPLETE\r\n')
            assert (b'COLLECTION_STATUS=COMPLETE\r\n' if self.case in ('normal','keyboard_error') else b'COLLECTION_STATUS=PARTIAL\r\n') in log
            if self.case=='normal':
                for name in ('AMITSE','Setup'):assert (self.tag+'/'+name).encode() in log
                (OUT/'capture_tests'/f'MOCK-{self.tag}.txt').write_bytes(b'SYNTHETIC SERVICES - NOT A PHYSICAL BOARD LOG\r\n'+log)
        return {'board':self.tag,'case':self.case,'passed':True,'bytes':len(log),'firmware_memory_unchanged':True,'filesystem_calls':0,'runtime_services_calls':0}
def main():
    (OUT/'capture_tests').mkdir(exist_ok=True);results=[]
    cases=('normal','no_protocols','no_modules','malformed_hii','allocation_failure','unknown_build','watchdog_error','no_keyboard','keyboard_error')
    for tag in ref.TAGS:
        for case in cases:
            results.append(Machine(tag,case).check());print(tag,case,'PASS',flush=True)
    result={'passed':True,'count':len(results),'cases':results,'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),
      'scope':'original ASUS modules with synthetic UEFI services; no physical board validation'}
    (OUT/'inventory_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
if __name__=='__main__':main()
