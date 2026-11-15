"""Execute the shipped EFI bytes in Unicorn with synthetic EFI/PCI/KCS devices.

No host firmware, devices or networking are accessed. A pass verifies bounded
software behavior, not operation on HERO hardware or the experimental CAP.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_probe'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
ERR=lambda n: 0x8000000000000000|n
P64=lambda v:struct.pack('<Q',v)

class Device:
    def __init__(self,case):
        self.case=case; self.state=0; self.obf=False; self.end=False
        self.tx=[]; self.rx=b''; self.pos=0; self.writes=[]; self.packets=[]; self.delays=0
    def response(self,tx):
        self.packets.append(bytes(tx))
        netfn,cmd=tx[0]>>2,tx[1]
        assert (netfn,cmd) in ((6,1),(10,32),(10,35),(4,45)),('unapproved command',tx)
        prefix=bytes([(netfn+1)<<2,cmd,0])
        if self.case=='bad_header': return b'\0\0\0'
        if self.case=='nonzero_completion': return prefix[:2]+b'\xc1'
        if self.case=='oversize_response': return prefix+bytes(400)
        if (netfn,cmd)==(6,1): return prefix+bytes.fromhex('20 01 01 13 02 00 57 01 00 34 12')
        if (netfn,cmd)==(10,32):
            return prefix+bytes.fromhex('51 00 00 ff ff 00 00 00 00 00 00 00 00 00') if self.case=='empty_sdr' else prefix+bytes.fromhex('51 01 00 ff ff 00 00 00 00 00 00 00 00 00')
        if (netfn,cmd)==(10,35):
            assert tx[2:]==[0,0,0,0,0,255]
            body=bytearray(47); body[0]=0x20; body[2]=1; body[7]=1; body[42]=0xc4; body[43:]=b'TEST'
            record=struct.pack('<HBBB',7,0x51,1,len(body))+body
            if self.case=='malformed_sdr': record=record[:-2]
            return prefix+b'\xff\xff'+record
        if (netfn,cmd)==(4,45):
            assert tx[2:]==[1]
            return prefix+bytes([42,0x20 if self.case=='reading_unavailable' else 0xc0,0])
        raise AssertionError(tx)
    def read(self,reg):
        if reg:
            if self.case=='busy' and not self.writes: return 0x82
            if self.case=='status_ff': return 255
            if self.case=='timeout' and self.writes: return 0x82
            return self.state | int(self.obf)
        assert self.obf,('read data with OBF clear',self.state)
        self.obf=False
        return self.rx[self.pos] if self.state==0x40 else 0
    def write(self,reg,value):
        self.writes.append((reg,value))
        if reg:
            if value==0x61:
                assert self.state==0 and not self.obf
                self.state=0x80;self.obf=True;self.end=False;self.tx=[]
            elif value==0x62:
                assert self.state==0x80 and not self.obf
                self.end=True;self.obf=True
            else: raise AssertionError(('unexpected KCS command',value))
        elif self.state==0x80:
            assert not self.obf
            self.tx.append(value)
            if self.end:
                self.rx=self.response(self.tx);self.pos=0;self.state=0x40;self.obf=True
            else:self.obf=True
        else:
            assert self.state==0x40 and not self.obf and value==0x68
            self.pos+=1
            if self.pos==len(self.rx):
                self.state=0;self.obf=self.case!='no_final_dummy'
            else:self.obf=True

class Machine:
    def __init__(self,case='normal'):
        self.case=case;self.dev=Device(case);self.u=Uc(UC_ARCH_X86,UC_MODE_64)
        self.u.mem_map(0x100000,0x100000)
        self.u.mem_map(0x600000,0x300000)
        self.u.mem_map(0xd00000,0x200000)
        p=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'))
        self.entry=0x100000+p.OPTIONAL_HEADER.AddressOfEntryPoint
        p.relocate_image(0x100000);self.u.mem_write(0x100000,p.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'probe.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+(\w+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        self.heap=0x600000;self.stubs={};self.next_stub=0x800000
        self.output='';self.log=bytearray();self.opened=[];self.calls=[];self.freed=[]
        self.keys=list('PRQQ' if case=='uppercase_keys' else 'prqq');self.guard=[]
        self.st=0x700000;self.bs=0x701000;self.rt=0x702000;self.textout=0x703000
        self.textin=0x704000;self.pci=0x705000;self.loaded=0x706000;self.fs=0x707000
        self.root=0x708000;self.tag=0x709000;self.file=0x70a000;self.existing=0x70b000
        self.w64(self.st,0x5453595320494249)
        for off,addr in ((0x58,self.rt),(0x60,self.bs),(0x30,self.textin),(0x40,self.textout)):
            self.w64(self.st+off,addr)
        for off in range(0x18,0x178,8):self.stub(self.bs+off,'FORBIDDEN_BS_'+hex(off))
        for off,name in ((0x48,'FreePool'),(0x60,'WaitEvent'),(0x98,'HandleProtocol'),(0xf8,'Stall'),
                         (0x100,'Watchdog'),(0x138,'LocateHandles'),(0x140,'LocateProtocol')):
            self.stub(self.bs+off,name)
        for off in range(0x18,0x90,8):self.stub(self.rt+off,'FORBIDDEN_RT_'+hex(off))
        self.stub(self.rt+0x18,'GetTime');self.stub(self.rt+0x48,'GetVariable')
        self.stub(self.textout+8,'Output');self.stub(self.textin+8,'ReadKey')
        self.stub(self.pci+0x10,'MemRead');self.stub(self.pci+0x18,'MemWrite')
        self.stub(self.pci+0x30,'PciRead');self.stub(self.pci+0x38,'FORBIDDEN_PCI_WRITE')
        self.stub(self.pci+0x70,'Location');self.stub(self.pci+0x80,'BarAttributes')
        self.w64(self.loaded+0x18,0x4444)
        self.stub(self.fs+8,'OpenVolume')
        for ptr in (self.root,self.tag,self.file,self.existing):self.stub(ptr+0x10,'CloseFile')
        self.stub(self.root+8,'OpenFile');self.stub(self.tag+0x20,'ReadFile')
        self.stub(self.file+0x28,'WriteFile');self.stub(self.file+0x50,'FlushFile')
        config=bytearray(64);config[:4]=bytes.fromhex('031a0224');config[4]=6;config[8]=1
        struct.pack_into('<I',config,20,0x90000000)
        if case=='decode_disabled':config[4]=0
        if case=='revision_not_ready':config[8]=0
        if case=='bar0_64bit':config[16]=4
        self.config=bytes(config)
        board='OTHER BOARD' if case=='wrong_board' else 'ROG MAXIMUS Z790 HERO'
        sm=bytearray(24);sm[:2]=bytes([0,24]);sm[5]=1
        sm+=b'3001\0\0'
        r=bytearray(15);r[:2]=bytes([2,15]);r[5]=1
        sm+=r+board.encode()+b'\0\0'+bytes.fromhex('7f04ffff0000')
        smptr=self.alloc(sm)
        ep=bytearray(24);ep[:5]=b'_SM3_';ep[6:9]=bytes([24,3,2]);ep[10]=1
        struct.pack_into('<IQ',ep,12,len(sm),smptr);ep[5]=(-sum(ep))&255
        epptr=self.alloc(ep)
        table=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+P64(epptr))
        self.w64(self.st+0x68,1);self.w64(self.st+0x70,table)
        self.u.hook_add(UC_HOOK_CODE,self.hook)
    def alloc(self,data):
        a=self.heap+16;self.heap+=(len(data)+47)&~15
        self.u.mem_write(a-16,b'\xa5'*16+bytes(data)+b'\xa5'*16)
        self.guard.append((a,len(data)));return a
    def w64(self,a,v):self.u.mem_write(a,P64(v))
    def r64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
    def wide(self,a):
        out=[]
        for i in range(4096):
            c=struct.unpack('<H',self.u.mem_read(a+2*i,2))[0]
            if not c:return ''.join(out)
            out.append(chr(c))
        raise AssertionError('unterminated wide string')
    def stub(self,slot,name):
        a=self.next_stub;self.next_stub+=16
        self.w64(slot,a);self.stubs[a]=name;self.u.mem_write(a,b'\xc3')
    def hook(self,uc,addr,size,user):
        if addr not in self.stubs:return
        name=self.stubs[addr];rsp=uc.reg_read(UC_X86_REG_RSP)
        assert rsp%16==8,(name,'stack alignment',hex(rsp))
        a,b,c,d=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f,g,h=[self.r64(rsp+off) for off in (0x28,0x30,0x38,0x40)]
        result=0;self.calls.append(name)
        assert not name.startswith('FORBIDDEN'),name
        if name=='Output':self.output+=self.wide(b)
        elif name=='ReadKey':
            assert self.keys, 'unbounded key loop'
            self.u.mem_write(b,struct.pack('<HH',0,ord(self.keys.pop(0))))
        elif name=='WaitEvent':raise AssertionError('unexpected wait with keys available')
        elif name=='GetTime':self.u.mem_write(a,struct.pack('<H6BIh2B',2026,9,20,12,34,56,0,0,2047,0,0))
        elif name=='GetVariable':
            assert self.wide(a)=='SecureBoot';assert self.r64(d)==1
            self.u.mem_write(e,b'\0')
        elif name=='Watchdog':assert a==0 and b==0 and c==0 and d==0
        elif name=='HandleProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(self.u.mem_read(b,16))))
            p={'5b1b31a1-9562-11d2-8e3f-00a0c969723b':self.loaded,
               '964e5b22-6459-11d2-8e39-00a0c969723b':self.fs,
               '4cf5b200-68b8-4ca5-9eec-b23e3f50029a':self.pci}.get(guid)
            if p:self.w64(c,p)
            else:result=ERR(14)
        elif name=='LocateProtocol':result=ERR(14)
        elif name=='LocateHandles':
            if self.case=='no_card':result=ERR(14)
            else:self.w64(d,1);self.w64(e,self.alloc(P64(0x5555)))
        elif name=='FreePool':self.freed.append(a)
        elif name=='PciRead':
            assert a==self.pci and b==0 and c==0 and d==64
            self.u.mem_write(e,self.config)
        elif name=='Location':
            for ptr,v in ((b,0),(c,2),(d,0),(e,0)):self.w64(ptr,v)
        elif name=='BarAttributes':
            assert a==self.pci and (b&255)==1
            desc=bytearray(46);desc[0]=0x8a;desc[1]=43
            struct.pack_into('<Q',desc,14,0x90000000)
            struct.pack_into('<Q',desc,38,0x10000 if self.case!='short_bar' else 0x100)
            self.w64(c,0);self.w64(d,self.alloc(desc))
        elif name in ('MemRead','MemWrite'):
            assert a==self.pci and (b&0xffffffff)==0 and (c&255)==1 and d in (0xe88,0xe8c) and e==1
            if self.case=='pci_io_failure':result=ERR(7)
            elif name=='MemRead':self.u.mem_write(f,bytes([self.dev.read(d==0xe8c)]))
            else:self.dev.write(d==0xe8c,self.u.mem_read(f,1)[0])
        elif name=='Stall':assert a==1000;self.dev.delays+=1
        elif name=='OpenVolume':self.w64(b,self.root)
        elif name=='OpenFile':
            path=self.wide(c)
            if path=='\\HERO-PROBE-USB.TAG':
                if self.case=='no_marker':result=ERR(14)
                else:self.w64(b,self.tag)
            elif d==1:
                if self.case=='existing_log' and path=='\\HEROIPMI-000.TXT':self.w64(b,self.existing)
                else:result=ERR(14)
            else:
                assert d==0x8000000000000003 and e==0
                assert path==('\\HEROIPMI-001.TXT' if self.case=='existing_log' else '\\HEROIPMI-000.TXT')
                self.opened.append(path);self.w64(b,self.file)
        elif name=='ReadFile':
            marker=b'HERO-IPMI-PROBE-A1\r\n';self.w64(b,len(marker));self.u.mem_write(c,marker)
        elif name=='WriteFile':
            if self.case=='log_failure':result=ERR(7)
            else:self.log+=bytes(self.u.mem_read(c,self.r64(b)))
        elif name in ('FlushFile','CloseFile'):pass
        else:raise AssertionError(name)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):
            uc.reg_write(reg,0xcccccccccccccccc)
        for reg in (UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3,UC_X86_REG_XMM4,UC_X86_REG_XMM5):
            uc.reg_write(reg,0xcccccccccccccccc)
        uc.reg_write(UC_X86_REG_RAX,result)
    def run(self):
        rsp=0xef0000-8;stop=0x8f0000;self.u.mem_write(stop,b'\xcc');self.w64(rsp,stop)
        self.u.reg_write(UC_X86_REG_RSP,rsp)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        saved=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
        for i,r in enumerate(saved):self.u.reg_write(r,0x11110000+i)
        self.u.emu_start(self.entry,stop,count=10000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,('did not return',self.case)
        assert self.u.reg_read(UC_X86_REG_RAX)==0
        assert self.u.reg_read(UC_X86_REG_RSP)==rsp+8
        for i,r in enumerate(saved):assert self.u.reg_read(r)==0x11110000+i
        for a,n in self.guard:
            assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        return self

def main():
    cases=['normal','uppercase_keys','existing_log','no_marker','log_failure','no_card','wrong_board',
        'decode_disabled','revision_not_ready','bar0_64bit','short_bar','busy','status_ff',
        'pci_io_failure','timeout','bad_header','nonzero_completion','oversize_response',
        'empty_sdr','malformed_sdr','reading_unavailable','no_final_dummy']
    results=[]
    for case in cases:
        m=Machine(case).run()
        if case in ('no_card','wrong_board','decode_disabled','revision_not_ready','bar0_64bit','short_bar','busy','status_ff','pci_io_failure'):
            assert not m.dev.writes,(case,m.dev.writes)
        elif case=='timeout':assert m.dev.delays==9999 and len(m.dev.writes)==1
        elif case=='bad_header':assert 'RESPONSE_HEADER_MISMATCH' in m.output and len(m.dev.packets)==1
        elif case=='nonzero_completion':assert 'completion code=0xC1' in m.output and len(m.dev.packets)==1
        elif case=='oversize_response':assert 'RESPONSE_TOO_LARGE' in m.output
        elif case=='empty_sdr':assert 'EMPTY_REPOSITORY' in m.output
        elif case=='malformed_sdr':assert 'Invalid SDR record length' in m.output
        elif case=='reading_unavailable':assert 'READING_UNAVAILABLE' in m.output
        else:assert 'SDR_SCAN_COMPLETE' in m.output and m.output.count('READING_REPORTED')==2
        if case=='no_marker':assert not m.opened and not m.log
        if case not in ('no_marker','log_failure'):assert b'PROBE_END' in m.log
        results.append(dict(case=case,passed=True,kcs_messages=len(m.dev.packets),log_bytes=len(m.log)))
        print(case,'PASS',flush=True)
        if case=='normal':(OUT/'example-MOCK-log.txt').write_bytes(m.log)
    report=dict(scope='SHIPPED_X64_EFI_IN_UNICORN_WITH_SYNTHETIC_EFI_PCI_KCS',
        no_hardware_validation=True,no_CAP_boot_validation=True,
        image_sha256=hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
        scenarios=results,checked=['EFI callback ABI stack alignment and caller-register clobbering',
        'callee-saved integer registers and return stack','guarded mock allocation boundaries',
        'no runtime writes, PCI config writes, driver loading, OEM IPMI, abort/reset or flash services',
        'KCS read/write handshake including omitted final dummy byte',
        'timeouts, completion codes, invalid headers and oversized/truncated responses',
        'target/BAR gating, USB marker and non-overwriting log selection'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('All',len(results),'mock scenarios passed. No target hardware used.')

if __name__=='__main__':main()
