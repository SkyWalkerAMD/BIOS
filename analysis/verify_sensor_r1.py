"""Structural checks and bounded x64 emulation with MOCK EFI/BMC services.

Does not execute firmware on the host CPU, touch host devices or authenticate a
capsule. Mock responses are synthetic and are not evidence of target boot or
sensor correctness. Emulates modified bootstrap and metadata routines, not the
physical KCS/SMBus implementation or the complete UEFI startup environment.
"""
from pathlib import Path
from collections import Counter
import hashlib, json, struct, sys, uuid
from build_sensor_r1 import ROOT, OUT, HERO, DONOR, EXPECTED, BOOTSTRAP, PARAM, TRANSPORT, READY_TO_BOOT, PARAM_PROTO, BMC_READY, PCI_ENUM, assert_ffs
from inventory import inventory
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *

def sha(b): return hashlib.sha256(b).hexdigest()
def p64(v): return struct.pack('<Q',v)
IPMI='4A1D0E66-5271-4E22-83FE-90921B748213'
PCIIO='4CF5B200-68B8-4CA5-9EEC-B23E3F50029A'
ERR=0x800000000000000e

class Mock:
    def __init__(self,card=True,server_setup=None,allocation_failure=False,event_failure=False):
        self.u=Uc(UC_ARCH_X86,UC_MODE_64)
        self.u.mem_map(0x100000,0xf00000)
        self.bases={BOOTSTRAP:0x100000,PARAM:0x200000,TRANSPORT:0x300000}
        for g,base in self.bases.items():
            pe=pefile.PE(data=(OUT/'modules'/g/'patched.efi').read_bytes())
            pe.relocate_image(base)
            self.u.mem_write(base,pe.get_memory_mapped_image())
        self.bs=0x800000; self.rt=0x801000; self.st=0x802000
        self.pci=0x803000; self.ipmi=0x804000
        self.w64(self.st+0x60,self.bs); self.w64(self.st+0x58,self.rt)
        self.protocols={PCIIO:self.pci, PCI_ENUM:0x805000}
        self.events={}; self.next_event=0x880000; self.notifications=[]
        self.callbacks={}; self.next_stub=0x810000
        self.next_heap=0xc00000
        self.card=card; self.server_setup=server_setup
        self.allocation_failure=allocation_failure; self.event_failure=event_failure
        self.var_reads=[]; self.var_writes=[]; self.commands=[]; self.calls=[]
        self.closed=[]; self.guards=[]; self.last_event=None
        for off,name in [(0x40,'AllocatePool'),(0x48,'FreePool'),(0x50,'CreateEvent'),(0x70,'CloseEvent'),
                (0x80,'InstallProtocolInterface'),(0x98,'HandleProtocol'),(0xa8,'RegisterProtocolNotify'),
                (0xf8,'Stall'),(0x138,'LocateHandleBuffer'),(0x140,'LocateProtocol'),
                (0x160,'CopyMem'),(0x168,'SetMem'),(0x170,'CreateEventEx')]:
            self.stub(self.bs+off,name)
        self.stub(self.rt+0x48,'GetVariable');self.stub(self.rt+0x58,'SetVariable')
        self.stub(self.pci+0x30,'PciRead');self.stub(self.pci+0x38,'PciWrite')
        self.stub(self.ipmi+8,'SendIpmi')
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.u.hook_add(UC_HOOK_INSN,lambda uc,port,size,val,user:None,None,1,0,UC_X86_INS_OUT)
        self.u.hook_add(UC_HOOK_INSN,lambda uc,port,size,user:0,None,1,0,UC_X86_INS_IN)
    def w64(self,a,v): self.u.mem_write(a,p64(v))
    def r64(self,a): return struct.unpack('<Q',self.u.mem_read(a,8))[0]
    def guid(self,a): return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(a,16)))).upper()
    def wide(self,a):
        b=b''
        for i in range(200):
            c=bytes(self.u.mem_read(a+i*2,2))
            if c==b'\0\0': return b.decode('utf-16-le')
            b+=c
        raise AssertionError('unterminated variable name')
    def stub(self,slot,name):
        addr=self.next_stub;self.next_stub+=16
        self.callbacks[addr]=name;self.w64(slot,addr);self.u.mem_write(addr,b'\xc3')
    def alloc(self,n):
        a=self.next_heap;self.next_heap+=((n+31)//16+2)*16
        # Deliberately dirty allocation, with guard bytes around the exact extent.
        self.u.mem_write(a,b'\xa5'*(n+32));self.guards.append((a,n))
        return a+16
    def hook(self,uc,address,size,user):
        if address not in self.callbacks: return
        name=self.callbacks[address]
        rsp=uc.reg_read(UC_X86_REG_RSP)
        # At a called EFI function's entry, return address precedes shadow space.
        assert rsp%16==8,(name,hex(rsp))
        args=[uc.reg_read(r) for r in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]]
        args += [self.r64(rsp+x) for x in [0x28,0x30,0x38,0x40]]
        a,b,c,d,e,f,g,h=args
        result=0;self.calls.append(name)
        if name=='AllocatePool':
            if self.allocation_failure:
                result=0x8000000000000009
            else: self.w64(c,self.alloc(b))
        elif name in ('CreateEvent','CreateEventEx'):
            if self.event_failure and name=='CreateEventEx': result=0x8000000000000009
            else:
                ev=self.next_event;self.next_event+=16
                self.events[ev]=dict(type=a,tpl=b,callback=c,context=d,group=self.guid(e) if name=='CreateEventEx' else None)
                self.w64(f if name=='CreateEventEx' else e,ev);self.last_event=ev
        elif name=='CloseEvent':
            self.closed.append(a)
            if a not in self.events: result=0x8000000000000002
        elif name=='RegisterProtocolNotify':
            self.notifications.append((self.guid(a),b));self.w64(c,0x899000)
        elif name=='LocateProtocol':
            guid=self.guid(a)
            if guid in self.protocols:self.w64(c,self.protocols[guid])
            else:result=ERR
        elif name=='InstallProtocolInterface':
            self.protocols[self.guid(b)]=d
            if not self.r64(a): self.w64(a,0x880800)
        elif name=='LocateHandleBuffer':
            assert self.guid(b)==PCIIO
            if self.card:
                handles=self.alloc(8);self.w64(handles,0x880900);self.w64(d,1);self.w64(e,handles)
            else:self.w64(d,0);result=ERR
        elif name=='HandleProtocol':
            assert self.guid(b)==PCIIO
            self.w64(c,self.pci)
        elif name=='PciRead':
            value={0:0x24021a03,8:1,0x14:0xf0000000}.get(c)
            assert value is not None,('unexpected PCI read',hex(c))
            width=1<<b
            uc.mem_write(e,value.to_bytes(width,'little')*d)
        elif name=='PciWrite':
            assert c==4
        elif name=='GetVariable':
            vn=self.wide(a);self.var_reads.append(vn)
            assert vn=='ServerSetup',('unexpected variable read',vn)
            if self.server_setup is None: result=ERR
            else:
                assert self.r64(d)>=len(self.server_setup)
                uc.mem_write(e,self.server_setup);self.w64(d,len(self.server_setup))
        elif name=='SetVariable':
            vn=self.wide(a);self.var_writes.append((vn,c,bytes(uc.mem_read(e,d)).hex()))
            assert vn in ['BmcPresentVar','BmcFanCtrl']
            assert c==6 # BS+RT volatile variables; no NV bit.
        elif name=='SetMem': uc.mem_write(a,bytes([c&255])*b)
        elif name=='CopyMem': uc.mem_write(a,bytes(uc.mem_read(b,c)))
        elif name=='SendIpmi':
            payload=bytes(uc.mem_read(e,f&255))
            self.commands.append(dict(netfn=b&255,command=d&255,payload=payload.hex()))
            # Synthetic successful response; no real BMC is contacted.
            uc.mem_write(g,b'\x00');uc.mem_write(h,b'\x01')
        elif name in ('Stall','FreePool'): pass
        else: raise AssertionError(name)
        # EFI ABI volatile registers are allowed to be destroyed by every call.
        for reg in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11]:
            uc.reg_write(reg,0xaabbccdd)
        uc.reg_write(UC_X86_REG_RAX,result)
    def call(self,g,rva,rcx=0,rdx=None):
        rsp=0xb00000-8;stop=0x8f0000
        self.u.mem_write(rsp,p64(stop)+b'\x00'*0x80)
        self.u.reg_write(UC_X86_REG_RSP,rsp)
        self.u.reg_write(UC_X86_REG_RCX,rcx)
        self.u.reg_write(UC_X86_REG_RDX,self.st if rdx is None else rdx)
        saved=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
        for i,r in enumerate(saved):self.u.reg_write(r,0x600010+i*0x10)
        try:
            self.u.emu_start(self.bases[g]+rva,stop,count=200000)
        except Exception:
            print('EMU FAILURE',g,hex(rva),'RIP',hex(self.u.reg_read(UC_X86_REG_RIP)),
                'RSP',hex(self.u.reg_read(UC_X86_REG_RSP)),'recent calls',self.calls[-12:])
            raise
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,hex(self.u.reg_read(UC_X86_REG_RIP))
        assert self.u.reg_read(UC_X86_REG_RSP)==rsp+8
        for i,r in enumerate(saved):assert self.u.reg_read(r)==0x600010+i*0x10,(g,hex(rva),r)
        for a,n in self.guards:
            assert bytes(self.u.mem_read(a,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(a+16+n,16))==b'\xa5'*16
        return self.u.reg_read(UC_X86_REG_RAX)
    def notify_transport(self):
        self.protocols[IPMI]=self.ipmi
        for guid,ev in list(self.notifications):
            if guid==IPMI and ev not in self.closed:
                cb=self.events[ev]['callback']
                self.call(BOOTSTRAP,cb-self.bases[BOOTSTRAP],ev,0)
    def ready(self):
        ev=next(ev for ev,item in self.events.items() if item['group']==READY_TO_BOOT)
        assert self.events[ev]['tpl']==8
        self.call(BOOTSTRAP,self.events[ev]['callback']-self.bases[BOOTSTRAP],ev,0)

def emulation():
    checks=[]
    for description,ss in [('missing ServerSetup',None),('existing ServerSetup',bytes(615))]:
        m=Mock(server_setup=ss)
        assert m.call(BOOTSTRAP,0x2c0)==0
        assert BMC_READY in m.protocols
        assert m.var_writes==[('BmcPresentVar',6,'01')]
        m.notify_transport()
        ptr=m.protocols[PARAM_PROTO]
        assert bytes(m.u.mem_read(ptr,0x80))==b'\x00'*0x80
        assert m.call(PARAM,0x55c)==0
        metadata=bytes(m.u.mem_read(ptr,0x80))
        assert metadata[:3]==bytes([4,2,1])
        assert metadata[0x1f]==0 and metadata[0x52]==0
        assert list(struct.unpack_from('<5H',metadata,0x26))==[0x25ca,0x25d6,0x25d0,0x2600,0x2614]
        assert metadata[0x32:0x43]==bytes.fromhex('010317191a1b1c1d1e1f20212223242900')
        m.ready()
        assert [(x['netfn'],x['command']) for x in m.commands]==[(0x30,0x90),(0x30,0x94),(0x30,0x92),(0x30,2)]
        assert m.commands[0]['payload']=='80'
        assert m.commands[1]['payload']=='01010301170119011a011b011c011d011e011f01200121012201230124012901'
        assert m.commands[2]['payload']=='0000' and m.commands[3]['payload']=='01'
        assert m.var_reads==['ServerSetup']
        assert m.var_writes==[('BmcPresentVar',6,'01')]
        assert 'PciWrite' not in m.calls # transport itself is not emulated here.
        checks.append(dict(case=description,commands=m.commands,variable_reads=m.var_reads,metadata=metadata.hex()))
    m=Mock(card=False);m.call(BOOTSTRAP,0x2c0)
    assert BMC_READY not in m.protocols and not m.commands
    checks.append(dict(case='card absent',result='No card-ready protocol or sensor commands'))
    m=Mock();m.call(BOOTSTRAP,0x2c0);m.allocation_failure=True;m.notify_transport();m.ready()
    assert PARAM_PROTO not in m.protocols and not m.commands
    checks.append(dict(case='metadata allocation fails',result='ReadyToBoot exits without null dereference or commands'))
    m=Mock();m.call(BOOTSTRAP,0x2c0);m.notify_transport();m.ready()
    assert not m.commands
    checks.append(dict(case='metadata not initialized',result='No sensor commands until parameter driver has initialized metadata'))
    m=Mock();m.call(BOOTSTRAP,0x2c0);m.event_failure=True;m.notify_transport()
    assert not any(e['group']==READY_TO_BOOT for e in m.events.values())
    checks.append(dict(case='CreateEventEx fails',result='No invalid event dereference or sensor commands'))
    return checks

def structure():
    manifest=json.loads((OUT/'manifest.json').read_text())
    path=OUT/manifest['output'];b=path.read_bytes();a=(ROOT/HERO).read_bytes()
    assert sha(b)==manifest['output_sha256']
    for n,h in EXPECTED.items():assert sha((ROOT/n).read_bytes())==h
    start=int(manifest['insertion_start'],16);end=int(manifest['insertion_end_exclusive'],16)
    assert len(a)==len(b) and a[:start]==b[:start] and a[end:]==b[end:]
    assert set(a[start:end])=={255}
    for mod in manifest['modules']:
        off=int(mod['cap_offset'],16);ffs=b[off:off+mod['ffs_bytes']]
        assert_ffs(ffs);assert sha(ffs)==mod['patched_ffs_sha256']
        pe=pefile.PE(data=(OUT/'modules'/mod['guid']/'patched.efi').read_bytes())
        assert pe.OPTIONAL_HEADER.CheckSum==pe.generate_checksum()
    original=json.loads((ROOT/'analysis/inventory.json').read_text())[HERO]
    edited=inventory(str(path.relative_to(ROOT)))
    orig_counts=Counter((m['guid'],m['sha256']) for m in original)
    new_counts=Counter((m['guid'],m['sha256']) for m in edited)
    assert not orig_counts-new_counts
    added=new_counts-orig_counts
    assert set(added)=={(m['guid'],m['patched_ffs_sha256']) for m in manifest['modules']}
    (OUT/'extracted_inventory.json').write_text(json.dumps(edited,indent=2),encoding='utf-8')
    return dict(original_ffs_nodes=len(original),new_ffs_nodes=len(edited),all_original_ffs_byte_identical=True,
                added_ffs=3,changed_original_ffs=0,all_modified_bytes_were_originally_erased=True,
                capsule_authenticated=False,hardware_tested=False)

if __name__=='__main__':
    emu=emulation()
    result=dict(structural=structure(),mock_x64_cases=emu,
        limits='Mock EFI/BMC responses only. No full boot, physical IPMI transport, hardware access, capsule authentication or target sensor validation.')
    (OUT/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(structural=result['structural'],mock_cases_passed=len(emu)),indent=2))
