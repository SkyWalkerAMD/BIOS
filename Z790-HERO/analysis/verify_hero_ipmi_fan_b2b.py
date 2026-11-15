"""Execute the shipped EFI bytes in Unicorn with synthetic EFI/PCI/KCS devices.

No host firmware, devices or networking are accessed. A pass verifies bounded
software behavior, not operation on HERO hardware or the experimental CAP.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_fan_b2b'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
ERR=lambda n: 0x8000000000000000|n
P64=lambda v:struct.pack('<Q',v)
REAL_CONFIG=bytes.fromhex('03 1A 02 24 00 00 10 02 01 01 07 0C 00 00 00 00 00 00 00 74 00 00 10 74 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 1A 02 24 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00')
TEMP_CASES={
    'decode_disabled','real_3107','temp_uppercase','temp_decline','temp_timeout','temp_busy',
    'temp_pci_io_failure','temp_nonzero_completion','temp_no_log','temp_log_failure',
    'enable_write_failure','enable_partial_failure','enable_false_success','enable_readback_failure',
    'enable_other_bits_changed','restore_write_failure','restore_false_success',
    'restore_readback_failure','restore_config_read_failure','restore_other_bits_changed',
    'bar_changed_before_enable','wrong_board_disabled','wrong_bios_disabled',
    'no_query_on_partial_enable','already_enabled_at_prompt',
}

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
            body=bytearray(47); body[0]=0x20; body[2]=1; body[7]=1; body[8]=1; body[42]=0xc4; body[43:]=b'TEST'
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
        self.case=case
        device_case=case[5:] if case in ('temp_timeout','temp_busy','temp_pci_io_failure','temp_nonzero_completion') else case
        self.dev=Device(device_case);self.u=Uc(UC_ARCH_X86,UC_MODE_64)
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
        self.pci_writes=[];self.full_reads=0;self.word_reads=0;self.queried_protocols=[]
        self.startup_waits=0
        self.keys=list('erqq' if case in TEMP_CASES else 'prqq')
        if case in ('uppercase_keys','temp_uppercase'):self.keys=[x.upper() for x in self.keys]
        if case=='temp_decline':self.keys=list('qq')
        self.guard=[]
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
        self.stub(self.pci+0x30,'PciRead');self.stub(self.pci+0x38,'PciWrite')
        self.stub(self.pci+0x70,'Location');self.stub(self.pci+0x80,'BarAttributes')
        self.w64(self.loaded+0x18,0x4444)
        self.stub(self.fs+8,'OpenVolume')
        for ptr in (self.root,self.tag,self.file,self.existing):self.stub(ptr+0x10,'CloseFile')
        self.stub(self.root+8,'OpenFile');self.stub(self.tag+0x20,'ReadFile')
        self.stub(self.file+0x28,'WriteFile');self.stub(self.file+0x50,'FlushFile')
        config=bytearray(REAL_CONFIG);config[4]=0 if case in TEMP_CASES else 6
        self.initial_command=config[4]
        if case=='revision_not_ready':config[8]=0
        if case=='bar0_64bit':config[16]=4
        self.config=config
        board='OTHER BOARD' if case in ('wrong_board','wrong_board_disabled') else 'ROG MAXIMUS Z790 HERO'
        bios='3107' if case in TEMP_CASES else '3001'
        if case=='wrong_bios_disabled':bios='9999'
        sm=bytearray(24);sm[:2]=bytes([0,24]);sm[5]=1
        sm+=bios.encode()+b'\0\0'
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
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(self.u.mem_read(a,16))))
            self.queried_protocols.append(guid)
            result=ERR(14)
        elif name=='LocateHandles':
            if self.case=='no_card':result=ERR(14)
            else:self.w64(d,1);self.w64(e,self.alloc(P64(0x5555)))
        elif name=='FreePool':self.freed.append(a)
        elif name=='PciRead':
            assert a==self.pci
            if (b&0xffffffff)==0:
                assert c==0 and d==64
                self.full_reads+=1
                if self.full_reads==2 and self.case=='bar_changed_before_enable':self.config[22]^=1
                if self.full_reads==2 and self.case=='already_enabled_at_prompt':self.config[4]|=2
                if self.full_reads==2 and self.case=='decode_lost_before_query':self.config[4]&=~2
                restoring='PCI_RESTORE_BEGIN' in self.output
                if restoring and self.case=='restore_other_bits_changed':self.config[4]|=4
                if restoring and self.case=='restore_config_read_failure':result=ERR(7)
                else:self.u.mem_write(e,bytes(self.config))
            else:
                assert (b&0xffffffff)==1 and c==4 and d==1
                self.word_reads+=1
                if ((self.word_reads==1 and self.case=='enable_readback_failure') or
                    (self.word_reads==2 and self.case=='restore_readback_failure')):result=ERR(7)
                else:self.u.mem_write(e,bytes(self.config[4:6]))
        elif name=='PciWrite':
            assert self.case in TEMP_CASES,(self.case,'unexpected PCI change')
            assert a==self.pci and (b&0xffffffff)==1 and c==4 and d==1
            before=struct.unpack('<H',self.config[4:6])[0]
            requested=struct.unpack('<H',self.u.mem_read(e,2))[0]
            assert (before^requested)==2,('must change memory bit only',before,requested)
            self.pci_writes.append((before,requested))
            if len(self.pci_writes)==1:
                assert requested==2 and 'PCI_MEMORY_ENABLE_REQUESTED' in self.output
                assert self.opened and self.log, 'write requires a working log'
                if self.case in ('enable_write_failure','enable_false_success'):
                    if self.case=='enable_write_failure':result=ERR(7)
                else:
                    self.config[4:6]=struct.pack('<H',requested)
                    if self.case in ('enable_partial_failure','no_query_on_partial_enable'):result=ERR(7)
                    if self.case=='enable_other_bits_changed':self.config[4]|=4
            else:
                assert len(self.pci_writes)==2
                if self.case=='restore_write_failure':result=ERR(7)
                elif self.case!='restore_false_success':self.config[4:6]=struct.pack('<H',requested)
            assert self.config[6:8]==REAL_CONFIG[6:8], 'adjacent W1C Status must be untouched'
        elif name=='Location':
            for ptr,v in ((b,0),(c,4),(d,1),(e,0)):self.w64(ptr,v)
        elif name=='BarAttributes':
            assert a==self.pci and (b&255)==1
            desc=bytearray(46);desc[0]=0x8a;desc[1]=43
            struct.pack_into('<Q',desc,14,0x74100000)
            struct.pack_into('<Q',desc,38,0x40000 if self.case!='short_bar' else 0x100)
            self.w64(c,0);self.w64(d,self.alloc(desc))
        elif name in ('MemRead','MemWrite'):
            assert a==self.pci and (b&0xffffffff)==0 and (c&255)==1 and d in (0xe88,0xe8c) and e==1
            assert self.config[4]&2, 'no MMIO until memory decoding is enabled'
            if self.case in ('pci_io_failure','temp_pci_io_failure'):result=ERR(7)
            elif name=='MemRead':self.u.mem_write(f,bytes([self.dev.read(d==0xe8c)]))
            else:self.dev.write(d==0xe8c,self.u.mem_read(f,1)[0])
        elif name=='Stall':
            if a==1000000:
                assert 'READINESS_BEGIN' in self.output and 'READINESS_IDLE_STABLE' not in self.output
                self.startup_waits+=1
            else:assert a==1000;self.dev.delays+=1
        elif name=='OpenVolume':self.w64(b,self.root)
        elif name=='OpenFile':
            path=self.wide(c)
            if path=='\\HERO-PROBE-USB.TAG':
                if self.case in ('no_marker','temp_no_log'):result=ERR(14)
                else:self.w64(b,self.tag)
            elif d==1:
                if self.case=='existing_log' and path=='\\HEROIPMI-000.TXT':self.w64(b,self.existing)
                else:result=ERR(14)
            else:
                assert d==0x8000000000000003 and e==0
                assert path==('\\HEROIPMI-001.TXT' if self.case=='existing_log' else '\\HEROIPMI-000.TXT')
                self.opened.append(path);self.w64(b,self.file)
        elif name=='ReadFile':
            marker=b'HERO-IPMI-PROBE-A2\r\n' if self.case=='legacy_marker' else b'HERO-IPMI-FAN--B2b\r\n'
            self.w64(b,len(marker));self.u.mem_write(c,marker)
        elif name=='WriteFile':
            if self.case in ('log_failure','temp_log_failure'):result=ERR(7)
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
        self.u.emu_start(self.entry,stop,count=80000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,('did not return',self.case)
        assert self.u.reg_read(UC_X86_REG_RAX)==0
        assert self.u.reg_read(UC_X86_REG_RSP)==rsp+8
        for i,r in enumerate(saved):assert self.u.reg_read(r)==0x11110000+i
        for a,n in self.guard:
            assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        return self

FIXTURE=json.loads((OUT/'evidence/findings.json').read_text(encoding='utf-8'))
R1_COMMANDS=json.loads((ROOT/'analysis/hero_sensor_r1/verification.json').read_text())['mock_x64_cases'][0]['commands']
EXPECTED_OEM=[bytes([c['netfn']<<2,c['command']])+bytes.fromhex(c['payload']) for c in R1_COMMANDS]
assert [p.hex() for p in EXPECTED_OEM]==[
    'c09080','c09401010301170119011a011b011c011d011e011f01200121012201230124012901','c0920000','c00201']


class ReplayDevice(Device):
    """Real A2 replies replayed; OEM and post-init changes are strictly MOCKS."""
    def __init__(self,scenario,full=False):
        super().__init__('normal')
        self.scenario=scenario;self.full=full;self.oem_packets=[];self.initialized=False
        self.identity_reads=0;self.version_reads=0;self.oem_timeout=False
        self.device_id=bytes.fromhex(FIXTURE['bmc']['raw_device_id'])
        self.records=[bytes.fromhex(r['raw']) for r in FIXTURE['records']
                      if full or r.get('sensor') in (0xcc,0xfb)]
        self.readings={bytes.fromhex(t['data'])[0]:bytes.fromhex(t['response'])
                       for t in FIXTURE['transactions'] if (t['netfn'],t['command'],t['sample'])==(4,45,0)}
    def read(self,reg):
        if reg and self.oem_timeout:return 0x82
        return super().read(reg)
    def current_records(self):
        records=list(self.records)
        if self.initialized and self.scenario=='mock_sensor_appears':
            # Synthetic response, deliberately named MOCK so it cannot be
            # mistaken for observed target hardware behavior.
            body=bytearray(56);body[0]=0x20;body[2]=1;body[7]=1;body[8]=1
            body[16]=1;body[19]=1;body[42]=0xcd;body[43:]=b'MOCK CPU Temp'
            records.append(struct.pack('<HBBB',0x58,0x51,1,len(body))+body)
        return records
    def response(self,tx):
        tx=bytes(tx);self.packets.append(tx)
        netfn,cmd=tx[0]>>2,tx[1];prefix=bytes([(netfn+1)<<2,cmd,0])
        if netfn==0x30:
            i=len(self.oem_packets)
            assert i<4 and tx==EXPECTED_OEM[i],('unapproved/out-of-order OEM',tx.hex(),i)
            self.oem_packets.append(tx)
            if self.scenario==f'reject_step_{i+1}':return prefix[:2]+b'\xc1'
            if self.scenario=='oem_bad_header' and i==1:return b'\x00\x00\x00'
            if self.scenario=='oem_timeout' and i==1:self.oem_timeout=True
            if i==3:self.initialized=True
            return prefix
        if (netfn,cmd)==(6,1):
            assert len(tx)==2
            self.identity_reads+=1
            reply=bytearray(self.device_id)
            if self.scenario=='identity_mismatch' or (self.scenario=='identity_changed' and self.identity_reads>1):reply[9]^=1
            if self.scenario=='bmc_update_in_progress':reply[5]|=0x80
            if self.scenario=='firmware_mismatch':reply[14]^=1
            return bytes(reply)
        if (netfn,cmd)==(10,32):
            assert len(tx)==2
            return prefix+b'\x51'+struct.pack('<H',len(self.current_records()))+bytes.fromhex('C0 12 FF FF FF FF B9 5F CE 12 27')
        if (netfn,cmd)==(10,35):
            assert len(tx)==8 and tx[2:4]==b'\0\0' and tx[6:8]==b'\0\xff'
            rid=int.from_bytes(tx[4:6],'little');records=self.current_records()
            index=0 if rid==0 else next(i for i,r in enumerate(records) if int.from_bytes(r[:2],'little')==rid)
            following=records[index+1][:2] if index+1<len(records) else b'\xff\xff'
            reply=prefix+following+records[index]
            if self.scenario=='sdr_incomplete' and index==len(records)-1:reply=reply[:-1]
            return reply
        if (netfn,cmd)==(4,45):
            assert len(tx)==3
            sid=tx[2]
            if self.scenario=='baseline_sensor_reject' and sid==0xcc:return prefix[:2]+b'\xcb'
            if sid==1 and self.initialized and self.scenario=='mock_sensor_appears':return prefix+bytes([43,0xc0,0])
            reply=bytearray(self.readings[sid])
            if sid==0xfb:
                self.version_reads+=1
                if (self.scenario=='version_clear' or
                    (self.scenario=='version_changed' and self.version_reads>1) or
                    (self.scenario=='mock_sensor_appears' and self.initialized)):reply[5]=0
                if self.scenario=='version_unavailable':reply[4]|=0x20
            return bytes(reply)
        raise AssertionError(('unexpected standard command',tx.hex()))


class CandidateMachine(Machine):
    def __init__(self,scenario,full=False):
        # Inherited EFI/PCI hooks stay unchanged for the already tested paths.
        super().__init__('normal' if scenario=='bios_3001_blocked' else 'real_3107')
        self.scenario=scenario;self.dev=ReplayDevice(scenario,full)
        first='p' if scenario=='bios_3001_blocked' else 'e'
        self.keys=list(first+'irqq')
        if scenario=='decline_init':self.keys=list(first+'qq')
        if scenario=='repeat_i_blocked':self.keys=list(first+'iiqq')
        if scenario=='uppercase_i':self.keys=list((first+'iqq').upper())
        if scenario in ('oem_bad_header','oem_timeout'):self.keys=list(first+'iqq')
    def hook(self,uc,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        a,b,c,d=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        fail=False
        if name=='WriteFile':
            chunk=bytes(uc.mem_read(c,self.r64(b)))
            if self.scenario=='log_fails_before_first_oem' and b'OEM_STEP 1/4' in chunk:fail=True
            if self.scenario=='log_fails_after_first_oem' and len(self.dev.oem_packets)==1 and b'OEM_COMPLETION=0x00' in chunk:fail=True
        previous=self.case
        if fail:self.case='log_failure'
        super().hook(uc,addr,size,user)
        self.case=previous
        if name=='LocateProtocol' and self.scenario=='resident_driver':
            guid=str(uuid.UUID(bytes_le=bytes(uc.mem_read(a,16))))
            if guid=='4a1d0e66-5271-4e22-83fe-90921b748213':
                self.w64(c,0x707700);uc.reg_write(UC_X86_REG_RAX,0)


def candidate_scenarios():
    cases=['accepted_unchanged','mock_sensor_appears','decline_init','repeat_i_blocked','uppercase_i',
           'identity_mismatch','identity_changed','bmc_update_in_progress','firmware_mismatch',
           'version_clear','version_changed','version_unavailable','bios_3001_blocked','resident_driver',
           'sdr_incomplete','baseline_sensor_reject',
           'reject_step_1','reject_step_2','reject_step_3','reject_step_4',
           'oem_bad_header','oem_timeout','log_fails_before_first_oem','log_fails_after_first_oem']
    results=[]
    for case in cases:
        full=case in ('accepted_unchanged','mock_sensor_appears')
        m=CandidateMachine(case,full).run()
        packets=m.dev.oem_packets
        if case in ('accepted_unchanged','mock_sensor_appears','repeat_i_blocked','uppercase_i'):
            assert packets==EXPECTED_OEM and 'OEM_SEQUENCE_ACCEPTED acknowledged=4/4' in m.output
            assert 'BMC changes are NOT rolled back' in m.output
            assert 'POST_INIT_SNAPSHOT_END' in m.output
            if case=='accepted_unchanged':
                assert 'AFTER target IDs present in SDR: 0/16' in m.output
                assert 'VERSION_ERR current status: ASSERTED' in m.output
            if case=='mock_sensor_appears':
                assert 'AFTER target IDs present in SDR: 01 1/16' in m.output
                assert 'SDR repository record count: 42' in m.output
                assert 'NEW_SDR_SENSOR_IDS: 01' in m.output
                assert 'VERSION_ERR current status: NOT_ASSERTED' in m.output
                assert m.dev.packets.count(bytes.fromhex('102d01'))==2
            if case=='repeat_i_blocked':assert 'OEM_GATE_CLOSED' in m.output
        elif case.startswith('reject_step_'):
            count=int(case.rsplit('_',1)[1]);assert packets==EXPECTED_OEM[:count]
            assert f'OEM_SEQUENCE_INCOMPLETE acknowledged={count-1}/4' in m.output
            assert 'OEM_REJECTED' in m.output
        elif case in ('oem_bad_header','oem_timeout'):
            assert packets==EXPECTED_OEM[:2]
            assert 'OEM_TRANSPORT_FAILED' in m.output
            assert m.dev.packets[-1]==EXPECTED_OEM[1]
        elif case=='log_fails_after_first_oem':
            assert packets==EXPECTED_OEM[:1] and 'OEM_STOPPED_LOG_FAILURE' in m.output
        else:
            assert not packets,(case,packets)
        if case!='bios_3001_blocked':
            assert m.pci_writes==[(0,2),(2,0)] and m.config[4]==0
            assert 'PCI_MEMORY_RESTORED_VERIFIED' in m.output
        else:assert not m.pci_writes
        assert m.config[6:8]==REAL_CONFIG[6:8]
        if not case.startswith('log_fails_'):assert b'PROBE_END' in m.log
        results.append(dict(case='B1_'+case,passed=True,full_A2_replay=full,
                            input_replies='Recorded real A2 baseline; OEM replies and post-init changes SIMULATED',
                            kcs_messages=len(m.dev.packets),oem_packets=[p.hex() for p in packets],
                            pci_command_writes=m.pci_writes,log_bytes=len(m.log)))
        print('B1_'+case,'PASS',flush=True)
        if full:
            (OUT/('example-MOCK-'+case+'.txt')).write_bytes(b'OFFLINE REPLAY / SIMULATED OEM RESULTS / NOT A REAL B1 HARDWARE LOG\r\n'+m.log)
    return results


B1_FIXTURE=json.loads((ROOT/'analysis/hero_ipmi_b1_result/findings.json').read_text(encoding='utf-8'))
assert B1_FIXTURE['sha256']=='a3c0bb55983bc243ed403599dba419663087dc664e0ee8f66a01fc6b52b0f534'

class FanDevice(ReplayDevice):
    """Replay real post-B1 SDR/readings; all 9A responses/RPM changes are MOCKS."""
    def __init__(self,scenario,full=False):
        super().__init__(scenario,False)
        self.fan_packets=[];self.fan_writes=[];self.fan_enabled=False
        self.mode=1 if scenario=='mode_nonzero' else 0
        self.rpm=bytearray(15);self.pwm=bytes(range(0xa0,0xaf));self.types=bytes(range(15))
        if scenario=='preserve_other_map':self.rpm[:2]=b'\x60\x61';self.rpm[3:]=bytes(range(0x63,0x6f))
        if scenario=='existing_rpm_map':self.rpm[2]=0x62
        self.original_rpm=bytes(self.rpm)
        self.full_fan=full
        if scenario!='combo_init_fan':self.post_b1()
    def post_b1(self):
        rr=B1_FIXTURE['snapshots'][2]['records']
        self.records=[bytes.fromhex(r['raw']) for r in rr if self.full_fan or r.get('sensor') in (0x20,0xfb)]
        self.readings={r['sensor']:bytes.fromhex(r['reading']['response']) for r in rr if 'reading' in r}
        if self.scenario=='fan_name_mismatch':self.records=[r.replace(b'MB_CHA_FAN1',b'MB_CHA_FAN9') for r in self.records]
        if self.scenario=='fan_wrong_type':
            self.records=[r[:12]+b'\x02'+r[13:] if len(r)>7 and r[3]==1 and r[7]==0x20 else r for r in self.records]
    def response(self,tx):
        tx=bytes(tx)
        if tx[0]==0xc0 and (tx[1]==0x9a or tx==bytes.fromhex('c0942001')):
            self.packets.append(tx);self.fan_packets.append(tx)
            step=len(self.fan_packets);prefix=bytes([0xc4,tx[1],0])
            if (tx[1]==0x94 or tx[3]==1):self.fan_writes.append(tx)
            if self.scenario==f'fan_reject_{step}':return prefix[:2]+b'\xc1'
            if self.scenario=='fan_bad_header' and step==5:return b'\0\0\0'
            if self.scenario=='fan_timeout' and step==5:self.oem_timeout=True;return prefix
            if tx==bytes.fromhex('c0942001'):
                self.fan_enabled=True
                return prefix
            assert tx[1]==0x9a and tx[2]<=3
            sub=tx[2]
            if tx[3]:
                assert sub==1 and len(tx)==19 and tx[3]==1,('forbidden setter',tx.hex())
                candidate=bytearray(self.rpm);candidate[2]=0x62
                assert tx[4:]==candidate,('altered other RPM mapping',tx.hex())
                if self.scenario!='rpm_readback_mismatch':self.rpm=candidate
                reply=prefix+candidate
                if self.scenario=='rpm_echo_mismatch':reply=reply[:-1]+bytes([reply[-1]^1])
                return bytes(reply)
            assert len(tx)==4 and tx[3]==0
            if self.scenario=='wrong_length_response' and step==1:return prefix
            mode=self.mode
            if self.scenario=='mode_changed' and step==7:mode=1
            if self.scenario=='post_enable_mode_changed' and step==11:mode=1
            data=[bytes([mode]),bytes(self.rpm),self.pwm,self.types][sub]
            if self.scenario=='pwm_changed' and step==8:data=bytes([data[0]^1])+data[1:]
            if self.scenario=='type_changed' and step==9:data=bytes([data[0]^1])+data[1:]
            return prefix+data
        reply=super().response(tx)
        if self.scenario=='combo_init_fan' and self.initialized and tx==EXPECTED_OEM[3]:self.post_b1()
        if tx==bytes.fromhex('102d20'):
            if self.scenario=='fan_already_available' or (self.fan_enabled and self.scenario in ('mock_rpm_available','combo_init_fan')):
                return reply[:3]+bytes([24,0xc0,0,0])
        if tx==bytes.fromhex('102dfb') and (self.scenario=='version_asserted' or (self.scenario=='version_changed' and self.version_reads>1)):
            reply=reply[:5]+b'\x10'+reply[6:]
        return reply

class FanMachine(Machine):
    def __init__(self,scenario,full=False):
        super().__init__('normal' if scenario=='bios_3001_blocked' else 'real_3107')
        self.scenario=scenario;self.dev=FanDevice(scenario,full)
        self.keys=list(('p' if scenario=='bios_3001_blocked' else 'e')+'fqq')
        if scenario=='decline_f':self.keys=list('eqq')
        if scenario=='repeat_f':self.keys=list('effqq')
        if scenario=='uppercase_f':self.keys=list('EFQQ')
        if scenario=='combo_init_fan':self.keys=list('eifqq')
    def hook(self,uc,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        a,b,c,d=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        fail=False
        if name=='WriteFile':
            chunk=bytes(uc.mem_read(c,self.r64(b)))
            target={'fan_log_before_write':b'FAN_STEP 5/14','fan_log_before_enable':b'FAN_STEP 10/14'}.get(self.scenario)
            if target and target in chunk:fail=True
            if self.scenario=='fan_log_after_write' and len(self.dev.fan_packets)==5 and b'FAN_COMPLETION' in chunk:fail=True
            if self.scenario=='fan_log_after_enable' and len(self.dev.fan_packets)==10 and b'FAN_COMPLETION' in chunk:fail=True
        previous=self.case
        if fail:self.case='log_failure'
        super().hook(uc,addr,size,user);self.case=previous
        if name=='ReadFile' and self.scenario=='old_B1_tag':
            uc.mem_write(c,b'HERO-IPMI-INIT--B1\r\n');self.w64(b,20)
        if name=='LocateProtocol' and self.scenario=='resident_driver':
            guid=str(uuid.UUID(bytes_le=bytes(uc.mem_read(a,16))))
            if guid=='4a1d0e66-5271-4e22-83fe-90921b748213':self.w64(c,0x707700);uc.reg_write(UC_X86_REG_RAX,0)

def fan_scenarios():
    counts={'accepted_still_unavailable':14,'mock_rpm_available':14,'preserve_other_map':14,'repeat_f':14,'uppercase_f':14,
        'decline_f':0,'identity_mismatch':0,'identity_changed':0,'firmware_mismatch':0,'bios_3001_blocked':0,
        'resident_driver':0,'sdr_incomplete':0,'version_asserted':0,'version_changed':0,'version_unavailable':0,
        'fan_already_available':0,'fan_name_mismatch':0,'fan_wrong_type':0,'old_B1_tag':0,
        'mode_nonzero':1,'existing_rpm_map':2,'wrong_length_response':1,'rpm_echo_mismatch':5,'rpm_readback_mismatch':6,
        'mode_changed':7,'pwm_changed':8,'type_changed':9,'post_enable_mode_changed':11,
        'fan_bad_header':5,'fan_timeout':5,'fan_log_before_write':4,'fan_log_after_write':5,
        'fan_log_before_enable':9,'fan_log_after_enable':10,'combo_init_fan':14}
    counts.update({f'fan_reject_{i}':i for i in range(1,15)})
    results=[]
    for case,count in counts.items():
        full=case in ('accepted_still_unavailable','mock_rpm_available')
        m=FanMachine(case,full).run();p=m.dev.fan_packets
        assert len(p)==count,(case,len(p),count,m.output[-1200:])
        if count==14 and not case.startswith('fan_reject_'):
            assert 'FAN_SEQUENCE_ACCEPTED acknowledged_and_verified=14/14' in m.output
            assert 'FAN_CONTROL_TABLES_UNCHANGED_VERIFIED' in m.output
            assert len(m.dev.fan_writes)==2 and m.dev.fan_writes[-1]==bytes.fromhex('c0942001')
            assert bytes(m.dev.rpm)==m.dev.original_rpm[:2]+b'\x62'+m.dev.original_rpm[3:]
            if case=='accepted_still_unavailable':assert m.output.count('Sensor 0x20 raw=0x00 flags=0xA0 READING_UNAVAILABLE SCANNING_DISABLED')>=3
            if case in ('mock_rpm_available','combo_init_fan'):assert 'Sensor 0x20 raw=0x18 flags=0xC0 READING_REPORTED' in m.output
        else:assert 'FAN_SEQUENCE_ACCEPTED' not in m.output
        if case=='repeat_f':assert m.output.count('FAN_AUTHORIZED_BY_F')==1
        if case=='combo_init_fan':assert m.dev.oem_packets==EXPECTED_OEM
        else:assert not m.dev.oem_packets
        if case=='old_B1_tag':assert not m.pci_writes and not m.dev.packets
        elif case!='bios_3001_blocked':assert m.pci_writes==[(0,2),(2,0)] and m.config[4]==0
        else:assert not m.pci_writes
        assert m.config[6:8]==REAL_CONFIG[6:8]
        results.append(dict(case='B2_'+case,passed=True,full_B1_replay=full,
            input_replies='Real B1 post-init baseline; all 9A and changed fan readings SIMULATED',
            fan_packets=[x.hex() for x in p],fan_write_packets=[x.hex() for x in m.dev.fan_writes],
            pci_command_writes=m.pci_writes,log_bytes=len(m.log)))
        print('B2_'+case,'PASS',flush=True)
        if full:(OUT/('example-MOCK-B2-'+case+'.txt')).write_bytes(b'OFFLINE MOCK B2 FAN EXPERIMENT / NOT A REAL HARDWARE LOG\r\n'+m.log)
    return results


class ReadinessDevice(FanDevice):
    """Synthetic timing boundaries, with recorded sensor fixtures after ready."""
    def __init__(self,case):
        super().__init__('combo_init_fan' if case in ('explicit_i_f_after_ready','no_auto_i_f') else 'accepted_still_unavailable',False)
        self.ready_case=case;self.status_history=[];self.prewrite_data_reads=0;self.first_write_status_count=None
    def read(self,reg):
        if not self.writes:
            if not reg:self.prewrite_data_reads+=1;raise AssertionError('Readiness consumed KCS data')
            index=len(self.status_history)
            c=self.ready_case
            prefixes={'one_ff_then_idle':[255], 'longer_ff_then_idle':[255]*22,
                'ready_at_last_sample':[255]*28, 'too_late':[255]*29,
                'ff_before_first_write':[0,0,0,255],
                'nonidle_busy':[0x82], 'nonidle_output':[1], 'nonidle_error':[0xc0], 'nonidle_attention':[4]}
            if c=='persistent_ff':value=255
            elif c=='unstable_idle':value=(0,0,255)[index%3]
            elif c in ('explicit_i_f_after_ready','no_auto_i_f'):value=255 if index==0 else 0
            else:
                prefix=prefixes.get(c,[]);value=prefix[index] if index<len(prefix) else 0
            self.status_history.append(value);return value
        if reg and self.ready_case=='ff_after_write_start' and len(self.writes)==1:return 255
        return super().read(reg)
    def write(self,reg,value):
        if not self.writes:
            assert self.status_history[-4:]==[0,0,0,0],('first request before stable idle',self.ready_case,self.status_history)
            self.first_write_status_count=len(self.status_history)
        return super().write(reg,value)

class ReadinessMachine(Machine):
    def __init__(self,case):
        super().__init__('real_3107');self.ready_case=case;self.dev=ReadinessDevice(case)
        self.keys=list('eifqq' if case=='explicit_i_f_after_ready' else 'eqq')
        self.changed_config=False
    def hook(self,uc,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        a,b,c,d=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        active=('READINESS_BEGIN' in self.output and 'READINESS_IDLE_STABLE' not in self.output and
                'READINESS_STOPPED_NO_REQUEST' not in self.output)
        case=self.ready_case;fail=False
        if name=='WriteFile':
            chunk=bytes(uc.mem_read(c,self.r64(b)))
            needle={'log_before_sampling':b'READINESS_BEGIN','log_during_sampling':b'READINESS_SAMPLE index=1',
                    'log_at_ready':b'READINESS_IDLE_STABLE','log_before_first_request':b'TX netfn=06 cmd=01'}.get(case)
            if needle and needle in chunk:fail=True
        if name=='PciRead' and active and self.startup_waits>=1 and not self.changed_config:
            if case=='bar_changed':self.config[22]^=1;self.changed_config=True
            if case=='decode_cleared':self.config[4]&=~2;self.changed_config=True
            if case=='identity_changed':self.config[0]^=1;self.changed_config=True
        previous=self.case
        if fail:self.case='log_failure'
        super().hook(uc,addr,size,user);self.case=previous
        if name=='ReadFile' and case in ('old_B2_marker','old_B2a_marker'):
            marker=b'HERO-IPMI-FAN---B2\r\n' if case=='old_B2_marker' else b'HERO-IPMI-FAN--B2a\r\n'
            uc.mem_write(c,marker);self.w64(b,len(marker))
        if active and name=='MemRead' and case=='status_read_failure':uc.reg_write(UC_X86_REG_RAX,ERR(7))
        if active and name=='PciRead' and case=='config_read_failure':uc.reg_write(UC_X86_REG_RAX,ERR(7))
        if active and name=='Stall' and case=='stall_failure':uc.reg_write(UC_X86_REG_RAX,ERR(7))

def readiness_scenarios():
    expected={
        'already_idle':(3,True), 'one_ff_then_idle':(4,True),'longer_ff_then_idle':(25,True),
        'ready_at_last_sample':(31,True),'too_late':(31,False),'persistent_ff':(31,False),'unstable_idle':(31,False),
        'nonidle_busy':(1,False),'nonidle_output':(1,False),'nonidle_error':(1,False),'nonidle_attention':(1,False),
        'ff_before_first_write':(3,False),'ff_after_write_start':(3,False),
        'log_before_sampling':(0,False),'log_during_sampling':(2,False),'log_at_ready':(3,False),'log_before_first_request':(3,False),
        'bar_changed':(1,False),'decode_cleared':(1,False),'identity_changed':(1,False),
        'status_read_failure':(1,False),'config_read_failure':(0,False),'stall_failure':(1,False),
        'explicit_i_f_after_ready':(4,True),'no_auto_i_f':(4,True),
        'old_B2_marker':(0,False),'old_B2a_marker':(0,False)}
    results=[]
    for case,(count,completed) in expected.items():
        m=ReadinessMachine(case).run();dev=m.dev
        assert dev.prewrite_data_reads==0
        if completed:
            assert 'GET_DEVICE_ID_OK' in m.output and dev.first_write_status_count==count+1
            assert m.startup_waits==count-1
            assert dev.packets[0]==bytes.fromhex('1801')
        else:
            assert not dev.packets,(case,[p.hex() for p in dev.packets])
            if case=='ff_after_write_start':assert dev.writes==[(1,0x61)]
            else:assert not dev.writes
            assert len(dev.status_history)==count+(case in ('ff_before_first_write','ff_after_write_start')),(case,dev.status_history)
        if case=='explicit_i_f_after_ready':
            assert dev.oem_packets==EXPECTED_OEM and len(dev.fan_packets)==14
            assert 'FAN_SEQUENCE_ACCEPTED' in m.output
        else:assert not dev.oem_packets and not dev.fan_packets
        if case=='identity_changed':
            assert 'PCI_MEMORY_RESTORE_UNCONFIRMED' in m.output
            assert 'PCI_MEMORY_RESTORED_VERIFIED' not in m.output
        else:assert m.config[4]&2==0
        if case not in ('old_B2_marker','old_B2a_marker','identity_changed'):
            assert 'PCI_MEMORY_RESTORED_VERIFIED' in m.output
        assert m.config[6:8]==REAL_CONFIG[6:8]
        if case in ('persistent_ff','unstable_idle','too_late'):assert m.startup_waits==30
        if case in ('ff_before_first_write','ff_after_write_start'):assert m.startup_waits==2
        assert m.startup_waits<=30
        results.append(dict(case='B2b_'+case,passed=True,ready_status_history=dev.status_history,
            first_write_status_count=dev.first_write_status_count,startup_waits=m.startup_waits,
            prewrite_data_reads=dev.prewrite_data_reads,kcs_write_attempts=len(dev.writes),complete_packets=len(dev.packets),
            oem_packets=[x.hex() for x in dev.oem_packets],fan_packets=[x.hex() for x in dev.fan_packets],
            pci_command_writes=m.pci_writes))
        print('B2b_'+case,'PASS',flush=True)
        if case in ('one_ff_then_idle','persistent_ff','explicit_i_f_after_ready'):
            (OUT/('example-MOCK-B2b-'+case+'.txt')).write_bytes(b'OFFLINE SYNTHETIC READINESS + RECORDED SENSOR FIXTURES / NOT A HARDWARE LOG\r\n'+m.log)
    return results

def main():
    evidence=(OUT/'evidence/HEROIPMI-000(1).TXT').read_bytes()
    findings=json.loads((OUT/'evidence/findings.json').read_text())
    assert hashlib.sha256(evidence).hexdigest()==findings['sha256']
    observed=re.search(rb'PCI_CONFIG_00_3F ([0-9A-F ]+)\r?\n',evidence)
    assert observed and bytes.fromhex(observed[1].decode())==REAL_CONFIG
    assert b'BIOS: 3107' in evidence and b'PCI_MEMORY_RESTORED_VERIFIED' in evidence
    assert findings['command_count']==121 and not findings['errors']
    cases=['normal','uppercase_keys','existing_log','no_marker','log_failure','no_card','wrong_board',
        'decode_disabled','revision_not_ready','bar0_64bit','short_bar','busy','status_ff',
        'pci_io_failure','timeout','bad_header','nonzero_completion','oversize_response',
        'empty_sdr','malformed_sdr','reading_unavailable','no_final_dummy',
        'legacy_marker','decode_lost_before_query']
    cases+=sorted(TEMP_CASES-set(cases))
    results=[]
    for case in cases:
        m=Machine(case).run()
        assert '30cfe3e7-3de1-4586-be20-deaba1b3b793' in m.queried_protocols
        assert '72338391-fb43-44a1-a9a2-64fee1fc5e41' in m.queried_protocols
        if case in ('no_card','wrong_board','revision_not_ready','bar0_64bit','short_bar','busy','status_ff','pci_io_failure','decode_lost_before_query'):
            assert not m.dev.writes,(case,m.dev.writes)
        elif case=='timeout':assert m.dev.delays==9999 and len(m.dev.writes)==1
        elif case=='bad_header':assert 'RESPONSE_HEADER_MISMATCH' in m.output and len(m.dev.packets)==1
        elif case=='nonzero_completion':assert 'completion code=0xC1' in m.output and len(m.dev.packets)==1
        elif case=='oversize_response':assert 'RESPONSE_TOO_LARGE' in m.output
        elif case=='empty_sdr':assert 'EMPTY_REPOSITORY' in m.output
        elif case=='malformed_sdr':assert 'Invalid SDR record length' in m.output
        elif case=='reading_unavailable':assert 'READING_UNAVAILABLE' in m.output
        elif case not in TEMP_CASES and case not in ('no_marker','log_failure','legacy_marker'):assert 'SDR_SCAN_COMPLETE' in m.output and m.output.count('READING_REPORTED')==2
        if case in TEMP_CASES:
            no_write={'temp_decline','temp_no_log','temp_log_failure','bar_changed_before_enable','wrong_board_disabled','wrong_bios_disabled'}
            no_query={'enable_write_failure','enable_partial_failure','enable_false_success','enable_readback_failure',
                      'enable_other_bits_changed','no_query_on_partial_enable','temp_busy','temp_pci_io_failure','temp_timeout'}
            unconfirmed={'restore_write_failure','restore_false_success','restore_readback_failure','restore_config_read_failure'}
            if case in no_write:
                assert not m.pci_writes and not m.dev.writes
            elif case=='already_enabled_at_prompt':
                assert not m.pci_writes and 'SDR_SCAN_COMPLETE' in m.output
            else:
                assert m.pci_writes
                if case in no_query:assert not m.dev.packets
                elif case=='temp_nonzero_completion':assert len(m.dev.packets)==1
                else:assert 'SDR_SCAN_COMPLETE' in m.output
                if case in unconfirmed:
                    assert 'PCI_MEMORY_RESTORE_UNCONFIRMED' in m.output
                    assert 'PCI_MEMORY_RESTORED_VERIFIED' not in m.output
                else:
                    assert m.config[4]&2==0 and 'PCI_MEMORY_RESTORED_VERIFIED' in m.output
                if case in ('enable_other_bits_changed','restore_other_bits_changed'):
                    assert m.config[4]==4 and 'PCI_OTHER_COMMAND_BITS_CHANGED' in m.output
            if case=='temp_timeout':assert m.dev.delays==9999 and len(m.dev.writes)==1
        else:assert not m.pci_writes
        if case in ('no_marker','temp_no_log'):assert not m.opened and not m.log
        if case not in ('no_marker','log_failure','temp_no_log','temp_log_failure','legacy_marker'):assert b'PROBE_END' in m.log
        results.append(dict(case=case,passed=True,kcs_messages=len(m.dev.packets),
                       pci_command_writes=m.pci_writes,final_command=m.config[4],log_bytes=len(m.log)))
        print(case,'PASS',flush=True)
        assert not any(p[0]>>2==0x30 for p in m.dev.packets)
    results.extend(candidate_scenarios())
    results.extend(fan_scenarios())
    results.extend(readiness_scenarios())
    report=dict(scope='SHIPPED_X64_EFI_IN_UNICORN_WITH_SYNTHETIC_EFI_PCI_KCS',
        no_hardware_validation=True,no_CAP_boot_validation=True,
        discovery_fixture_sha256=findings['sha256'],
        image_sha256=hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
        scenarios=results,checked=['EFI callback ABI stack alignment and caller-register clobbering',
        'callee-saved integer registers and return stack','guarded mock allocation boundaries',
        'no runtime writes, driver loading, abort/reset or flash services; baseline cases emit no OEM packets',
        'explicit E input required before temporary PCI memory enable; Q causes no change',
        'PCI writes restricted to 16-bit Command at offset 4, memory bit only; W1C Status unchanged',
        'restoration and readback after success, transport errors, partial enable and failed verification',
        'restoration failures are reported without claiming success; other bits are preserved',
        'real A2 PCI/identity/SDR/read replies replayed in offline cases; OEM replies and changed readings are simulated',
        'KCS read/write handshake including omitted final dummy byte',
        'timeouts, completion codes, invalid headers and oversized/truncated responses',
        'target/BAR gating, USB marker and non-overwriting log selection',
        'candidate fingerprint, baseline, VERSION_ERR, BIOS 3107, resident-driver and explicit I gates',
        'exact four-packet candidate sequence; stop on first OEM completion/transport/log failure',
        'one attempt per application session; accepted commands never reported as successful port',
        'SDR rescan discovers new IDs instead of reusing the old sensor list',
        'F requires initialized B1 state; exact CHA1 SDR identity and disabled/unavailable reading',
        'F changes only RPM map index 2; all other entries preserved; only sensor 20 scan is enabled',
        'control mode must be zero; mode/PWM/type getters checked before and after scan enable',
        'wrong mode/existing mapping, setter echo/readback, control-table changes, rejected commands and log failures stop the sequence',
        '14/14 accepted remains distinct from a valid actual fan reading',
        'B2a first FF error distinguished from actual PCI API failure; zero-write diagnostic gate',
        'B2b initial readiness: 31 samples maximum, consecutive 00 gate, FF resets the count',
        'no startup KCS writes/data reads; nonidle, config/BAR changes and log/PCI/stall failures stop',
        'readiness does not replay a started request or trigger I/F automatically'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('All',len(results),'mock scenarios passed. No target hardware used.')

if __name__=='__main__':main()
