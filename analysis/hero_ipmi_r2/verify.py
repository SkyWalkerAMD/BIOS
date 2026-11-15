"""Failure-injection of the actual R2 DXE machine code in Unicorn.

The PCI/KCS double replays recorded A2/B1 responses. Transition timing and
failure cases are synthetic. This does not establish operation on HERO.
"""
from pathlib import Path
import sys,struct,re,json,uuid,hashlib,copy
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(ROOT/'analysis'))
import verify_hero_ipmi_fan_b2c as base
import pefile
from unicorn.x86_const import *
ERR=base.ERR
CONFIG_GUID='c2614243-a877-4acf-a458-ce2904ec3e10'
GOOD=struct.pack('<IBBBB',0x31495048,1,1,0,0)
class Device(base.ReplayDevice):
    def __init__(self,case,full=False):
        super().__init__(case,full);self.test=case;self.initial_status_count=0;self.repository_reads=0
        if case=='already_initialized':self.post()
    def post(self):
        self.records=[bytes.fromhex(r['raw']) for r in base.B1_FIXTURE['snapshots'][2]['records']]
        self.readings={r['sensor']:bytes.fromhex(r['reading']['response']) for r in base.B1_FIXTURE['snapshots'][2]['records'] if 'reading' in r}
    def read(self,reg):
        if reg and not self.writes:
            self.initial_status_count+=1
            if self.test=='startup_c1':return 0xc1
            if self.test=='startup_ff':return 255
            if self.test=='transient_ff' and self.initial_status_count==1:return 255
            if self.test=='startup_busy':return 0x82
        return super().read(reg)
    def response(self,tx):
        reply=super().response(tx)
        if bytes(tx)==base.EXPECTED_OEM[3] and self.test!='postcheck_unchanged':self.post()
        if bytes(tx[:2])==b'\x28\x20':
            self.repository_reads+=1
            if self.test=='repository_changed' and self.repository_reads==2:reply=reply[:-1]+bytes([reply[-1]^1])
        if self.test=='oem_extra_reply' and tx[0]==0xc0:return reply+b'\0'
        return reply
class Machine(base.Machine):
    def __init__(self,case='success',full=False):
        super().__init__('wrong_board_disabled' if case=='wrong_board' else 'wrong_bios_disabled' if case=='wrong_bios' else 'real_3107')
        self.test=case;self.dev=Device(case,full);self.vars={'HeroIpmiCfg':(3,GOOD)};self.nv_writes=[];self.elapsed_ms=0
        self.inject=False;self.config_writes=[];self.hii_values={}
        if case in ('disabled','auto_disabled'):self.vars={'HeroIpmiCfg':(3,GOOD[:4]+b'\0'+GOOD[5:])}
        if case=='invalid_config':self.vars={'HeroIpmiCfg':(3,b'BROKEN!!')}
        if case=='invalid_attrs':self.vars={'HeroIpmiCfg':(7,GOOD)}
        if case=='prior_lock':self.vars['HeroIpmiAttempt']=(3,b'\x01')
        p=pefile.PE(str(OUT/'USB/EFI/HERO/HeroIpmiR2.efi'));p.relocate_image(0x100000)
        self.u.mem_write(0x100000,bytes(0x100000));self.u.mem_write(0x100000,p.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'driver.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        self.w64(self.functions['gST'],self.st)
        self.stub(self.rt+0x58,'SetVariable')
        self.u.mem_write(self.functions['installed'],struct.pack('<I',1)) # Isolated callback tests model an active core.
    def audit(self):
        n=self.r64(self.functions['audit_len']);assert n<131072
        return bytes(self.u.mem_read(self.functions['audit'],n)).decode('ascii')
    def hook(self,u,addr,size,user):
        if addr not in self.stubs:return
        name=self.stubs[addr];rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f=[self.r64(rsp+off) for off in (0x28,0x30)]
        result=0;handled=True
        if name in ('GetVariable','SetVariable'):
            key=self.wide(a);guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            assert guid==CONFIG_GUID and key in ('HeroIpmiCfg','HeroIpmiAttempt'),('foreign NVRAM access',guid,key)
            if name=='GetVariable':
                if self.test=='nv_read_failure':result=ERR(7)
                elif key not in self.vars:result=ERR(14)
                else:
                    attrs,data=self.vars[key];n=self.r64(d);self.w64(d,len(data))
                    if n<len(data):result=ERR(5)
                    else:
                        if c:u.mem_write(c,struct.pack('<I',attrs))
                        u.mem_write(e,data)
            else:
                data=bytes(u.mem_read(e,d)) if d else b'';self.nv_writes.append((key,c,data.hex(),len(self.dev.oem_packets)))
                assert len(self.dev.oem_packets)==0 or key=='HeroIpmiAttempt'
                if self.test=='lock_write_failure' or (self.test=='lock_delete_failure' and not d):result=ERR(7)
                elif self.test=='lock_false_success':pass
                elif d:self.vars[key]=(c,data)
                else:self.vars.pop(key,None)
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            if guid=='30cfe3e7-3de1-4586-be20-deaba1b3b793':
                if self.test=='pci_enumeration_missing':result=ERR(14)
                else:self.w64(c,0) # Marker protocol is allowed to have NULL interface.
            elif guid=='4a1d0e66-5271-4e22-83fe-90921b748213':result=0 if self.test=='resident_transport' else ERR(7) if self.test=='protocol_error' else ERR(14)
            else:result=ERR(14)
        elif name=='Stall':
            assert a in (1000,1000000);self.elapsed_ms+=a//1000
            if self.test=='stall_failure':result=ERR(7)
        elif name=='PciWrite':
            assert a==self.pci and b==1 and c==4 and d==1
            before=int.from_bytes(self.config[4:6],'little');wanted=int.from_bytes(u.mem_read(e,2),'little')
            assert (before^wanted)==2
            self.pci_writes.append((before,wanted));self.config_writes.append((c,d,wanted))
            if self.test=='enable_failure' and len(self.pci_writes)==1:result=ERR(7)
            elif self.test=='restore_failure' and len(self.pci_writes)>1:result=ERR(7)
            elif self.test=='enable_false_success' and len(self.pci_writes)==1:pass
            else:self.config[4:6]=wanted.to_bytes(2,'little')
        elif name=='PciRead' and self.test=='bar_change' and self.dev.identity_reads>1:
            self.config[22]^=1;self.test='bar_changed';u.mem_write(e,bytes(self.config))
        elif name=='Location' and self.test=='wrong_location':
            for ptr,v in ((b,0),(c,5),(d,1),(e,0)):self.w64(ptr,v)
        elif name=='MemWrite':
            assert a==self.pci and b==0 and c==1 and d in (0xe88,0xe8c) and e==1 and self.config[4]&2
            self.dev.write(d==0xe8c,u.mem_read(f,1)[0])
            if self.dev.oem_packets:assert 'HeroIpmiAttempt' in self.vars,'OEM write without durable lock'
        elif name=='HiiSetString':raise AssertionError('R2 core must not use HII')
        else:handled=False
        if not handled:return super().hook(u,addr,size,user)
        self.calls.append(name)
        u.reg_write(UC_X86_REG_RAX,result)
        for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)
    def call(self,name,*args):
        rsp=0xef0000-8;stop=0x8f0000;self.w64(rsp,stop)
        self.u.reg_write(UC_X86_REG_RSP,rsp)
        regs=(UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)
        for i,arg in enumerate(args):
            if i<4:self.u.reg_write(regs[i],arg)
            else:self.w64(rsp+0x28+(i-4)*8,arg)
        self.u.emu_start(self.functions[name],stop,count=100000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,(name,self.test,'instruction budget exhausted')
        for a,n in self.guard:
            assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16
            assert bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        return self.u.reg_read(UC_X86_REG_RAX)

def run():
    rows=[]
    cases={'success':4,'transient_ff':4,'already_initialized':0,'disabled':0,'invalid_config':0,'invalid_attrs':0,
     'wrong_board':0,'wrong_bios':0,'wrong_location':0,'pci_enumeration_missing':0,'resident_transport':0,'protocol_error':0,
     'prior_lock':0,'nv_read_failure':0,'lock_write_failure':0,'lock_false_success':0,'lock_delete_failure':4,
     'startup_c1':0,'startup_ff':0,'startup_busy':0,'stall_failure':0,'enable_failure':0,'enable_false_success':0,
     'identity_mismatch':0,'identity_changed':0,'firmware_mismatch':0,'bmc_update_in_progress':0,
     'sdr_incomplete':0,'baseline_sensor_reject':0,'version_unavailable':0,'version_clear':0,'version_changed':0,
     'repository_changed':0,'bar_change':0,'postcheck_unchanged':4,'oem_extra_reply':1,
     'reject_step_1':1,'reject_step_2':2,'reject_step_3':3,'reject_step_4':4,'oem_bad_header':2,'oem_timeout':2,'restore_failure':4}
    for case,count in cases.items():
        m=Machine(case,full=case=='success');status=m.call('engine_run',1);log=m.audit()
        assert len(m.dev.oem_packets)==count,(case,len(m.dev.oem_packets),log[-1800:])
        assert m.dev.oem_packets==base.EXPECTED_OEM[:count],case
        if case in ('success','transient_ff','already_initialized'):assert status==0,(case,log[-1800:])
        else:assert status!=0,(case,log[-1800:])
        if count and case not in ('success','transient_ff'):assert 'HeroIpmiAttempt' in m.vars,(case,'must stay locked')
        if case in ('success','transient_ff'):assert 'HeroIpmiAttempt' not in m.vars
        if case not in ('restore_failure','bar_change'):assert not(m.config[4]&2),(case,'PCI memory bit leaked')
        assert m.elapsed_ms<=45000
        if case in ('disabled','invalid_config','invalid_attrs','wrong_board','wrong_bios','prior_lock','nv_read_failure','resident_transport','protocol_error','pci_enumeration_missing'):assert not m.dev.writes and not m.pci_writes
        if case in ('startup_c1','startup_ff','startup_busy','stall_failure','enable_failure','enable_false_success'):assert not m.dev.writes
        if count:
            before=len(m.dev.packets);m.call('engine_run',1);assert len(m.dev.packets)==before,'same-boot replay'
        if case=='restore_failure':
            before=len(m.dev.packets);writes=len(m.pci_writes)
            assert m.call('engine_run',0)!=0
            assert len(m.dev.packets)==before and len(m.pci_writes)==writes,'Do not resume hardware access after unconfirmed PCI restore'
        row=dict(case=case,passed=True,status=f'{status:016X}',oem_packets=count,requests=len(m.dev.packets),delay_ms=m.elapsed_ms,pci_writes=m.pci_writes,nv_writes=m.nv_writes)
        rows.append(row);print(case,'PASS',flush=True)
        if case in ('success','postcheck_unchanged','startup_c1'):(OUT/f'OFFLINE-{case}.txt').write_text('OFFLINE EMULATION / NOT HARDWARE EVIDENCE\n'+log,encoding='utf-8')
    m=Machine();assert m.call('engine_run',0)==0;assert not m.dev.oem_packets and not m.nv_writes
    rows.append(dict(case='read_only_no_oem_no_nv_write',passed=True))
    for mode in ('auto_disabled','success'):
        m=Machine(mode);m.call('ready_callback',0,0);before=len(m.dev.packets);m.call('ready_callback',0,0)
        assert len(m.dev.packets)==before
        assert len(m.dev.oem_packets)==(0 if mode=='auto_disabled' else 4)
        rows.append(dict(case='ready_to_boot_once_'+mode,passed=True))
    # A new boot inherits the persistent lock; no OEM replay after partial failure.
    m=Machine('reject_step_2');m.call('engine_run',1);next_boot=Machine();next_boot.vars=copy.deepcopy(m.vars)
    assert next_boot.call('engine_run',1)==ERR(15) and not next_boot.dev.packets
    rows.append(dict(case='new_boot_pending_lock_blocks_replay',passed=True))
    # Configuration integrity and wear: unchanged values do not write NVRAM.
    m=Machine();cfg=m.alloc(GOOD);assert m.call('config_write',cfg)==0 and not m.nv_writes
    for bad in (b'BROKEN!!',GOOD[:4]+b'\x02'+GOOD[5:],GOOD[:-1]+b'\x01'):
        assert m.call('config_write',m.alloc(bad))==ERR(2) and not m.nv_writes
    rows.append(dict(case='config_integrity_and_no_redundant_writes',passed=True))
    for enabled in (False,True):
        m=Machine('prior_lock')
        if not enabled:m.vars['HeroIpmiCfg']=(3,GOOD[:4]+b'\0'+GOOD[5:])
        assert m.call('api_unlock')==(ERR(15) if enabled else 0)
        assert ('HeroIpmiAttempt' in m.vars)==enabled
        assert not m.dev.writes and not m.pci_writes
        rows.append(dict(case='unlock_requires_saved_disabled_'+str(enabled),passed=True))
    m=Machine();assert m.call('api_run',2)==ERR(2) and not m.dev.packets
    rows.append(dict(case='api_rejects_unknown_operation',passed=True))
    m=Machine();m.vars={};cfg=m.alloc(bytes(8));source=m.alloc(bytes(4))
    assert m.call('api_config',cfg,source)==0
    assert bytes(m.u.mem_read(cfg,8))==GOOD and m.r64(source)&0xffffffff==0 and not m.nv_writes
    assert m.call('api_enable',0)==0 and m.vars['HeroIpmiCfg'][1][4]==0
    assert m.call('api_enable',0)==0 and len(m.nv_writes)==1
    rows.append(dict(case='missing_default_enabled_explicit_disable_persisted',passed=True))
    m=Machine();m.vars={};assert m.call('api_enable',1)==0 and m.vars['HeroIpmiCfg'][1]==GOOD
    rows.append(dict(case='explicit_enable_creates_record_even_when_default_matches',passed=True))
    (OUT/'verification.json').write_text(json.dumps(dict(driver_sha256=hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiR2.efi').read_bytes()).hexdigest(),cases=rows,count=len(rows),all_passed=True,limitations=['Synthetic devices and recorded response replay; not a target motherboard test.','Entry lifecycle and actual QEMU console tests are recorded separately.']),indent=2)+'\n')
    print('ALL PASS',len(rows))
if __name__=='__main__':run()
