"""Failure-injection tests of the actual B2c EFI, not a recovery reimplementation.

The device double implements the KCS abort exchange described by IPMI 9.18.
All responses after recovery are earlier real A2/B1 fixtures or explicit mocks.
No target hardware is accessed.
"""
import struct, uuid
import verify_hero_ipmi_fan_b2c as base
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RSP,UC_X86_REG_RAX

class RecoveryDevice(base.FanDevice):
    def __init__(self,case):
        super().__init__('combo_init_fan' if case=='explicit_i_f' else 'accepted_still_unavailable',False)
        self.recovery_case=case;self.phase='initial';self.state=0xc0
        self.obf=case!='error_c0';self.status_count=0;self.phase_reads=0
        self.reads=[];self.post_status_count=0;self.m=None
        self.abort_writes=[]

    def read(self,reg):
        case=self.recovery_case
        if self.phase=='normal':
            if reg and not self.packets and 'KCS_RECOVERY_HANDSHAKE_COMPLETE' in self.m.output:
                self.post_status_count+=1
                if case=='ff_after_handshake':return 255
                if case=='busy_after_handshake':return 0x82
                if case=='ff_first_transfer' and self.post_status_count==4:return 255
                if case=='ff_after_write_start' and len(self.writes)==4:return 255
            return super().read(reg)
        if reg:
            self.status_count+=1;self.phase_reads+=1
            if self.phase=='initial':
                if case=='transient_error' and self.status_count>1:
                    self.state=0;self.obf=False;self.phase='normal';return 0
                if case in ('input_busy','initial_read','initial_write','initial_attention'):
                    return {'input_busy':0xc3,'initial_read':0x41,'initial_write':0x81,'initial_attention':0xc5}[case]
                if 'KCS_RECOVERY_BEGIN' in self.m.output:
                    if case=='entry_ff':return 255
                    if case=='entry_busy':return 0xc3
                    if case=='entry_idle':return 0
                if case=='ff_before_error' and self.status_count<=2:return 255
            if self.phase in ('abort','code','final'):
                if case=='status_ff_'+self.phase:return 255
                if case=='attention_'+self.phase:return self.state|4|int(self.obf)
                if case=='wrong_state_'+self.phase:return { 'abort':0xc0,'code':0x80,'final':0x40 }[self.phase]
                if case=='ibf_timeout_'+self.phase:return self.state|2|int(self.obf)
                if case=='delayed_ibf' and self.phase_reads<=3:return self.state|2|int(self.obf)
                if case=='delayed_obf' and self.phase in ('code','final') and self.phase_reads<=4:return self.state
                if case=='obf_timeout_'+self.phase:return self.state
            value=self.state|int(self.obf)
            if case=='command_data_bit' and self.phase=='abort':value|=8
            self.reads.append((1,value,self.phase));return value
        assert self.obf,('data read with OBF clear',case,self.phase)
        self.obf=False
        value={'initial':0x5a,'abort':0,'code':1,'final':0}[self.phase]
        if self.phase=='code':value={'error_code_zero':0,'error_code_illegal':2,'error_code_length':6,'error_code_ff':255,'error_code_oem':0xc1}.get(case,1)
        self.reads.append((0,value,self.phase))
        if self.phase=='final':self.phase='normal'
        return value

    def write(self,reg,value):
        if self.phase=='normal':return super().write(reg,value)
        assert not self.obf,('write before clearing OBF',self.phase)
        self.writes.append((reg,value));self.abort_writes.append((reg,value))
        if self.phase=='initial':
            assert (reg,value)==(1,0x60)
            self.phase='abort';self.state=0x80;self.obf=self.recovery_case!='no_write_dummy'
        elif self.phase=='abort':
            assert (reg,value)==(0,0)
            self.phase='code';self.state=0x40;self.obf=True
        elif self.phase=='code':
            assert (reg,value)==(0,0x68)
            self.phase='final';self.state=0;self.obf=True
        else:raise AssertionError(('unexpected recovery write',self.phase,reg,value))
        self.phase_reads=0

class RecoveryMachine(base.Machine):
    def __init__(self,case):
        super().__init__('normal' if case=='bios_3001' else 'real_3107')
        self.recovery_case=case;self.dev=RecoveryDevice(case);self.dev.m=self
        self.keys=list(('p' if case=='bios_3001' else 'e')+'kqq')
        if case=='decline':self.keys=list('eqq')
        if case=='explicit_i_f':self.keys=list('ekifqq')
        if case=='uppercase_k':self.keys=list('EKQQ')
        if case=='repeat_k':self.keys=list('ekkqq')
        self.mutated=False;self.injected=False

    def hook(self,uc,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        a,b,c,d=[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        rsp=uc.reg_read(UC_X86_REG_RSP);e=self.r64(rsp+0x28)
        case=self.recovery_case;active='KCS_RECOVERY_BEGIN' in self.output and 'KCS_RECOVERY_HANDSHAKE_COMPLETE' not in self.output and 'KCS_RECOVERY_STOPPED' not in self.output
        before_phase=self.dev.phase
        log_failed=False
        if name=='WriteFile':
            chunk=bytes(uc.mem_read(c,self.r64(b)))
            needles={'log_prompt':b'K = attempt', 'log_begin':b'KCS_RECOVERY_BEGIN',
                'log_before_abort':b'WRITE_INTENT phase=GET_STATUS_ABORT',
                'log_before_data':b'WRITE_INTENT phase=REQUEST_ERROR_CODE',
                'log_before_finish':b'WRITE_INTENT phase=FINISH_READ',
                'log_after_abort':b'WRITE_RESULT phase=GET_STATUS_ABORT',
                'log_after_code':b'DATA phase=ERROR_CODE',
                'log_complete':b'KCS_RECOVERY_HANDSHAKE_COMPLETE'}
            needle=needles.get(case)
            log_failed=bool(needle and needle in chunk)
        if name=='PciRead' and active and not self.mutated:
            if case=='bar_changed':self.config[22]^=1;self.mutated=True
            if case=='decode_cleared':self.config[4]&=~2;self.mutated=True
            if case=='identity_changed':self.config[0]^=1;self.mutated=True
        old=self.case
        if log_failed:self.case='log_failure'
        super().hook(uc,addr,size,user);self.case=old
        if name=='ReadFile' and case=='old_b2b_marker':
            uc.mem_write(c,b'HERO-IPMI-FAN--B2b\r\n');self.w64(b,20)
        if name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(uc.mem_read(a,16))))
            if guid=='4a1d0e66-5271-4e22-83fe-90921b748213':
                if case=='resident_driver' or (active and case=='driver_appears'):
                    self.w64(c,0x707700);uc.reg_write(UC_X86_REG_RAX,0)
                if active and case=='protocol_lookup_error':uc.reg_write(UC_X86_REG_RAX,base.ERR(7))
        if active and name=='Location':
            if case=='wrong_bdf':self.w64(c,5)
            if case=='location_error':uc.reg_write(UC_X86_REG_RAX,base.ERR(7))
        if active and name=='PciRead' and case=='pci_failure':uc.reg_write(UC_X86_REG_RAX,base.ERR(7))
        if active and name=='Stall' and case=='stall_failure':uc.reg_write(UC_X86_REG_RAX,base.ERR(7))
        if active and name=='MemWrite' and case=='write_error_'+before_phase:
            uc.reg_write(UC_X86_REG_RAX,base.ERR(7));self.injected=True
        if active and name=='MemRead':
            if d==0xe88 and case=='data_error_'+before_phase:
                uc.reg_write(UC_X86_REG_RAX,base.ERR(7));self.injected=True
            if d==0xe8c and case=='status_error_'+before_phase:
                uc.reg_write(UC_X86_REG_RAX,base.ERR(7));self.injected=True
        if active and name=='FlushFile' and case=='flush_failure' and self.dev.abort_writes:
            uc.reg_write(UC_X86_REG_RAX,base.ERR(7));self.injected=True

def scenarios():
    successful=['error_c1','error_c0','command_data_bit','delayed_ibf','delayed_obf','no_write_dummy',
        'error_code_zero','error_code_illegal','error_code_length','error_code_ff','error_code_oem',
        'uppercase_k','repeat_k','explicit_i_f','ff_before_error']
    blocked=['decline','input_busy','initial_read','initial_write','initial_attention',
        'entry_ff','entry_busy','entry_idle','bios_3001','resident_driver','driver_appears','protocol_lookup_error',
        'wrong_bdf','location_error','bar_changed','identity_changed','decode_cleared','pci_failure',
        'old_b2b_marker','log_prompt','log_begin','log_before_abort','data_error_initial','status_error_initial']
    failed=['log_before_data','log_before_finish','log_after_abort','log_after_code','log_complete','flush_failure']
    failed += [prefix+phase for prefix in ('status_ff_','attention_','wrong_state_','ibf_timeout_','status_error_') for phase in ('abort','code','final')]
    failed += ['obf_timeout_code','obf_timeout_final','write_error_initial','write_error_abort','write_error_code',
        'data_error_abort','data_error_code','data_error_final','stall_failure']
    after=['ff_after_handshake','busy_after_handshake','ff_first_transfer','ff_after_write_start']
    cases=successful+blocked+failed+after+['transient_error']
    results=[]
    for case in cases:
        m=RecoveryMachine(case)
        if case=='stall_failure':
            # Make the device wait in the first handshake phase to exercise Stall.
            original_read=m.dev.read
            def read(reg,original=original_read,dev=m.dev):
                return 0x82 if reg and dev.phase=='abort' else original(reg)
            m.dev.read=read
        try:m.run()
        except Exception:
            (base.OUT/'FAILED-recovery-output.txt').write_text(m.output,encoding='utf-8')
            raise
        dev=m.dev
        assert dev.abort_writes==[(1,0x60),(0,0),(0,0x68)][:len(dev.abort_writes)],case
        assert len(dev.abort_writes)<=3 and m.output.count('KCS_RECOVERY_BEGIN')<=1,case
        assert m.recovery_waits<=999 and m.startup_waits<=34,(case,m.recovery_waits,m.startup_waits)
        if case in successful or case=='transient_error':
            assert 'GET_DEVICE_ID_OK' in m.output and 'SDR_SCAN_COMPLETE' in m.output,case
            assert dev.packets[0]==bytes.fromhex('1801')
            if case=='transient_error':assert not dev.abort_writes and 'KCS_RECOVERY_BEGIN' not in m.output
            else:assert len(dev.abort_writes)==3 and 'KCS_RECOVERY_HANDSHAKE_COMPLETE' in m.output
        else:
            assert not dev.packets,(case,[x.hex() for x in dev.packets])
            if case in blocked:assert not dev.abort_writes,case
        if case=='ff_after_write_start':assert dev.writes==[(1,0x60),(0,0),(0,0x68),(1,0x61)]
        if case=='explicit_i_f':
            assert dev.oem_packets==base.EXPECTED_OEM and len(dev.fan_packets)==14
            assert 'FAN_SEQUENCE_ACCEPTED' in m.output
        else:assert not dev.oem_packets and not dev.fan_packets,case
        if case in ('error_code_zero','error_code_illegal','error_code_length','error_code_ff','error_code_oem'):
            expected={'error_code_zero':'00','error_code_illegal':'02','error_code_length':'06','error_code_ff':'FF','error_code_oem':'C1'}[case]
            assert 'KCS_RECOVERY_ERROR_CODE='+expected in m.output
        if case=='decline':assert not dev.writes and not any(r[0]==0 for r in dev.reads)
        if case=='identity_changed':assert 'PCI_MEMORY_RESTORE_UNCONFIRMED' in m.output
        elif case!='bios_3001':assert m.config[4]&2==0
        assert m.config[6:8]==base.REAL_CONFIG[6:8]
        if case=='bios_3001':assert not m.pci_writes
        results.append(dict(case='B2c_recovery_'+case,passed=True,
            recovery_writes=dev.abort_writes,recovery_waits=m.recovery_waits,startup_waits=m.startup_waits,
            recovery_reads=dev.reads,complete_ipmi_requests=len(dev.packets),
            oem_packets=[p.hex() for p in dev.oem_packets],fan_packets=[p.hex() for p in dev.fan_packets],
            pci_command_writes=m.pci_writes))
        print('B2c_recovery_'+case,'PASS',flush=True)
        if case in ('error_c1','decline','ibf_timeout_abort','explicit_i_f'):
            (base.OUT/('example-MOCK-B2c-recovery-'+case+'.txt')).write_bytes(b'OFFLINE SYNTHETIC KCS RECOVERY / NOT A TARGET HARDWARE LOG\r\n'+m.log)
    return results
