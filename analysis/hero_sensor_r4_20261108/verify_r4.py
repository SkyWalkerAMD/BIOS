"""Execute the real R4 PE with synthetic UEFI/KCS, no hardware/network.
Real V3b/apply bytes establish only the map/SDR interpretation; fresh scanner
timing and failure injections here remain a device model, not a motherboard test.
"""
from pathlib import Path
import json,hashlib,struct,copy
import verify as core
from unicorn.x86_const import *
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
ERR=core.ERR

class Device(core.Device):
    def __init__(self,fault=''):
        super().__init__('success');self.fault=fault
        if fault=='existing62':self.maps[1][2]=0x62
        if fault=='custom_index2':self.maps[1][2]=0x61
        if fault=='preserve_other14':
            self.maps[1][:]=bytes([0x60,0x61,0]+list(range(0x63,0x6f)))
        if fault=='custom_mode':self.maps[0][0]=1
        if fault=='custom_pwm':self.maps[2][7]=0x62
        if fault=='custom_type':self.maps[3][7]=2
        if fault in ('already_zero','already62'):
            self.post()
            if fault=='already62':self.maps[1][2]=0x62
        if fault=='fresh_but_visible20':
            r=(ROOT/'analysis/hero_fan_apply_20261108/fixtures/mb-cha-fan1-sdr.bin').read_bytes()
            self.records.append(r);self.readings[0x20]=bytes.fromhex('142d0000a0c000')
        self.initial_maps=copy.deepcopy(self.maps)
    def response(self,tx):
        tx=bytes(tx)
        if tx[:2]==b'\xc0\x9a':
            if tx[3]==0:
                at=self.fan_gets+1
                if self.fault=='drift_after_board' and at==5:self.maps[1][3]^=1
                if self.fault=='drift_before_set' and at==9:self.maps[1][3]^=1
                if self.fault=='readback_wrong' and at==13:self.maps[1][2]=0
                if self.fault=='post_init_control_drift' and at==17:self.maps[2][8]=9
                reply=super().response(tx)
                if self.fault==f'get_reject_{at}':return b'\xc4\x9a\xc1'
                if self.fault==f'get_short_{at}':return reply[:-1]
                return reply
            reply=super().response(tx)
            if self.fault=='set_echo_wrong':return reply[:-1]+bytes([reply[-1]^1])
            if self.fault=='set_bad_header':return b'\0\x9a\0'+reply[3:]
            if self.fault=='set_reject':return b'\xc4\x9a\xc1'
            if self.fault=='set_timeout':self.oem_timeout=True
            return reply
        reply=super().response(tx)
        if tx==core.base.EXPECTED_OEM[3] and self.fault=='post_sdr_wrong':
            self.records=[r[:24]+bytes([r[24]^1])+r[25:] if len(r)>7 and r[7]==0x20 else r for r in self.records]
        if tx==bytes.fromhex('102d20'):
            if self.fault=='fan_unavailable':return bytes.fromhex('142d0000a0c000')
            return bytes.fromhex('142d00')+bytes([23 if self.maps[1][2]==0x62 else 0,0xc0,0xc0,0])
        return reply

class Machine(core.Machine):
    def __init__(self,fault='',case='success'):
        super().__init__(case);self.dev=Device(fault)
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name=='MemWrite':
            rsp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
            e,f=[self.r64(rsp+x) for x in (0x28,0x30)]
            assert a==self.pci and b==0 and c==1 and d in (0xe88,0xe8c) and e==1 and self.config[4]&2
            previous=len(self.dev.oem_packets)+len(self.dev.fan_writes)
            self.dev.write(d==0xe8c,u.mem_read(f,1)[0])
            if len(self.dev.oem_packets)+len(self.dev.fan_writes)>previous:assert 'HeroIpmiAttempt' in self.vars
            self.calls.append(name);u.reg_write(UC_X86_REG_RAX,0)
            for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)
        else:super().hook(u,addr,size,user)

def main():
    rows=[]
    cases=[('',4,1,True),('existing62',4,0,True),('preserve_other14',4,1,True),
      ('custom_index2',0,0,False),('custom_mode',0,0,False),('custom_pwm',0,0,False),('custom_type',0,0,False),
      ('fresh_but_visible20',0,0,False),('already_zero',0,0,True),('already62',0,0,True),
      ('drift_after_board',1,0,False),('drift_before_set',1,0,False),
      ('set_echo_wrong',1,1,False),('set_bad_header',1,1,False),('set_reject',1,1,False),('set_timeout',1,1,False),
      ('readback_wrong',1,1,False),('post_init_control_drift',4,1,False),('post_sdr_wrong',4,1,False),
      ('fan_unavailable',4,1,True)]
    cases += [(f'get_{fault}_{n}',0 if n<=4 else 1,0 if n<=12 else 1,False) for fault in ('reject','short') for n in (1,4,5,9,13,16)]
    for fault,oems,fan,ok in cases:
        m=Machine(fault);st=m.call('engine_run',1);audit=m.audit()
        assert (st==0)==ok,(fault,hex(st),audit[-2500:])
        assert len(m.dev.oem_packets)==oems and len(m.dev.fan_writes)==fan,(fault,audit[-2500:])
        assert len(m.dev.fan_writes)<=1 and m.dev.oem_packets==core.base.EXPECTED_OEM[:oems]
        assert not(m.config[4]&2),(fault,'PCI Command not restored')
        if oems:
            assert ('HeroIpmiAttempt' not in m.vars)==ok
            before=len(m.dev.packets);m.call('engine_run',1);assert len(m.dev.packets)==before
        else:assert not m.nv_writes
        if ok and fan:
            for i in range(15):
                if i!=2:assert m.dev.maps[1][i]==m.dev.initial_maps[1][i]
            assert m.dev.maps[1][2]==0x62
        if fault in ('','preserve_other14','fan_unavailable'):
            (OUT/('OFFLINE-r4-'+(fault or 'success')+'.txt')).write_text('SIMULATED KCS/UEFI; NOT FRESH-BMC HARDWARE EVIDENCE\n'+audit)
        rows.append(dict(case=fault or 'fresh_success',passed=True,status=f'{st:016X}',original_oem=oems,rpm_set=fan,requests=len(m.dev.packets)))
        print(fault or 'fresh_success','PASS',flush=True)
    # Read-only inspection and repeat boots never compensate or restore a zero map.
    for fault in ('','already_zero','already62','custom_index2'):
        m=Machine(fault);st=m.call('engine_run',0);assert st==0 and not m.dev.fan_writes and not m.dev.oem_packets and not m.nv_writes
        rows.append(dict(case='read_only_'+(fault or 'fresh'),passed=True))
    m=Machine();m.call('engine_run',1);n=Machine('already62');n.vars=copy.deepcopy(m.vars)
    assert n.call('engine_run',1)==0 and not n.dev.fan_writes and not n.dev.oem_packets and not n.nv_writes
    rows.append(dict(case='new_boot_no_replay',passed=True))
    # One-use low-level setter rejects arbitrary selectors/differences; no calls.
    m=Machine();k=m.alloc(bytes(272));before=m.alloc(bytes(15));after=m.alloc(bytes([0,0,0x62])+bytes(12))
    assert m.call('rpm_arm',k,before,after)==0
    m.u.mem_write(k+40,struct.pack('<II',1,1));assert m.call('rpm_arm',k,before,after)==1
    for idx in (0,1,3,14):
        bad=bytearray(15);bad[2]=0x62;bad[idx]=1;assert m.call('rpm_arm',k,before,m.alloc(bad))==0
    m.u.mem_write(k+52,struct.pack('<I',1));assert m.call('rpm_arm',k,before,after)==0
    assert not m.dev.packets
    rows.append(dict(case='low_level_preimage_stage_and_consumption_guards',passed=True))
    result={'all_passed':True,'count':len(rows),'cases':rows,'driver_sha256':hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiR4.efi').read_bytes()).hexdigest(),
      'limits':['UEFI/KCS devices are synthetic. Real fresh-BMC R4 sequence is pending.','R3 lifecycle and dashboard regression results are separate.']}
    (OUT/'r4-verification.json').write_text(json.dumps(result,indent=2)+'\n');print('R4 ALL PASS',len(rows))
if __name__=='__main__':main()
