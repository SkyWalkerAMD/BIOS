"""Execute final R3 PE in Unicorn. Synthetic services only; no hardware/network.

SMBIOS and baseline reads come from .71 captures. OEM effects/readbacks and
post-initialization sensor state are simulation, not new real-machine evidence.
"""
from pathlib import Path
import hashlib,json,re,struct,uuid,copy,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
import verify as core
from unicorn.x86_const import *
ERR=core.ERR
capture=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT'
TABLE=bytes.fromhex(capture.read_text().split('TABLE_HEX_BEGIN')[1].split('TABLE_HEX_END')[0])
BASELINE=ROOT/'analysis/hero_ipmi_complete_live_20261108/probe/baseline-before.json'
BASE=json.loads(BASELINE.read_text())
BOARD=(ROOT/'analysis/hero_dashboard_20261108/donor/hero71-selector2.request.bin').read_bytes()
BIOS=(ROOT/'analysis/hero_dashboard_20261108/donor/hero71-selector0.request.bin').read_bytes()

class Device(core.Device):
    def __init__(self,case='success',dmi='equal',latest=False):
        super().__init__(case,full=False);self.dmi_case=dmi;self.dmi_writes=[];self.dmi_reads=[]
        self.files={2:BOARD[1:],0:BIOS[1:]} if dmi=='equal' else {2:b'',0:b''}
        if dmi=='long':self.files[2]=BOARD[1:]+b'EXTRA\0'
        if dmi=='malformed':self.files[2]=b'broken'
        if latest:
            events=[e for e in BASE['events'] if e['type']=='read' and e.get('ok')]
            self.records=[bytes.fromhex(e['response_hex'])[2:] for e in events if (e['netfn'],e['command'])==(10,35)]
            self.readings={int(e['request_hex'],16):b'\x14\x2d\0'+bytes.fromhex(e['response_hex']) for e in events if (e['netfn'],e['command'])==(4,45)}
    def response(self,tx):
        tx=bytes(tx)
        if tx[:2] not in (b'\xc0\x03',b'\xc0\x04'):return super().response(tx)
        self.packets.append(tx);selector=tx[2];assert selector in (0,2)
        if tx[1]==3:
            assert tx[3:]==b'\0\0\xc0';self.dmi_reads.append(selector)
            body=self.files[selector][:192]
            if self.dmi_case=='read_reject':return b'\xc4\x03\xc1'
            if self.dmi_case=='read_short':return b'\xc4\x03\0\x02\x00'
            if self.dmi_case=='readback_bad' and self.dmi_writes:body=b'X'+body[1:]
            return b'\xc4\x03\0'+bytes([len(body)])+body
        self.dmi_writes.append(tx)
        if self.dmi_case=='set_reject':return b'\xc4\x04\xc1'
        if self.dmi_case=='set_timeout':self.oem_timeout=True
        if self.dmi_case=='set_bad_header':return b'\x00\x04\0'
        self.files[selector]=tx[3:]+self.files[selector][len(tx)-3:]
        return b'\xc4\x04\0'+bytes([len(tx)-3+(1 if self.dmi_case=='set_bad_count' else 0)])

class Machine(core.Machine):
    def __init__(self,case='success',dmi='equal',fault='',latest=False,table=TABLE):
        super().__init__(case);self.dev=Device(case,dmi,latest);self.fault=fault
        self.sm_table=table;self.smptr=self.alloc(table);self.set_table(self.smptr,len(table))
    def set_table(self,address,length):
        ep=bytearray(24);ep[:5]=b'_SM3_';ep[6:9]=bytes([24,3,5]);ep[10]=1
        struct.pack_into('<IQ',ep,12,length,address);ep[5]=(-sum(ep))&255
        self.ep=self.alloc(ep);self.ct=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',self.ep))
        self.w64(self.st+0x68,1);self.w64(self.st+0x70,self.ct)
    def _return(self,u,name,value):
        self.calls.append(name);u.reg_write(UC_X86_REG_RAX,value)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if not name:return
        rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f=[self.r64(rsp+o) for o in (0x28,0x30)]
        result=0;handled=True
        if name=='MemWrite':
            assert a==self.pci and b==0 and c==1 and d in (0xe88,0xe8c) and e==1 and self.config[4]&2
            old=(len(self.dev.oem_packets),len(self.dev.dmi_writes));self.dev.write(d==0xe8c,u.mem_read(f,1)[0])
            if len(self.dev.oem_packets)>old[0]:assert 'HeroIpmiAttempt' in self.vars
            if len(self.dev.dmi_writes)>old[1]:assert 'HeroIpmiDmiAttempt' in self.vars
        elif name in ('GetVariable','SetVariable') and self.wide(a)=='HeroIpmiDmiAttempt':
            assert str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==core.CONFIG_GUID
            if name=='GetVariable':
                if self.fault=='dmi_lock_read':result=ERR(7)
                elif 'HeroIpmiDmiAttempt' not in self.vars:result=ERR(14)
                else:
                    attrs,data=self.vars['HeroIpmiDmiAttempt'];n=self.r64(d);self.w64(d,len(data))
                    if n<len(data):result=ERR(5)
                    else:
                        if c:u.mem_write(c,struct.pack('<I',attrs))
                        u.mem_write(e,data)
            else:
                data=bytes(u.mem_read(e,d)) if d else b'';self.nv_writes.append(('HeroIpmiDmiAttempt',c,data.hex(),len(self.dev.dmi_writes)))
                if self.fault=='dmi_lock_write' or (not d and self.fault=='dmi_lock_delete'):result=ERR(7)
                elif self.fault=='dmi_lock_false':pass
                elif d:self.vars['HeroIpmiDmiAttempt']=(c,data)
                else:self.vars.pop('HeroIpmiDmiAttempt',None)
        elif name=='GetMemoryMap' and self.fault:
            if self.fault=='map_error':result=ERR(7)
            elif self.fault in ('map_mmio','map_stride','map_version','map_high'):
                desc=struct.pack('<IIQQQQ',11 if self.fault=='map_mmio' else 4,0,0x100000,0,4096,0)
                if self.fault=='map_high':desc+=struct.pack('<IIQQQQ',4,0,0x100000000,0,16,0)
                u.mem_write(b,desc);self.w64(a,len(desc));self.w64(c,1);self.w64(d,32 if self.fault=='map_stride' else 40);u.mem_write(e,struct.pack('<I',2 if self.fault=='map_version' else 1))
            else:handled=False
        else:handled=False
        if handled:self._return(u,name,result)
        else:super().hook(u,addr,size,user)

def run():
    rows=[]
    def record(name,m,status):
        assert not(m.config[4]&2),(name,'PCI bit leaked')
        rows.append(dict(case=name,passed=True,status=f'{status:016X}',sensors_set=len(m.dev.oem_packets),dmi_set=len(m.dev.dmi_writes),requests=len(m.dev.packets)))
        print(name,'PASS',flush=True)
    for name,mode,fault,expected in [
        ('equal_no_writes','equal','',0),('empty_publish','empty','',2),('read_reject','read_reject','',0),('read_short','read_short','',0),
        ('set_reject','set_reject','',1),('set_bad_count','set_bad_count','',1),('set_bad_header','set_bad_header','',1),
        ('readback_bad','readback_bad','',1),('no_truncation','long','',0),('malformed_prior','malformed','',0),
        ('latch_failure','empty','dmi_lock_write',0),('latch_false_success','empty','dmi_lock_false',0),('latch_unreadable','empty','dmi_lock_read',0),
        ('latch_delete_failure','empty','dmi_lock_delete',2)]:
        m=Machine(dmi=mode,fault=fault);s=m.call('r3_run',0x102)
        assert len(m.dev.dmi_writes)==expected,(name,m.audit()[-1500:])
        assert (s==0)==(name in ('equal_no_writes','empty_publish')),(name,s,m.audit()[-1500:])
        assert not m.dev.oem_packets
        if name=='equal_no_writes':assert not m.nv_writes
        if name=='empty_publish':assert m.dev.dmi_writes==[b'\xc0\x04'+BOARD,b'\xc0\x04'+BIOS] and not m.vars.get('HeroIpmiDmiAttempt')
        if expected and name!='empty_publish':assert 'HeroIpmiDmiAttempt' in m.vars
        if expected:
            before=len(m.dev.dmi_writes);assert m.call('r3_run',0x102)!=0;assert len(m.dev.dmi_writes)==before
        record(name,m,s)
    m=Machine(dmi='empty');s=m.call('r3_run',2);assert s==0 and not m.dev.dmi_writes and not m.nv_writes;record('compare_never_sets',m,s)
    m=Machine(dmi='empty');m.vars['HeroIpmiAttempt']=(3,b'unknown');s=m.call('r3_run',0x103)
    assert s==ERR(15) and not m.dev.oem_packets and len(m.dev.dmi_writes)==2;record('sensor_latch_does_not_skip_identity',m,s)
    m=Machine(case='already_initialized',dmi='empty');s=m.call('r3_run',0x103)
    assert s==0 and not m.dev.oem_packets and len(m.dev.dmi_writes)==2;record('already_initialized_does_not_skip_identity',m,s)
    m=Machine(dmi='empty');m.vars['HeroIpmiDmiAttempt']=(3,b'unknown');s=m.call('r3_run',0x103)
    assert s==ERR(15) and len(m.dev.oem_packets)==4 and not m.dev.dmi_writes;record('identity_latch_does_not_skip_sensors',m,s)
    bad=TABLE.replace(b'11/28/2025',b'99/99/2025');m=Machine(table=bad);s=m.call('r3_run',0x103)
    assert len(m.dev.oem_packets)==4 and not m.dev.dmi_reads and s!=0;record('bad_identity_date_does_not_block_sensors',m,s)
    m=Machine(case='oem_bad_header',dmi='empty');s=m.call('r3_run',0x103)
    assert len(m.dev.oem_packets)==2 and not m.dev.dmi_reads and s!=0;record('sensor_transport_poison_blocks_identity',m,s)
    m=Machine(case='success',dmi='equal',latest=True);s=m.call('r3_run',0x103)
    assert s==0 and len(m.dev.oem_packets)==4 and not m.dev.dmi_writes
    (OUT/'OFFLINE-latest71-and-dashboard.txt').write_text('OFFLINE replay / synthetic KCS and OEM effects / not hardware evidence\n'+m.audit())
    record('latest71_baseline_and_already_synced_dashboard',m,s)
    for fault in ('map_error','map_mmio','map_stride','map_version'):
        m=Machine(fault=fault);s=m.call('r3_run',0x103);assert s and not m.dev.packets;record(fault,m,s)
    m=Machine(fault='map_high');m.u.mem_map(0x100000000,65536);m.u.mem_write(0x100000000,TABLE);m.set_table(0x100000000,len(TABLE))
    s=m.call('identity_read');assert s==0;record('smbios3_pointer_above_4GiB',m,s)
    m=Machine();m.tpl=16;s=m.call('r3_run',0x103);assert s==ERR(3) and m.tpl==16 and not m.dev.packets;record('TPL_NOTIFY_rejected_before_hardware',m,s)
    m=Machine();m.call('identity_read');v=bytes(m.u.mem_read(m.functions['local_identity'],412))
    assert v[180:197]==BIOS and v[197:197+len(BOARD)]==BOARD
    assert struct.unpack_from('<IIIII',v,392)==(17,70,0x97f9e765,len(TABLE),1);record('local_identity_exact_donor_and_live_bytes',m,0)
    m=Machine();out=m.alloc(bytes(412))
    for n in (0,5,262145):assert m.call('identity_parse',m.smptr,n,out)!=0
    for data in (TABLE[:-1],TABLE[:-6],TABLE+b'ignored',TABLE.replace(b'3107\0',b'31\x017\0')):
        s=m.call('identity_parse',m.alloc(data),len(data),out)
        assert (s==0)==data.endswith(b'ignored')
    record('parse_bounds_and_end_marker',m,0)
    summary=next(e for e in BASE['events'] if e['type']=='summary')
    target=[1,3,0x17,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x29]
    have={s['sensor_number'] for s in summary['sensors']}
    report=dict(all_passed=True,count=len(rows),cases=rows,driver_sha256=hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiR5.efi').read_bytes()).hexdigest(),
        baseline_sha256=hashlib.sha256(BASELINE.read_bytes()).hexdigest(),baseline=summary['sdr'],target_ids_present=[x for x in target if x in have],
        version_err=next(s for s in summary['sensors'] if s['sensor_number']==251),
        limitations=['OEM effects are synthetic. Real fresh-BMC R4 execution remains required.','The final .71 baseline payloads are replayed through an emulated KCS interface.'])
    (OUT/'r3-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('R3 ALL PASS',len(rows))
if __name__=='__main__':run()
