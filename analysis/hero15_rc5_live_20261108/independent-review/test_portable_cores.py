"""Independent actual-PE R5/S22 PCI selection/restore tests. No target access."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys, uuid
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'tools/pydeps'))
from unicorn.x86_const import *
R5 = ROOT/'analysis/hero_sensor_r5_20261108'
S22 = ROOT/'analysis/hero_p6_s22_20261108'
PIN_R5 = '81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4'
PIN_S22 = 'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75'
ERR = lambda n: (1 << 63) | n
LIVE = json.loads((HERE.parent/'host-read-01.json').read_text())
LIVE_CONFIG = {int(p['device'],16): bytes.fromhex(p['config64']) for p in LIVE['aspeed_pci']}

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod
    spec.loader.exec_module(mod);return mod

def pin(path,expected):
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    if len(expected)!=64 or actual!=expected:raise ValueError(f'Unapproved PE: {path.name} {actual}')
    return actual

def make_class(base):
    class Machine(base.Machine):
        def __init__(self,case='',bus=0x74,command=2,management_first=False):
            super().__init__()
            self.review_case=case;self.review_bus=bus
            self.config=bytearray(LIVE_CONFIG[0x2402]);struct.pack_into('<H',self.config,4,command)
            bridge=self.alloc(bytes(self.u.mem_read(self.pci,0x90)))
            vga=self.alloc(bytes(self.u.mem_read(self.pci,0x90)))
            self.devices={0x9001:(bridge,bytearray(LIVE_CONFIG[0x1150])),0x9002:(vga,bytearray(LIVE_CONFIG[0x2000])),0x9003:(self.pci,self.config)}
            self.order=[0x9003,0x9001,0x9002] if management_first else [0x9001,0x9002,0x9003]
            if case=='duplicate_bad_subsystem':
                self.devices[0x9002][1][:]=self.config;self.devices[0x9002][1][44]^=1
            self.pci_targets=[];self.mmio_targets=[];self.handle_reads=[];self.frees=[];self.allocations=[]
        def finish(self,u,name,result=0):
            self.calls.append(name);u.reg_write(UC_X86_REG_RAX,result)
            for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
        def hook(self,u,addr,size,user):
            name=self.stubs.get(addr)
            if not name:return
            sp=u.reg_read(UC_X86_REG_RSP)
            a,b,c,d=[u.reg_read(reg) for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
            e=self.r64(sp+0x28);case=self.review_case
            if name=='LocateHandles':
                self.w64(d,len(self.order));ptr=self.alloc(b''.join(struct.pack('<Q',x) for x in self.order))
                self.allocations.append(ptr);self.w64(e,ptr);self.finish(u,name);return
            if name=='HandleProtocol' and str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))=='4cf5b200-68b8-4ca5-9eec-b23e3f50029a':
                self.handle_reads.append(a);self.w64(c,self.devices[a][0])
                self.finish(u,name,ERR(7) if case=='later_handle_failure' and a==0x9002 else 0);return
            if name=='PciRead':
                config=next(v for p,v in self.devices.values() if p==a)
                self.pci_targets.append((name,a,b,c,d))
                if case=='later_config_failure' and a==self.devices[0x9002][0]:self.finish(u,name,ERR(7));return
                if (b,c,d)==(0,0,64):u.mem_write(e,bytes(config))
                else:
                    assert (b,c,d)==(1,4,1),(b,c,d)
                    u.mem_write(e,bytes(config[4:6]))
                self.finish(u,name);return
            if name=='PciWrite':
                assert a==self.pci and (b,c,d)==(1,4,1),'unexpected config write target/range'
                before=int.from_bytes(self.config[4:6],'little');wanted=int.from_bytes(u.mem_read(e,2),'little')
                assert before^wanted==2,'writes must change memory decode bit only'
                self.pci_targets.append((name,a,b,c,d));self.pci_writes.append((before,wanted))
                if case!='write_false_success':self.config[4:6]=wanted.to_bytes(2,'little')
                self.finish(u,name);return
            if name=='Location':
                assert a==self.pci
                for ptr,val in zip((b,c,d,e),(0,self.review_bus,1,0)):self.w64(ptr,val)
                self.finish(u,name);return
            if name=='BarAttributes':
                assert a==self.pci and b==1
                desc=bytearray(48);desc[:4]=bytes.fromhex('8a2b0000')
                bar=int.from_bytes(self.config[20:24],'little')&0xfffffff0
                length=0xffffffffffffffff if case=='range_wrap' else 0xe8c if case=='last_kcs_byte_missing' else 0x40000
                struct.pack_into('<Q',desc,14,bar);struct.pack_into('<Q',desc,22,bar+0x40000-1);struct.pack_into('<Q',desc,38,length);desc[46]=0x79
                ptr=self.alloc(bytes(desc));self.allocations.append(ptr);self.w64(c,0);self.w64(d,ptr);self.finish(u,name);return
            if name=='FreePool':
                assert a in self.allocations and a not in self.frees
                self.frees.append(a);self.finish(u,name);return
            if name in ('MemRead','MemWrite'):self.mmio_targets.append((name,a))
            return super().hook(u,addr,size,user)
    return Machine

def run_core(label,base):
    M=make_class(base);rows=[]
    def record(name,fn):fn();rows.append({'case':name,'passed':True})
    def unique(first):
        m=M(management_first=first);assert m.call('discover')==1
        assert m.handle_reads==m.order and m.r64(m.functions['card'])==m.pci
        assert m.allocations==m.frees
        assert not m.mmio_targets and not m.pci_writes and not m.nv_writes
    for first in (False,True):record('unique_three_interfaces_'+str(first),lambda first=first:unique(first))
    for case in ('duplicate_bad_subsystem','later_handle_failure','later_config_failure','range_wrap','last_kcs_byte_missing'):
        def check(case=case):
            m=M(case,management_first=True);assert m.call('discover')==0
            assert m.allocations==m.frees
            assert not m.mmio_targets and not m.pci_writes and not m.nv_writes
        record(case,check)
    for bus in (0,0x74,255,256,0x100000074):
        def check(bus=bus):
            m=M(bus=bus);assert bool(m.call('discover'))==(bus<=255)
            assert not m.mmio_targets and not m.pci_writes and not m.nv_writes
        record('location_width_'+str(bus),check)
    def already_enabled():
        m=M(command=7);assert m.call('discover')==1
        assert m.call('enable_memory')==1 and m.call('restore_memory')==1
        assert not m.pci_writes and m.config[4:6]==b'\x07\0'
    record('already_enabled_preserves_all_bits_without_write',already_enabled)
    def other_bits():
        m=M(command=5);assert m.call('discover')==1
        assert m.call('enable_memory')==1 and m.config[4:6]==b'\x07\0'
        m.config[5]|=1
        assert m.call('restore_memory')==1
        assert m.config[4:6]==b'\x05\x01' and m.pci_writes==[(5,7),(0x107,0x105)]
        assert all(x[1]==m.pci for x in m.pci_targets if x[0]=='PciWrite')
        assert not m.mmio_targets and not m.nv_writes
    record('restore_only_owned_bit_preserves_new_other_bit',other_bits)
    def false_success():
        m=M('write_false_success',command=0);assert m.call('discover')==1
        assert m.call('enable_memory')==0
        assert m.call('restore_memory')==1 and not m.mmio_targets
    record('enable_false_success_readback_stops',false_success)
    for off in (8,9,10,11,14,16,20,44,46):
        def check(off=off):
            m=M(command=0);assert m.call('discover')==1 and m.call('enable_memory')==1
            m.config[off]^=1;m.u.mem_write(m.functions['io_left'],struct.pack('<I',2));before=len(m.pci_writes)
            assert m.call('io_guard')==0 and m.call('restore_memory')==0
            assert len(m.pci_writes)==before and not m.mmio_targets and not m.nv_writes
        record('selected_identity_or_bar_drift_'+str(off),check)
    return {'core':label,'passed':True,'cases':rows,'count':len(rows)}

def main():
    pins={'r5':pin(R5/'USB/EFI/HERO/HeroIpmiR5.efi',PIN_R5),'s22':pin(S22/'HeroIpmiP6.efi',PIN_S22)}
    r5=load('review_r5_verify',R5/'verify.py');s22=load('review_s22_verify',S22/'verify_runtime.py')
    reports=[run_core('R5',r5),run_core('P6-S22',s22)]
    result={'passed':True,'pins':pins,'reports':reports,'count':sum(x['count'] for x in reports),
            'scope':'Actual PE selector/enable/guard/restore code with emulated UEFI services, no hardware. Existing fixture services reused; no production function stubbed. Does not replace complete core or launcher regression.'}
    (HERE/'portable-core-actual-pe-review.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'count':result['count'],'pins':pins},indent=2))
if __name__=='__main__':main()
