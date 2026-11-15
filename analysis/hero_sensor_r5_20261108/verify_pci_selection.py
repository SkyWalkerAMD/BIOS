"""Execute actual R5 PE PCI discovery/guards with bounded UEFI doubles. No hardware."""
from pathlib import Path
import hashlib,json,struct
import verify as core
from unicorn.x86_const import *

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
ERR=core.ERR
LIVE=json.loads((ROOT/'analysis/hero15_rc5_live_20261108/host-read-01.json').read_text('utf-8'))
assert hashlib.sha256((ROOT/'analysis/hero15_rc5_live_20261108/host-read-01.json').read_bytes()).hexdigest()=='26a6c61793e820e053044d9673297e2a0f1cf3643aaff81e8aafe5da5316dced'
CONFIG15=bytes.fromhex(next(x['config64'] for x in LIVE['aspeed_pci'] if x['device']=='0x2402'))

class Machine(core.Machine):
    def __init__(self,case='',bus=0x74):
        super().__init__('success')
        self.selector_case=case;self.bus_value=bus;self.config=bytearray(CONFIG15);self.selector_pci_reads=0
        self.free_count=0
        mutations={'vendor':(0,1),'device':(2,1),'revision':(8,2),'class':(11,3),'subclass':(10,6),
                   'prog_if':(9,0),'subsystem_vendor':(44,0x86),'subsystem_device':(46,3),'header':(14,1)}
        if case in mutations:
            offset,value=mutations[case];self.config[offset]=value
        if case=='bar0_64bit':self.config[16]|=4
        if case=='bar1_io':self.config[20]|=1
        if case=='bar1_64bit':self.config[20]|=4
        if case=='bar1_zero':self.config[20:24]=bytes(4)
        if case=='bar1_allones':self.config[20:24]=bytes.fromhex('f0ffffff')
        offsets={'missing_cfg_read':0x30,'missing_cfg_write':0x38,'missing_mem_read':0x10,
                 'missing_mem_write':0x18,'missing_location':0x70,'missing_bar':0x80}
        if case in offsets:self.w64(self.pci+offsets[case],0)
    def ret(self,u,name,result):
        self.calls.append(name);u.reg_write(UC_X86_REG_RAX,result)
        for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if not name:return
        rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e=self.r64(rsp+0x28);case=self.selector_case
        if name=='LocateHandles':
            count=0 if case=='zero_count' else 4097 if case=='too_many' else 2 if case in ('duplicate','duplicate_bad_subsystem','second_config_error') else 1
            if case=='enum_error':self.ret(u,name,ERR(7));return
            self.w64(d,count);self.w64(e,0 if case=='null_handles' else self.alloc(struct.pack('<Q',0x5555)*max(1,count)))
            self.ret(u,name,0);return
        if name=='HandleProtocol' and self.guid_at(b)=='4cf5b200-68b8-4ca5-9eec-b23e3f50029a':
            self.w64(c,0 if case=='null_pci' else self.pci);self.ret(u,name,ERR(7) if case=='handle_error' else 0);return
        if name=='PciRead':
            self.selector_pci_reads+=1
            if case=='config_error' or (case=='second_config_error' and self.selector_pci_reads==2):self.ret(u,name,ERR(7));return
            data=bytearray(self.config)
            if case=='duplicate_bad_subsystem' and self.selector_pci_reads==2:data[44]^=1
            assert b==0 and c==0 and d==64
            u.mem_write(e,bytes(data));self.ret(u,name,0);return
        if name=='Location':
            vals=(1 if case=='segment1' else 0,self.bus_value,2 if case=='device2' else 1,1 if case=='function1' else 0)
            for pointer,value in zip((b,c,d,e),vals):self.w64(pointer,value)
            self.ret(u,name,ERR(7) if case=='location_error' else 0);return
        if name=='BarAttributes':
            desc=bytearray(46);desc[0]=0x89 if case=='bad_descriptor' else 0x8a;desc[1]=42 if case=='bad_descriptor_length' else 43
            desc[3]=1 if case=='io_descriptor' else 0
            base=int.from_bytes(self.config[20:24],'little')&0xfffffff0
            length=0xe8c if case=='short_bar' else 0xe8d if case=='minimum_bar' else 0x40000
            if case=='over_4g':length=0x100000001-base
            if case=='overflow':length=0xffffffffffffffff
            if case=='exact_4g_end':length=0x100000000-base
            struct.pack_into('<Q',desc,14,base+16 if case=='base_mismatch' else base)
            struct.pack_into('<Q',desc,38,length)
            self.w64(c,0);self.w64(d,0 if case=='null_bar' else self.alloc(desc))
            self.ret(u,name,ERR(7) if case=='bar_error' else 0);return
        if name=='FreePool':
            self.free_count+=1
            self.ret(u,name,ERR(7) if (case=='free_handles_error' and self.free_count==1) or (case=='free_bar_error' and self.free_count==2) else 0);return
        return super().hook(u,addr,size,user)
    def guid_at(self,address):
        import uuid
        return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(address,16))))

def main():
    rows=[]
    for bus in (0,4,5,0x74,255):
        m=Machine(bus=bus);assert m.call('discover')==1
        assert f'PCI_SELECTED_BDF=0000:{bus:02X}:01.0' in m.audit()
        assert not m.dev.writes and not m.pci_writes and not m.nv_writes
        rows.append({'case':f'dynamic_bus_{bus:02x}','passed':True})
    good=('minimum_bar','exact_4g_end')
    bad=('vendor','device','revision','class','subclass','prog_if','subsystem_vendor','subsystem_device','header',
         'bar0_64bit','bar1_io','bar1_64bit','bar1_zero','bar1_allones','missing_cfg_read','missing_cfg_write',
         'missing_mem_read','missing_mem_write','missing_location','missing_bar','zero_count','too_many',
         'duplicate','duplicate_bad_subsystem','second_config_error','enum_error','null_handles','null_pci',
         'handle_error','config_error','segment1','device2','function1','location_error','bad_descriptor',
         'bad_descriptor_length','io_descriptor','short_bar','over_4g','overflow','base_mismatch','null_bar',
         'bar_error','free_handles_error','free_bar_error')
    for case in good+bad:
        m=Machine(case);assert bool(m.call('discover'))==(case in good),(case,m.audit())
        assert not m.dev.writes and not m.pci_writes and not m.nv_writes
        rows.append({'case':case,'passed':True})
    for bus in (256,0x100000074,0xffffffffffffffff):
        m=Machine(bus=bus);assert m.call('discover')==0;rows.append({'case':f'bus_out_of_range_{bus:x}','passed':True})
    for offset in (9,10,11,44,46):
        m=Machine();assert m.call('discover')==1;m.config[offset]^=1
        m.u.mem_write(m.functions['io_left'],struct.pack('<I',2))
        assert m.call('io_guard')==0 and m.call('enable_memory')==0
        m.u.mem_write(m.functions['changed_memory'],struct.pack('<I',1))
        assert m.call('restore_memory')==0
        assert not m.dev.writes and not m.pci_writes and not m.nv_writes
        rows.append({'case':f'identity_drift_offset_{offset}_blocks_io_enable_restore','passed':True})
    report={'passed':True,'cases':rows,'count':len(rows),'driver_sha256':hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiR5.efi').read_bytes()).hexdigest(),
            'limits':'Actual PE executed against synthetic UEFI PCI services; .15 Linux PCI bytes are input evidence, not proof of UEFI BDF or hardware operation.'}
    (OUT/'pci-selection-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('R5 PCI SELECTION ACTUAL PE PASS',len(rows))

if __name__=='__main__':main()
