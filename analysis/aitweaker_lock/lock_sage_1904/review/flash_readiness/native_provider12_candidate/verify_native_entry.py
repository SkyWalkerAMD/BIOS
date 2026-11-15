"""Actual complete provider entry/event lifecycle under simulated standard UEFI."""
from pathlib import Path
import hashlib,json,uuid
from verify_native_owner import VM,HERE,OUT,EFI,SY,HEAP,BASE,ERR,u32,u64
PGUID=uuid.UUID('f29d11ab-c12a-455a-95d3-9a8ecf045c04').bytes_le
BEFORE=uuid.UUID('8be0e274-3970-4b44-80c5-1a9b502f3bfc').bytes_le
RESULTS=[]
class EntryVM(VM):
 def __init__(self):
    super().__init__(initialize=False);self.events=[];self.registers=[];self.timers=[];self.installs=[]
    self.existing=False;self.fail_exit=False;self.fail_before=False;self.fail_publish=False;self.fail_self=False;self.readonly_self=False
    self.fail_loaded=False;self.fail_timer=False;self.liself=HEAP+0x7000
    self.w(self.liself+0x40,u64(BASE)+u64(0xc000))
    self.bsfn(0x98,'handle_protocol',self.protocol);self.bsfn(0x140,'locate_protocol',self.locate)
    for off,name,callback in [(0x50,'create_event',self.create),(0x170,'create_event_ex',self.create_ex),
                              (0x80,'install_protocol',self.install),(0xa8,'register_notify',self.register),(0x58,'set_timer',self.timer)]:self.bsfn(off,name,callback)
    self.tables_before=(self.r(self.bs,0x178),self.r(self.rt,0x88))
 def protocol(self):
    if self.arg(0)==0x333:
        if self.fail_self:return ERR(14)
        if self.readonly_self:
            leaf=self.leaf(self.liself);self.w(leaf,u64(self.q(leaf)&~2))
        self.w(self.arg(2),u64(self.liself));return 0
    return self.handle()
 def locate(self):
    if self.r(self.arg(0),16)==PGUID and self.existing:self.w(self.arg(2),u64(SY['native_provider']));return 0
    return ERR(14)
 def create(self):
    typ=self.arg(0)
    if (typ==0x201 and self.fail_exit)or(typ==0x200 and self.fail_loaded)or(typ==0x80000200 and self.fail_timer):return ERR(9)
    event=0xcc000+len(self.events)*16;self.events.append({'type':typ,'notify':self.arg(2),'event':event});self.w(self.arg(4),u64(event));return 0
 def create_ex(self):
    guid=self.r(self.arg(4),16)
    if guid==BEFORE and self.fail_before:return ERR(3)
    event=0xcc000+len(self.events)*16;self.events.append({'type':self.arg(0),'notify':self.arg(2),'event':event,'before':guid==BEFORE});self.w(self.arg(5),u64(event));return 0
 def install(self):
    assert self.r(self.arg(1),16)==PGUID and self.arg(3)==SY['native_provider'];self.installs.append(self.arg(3))
    if self.fail_publish:return ERR(9)
    self.existing=True;self.w(self.arg(0),u64(0x777));return 0
 def register(self):self.registers.append(self.arg(1));self.w(self.arg(2),u64(0x888));return 0
 def timer(self):self.timers.append([self.arg(0),self.arg(1),self.arg(2)]);return 0
 def run(self,name,expected,verify):
    got=self.call('efi_main',[0x333,self.st]);assert got==expected,(name,hex(got),hex(expected));assert verify(self),name
    assert not self.variable_writes and (self.r(self.bs,0x178),self.r(self.rt,0x88))==self.tables_before
    RESULTS.append({'case':name,'passed':True,'entry_status':hex(got),'event_count':len(self.events),'provider_install_attempts':len(self.installs),'no_runtime_or_boot_table_patch':True,'variable_writes':0})

def main():
 v=EntryVM();v.run('normal complete entry',0,lambda m:m.query()==1 and len(m.installs)==1 and len(m.events)==5 and m.existing)
 before=len(v.calls);assert v.call('no_unload',[0x333])==ERR(15) and len(v.calls)==before
 RESULTS.append({'case':'resident provider refuses unload','passed':True})
 v.run('duplicate entry refused before allocation',ERR(20),lambda m:len(m.events)==5 and len(m.installs)==1)
 v.call('ending',[v.events[0]['event'],0])
 before=len(v.calls);assert v.query()==64;v.call('discover',[0,0]);assert len(v.calls)==before
 RESULTS.append({'case':'real entry callback code permanently revokes; discovery has no post-EBS service calls','passed':True})
 for name,setting,expected,verify in [
    ('existing provider', 'existing',ERR(20),lambda m:not m.events and not m.installs and not m.gets),
    ('own LoadedImage absent','fail_self',ERR(3),lambda m:not m.events and not m.installs),
    ('own LoadedImage not writable','readonly_self',ERR(3),lambda m:not m.events and not m.installs),
    ('first EBS event allocation failure','fail_exit',ERR(7),lambda m:not m.events and not m.installs),
    ('protocol publication failure stays resident faulted','fail_publish',0,lambda m:len(m.events)==2 and len(m.installs)==1 and m.query()==33),
    ('optional BeforeExit unavailable final EBS remains','fail_before',0,lambda m:any(e['type']==0x201 for e in m.events)and not any(e.get('before')for e in m.events)and m.query()==1),
    ('loaded notification allocation failure leaves other discovery','fail_loaded',0,lambda m:not m.registers and bool(m.timers)and m.query()==1),
    ('timer allocation failure leaves event discovery','fail_timer',0,lambda m:bool(m.registers)and not m.timers and m.query()==1),
 ]:
    v=EntryVM();setattr(v,setting,True)
    # Changing page-table metadata does not alter the actual service tables.
    v.run(name,expected,verify)
 v=EntryVM();v.attributes=7;v.run('invalid credential attributes publish fault only',0,lambda m:m.query()==33 and bool(m.installs))
 report={'status':'PASS_ACTUAL_EFI_ENTRY_SYNTHETIC_UEFI','case_count':len(RESULTS),'cases':RESULTS,
  'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'fixture_source_sha256':hashlib.sha256((HERE/'verify_native_owner.py').read_bytes()).hexdigest(),
  'scope':'Actual complete EFI entry and EBS callbacks; standard protocols/events are synthetic, no hardware or actual password UI.'}
 (OUT/'native_entry_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(RESULTS)}))
if __name__=='__main__':main()
