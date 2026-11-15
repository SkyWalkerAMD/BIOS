"""Actual EFI HII installer with original extracted ASUS IFR, mocked HII protocols."""
from pathlib import Path
import hashlib,json,struct,uuid
from verify_native_owner import VM,HERE,CASE,OUT,EFI,BIND,SY,HEAP,TSE,SETUP,ERR,u32,u64
PACKAGE=(CASE/'driver/build/setup_hii_policy_fixture.bin').read_bytes()
assert PACKAGE[:16]==uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le
assert int.from_bytes(PACKAGE[16:20],'little')==len(PACKAGE)
ROWS=[]
DB_GUID=uuid.UUID('ef9fc172-a1b2-4693-b327-6d32fc416042').bytes_le
STR_GUID=uuid.UUID('0fd96974-23aa-4cdc-b9cb-98d17750322a').bytes_le
class HiiVM(VM):
 def __init__(self):
    super().__init__();self.package=PACKAGE;self.updates=[];self.strings=[];self.next_id=0x100
    self.duplicate_hii=False;self.export_error=False;self.list_oversize=False;self.export_oversize=False
    self.string_error=False;self.language_oversize=False;self.update_error=False;self.update_no_commit=False;self.corrupt_readback=False;self.rollback_error=False
    self.db=HEAP+0xa000;self.stringsp=HEAP+0xb000;self.cfg=SETUP+0x2bdd0
    self.cfg_before=self.r(self.cfg,24)
    self.bsfn(0x140,'locate_protocol',self.locate)
    self.bsfn(0x98,'handle_protocol',self.protocol)
    for off,name,callback in [(0x10,'hii_update',self.update),(0x18,'hii_list',self.listhii),(0x20,'hii_export',self.exporthii),(0x50,'hii_get_driver',self.driver)]:self.fn(self.db+off,name,callback)
    for off,name,callback in [(0,'string_new',self.newstring),(0x10,'string_set',self.setstring),(0x18,'languages',self.languages)]:self.fn(self.stringsp+off,name,callback)
 def locate(self):
    guid=self.r(self.arg(0),16);p=self.db if guid==DB_GUID else self.stringsp if guid==STR_GUID else 0
    if not p:return ERR(14)
    self.w(self.arg(2),u64(p));return 0
 def protocol(self):
    if self.arg(0)==0xbbc:self.w(self.arg(2),u64(self.cfg));return 0
    return self.handle()
 def listhii(self):
    size=16 if self.duplicate_hii else 8;out=self.arg(4);n=self.arg(3)
    if not out:self.w(n,u64(size));return ERR(5)
    if self.list_oversize:self.w(n,u64(8200));return 0
    self.w(n,u64(size));self.w(out,u64(0xaaa)+(u64(0xaab)if self.duplicate_hii else b''));return 0
 def driver(self):self.w(self.arg(2),u64(0xbbc));return 0
 def exporthii(self):
    n=self.arg(2);out=self.arg(3)
    if self.export_error:return ERR(7)
    if not out:self.w(n,u64(len(self.package)));return ERR(5)
    if self.export_oversize:self.w(n,u64(self.q(n)+1));return 0
    assert self.q(n)>=len(self.package);self.w(n,u64(len(self.package)));self.w(out,self.package);return 0
 def languages(self):
    raw=b'en-US;zh-CN\0';out=self.arg(2);n=self.arg(3)
    if not out:self.w(n,u64(len(raw)));return ERR(5)
    if self.language_oversize:self.w(n,u64(0x100000));return 0
    assert self.q(n)>=len(raw);self.w(out,raw);self.w(n,u64(len(raw)));return 0
 def newstring(self):
    if self.string_error:return ERR(7)
    self.w(self.arg(2),struct.pack('<H',self.next_id));self.strings.append(self.next_id);self.next_id+=1;return 0
 def setstring(self):
    if self.string_error:return ERR(7)
    self.strings.append(self.arg(2));return 0
 def update(self):
    raw=self.arg(2);n=self.d(raw+16);assert 24<=n<=len(PACKAGE)+30
    packet=self.r(raw,n);self.updates.append(packet)
    if len(self.updates)==1:
        if not self.update_no_commit:self.package=packet
        if self.corrupt_readback:
            temp=bytearray(self.package);temp[24]^=0x80;self.package=bytes(temp)
        return ERR(7)if self.update_error else 0
    if self.rollback_error:return ERR(7)
    self.package=packet;return 0
 def verify(self,name,result,condition):
    observed=self.call('install_management');assert observed==result,(name,hex(observed),result)
    assert self.r(self.cfg,24)==self.cfg_before,name+' rewrote static guard ConfigAccess'
    assert not self.variable_writes,name+' unexpectedly wrote variable'
    assert condition(self),name
    ROWS.append({'case':name,'passed':True,'result':hex(observed),'updates':len(self.updates),'static_callbacks_preserved':True,'variable_writes':0})

def main():
 v=HiiVM();v.verify('positive dual-language actions',1,lambda m:len(m.package)==len(PACKAGE)+30 and m.query()==1 and m.strings==[0x100,0x100,0x101,0x101,0x102,0x102,0x103,0x103])
 changed=v.package
 v.verify('idempotent installation',1,lambda m:len(m.updates)==1 and m.package==changed)
 # Compare exact output against independently located original Security end.
 ifr=json.loads((CASE/'analysis/modules/Setup_IFR.json').read_text())[0]
 security=next(r for r in ifr['records']if r.get('form_id')==0x271e);insert=20+security['end']-ifr['offset']-2
 expected=bytearray(PACKAGE[:insert]+bytes.fromhex('0c0f00010101e0ff0000ffff0400000c0f02010301e1ff0000ffff040000')+PACKAGE[insert:])
 struct.pack_into('<I',expected,16,len(expected));expected[20:23]=(int.from_bytes(expected[20:23],'little')+30).to_bytes(3,'little')
 assert changed==expected
 ROWS.append({'case':'exact original-ASUS-IFR Security insertion','passed':True,'package_bytes':len(changed)})
 for name,setting,value,expected_result,condition in [
    ('duplicate Setup package refused','duplicate_hii',True,0,lambda m:not m.updates and not m.strings),
    ('HII list oversized reply refused','list_oversize',True,0,lambda m:not m.updates and not m.strings),
    ('export error refused','export_error',True,0,lambda m:not m.updates and not m.strings),
    ('export oversized reply refused','export_oversize',True,0,lambda m:not m.updates and not m.strings),
    ('string failure faults','string_error',True,0xffffffff,lambda m:not m.updates and bool(m.query()&32)),
    ('oversized language reply faults before out-of-bounds access','language_oversize',True,0xffffffff,lambda m:not m.updates and bool(m.query()&32)),
    ('success without commit faults and restores','update_no_commit',True,0xffffffff,lambda m:len(m.updates)==2 and m.package==PACKAGE and bool(m.query()&32)),
    ('update error after mutation faults and restores','update_error',True,0xffffffff,lambda m:len(m.updates)==2 and m.package==PACKAGE and bool(m.query()&32)),
    ('corrupt readback faults and restores','corrupt_readback',True,0xffffffff,lambda m:len(m.updates)==2 and m.package==PACKAGE and bool(m.query()&32)),
 ]:
    v=HiiVM();setattr(v,setting,value);v.verify(name,expected_result,condition)
 v=HiiVM();v.corrupt_readback=v.rollback_error=True;v.verify('unrestorable package remains faulted',0xffffffff,lambda m:len(m.updates)==2 and bool(m.query()&32));v.verify('failed installer never retries',0xffffffff,lambda m:len(m.updates)==2)
 v=HiiVM();v.w(v.cfg+16,u64(SETUP+0x1534));v.cfg_before=v.r(v.cfg,24);v.verify('original unguarded callback refused',0,lambda m:not m.updates and not m.strings)
 v=HiiVM();v.w(v.cfg+8,u64(SETUP+0x152c));v.cfg_before=v.r(v.cfg,24);v.verify('original unguarded RouteConfig refused',0,lambda m:not m.updates and not m.strings)
 v=HiiVM();v.package=changed;v.verify('existing reserved management QIDs fault',0xffffffff,lambda m:not m.updates and bool(m.query()&32))
 v=HiiVM();v.call('provider_end_boot');before=len(v.calls);v.verify('EBS prevents HII work',0xffffffff,lambda m:len(m.calls)==before)
 v=HiiVM();v.wrong_loaded_guid=True;v.verify('unverified image identity defers before all HII changes',0,lambda m:not m.updates and not m.strings)
 v=HiiVM();slot=TSE+BIND['AMITSE']['context_head_rva'];v.w(v.leaf(slot),u64(0));v.verify('unmapped head slot is unknown and defers',0,lambda m:not m.updates and not m.strings)
 v=HiiVM();v.w(slot,u64(0xdead000));v.verify('non-null unrecognized head cannot count as idle',0,lambda m:not m.updates and not m.strings)
 report={'status':'PASS_ACTUAL_EFI_HII_INSTALLER_SYNTHETIC_PROTOCOLS','case_count':len(ROWS),'cases':ROWS,
  'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'fixture_source_sha256':hashlib.sha256((HERE/'verify_native_owner.py').read_bytes()).hexdigest(),
  'original_ifr_fixture_sha256':hashlib.sha256(PACKAGE).hexdigest(),
  'scope':'Actual candidate HII installer and original-ASUS-IFR policy code under Unicorn. All UEFI HII services and string stores are simulated; no real BIOS UI or hardware claim.'}
 (OUT/'native_hii_verification.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'cases':len(ROWS)}))
if __name__=='__main__':main()
