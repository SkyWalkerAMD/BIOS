"""Real ownerless AMITSE wrapper must defer HII mutation until after it exits."""
from pathlib import Path
import argparse,hashlib,json,struct
from verify_native_owner import HERE,OUT,EFI,SY,BIND,TSE,HEAP,u64,UC_HOOK_CODE,UC_X86_REG_RIP
from verify_native_hii import HiiVM
class ActiveHii(HiiVM):
 def __init__(self,callback=False):
    super().__init__();self.w(TSE+0x83308,u64(self.bs));self.observed=[]
    self.bsfn(0x58,'set_timer',lambda:0);self.w(SY['timer_event'],u64(0xccc))
    payload=self.r(TSE+BIND['AMITSE']['payload_rva'],BIND['AMITSE']['payload_bytes']);magic=struct.pack('<Q',0x3430393145544147)
    matches=[i for i in range(len(payload)-72)if payload[i:i+8]==magic and payload[i+8:i+16]==struct.pack('<II',2,1)and int.from_bytes(payload[i+16:i+20],'little')==BIND['AMITSE']['payload_rva']+i]
    assert len(matches)==1;pos=matches[0];original=TSE+int.from_bytes(payload[pos+24:pos+28],'little')
    self.out=HEAP+0x340000;self.bodycode=HEAP+0x341000
    code=b'\x48\x83\xec\x28\x31\xc9\x31\xd2\x48\xb8'+u64(SY['discover'if callback else'install_management'])+b'\xff\xd0\x48\xa3'+u64(self.out)+b'\x48\xb8'+u64(0x12345678)+b'\x48\x83\xc4\x28\xc3'
    self.w(self.bodycode,code);self.u.hook_add(UC_HOOK_CODE,self.body,begin=original,end=original);SY['_active_hii_wrapper']=TSE+0xe1b8
 def body(self,u,address,size,unused):
    head=self.q(TSE+BIND['AMITSE']['context_head_rva']);assert head
    self.observed.append({'frame_depth':self.d(head+40),'provider':self.q(head+24),'token':self.q(head+32),'previous':self.q(head+16)})
    u.reg_write(UC_X86_REG_RIP,self.bodycode)
def main():
 p=argparse.ArgumentParser();p.add_argument('--expect-counterexample',action='store_true');a=p.parse_args()
 rows=[]
 for callback in [False,True]:
    v=ActiveHii(callback);assert v.call('_active_hii_wrapper')==0x12345678
    during={'installer_result':v.q(v.out)if not callback else None,'update_calls':len(v.updates),'string_mutations':len(v.strings),'timer_calls':v.calls.count('set_timer')}
    assert v.observed==[{'frame_depth':1,'provider':0,'token':0,'previous':0}]
    assert v.q(TSE+BIND['AMITSE']['context_head_rva'])==0
    if a.expect_counterexample:assert during['update_calls']==1
    else:
        assert during=={'installer_result':None if callback else 0,'update_calls':0,'string_mutations':0,'timer_calls':0}
        assert v.call('install_management')==1 and len(v.updates)==1
    rows.append({'entry':'actual discover event callback'if callback else'installer','real_native_frame':v.observed,'during_UI':during,'idle_retry_passed':not a.expect_counterexample})
 report={'status':'COUNTEREXAMPLE_ACTIVE_OWNERLESS_UI_HII_MUTATION'if a.expect_counterexample else'PASS_ACTIVE_OWNERLESS_UI_DEFERRAL_AND_IDLE_RETRY',
  'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'guard_binding_sha256':hashlib.sha256((HERE/'guard_binding.json').read_bytes()).hexdigest(),
  'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'case_count':len(rows),'cases':rows,
  'fixture_source_hashes':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest()for name in ['verify_native_owner.py','verify_native_hii.py']},
  'after_UI_retry_performed':not a.expect_counterexample,
  'scope':'Actual modified E1B8/gate_loop pushes an ownerless frame. Stubbed OEM body invokes real installer under synthetic HII services; no full ASUS GUI or hardware.'}
 name='active_hii_counterexample.json'if a.expect_counterexample else'active_hii_verification.json'
 (OUT/name).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'case_count':len(rows)}))
if __name__=='__main__':main()
