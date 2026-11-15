"""Real modified AMITSE wrapper plus real provider, with only OEM body stubbed."""
from pathlib import Path
import hashlib,json,struct,uuid
from verify_native_owner import VM,HERE,OUT,EFI,SY,BIND,TSE,HEAP,ERR,u64,UC_HOOK_CODE,UC_X86_REG_RIP
PGUID=uuid.UUID('f29d11ab-c12a-455a-95d3-9a8ecf045c04').bytes_le
ROWS=[]
class JointVM(VM):
 def __init__(self,mode='single'):
    super().__init__();self.mode=mode;self.provider_available=mode!='late';self.seen=[]
    self.w(TSE+0x83308,u64(self.bs));self.bsfn(0x140,'locate_protocol',self.locate)
    payload=self.r(TSE+BIND['AMITSE']['payload_rva'],BIND['AMITSE']['payload_bytes']);mark=struct.pack('<Q',0x3430393145544147)
    matches=[i for i in range(len(payload)-72)if payload[i:i+8]==mark and payload[i+8:i+16]==struct.pack('<II',2,1)and int.from_bytes(payload[i+16:i+20],'little')==BIND['AMITSE']['payload_rva']+i]
    assert len(matches)==1;pos=matches[0];self.original=TSE+int.from_bytes(payload[pos+24:pos+28],'little')
    self.u.hook_add(UC_HOOK_CODE,self.body,begin=self.original,end=self.original)
    self.body1=HEAP+0x320000;self.body2=HEAP+0x321000;self.flags1=HEAP+0x330000;self.flags2=HEAP+0x330010;self.inner_result=HEAP+0x330020
    self.return_value=0x1122334455667788
    self.w(self.body1,self.stub(self.flags1,nested=mode in ('nested','late')));self.w(self.body2,self.stub(self.flags2,False))
    SY['_actual_oem_wrapper']=TSE+0xe1b8
 def locate(self):
    if self.r(self.arg(0),16)==PGUID and self.provider_available:self.w(self.arg(2),u64(SY['native_provider']));return 0
    return ERR(14)
 def stub(self,out,nested=False):
    code=b'\x48\x83\xec\x28'
    if nested:code+=b'\x48\xb8'+u64(TSE+0xe1b8)+b'\xff\xd0\x48\xa3'+u64(self.inner_result)
    code+=b'\x48\xb9'+u64(SY['native_provider'])+b'\x48\xb8'+u64(SY['provider_query'])+b'\xff\xd0\x48\xa3'+u64(out)
    return code+b'\x48\xb8'+u64(self.return_value)+b'\x48\x83\xc4\x28\xc3'
 def body(self,u,address,size,unused):
    head=self.q(TSE+BIND['AMITSE']['context_head_rva']);depth=self.d(head+40)
    self.seen.append({'depth':depth,'head':hex(head),'previous':hex(self.q(head+16)),'token':self.q(head+32),'provider_present':bool(self.q(head+24))})
    if self.mode=='late'and depth==1:self.provider_available=True
    if self.mode=='post_auth':self.w(SY['password_core']+201,b'\x01')
    if self.mode=='lost_head':self.w(TSE+BIND['AMITSE']['context_head_rva'],u64(0))
    u.reg_write(UC_X86_REG_RIP,self.body1 if depth==1 else self.body2)
 def run(self,name,expected_outer,expected_inner=None):
    result=self.call('_actual_oem_wrapper')
    assert result==self.return_value and self.q(self.flags1)==expected_outer,(name,result,self.q(self.flags1))
    if expected_inner is not None:assert self.q(self.flags2)==expected_inner and self.q(self.inner_result)==self.return_value
    assert self.q(TSE+BIND['AMITSE']['context_head_rva'])==0
    assert self.query()in(1,33) and not self.variable_writes
    ROWS.append({'case':name,'passed':True,'outer_flags':self.q(self.flags1),'inner_flags':self.q(self.flags2)if expected_inner is not None else None,
                 'body_observations':self.seen,'original_return_value_preserved':True,'native_context_popped':True,'no_variable_write':True})

def main():
 v=JointVM();v.run('native wrapper establishes and closes owner',3)
 v=JointVM('nested');v.run('native nested wrappers share token and close in order',3,3)
 assert v.seen[0]['token']==v.seen[1]['token']!=0
 v=JointVM('late');v.run('provider first appears inside ownerless outer wrapper',1,1)
 assert all(x['token']==0 for x in v.seen)
 # The prior ownerless invocation fully popped. A subsequent genuine outer
 # invocation can acquire ownership; availability is not a permanent denial.
 v.mode='single';v.w(v.body1,v.stub(v.flags1,False));v.seen=[];v.run('next genuine outer entry after late appearance acquires normally',3)
 v=JointVM('post_auth');v.run('post-auth core grant removed by actual outer end',7)
 v=JointVM('lost_head');v.run('lost native head cannot leave observable grant',1)
 report={'status':'PASS_REAL_AMITSE_WRAPPER_REAL_PROVIDER_STUBBED_OEM_BODY','case_count':len(ROWS),'cases':ROWS,
  'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'guard_binding_sha256':hashlib.sha256((HERE/'guard_binding.json').read_bytes()).hexdigest(),
  'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'fixture_source_sha256':hashlib.sha256((HERE/'verify_native_owner.py').read_bytes()).hexdigest(),
  'scope':'Actual modified E1B8 jump, gate_loop code, frame linking/popping, exact indirect Begin/End calls and full provider execute together. Original OEM browser body alone is replaced by bounded query/nesting stubs.',
  'limitations':['No original ASUS browser body or navigation GUI in this fixture.','One case seeds the post-auth unlocked byte; actual PBKDF2 authentication is separately tested in the native core DLL.',
                 'UEFI services/page tables/LoadedImage records are synthetic.','No BMC or physical flash access.']}
 (OUT/'native_joint_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(ROWS)}))
if __name__=='__main__':main()
