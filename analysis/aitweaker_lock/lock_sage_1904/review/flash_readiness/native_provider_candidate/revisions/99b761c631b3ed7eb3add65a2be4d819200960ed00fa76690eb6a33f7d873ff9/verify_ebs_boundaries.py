"""Inject the actual EFI ending callback inside simulated service returns."""
from pathlib import Path
import argparse,hashlib,json,uuid
from verify_native_owner import VM,HERE,OUT,EFI,SY,HEAP,STUB,STOP,ERR,u32,u64,UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX
from verify_native_hii import HiiVM
from verify_native_entry import EntryVM
RNG=uuid.UUID('3152bca5-eade-433d-862e-c01cdc291f44').bytes_le
CPU=uuid.UUID('26baccb1-6f42-11d4-bce7-0080c73c8881').bytes_le
class Fault:
 def __init__(self,*a,**kw):
    self.target=None;self.counts={};self.injected=False;self.post=[];self.inject_status=None
    super().__init__(*a,**kw)
 def arm(self,name,nth=1):self.target=(name,nth);self.counts={};self.injected=False;self.post=[]
 def hook(self,u,address,size,unused):
    if address==self.stop:u.emu_stop();return
    if address not in self.callbacks:return
    name,cb=self.callbacks[address];self.calls.append(name);self.counts[name]=self.counts.get(name,0)+1
    if self.injected:self.post.append(name)
    result=cb()
    if not self.injected and self.target==(name,self.counts[name]):
        self.injected=True;self.inject_status=result
        # Keep the original method return address on the stack. Execute the
        # real ending(EVT,context) code before delivering the method result.
        code=b'\x48\x83\xec\x28\x31\xc9\x31\xd2\x48\xb8'+u64(SY['ending'])+b'\xff\xd0\x48\xb8'+u64(result)+b'\x48\x83\xc4\x28\xc3'
        self.w(STUB+0xfd00,code);u.reg_write(UC_X86_REG_RIP,STUB+0xfd00);return
    u.reg_write(UC_X86_REG_RAX,result);sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
class ServicesVM(Fault,VM):
 def __init__(self):
    super().__init__();self.rng=HEAP+0xa000;self.cpu=HEAP+0xb000;self.tick=100000
    self.bsfn(0x140,'locate_protocol',self.locate)
    self.fn(self.rng+8,'rng_get',self.rng_get);self.fn(self.cpu+0x30,'cpu_timer',self.cpu_timer);self.w(self.cpu+0x40,u32(1))
    f=self.frame();self.begin(f)
 def locate(self):
    g=self.r(self.arg(0),16);p=self.rng if g==RNG else self.cpu if g==CPU else 0
    if not p:return ERR(14)
    self.w(self.arg(2),u64(p));return 0
 def rng_get(self):self.w(self.arg(3),bytes(range(1,self.arg(2)+1)));return 0
 def cpu_timer(self):
    self.tick+=100000;self.w(self.arg(2),u64(self.tick))
    if self.arg(3):self.w(self.arg(3),u64(1000000000))
    return 0
class FaultHii(Fault,HiiVM):
 def __init__(self):super().__init__();self.bsfn(0x58,'set_timer',lambda:0)
class FaultEntry(Fault,EntryVM):pass

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--expect-counterexamples',action='store_true');a=parser.parse_args();rows=[]
    def result(name,v,value,contract=True):
        assert v.injected,name+' did not reach requested boundary'
        assert v.d(SY['boot_services_ended'])==1,name+' did not execute ending code'
        passed=not v.post and contract
        rows.append({'case':name,'target':list(v.target),'post_ending_service_calls':v.post,'returned':hex(value),
                     'contract_satisfied':bool(contract),'passed':passed,'real_ending_executed':True})
    for target,nth in [('locate_protocol',1),('rng_get',1)]:
        v=ServicesVM();data=HEAP+0xc000;v.w(data,b'\xa5'*32);v.arm(target,nth);value=v.call('entropy',[0,data,32])
        result('entropy after '+target,v,value,value==1 and not any(v.r(data,32)))
    for target,nth in [('locate_protocol',1),('cpu_timer',1),('cpu_timer',2),('stall',1),('cpu_timer',3),('cpu_timer',8)]:
        v=ServicesVM();out=HEAP+0xc000;v.w(out,u64(0xdead));v.arm(target,nth);value=v.call('now_ms',[0,out]);result('clock after '+target+str(nth),v,value,value==1)
    v=ServicesVM();v.arm('allocate_pool');value=v.call('alloc',[64]);result('allocation result cannot escape after ending',v,value,value==0)
    for target,nth in [('locate_protocol',1),('locate_protocol',2),('hii_list',1),('hii_list',2),('hii_export',1),('hii_export',2),
                        ('hii_get_driver',1),('handle_protocol',3),('languages',1),('languages',2),('string_new',1),('string_set',1),
                        ('hii_update',1),('hii_export',5),('hii_export',6)]:
        v=FaultHii();v.arm(target,nth);value=v.call('install_management');result('HII transaction '+target+str(nth),v,value,value!=1)
    v=FaultHii();v.update_error=True;v.arm('hii_update',2);value=v.call('install_management');result('HII rollback ending',v,value,value!=1)
    v=FaultHii();v.w(SY['timer_event'],u64(0xccc));v.arm('hii_update');value=v.call('discover',[0,0]);result('discover does not stop timer after ending',v,value)
    for target,nth in [('locate_protocol',1),('get_variable',1),('handle_protocol',1),('create_event',1),('create_event_ex',1),
                        ('install_protocol',1),('create_event',2),('register_notify',1),('create_event_ex',2),('create_event',3),('set_timer',1)]:
        v=FaultEntry();v.arm(target,nth);value=v.call('efi_main',[0x333,v.st]);result('driver entry '+target+str(nth),v,value)
    failed=[r for r in rows if not r['passed']]
    if a.expect_counterexamples:assert failed,'No independent defect reproduced'
    else:assert not failed,failed
    report={'status':'COUNTEREXAMPLES_REPRODUCED'if a.expect_counterexamples else'PASS_ACTUAL_EFI_EBS_CALLBACK_BOUNDARIES',
            'case_count':len(rows),'counterexample_count':len(failed),'cases':rows,'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),
            'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'scope':'Real candidate ending() code executes inside simulated standard-service callbacks before return. Subsequent firmware-service calls are counted; no direct manipulation of ended flag.',
            'limitations':['Synthetic UEFI callback/event scheduling, no physical board or actual OS handoff in these fault cases.']}
    name='ebs_boundary_counterexamples.json'if a.expect_counterexamples else'ebs_boundary_verification.json'
    (OUT/name).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'cases':len(rows),'counterexamples':len(failed)}))
if __name__=='__main__':main()
