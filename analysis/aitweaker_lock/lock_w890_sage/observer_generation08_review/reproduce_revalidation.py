"""Real observer PE revalidation races, with explicit modeled notification timing.

No private observer state is written. Original callbacks are scheduled at a
modeled RestoreTPL boundary. This probes observer contracts, not physical event
scheduling, full firmware execution, or a deployed lock.
"""
from pathlib import Path
import sys,json,hashlib,struct,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];O=B/'observer_generation08'
sys.path[:0]=[str(R/'tools/pydeps'),str(O)]
import verify_generation as g
from unicorn.x86_const import *
Q,I,DATA,TSE,OS,ns=g.Q,g.I,g.DATA,g.TSE,g.OS,g.ns
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def manifest():
 p=O/'component_manifest.json';assert sha(p)=='4fc68d969c583e39cf1bfbf798dcf52c5bcc6a7fe4e00e8616eb168b9e778d30'
 j=json.loads(p.read_text())
 for key in ('files','external_bindings'):
  for x in j[key]:assert bind(R/x['path'])==x
 return bind(p)

class VM(g.VM):
 def __init__(self):
  super().__init__();self.arm_target=None;self.pending_notify=None;self.notify_mode='setup';self.injections=[]
 def hook(self,u,address,size,opaque):
  if getattr(self,'arm_target',None) and address==OS[self.arm_target]:
   self.pending_notify=self.arm_target;self.arm_target=None
  if getattr(self,'pending_notify',None) and address==self.oh['restore']:
   target=self.pending_notify;self.pending_notify=None
   assert self.current_tpl==31 and self.arg(0)==4
   self.current_tpl=4
   handle=self.setup_hii if self.notify_mode=='setup' else 0x920000
   self.injections.append({'during':target,'boundary':'modeled RestoreTPL31->4','handle':hex(handle),'kind':2})
   self.nested(self.notify_callback,[2,0,0,handle,2],0);return
  return super().hook(u,address,size,opaque)
 def fault(self):
  assert self.run('no_identity',self.idbuf)==1
  return int.from_bytes(self.r(self.idbuf+96,4),'little')
 def publish_and_management_fixture(self):
  assert self.initialize()==0 and self.run('n05_bind')==0 and self.packet()==0
  self.apply();assert self.bind_real_host()==0
  self.publish_mode='good'
  assert self.run('no_native_entry',self.tse_handle,self.st)==0
  assert self.script_values==[0,1,0,1,1]
  self.setup_page(0x271d)
  forms=self.package[20:-4];off=4;opcode=None
  while off<len(forms):
   n=forms[off+1]&127
   if forms[off]==0x0c and n==15 and int.from_bytes(forms[off+6:off+8],'little')==0xffd0:opcode=forms[off:off+n];break
   off+=n
  assert opcode
  self.w(self.opcode,opcode)
  self.w(self.control,Q(TSE+0x95620));self.w(self.control+0x20,Q(self.setup_hii))
  self.w(self.control+0x34,struct.pack('<H',27));self.w(self.control+0x48,Q(self.opcode))
  self.w(self.cb,Q(self.setup_hii));self.w(self.cb+0x14,struct.pack('<H',27));self.w(self.cb+0x28,Q(self.opcode))
  self.w(TSE+0xafeb8,Q(1));self.w(TSE+0xafd88,b'\1');self.w(TSE+0xafff8,b'\1')
  self.mt=DATA+0x35000;self.mv=DATA+0x35100;self.mr=DATA+0x35200
  self.w(self.mt,Q(0));self.w(self.mv,bytes(8));self.w(self.mr,bytes(8))

def main():
 initial=manifest();rows=[]
 for name in ('no_catalog_generation','no_native_visit_identity'):
  start=time.monotonic();v=VM();v.ready();p=DATA+0x34000;r=p+16;v.w(p,Q(0));v.w(r,I(0))
  v.arm_target=name
  args=[p] if name=='no_catalog_generation' else[p,r]
  v.loop([(name,args),(name,args)])
  assert v.sequence_values==[1,0] and v.fault()==1 and len(v.injections)==1
  rows.append({'case':name+' reports success despite Setup revoke during identity services',
               'results':v.sequence_values,'value':v.q(p),'fault':1,'notification':v.injections,
               'seconds':round(time.monotonic()-start,3)})
  print(rows[-1]['case'],flush=True)
 start=time.monotonic();v=VM();v.ready();v.arm_target='no_scope_enter';v.w(v.result,bytes(64))
 v.loop([('og08_test_read',[v.app,v.result])]);r=v.result_fields()
 assert r['entered']==1 and r['before_valid']==0 and r['after_valid']==0 and v.fault()==1
 assert not v.lab_calls and not v.set_count
 rows.append({'case':'scope_enter mints then reports an already invalid ticket after Setup revoke',
              'report':r,'fault':1,'actual_registered_consumer_call':True,'variable_service_calls':v.lab_calls,
              'notification':v.injections,'seconds':round(time.monotonic()-start,3)})
 print(rows[-1]['case'],flush=True)
 start=time.monotonic();v=VM();v.publish_and_management_fixture();v.notify_mode='foreign';ticket=[]
 def after_enter(w):
  assert w.sequence_values==[1],w.sequence_values
  ticket.append(w.q(w.mt));assert ticket[0]
  w.sequence += [('no_management_valid',[0,ticket[0]]),arm,('no_management_valid',[0,ticket[0]]),('no_management_valid',[0,ticket[0]]),('no_management_leave',[0,ticket[0]])]
 def arm(w):w.arm_target='no_management_valid'
 enter=[0,TSE+0x3e4f0,v.config,1,0xffd0,10,v.mv,v.mr,v.mt]
 v.loop([('no_management_enter',enter),after_enter])
 assert v.sequence_values[:4]==[1,1,1,0],v.sequence_values
 assert v.fault()==0 and len(v.injections)==1 and not v.set_count
 rows.append({'case':'management validation accepts stale catalog generation for one call',
              'results_enter_valid_before_valid_during_valid_after':v.sequence_values[:4],
              'fault':0,'ticket_minted_by_real_code':True,'notification':v.injections,
              'caller_boundary':'Management enter ABI caller address is an explicit fixture; this case does not execute the original ConfigAccess CALL. Actual cold/private-loop wrappers and management-control/IFR checks execute.',
              'seconds':round(time.monotonic()-start,3)})
 print(rows[-1]['case'],flush=True)
 assert manifest()==initial
 out={'component':bind(O/'build/W890ObserverGeneration08.TESTONLY.dll'),'manifest':initial,
      'source':bind(Path(__file__)),'cases':rows,'private_observer_state_modified':False,
      'limits':['Notification delivery during modeled RestoreTPL is explicit scheduling; no hardware timing is claimed.',
                'Existing UEFI/native object/CPU/crypto fixtures remain; no full GUI or production authorization.',
                'All writes are local emulator fixtures and this review directory; frozen inputs unchanged.']}
 (H/'revalidation_repro.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'reproduced':len(rows),'component':out['component']['sha256']}))

if __name__=='__main__':main()
