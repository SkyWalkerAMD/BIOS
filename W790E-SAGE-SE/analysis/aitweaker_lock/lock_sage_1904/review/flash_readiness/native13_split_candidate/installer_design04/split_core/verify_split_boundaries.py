"""Actual guard callback-boundary replay; EBS notification itself is modeled.

Each fixture service first completes normally, then marks the owned state ENDED
before returning. No subsequent modeled firmware/provider/OEM call is allowed.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
from verify_split import make_namespace,HERE,OLD,BUILD,meta,sha

def main():
 scope=make_namespace();base=scope['GateVM'];checks=[]
 S=scope['S'];state=scope['SPLIT_STATE_ADDRESS'];d=scope['d']
 service_names=['LOC','HANDLE','GETDRIVER','LIST','BEGIN','END','QUERY','REQUEST','MANAGE','ALLOC','FREE','GETVAR','CONFIGBLOCK']
 services={scope[x]:x for x in service_names}
 originals={scope['TSE']+x:f'AMITSE+{x:x}'for x in [0x16a90,0x16c20,0x12168,0x1532f,0xe1ca]}
 originals.update({scope['SETUP']+x:f'Setup+{x:x}'for x in [0x1534,0x2568]})
 class BoundaryVM(base):
  def __init__(self,target,guid=None):
   self.boundary_target=target;self.boundary_guid=guid;self.boundary_ended=False;self.after=[];self.triggered=0
   super().__init__()
  def hook(self,u,a,n,data):
   if self.boundary_ended and (a in services or a in originals):self.after.append(services.get(a,originals.get(a)))
   trigger=a==self.boundary_target and not self.boundary_ended
   if trigger and self.boundary_guid is not None:trigger=bytes(u.mem_read(self.arg(0),16))==self.boundary_guid
   super().hook(u,a,n,data)
   if trigger:
    self.triggered+=1;self.boundary_ended=True;u.mem_write(state+24,d(3))
 def run(label,target,action,guid=None,provider=False):
  v=BoundaryVM(scope[target],guid);v.provider_present=provider
  v.provider_bits=3;v.request_accept=True
  action(v)
  assert v.triggered==1 and not v.after,(label,v.triggered,v.after)
  checks.append(label)
 run('Main LocateProtocol ending prevents HII and original render','LOC',lambda v:v.call(S['AMITSE']['gate_render'],v.pages[0]),scope['DB_GUID'])
 for name in ['GETDRIVER','HANDLE']:
  run('Main '+name+' ending prevents further services/original render',name,lambda v:v.call(S['AMITSE']['gate_render'],v.pages[0]))
 run('foreign identity List ending prevents later HandleProtocol','LIST',lambda v:v.call(S['AMITSE']['gate_owner'],0x99998888,0))
 run('provider LocateProtocol ending prevents Begin and original browser','LOC',lambda v:v.call(S['AMITSE']['gate_loop']),scope['PROVIDER_GUID'],True)
 run('provider Begin ending prevents original browser and unmatched End','BEGIN',lambda v:v.call(S['AMITSE']['gate_loop']),provider=True)
 run('provider Query ending prevents request and navigation','QUERY',lambda v:v.nav(0x2714),provider=True)
 run('provider Request ending prevents new query and navigation','REQUEST',lambda v:v.nav(0x2714),provider=True)
 run('management Query ending prevents Manage','QUERY',lambda v:v.callback(0xffe0),provider=True)
 for target in ['LOC','ALLOC','GETVAR','CONFIGBLOCK','FREE']:
  run('Route '+target+' ending prevents later services and OEM route',target,lambda v:v.route(),scope['ROUTING_GUID']if target=='LOC'else None)
 # Full private wrapper cleanup also must occur if Begin ends boot services.
 v=BoundaryVM(scope['BEGIN']);v.provider_present=True
 result=v.call(S['AMITSE']['gate_loop'])
 assert result==scope['ERR'](15)and v.getq(state)==0 and not v.after and v.body_context is None
 checks.append('Begin ending clears native frame and returns ACCESS_DENIED with no browser call')
 report={'status':'PASS_SPLIT_GUARD_CALLBACK_ENDING_BOUNDARIES','checks':len(checks),'check_names':checks,'split_build_sha256':sha(BUILD/'split_build.json'),'guard_sha256':{k:v['guard_sha256']for k,v in meta['module_fixtures'].items()},'test_source_sha256':sha(Path(__file__)),'fixture_adapter_sha256':sha(HERE/'verify_split.py'),'limits':['The compiled guard code is real; a firmware callback setting the shared ENDED phase is an explicit model, not the not-yet-built installer/provider EBS callback.','No claim that guard wrappers prevent a preexisting OEM function from calling services after an EBS event inside that original function.','No real UEFI services or native graphical BIOS executed.']}
 (BUILD/'split_boundary_regression.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'checks':len(checks)}))

if __name__=='__main__':main()
