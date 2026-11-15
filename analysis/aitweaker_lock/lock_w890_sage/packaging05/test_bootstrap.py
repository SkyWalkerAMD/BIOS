"""Execute the actual aggregate bootstrap with explicitly modeled DXE services.

Original vendor 6480 entry body is a named boundary model, not a real firmware
boot. Real immutable layout, service binding, independent password provider,
EBS notification and lifecycle failure decisions execute compiled instructions.
Native parser and GUI are intentionally NOT counted as passing here.
"""
from pathlib import Path
import hashlib,json,sys,time
H=Path(__file__).resolve().parent;B=H.parent
sys.path.insert(0,str(B/'integration05'))
import verify_static_chain as lab
from unicorn.x86_const import UC_X86_REG_RIP

class Bootstrap(lab.Static):
 def __init__(self,native_status=0):
  self.native_status=native_status;self.native_entries=[]
  super().__init__()
 def hook(self,u,a,n,x):
  if hasattr(self,'event_callbacks') and a==lab.TSE+0x6480:
   self.native_entries.append({'event_count_before_vendor_entry':len(self.event_callbacks)})
   self.ret(self.native_status);return
  return super().hook(u,a,n,x)

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

checks=[]
def check(name,ok):
 assert ok,name
 checks.append({'name':name,'pass':True})
 print('PASS '+name,flush=True)

start=time.monotonic();v=Bootstrap()
check('Actual static entry captures the modeled genuine LoadedImage',v.run('i05_entry',v.tse_handle,v.st)==0)
check('Own EBS notification is registered before vendor entry boundary',v.native_entries==[{'event_count_before_vendor_entry':1}])
check('Repeated cold entry is rejected without another vendor invocation',v.run('i05_entry',v.tse_handle,v.st)==lab.ERR(15) and len(v.native_entries)==1)
for rva in [0x19cf8,0x1b7dc,0x1c17c]:v.run(lab.TSE+rva)
check('Real service bootstrap accepts initial unconfigured password',v.run('i05_services')==0)
trace={name:value for name,value in v.init_trace}
check('Runtime returns AP_UNCONFIGURED while all other bindings succeed',trace.get('w890_runtime_bind')=='0x6' and all(trace.get(x)=='0x0' for x in ['no_initialize','no_prepare','mp_bind','n05_bind','n05_bridges_bind','ws05_prepare']))
check('ConfigAccess is bound to the actual composed management callback',v.q(v.config+16)==lab.symbols['mp_callback'])
check('Service bootstrap itself neither publishes HII nor writes credentials',v.hii_updates==0 and not v.new_strings and v.set_count==0)
event=v.q(lab.symbols['bootstrap_event']);callback,context=v.event_callbacks[event]
check('Registered bootstrap callback is the actual linked function',callback==lab.symbols['bootstrap_end'])
before=len(v.uefi_calls);v.run(callback,event,context)
check('EBS callback completes without a boot-service call',len(v.uefi_calls)==before)
check('After EBS service access is denied without UEFI calls',v.run('i05_services')==lab.ERR(15) and len(v.uefi_calls)==before)
v.run('i05_dispatch',0,0,0,0)
check('After EBS ordinary dispatcher cannot invoke stale firmware services',len(v.uefi_calls)==before)

bad=Bootstrap();bad.w(bad.li_tse+0x48,lab.Q(lab.size-4096))
check('Wrong LoadedImage extent rejects before vendor entry',bad.run('i05_entry',bad.tse_handle,bad.st)==lab.ERR(15) and not bad.native_entries)
failed=Bootstrap(native_status=lab.ERR(7))
check('Original entry failure is returned rather than converted to success',failed.run('i05_entry',failed.tse_handle,failed.st)==lab.ERR(7))
check('Failed original entry releases own EBS event',failed.q(lab.symbols['bootstrap_event'])==0)
check('Failure paths did not write HII or credentials',bad.hii_updates==failed.hii_updates==0 and bad.set_count==failed.set_count==0)

result={'status':'PASS_ACTUAL_AGGREGATE_BOOTSTRAP_WITH_MODELED_VENDOR_ENTRY',
 'scope':__doc__,'checks':checks,'check_count':len(checks),'candidate':lab.latest,
 'component_sha256':lab.build['sha256'],'init_trace':v.init_trace,
 'source_bindings':[{'path':str(p),'sha256':sha(p)}for p in [Path(__file__),B/'integration05/verify_static_chain.py',B/'management_live04/verify_observer_chain.py',B/'native_observer04/verify_observer.py']],
 'native_parser_pass':False,'full_firmware_boot_pass':False,'hardware_actions':0,
 'elapsed_seconds':round(time.monotonic()-start,3)}
out=Path(lab.latest['report']).parent/'bootstrap_tests.json';out.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'checks':len(checks),'report':str(out)}),flush=True)
