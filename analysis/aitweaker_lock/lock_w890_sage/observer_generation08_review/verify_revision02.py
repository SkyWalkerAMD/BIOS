"""Replay preserved regression cases against the separate revision02 DLL."""
from pathlib import Path
import sys,json,hashlib,importlib.util,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];P=B/'observer_generation08/revision02'
sys.path.insert(0,str(R/'tools/pydeps'))
spec=importlib.util.spec_from_file_location('observer_generation_r2_fixture',P/'verify_generation.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
# Reuse exactly the preserved independent injection/fixture class. Its imports
# resolve to the new harness, while no old main() or output function executes.
sys.modules['verify_generation']=g
spec=importlib.util.spec_from_file_location('preserved_independent_repro',H/'reproduce_revalidation.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
VM,DATA,TSE,Q,I,ns=a.VM,a.DATA,a.TSE,a.Q,a.I,a.ns
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def check_inputs():
 dll=P/'build/W890ObserverGeneration08r2.TESTONLY.dll'
 assert sha(dll)=='3d5e9bdbdeadd566494d7b9f6b67cc5ba32e50b981e71944845eeb4c50fab914'
 build=json.loads((P/'build/build.json').read_text())
 for p,h in build['sources'].items():assert sha(R/p)==h
 return {'dll':bind(dll),'source':bind(P/'observer08r2.c'),'build':bind(P/'build/build.json'),'preserved_repro':bind(H/'reproduce_revalidation.py')}

def main():
 initial=check_inputs();old=a.manifest();rows=[]
 for name in ('no_catalog_generation','no_native_visit_identity'):
  start=time.monotonic();v=VM();v.ready();p=DATA+0x34000;r=p+16;v.w(p,Q(0x1111));v.w(r,I(0x2222))
  v.arm_target=name;args=[p] if name=='no_catalog_generation' else[p,r]
  v.loop([(name,args),(name,args)])
  assert v.sequence_values==[0,0] and v.q(p)==0x1111 and v.fault()==1 and len(v.injections)==1
  assert not v.set_count
  rows.append({'case':name+' refuses Setup revocation during identity services','status':'PASS','results':v.sequence_values,'output_unmodified':True,'fault':1,'seconds':round(time.monotonic()-start,3)})
  print(rows[-1]['case'],flush=True)
 start=time.monotonic();v=VM();v.ready();v.arm_target='no_scope_enter';v.w(v.result,bytes(64))
 v.loop([('og08_test_read',[v.app,v.result])]);r=v.result_fields()
 assert v.sequence_values==[0] and r['entered']==0 and r['before_valid']==r['after_valid']==0 and v.fault()==1
 assert not v.lab_calls and not v.set_count
 rows.append({'case':'scope_enter refuses to mint after Setup revocation','status':'PASS','report':r,'consumer_result':v.sequence_values,'fault':1,'seconds':round(time.monotonic()-start,3)})
 print(rows[-1]['case'],flush=True)
 start=time.monotonic();v=VM();v.publish_and_management_fixture();v.notify_mode='foreign';tickets=[];details={}
 enter=[0,TSE+0x3e4f0,v.config,1,0xffd0,10,v.mv,v.mr,v.mt]
 def arm(w):w.arm_target='no_management_valid'
 def old_left(w):
  details['old_path']=list(w.sequence_values)
  assert w.sequence_values[:5]==[1,1,0,0,0],w.sequence_values
  w.sequence += [('no_management_enter',enter),new_minted]
 def new_minted(w):
  assert w.sequence_values[-1]==1;new=w.q(w.mt);assert new and new!=tickets[0]
  details['new_sequence_differs']=True
  w.sequence += [('no_management_valid',[0,new]),('no_management_leave',[0,new])]
 def after_enter(w):
  assert w.sequence_values==[1];tickets.append(w.q(w.mt));assert tickets[0]
  w.sequence += [('no_management_valid',[0,tickets[0]]),arm,
      ('no_management_valid',[0,tickets[0]]),('no_management_enter',enter),
      ('no_management_valid',[0,tickets[0]]),('no_management_leave',[0,tickets[0]]),old_left]
 v.loop([('no_management_enter',enter),after_enter])
 assert v.sequence_values[-2]==1 and v.fault()==0 and len(v.injections)==1 and not v.set_count
 rows.append({'case':'management generation rechecked and occupied until original owner leaves','status':'PASS','enter_before_during_nested_after':v.sequence_values[:5],
              'new_ticket_valid_after_owner_leave':True,'new_sequence_differs':details['new_sequence_differs'],'fault':0,
              'caller_boundary':'Enter caller value remains an explicit ABI fixture, not execution of original ConfigAccess CALL.',
              'seconds':round(time.monotonic()-start,3)})
 print(rows[-1]['case'],flush=True)
 start=time.monotonic();v=VM();v.ready();p=DATA+0x34000;v.w(p,Q(0));v.notify_mode='foreign';v.arm_target='no_catalog_generation'
 v.loop([('no_catalog_generation',[p]),('n05_check',[2,v.page_list[1],0]),('no_identity',[v.idbuf])])
 assert v.sequence_values==[1,0,1] and v.q(p)==2 and v.fault()==0 and not v.set_count
 rows.append({'case':'foreign notification during readonly query returns new generation and preserves ordinary Main','status':'PASS','results':v.sequence_values,'generation':2,'fault':0,'seconds':round(time.monotonic()-start,3)})
 print(rows[-1]['case'],flush=True)
 assert check_inputs()==initial and a.manifest()==old
 out={'status':'PASS_PRESERVED_REVALIDATION_REGRESSIONS_AND_BOUNDED_POSITIVES','source':bind(Path(__file__)),'inputs':initial,
      'cases':rows,'private_observer_state_modified':False,'frozen_revision01_unchanged':True,
      'limits':['Same declared UEFI/native-page/CPU/crypto fixtures as revision01; notification scheduling modeled.',
                'Actual compiled private Loop and registered notification execute; full BrowserLoop/physical timing not established.',
                'Twoog08_test_* functions remain test-only and must be excluded from production integration.',
                'No new callback route, credential/OC write, CAP, hardware action or full GUI claim.']}
 (H/'revision02_replay.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'cases':len(rows),'status':out['status']}))

if __name__=='__main__':main()
