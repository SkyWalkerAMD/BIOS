"""Regression of actual combined native UI component, never a boot/flash test.

The13-instance composite native parser data and complete FORMS are declared
fixtures. Tests exercise actual compiled observer/classifier/gate/history/Main
fallback code in the real private loop, but not full native GUI construction.
"""
from pathlib import Path
import argparse,hashlib,json,struct,time
import combined_vm as c
H=Path(__file__).resolve().parent
DENIED=c.ns['ERR'](15)

def expect(value,wanted):assert value==wanted,(value,wanted)
def assert_snapshot(v,kind,owner=None,hii=None):
 s=v.view();assert s['classification']==kind,s
 if owner is not None:assert s['owner']==owner,s
 if hii is not None:assert s['hii']==hii,s
 return s

def ordinary_menus(v):
 targets=[v.find_page('NvmeDynamicSetup',1),v.find_page('SocketSetup',0x510),
  v.find_page('NON_FV_25FD_INSTANCE_0'),v.find_page('NON_FV_25FD_INSTANCE_1')]
 transitions=[];steps=[]
 for target in targets:
  for destination in (target,v.main):
   step=['n05_menu',[]]
   def prepare(w,destination=destination,step=step):step[1]=list(w.prepare_menu(destination))
   def check(w,destination=destination):
    assert w.sequence_values[-1]==0 and w.index()==destination['index'],(w.sequence_values,w.index(),destination['index'])
    transitions.append({'destination_module':destination['module'],'destination_hii':destination['hii'],
     'destination_form':destination['form'],'destination_index':destination['index']})
   steps += [prepare,step,check]
 v.loop(steps)
 assert v.raw_calls.get('fp08_describe_page',0)>=8
 return {'native_menu_transitions':transitions,'foreign_executable_permission_added':False}

def foreign_current(v,module,form=None):
 row=v.find_page(module,form);v.set_current(row);seen=[]
 def save(w):seen.append(assert_snapshot(w,0,2,row['hii']))
 v.loop([('no_observe',[0,1,0,0,v.obs]),save,('n05_check',[1,0,0])])
 assert v.sequence_values==[1,0]
 return {'view':seen[0],'original_callback_executed':False,'callback_review_flags_do_not_globally_block_page':True}

def protected_page(v,module,form):
 row=v.find_page(module,form);v.set_current(row);seen=[];v.queue('\x1b')
 def save(w):seen.append(assert_snapshot(w,1,2,row['hii']))
 v.loop([('no_observe',[0,1,0,0,v.obs]),save,('n05_check',[1,0,0])])
 assert v.sequence_values==[1,DENIED] and v.index()==row['index']
 return {'view':seen[0],'denied':True,'write_or_callback_executed':False}

def protected_control(v,module,form,qid,op):
 row=v.find_page(module,form);v.set_current(row);control=v.prepare_control(row,qid,op);seen=[];v.queue('\x1b')
 def save(w):seen.append(assert_snapshot(w,1,2,row['hii']))
 v.loop([('no_observe',[0,4,control,0,v.obs]),save,('n05_check',[4,control,0])])
 assert v.sequence_values==[1,DENIED]
 return {'view':seen[0],'native_control':v.selected_controls[control],'write_or_callback_executed':False}

def ordinary_control(v):
 row=v.find_page('SocketSetup',0x510);v.set_current(row);control=v.prepare_control(row,1,15);seen=[]
 def save(w):seen.append(assert_snapshot(w,0,2,row['hii']))
 v.loop([('no_observe',[0,4,control,0,v.obs]),save,('n05_check',[4,control,0])])
 assert v.sequence_values==[1,0]
 return {'view':seen[0],'native_control':v.selected_controls[control],'handler_not_invoked':True}

def refresh(v):
 row=v.find_page('NvmeDynamicSetup',1);v.set_current(row);seen=[]
 def save(w):seen.append(assert_snapshot(w,0,2,row['hii']))
 v.loop([('no_observe',[0,1,0,0,v.obs]),save,(v.notify_callback,[2,0,0,row['hii'],2]),
  ('no_observe',[0,1,0,0,v.obs]),save,('n05_check',[1,0,0])])
 assert v.sequence_values==[1,0,1,0]
 assert seen[1]['catalog_generation']==seen[0]['catalog_generation']+1
 assert seen[0]['session']==seen[1]['session']
 return {'observations':seen,'same_native_visit':True,'actual_callback_invoked':True,
  'model_boundary':'Remove event with unchanged final FORMS; does not simulate native package rebuild.'}

def unknown_package(v,row,shadow_main=False):
 data=bytearray(v.package_models[row['hii']]['data'])
 # Existing Nvme form1 header at FORMS+139. Mutate only16-bit title (or
 # negative-fixture FormId), preserving complete IFR structure and extent.
 assert data[20+139:20+141]==b'\x01\x86'
 if shadow_main:
  data[20+141:20+143]=struct.pack('<H',0x2712)
  v.w(v.page_list[row['index']]+0x2a,struct.pack('<H',0x2712));v.w(row['raw']+10,struct.pack('<H',0x2712))
 else:data[20+143]^=1
 v.package_overrides[row['hii']]=bytes(data)
 return {'package_sha256':c.sha(data),'changed':'FormId1 to0x2712 in explicit negative fixture' if shadow_main else 'Form1 title16-bit value; original lengths/scopes preserved'}

def unknown_recovery(v,shadow=False):
 row=v.find_page('NvmeDynamicSetup',1);v.set_current(row);mutation=unknown_package(v,row,shadow);seen=[]
 def save(w):seen.append(assert_snapshot(w,-1,2,row['hii']))
 # The actual native push caller obtains tracked storage while identity is
 # valid but classification remains UNKNOWN. This grants no callback rights.
 v.loop([('no_observe',[0,1,0,0,v.obs]),save,('n05_check',[1,0,0]),
  (c.TSE+0x1b928,[v.main['index'],row['index']]),('n05_first',[])])
 assert v.sequence_values[:2]==[1,DENIED] and v.sequence_values[-1]==2,(v.sequence_values,v.index())
 assert v.main_ok() and not v.free_trace
 cached=[p for p in v.cached_trace if p['tpl']==16]
 assert cached and all(p['return_value']==1 and not p['services']for p in cached),cached
 return {'initial_view':seen[0],'unknown_gate_denied':True,'mutation':mutation,
  'final_index':v.index(),'final_hii':v.setup_hii,'shadow_main_rejected':shadow,
  'native_history_tracked':True,'cached_validation_services':0,'cached_calls':len(cached)}

def unknown_unowned_history(v):
 row=v.find_page('NvmeDynamicSetup',1);v.set_current(row);unknown_package(v,row)
 old=c.DATA+0x2a000;before=c.Q(row['hii'])+c.I(row['form'])+bytes(20);v.w(old,before)
 v.w(c.TSE+0xafde8,c.Q(old));v.w(c.TSE+0xafde0,c.I(len(v.page_list)+20));v.w(c.TSE+0xafe00,c.I(1));v.w(c.TSE+0xafddc,c.I(row['index']))
 v.loop([('n05_first',[])])
 assert v.sequence_values==[0] and v.index()==row['index'] and v.r(old,32)==before and not v.free_trace
 return {'caller_history_not_owned':True,'no_main_commit':True,'no_history_write_or_free':True}

def unknown_control(v):
 row=v.find_page('SocketSetup',0x510);v.set_current(row);control=v.prepare_control(row,1,15)
 data=bytearray(v.package_models[row['hii']]['data']);end=20+int.from_bytes(data[20:23],'little')
 at=24;changed=[]
 while at<end:
  length=data[at+1]&127;assert length>=2 and at+length<=end
  if data[at]==1 and int.from_bytes(data[at+2:at+4],'little')==row['form']:
   data[at+4]^=1;changed.append(at+4)
  at+=length
 assert len(changed)==1;v.package_overrides[row['hii']]=bytes(data);seen=[]
 def save(w):seen.append(assert_snapshot(w,-1,2,row['hii']))
 v.loop([('no_observe',[0,4,control,0,v.obs]),save,('n05_check',[4,control,0])])
 assert v.sequence_values==[1,DENIED]
 return {'view':seen[0],'native_control':v.selected_controls[control],
  'mutation':'Only16-bit Form510 title changed; control opcode unchanged',
  'package_sha256':c.sha(data),'unknown_operation_denied':True,'handler_not_invoked':True}

def escape_foreign_protected(v):
 row=v.find_page('Platform',0x3f0);v.set_current(row);v.queue('\x1b')
 v.loop([(c.TSE+0x1b928,[v.main['index'],row['index']]),('n05_first',[])])
 assert v.sequence_values[-1]==2 and v.main_ok()
 cached=[p for p in v.cached_trace if p['tpl']==16]
 assert cached and all(p['return_value']==1 and not p['services']for p in cached)
 return {'protected_form':row['form'],'cancel_returns_actual_Setup_Main':True,'cached_validation_services':0,
  'source_hii':row['hii'],'main_hii':v.setup_hii,'cached_calls':len(cached)}

def stale_raw_at_commit(v):
 row=v.find_page('NvmeDynamicSetup',1);v.set_current(row);unknown_package(v,row)
 def mutate(w):w.w(row['raw']+10,struct.pack('<H',2))
 v.exclusion_mutation=mutate
 v.loop([(c.TSE+0x1b928,[v.main['index'],row['index']]),('n05_first',[])])
 assert v.sequence_values[-1]==0 and v.index()==row['index'] and v.used()==1
 cached=[p for p in v.cached_trace if p['tpl']==16]
 assert cached and cached[-1]['return_value']==0 and not cached[-1]['services']
 return {'explicit_race_fixture':'Raw native FormId changes immediately before excluded commit',
  'cached_validation_denied':True,'cached_validation_services':0,'main_not_committed':True}

def mismatched_owner(v):
 row=v.find_page('NvmeDynamicSetup',1);v.set_current(row)
 v.w(v.page_list[row['index']]+0x20,c.Q(v.setup_hii))
 v.loop([('no_observe',[0,1,0,0,v.obs]),('n05_check',[1,0,0])])
 assert v.sequence_values==[0,DENIED]
 return {'foreign_page_cannot_spoof_setup_hii_without_matching_raw':True}

def run():
 ap=argparse.ArgumentParser();ap.add_argument('--candidate-dir');ap.add_argument('--filter',default='');args=ap.parse_args()
 candidate=c.bind_candidate(args.candidate_dir);cases=[]
 suite=[('Main-Nvme-Socket-NIC-roundtrips',ordinary_menus),
  ('Socket-ordinary-page-preserved',lambda v:foreign_current(v,'SocketSetup',0x510)),
  ('NIC0-ordinary-page-preserved',lambda v:foreign_current(v,'NON_FV_25FD_INSTANCE_0')),
  ('NIC1-distinct-handle-preserved',lambda v:foreign_current(v,'NON_FV_25FD_INSTANCE_1')),
  ('Platform-OC-page-denied',lambda v:protected_page(v,'Platform',0x3f0)),
  ('Socket-memory-page-denied',lambda v:protected_page(v,'SocketSetup',0x540)),
  ('Platform-OC-REF-denied',lambda v:protected_control(v,'Platform',1,7,15)),
  ('Socket-memory-REF-denied',lambda v:protected_control(v,'SocketSetup',0x510,4,15)),
  ('Platform-OC-field-denied',lambda v:protected_control(v,'Platform',0x3f0,0xd4,5)),
  ('Socket-shared-protected-field-denied',lambda v:protected_control(v,'SocketSetup',0x540,0x52,5)),
  ('Ordinary-Socket-REF-preserved',ordinary_control),('Foreign-generation-renews-view',refresh),
  ('Unknown-foreign-denied-tracked-recovery',unknown_recovery),
  ('Foreign-shadow-Main-not-selected',lambda v:unknown_recovery(v,True)),
  ('Unknown-foreign-control-denied',unknown_control),
  ('Unknown-external-history-never-owned',unknown_unowned_history),
  ('Escape-foreign-protected-to-Setup-Main',escape_foreign_protected),
  ('Cached-ticket-raw-drift-denied-without-services',stale_raw_at_commit),
  ('Foreign-outer-HII-spoof-denied',mismatched_owner)]
 out=H/('combination_selected_tests.json'if args.filter else'combination_tests.json')
 for name,body in suite:
  if args.filter and args.filter.lower()not in name.lower():continue
  started=time.monotonic();v=c.VM();v.ready()
  try:
   details=body(v);assert not v.set_count,'No test writes any modeled credential'
   assert not v.cached_pending,'Incomplete cached-validation instruction run'
  except Exception:
   (H/'failure.json').write_text(json.dumps({'name':name,'candidate':candidate,'sequence':v.sequence_values,
    'index':v.index(),'view':v.view(),'call_counts':v.raw_calls,'exports':v.export_trace[-15:],
    'cached_trace':v.cached_trace,'services_tail':v.service_trace[-15:]},indent=2)+'\n');raise
  cases.append({'name':name,'passed':True,'seconds':round(time.monotonic()-started,3),
   'details':details,'evidence':v.actual_identity_summary()})
  report={'passed':True,'checks':len(cases),'candidate':candidate,'snapshot_sha256':c.sha(v.snapshot_path.read_bytes()),
   'sources':{p.name:c.sha(p.read_bytes())for p in(H/'combined_vm.py',Path(__file__))},'cases':cases,
   'models':['UEFI/CPU/memory-map services and BrowserLoop body are explicit fixtures.',
    'Raw pages/control/IFR originate in bounded parser output over13composite HII instances.',
    'Parser preparation used two RAM-only bound experiments; GUI VM imports no modified text.',
    'Initial App/page/frame outer construction is a model; original menu/history functions execute.',
    'SHA/PBKDF/RDSEED use pre-existing independent oracles; this is not full cryptographic qualification.',
    'Ordinary page admission adds no callback/source privilege; no foreign callbacks are executed.',
    'No hardware, password setting, firmware image output, full GUI startup or flashing.'],
   'frozen_mains_executed':False,'hardware_actions':0,'firmware_changes':0}
  out.write_text(json.dumps(report,indent=2)+'\n');print(name,'PASS',round(time.monotonic()-started,2),flush=True)
 print('PASS',len(cases),flush=True)

if __name__=='__main__':run()
