"""Read only the redacted first normal-update run; never access BMC or stdin."""
from pathlib import Path
import datetime, hashlib, json, re

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
RUN=BASE/'bmc_flash05/run-20261108T052648098Z'
EXPECTED={
 'flash_api.mjs':'bf621240820b1fd1da8aa161c7f56f602a8422661ac1219c3feead5e0c172b73',
 'flash_core.mjs':'88fd56efa4005e5942ed966f72ccfe603481f9773f0804474331c3c1e5e3c108',
 'source_manifest.json':'f896d0acdb4ac32dffebf688cf38dc9acfa672b0ab647add81815eaf33d09dfc',
 'preflight-policy.json':'11bcff39325e0a67d567ffd637a931f151108dd464b4cc533b53c86d7f79a752',
}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def rel(p):return p.resolve().relative_to(ROOT.resolve()).as_posix()
def utc(value):return datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
def require(ok,message):
    if not ok:raise ValueError(message)
checks=[]
def check(ok,label):require(ok,label);checks.append(label)

files=sorted(p for p in RUN.glob('*.json') if re.fullmatch(r'\d{4}-[a-z-]+\.json',p.name))
require(files,'No redacted run logs found')
raw={p:p.read_bytes() for p in files};rows={p.name:json.loads(b) for p,b in raw.items()}
inputs=[{'path':rel(p),'sha256':sha(b),'bytes':len(b)} for p,b in raw.items()]
for name,expected in EXPECTED.items():
    p=BASE/'bmc_flash05'/name;data=p.read_bytes();check(sha(data)==expected,'frozen '+name+' identity')
    inputs.append({'path':rel(p),'sha256':sha(data),'bytes':len(data)})
binding=rows['0003-source-binding.json']
check(binding['source_manifest_sha256']==EXPECTED['source_manifest.json'],'live log binds frozen source manifest')
check(binding['manifest']['core_sha256']==EXPECTED['flash_core.mjs'] and binding['manifest']['api_sha256']==EXPECTED['flash_api.mjs'],'live source identity')
initial=rows['0001-metadata-before.json']
check(initial['power']=='Off' and initial['bios']=='1904' and initial['update']=={'status':None,'target':None,'percentage':None},'initial Off/1904/idle observation')
login=rows['0002-login.json']
check(login['http']==200 and login['body']['ok']==0 and login['body']['privilege']==4 and login['body']['user_id']==4,'normal administrator login visible fields')
check(login['body']['CSRFToken']=='[REDACTED]' and login['body']['racsession_id']=='[REDACTED]' and login['body']['passwordStatus']=='[REDACTED]','login private fields remain redacted')
events=[v for v in rows.values() if 'event' in v]
intents=[r for r in events if r['event']=='write_intent']
check([r['operation'] for r in intents]==['entry','prepare','exit'],'only Entry/Prepare/explicit Exit update writes observed')
entry=next(r for r in events if r['event']=='write_confirmed' and r.get('operation')=='entry')
entry_intent=intents[0]
check(entry_intent['method']=='PUT' and entry_intent['path']=='/api/maintenance/bios/updatemode' and entry_intent['body']=={},'Entry request is normal empty-parameter PUT')
check(entry['response']=={'status':200,'body':{'unique_id':'[REDACTED]'}} and entry['state']['phase']=='ENTERED' and entry['state']['update_id_received'] is True,'successful Entry with owned ID bound')
prepare=intents[1]
check(prepare['method']=='PUT' and prepare['path']=='/api/maintenance/bios/preparecomponents','normal Prepare route')
check(prepare['body']=={'COMPONENT_ID':2,'COMPONENT_DATA_LEN':67108864,'FWUPDATEID':'[REDACTED]','IS_MMC':0},'exact visible Prepare fields')
check(prepare['state']['phase']=='PREPARE_ATTEMPTED' and prepare['state']['update_id_received'] is True,'Prepare starts with owned update ID')
failed=next(r for r in events if r['event']=='write_rejected_or_unknown' and r.get('operation')=='prepare')
check(failed['response']=={'status':500,'body':{'error':'Error in initial Upgrade Action','code':1373}},'exact actual Prepare generic error')
check(failed['state']['phase']=='PREPARE_UNKNOWN' and failed['state']['unknown_operation']=='prepare','generic error preserved as UNKNOWN')
duration=(utc(failed['utc'])-utc(prepare['utc'])).total_seconds()
check(duration==32.482,'Prepare intent-to-result recorded interval is 32.482 seconds')
for state in [r['state'] for r in events if 'state' in r]:
    check(state['flash_request_sent'] is False and state['verify_request_sent'] is False and state['preflight_receipt_sha256'] is None and state['root_preflight_reviewed'] is False,'state retains no flash/verify dispatch or reviewed final preflight')
forbidden={'signature_upload','signature_verify','payload','flash','verify_image'}
check(not any(r.get('operation') in forbidden for r in events),'no CAP/payload upload, signature check, flash or readback request in this run')
check(not any(r.get('event') in {'actual_preflight_receipt','root_reviewed_actual_preflight'} for r in events) and not (RUN/'preflight-receipt.json').exists(),'actual MTD/CAP preflight and flash approval never reached')
check(not any('/biosversion?' in r.get('path','') for r in events),'native MTD/CAP version endpoint never reached')
abort=next(r for r in events if r['event']=='explicit_preflash_only_best_effort_abort')
check(abort['original_unknown']=={'phase':'PREPARE_UNKNOWN','operation':'prepare'} and abort['atomic_hardware_restoration_claimed'] is False,'explicit limited abort retains original unknown')
check(utc(abort['utc'])>utc(failed['utc']),'abort is a later explicit operation')
exit_intent=intents[2]
check(exit_intent['method']=='PUT' and exit_intent['path']=='/api/maintenance/bios/exitupdatemode' and exit_intent['body']=={'FWUPDATEID':'[REDACTED]','COMPONENT_ID':2},'single normal owned-ID Exit request')
exit_result=next(r for r in events if r['event']=='write_confirmed' and r.get('operation')=='exit')
check(exit_result['response']=={'status':200,'body':{'cc':0}} and exit_result['state']['phase']=='EXITED','Exit returned exact success contract')
fixed=next(r for r in events if r['event']=='preflash_abort_fixed_cleanup_confirmed')
check(fixed['state']['unknown_history_count']==1 and fixed['state']['preflash_abort_fixed_cleanup_confirmed'] is True and fixed['atomic_hardware_restoration_claimed'] is False and fixed['independent_host_restoration_check_required'] is True,'fixed cleanup success preserves unknown history and physical-restoration limit')
exit_seconds=(utc(exit_result['utc'])-utc(exit_intent['utc'])).total_seconds()
check(exit_seconds==6.158,'Exit intent-to-result recorded interval is 6.158 seconds')
logout=[r for n,r in rows.items() if n.endswith('-logout.json')]
if logout:check(len(logout)==1 and logout[0]['http']==200 and logout[0]['body']=={'ok':0} and logout[0]['confirmed'] is True,'normal logout success recorded')
after=[r for n,r in rows.items() if n.endswith('-metadata-after.json')]
for p,b in raw.items():check(p.read_bytes()==b,'snapshot input unchanged '+p.name)

result={
 'status':'PASS_REVIEW_PREPARE_UNKNOWN_PREFLASH_ABORT_NO_CANDIDATE_UPLOAD_OR_FLASH',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'scope':'Independent read-only review of frozen source and redacted files visible in the named run; no credentials/session memory or BMC access.',
 'run':rel(RUN),'snapshot_first_utc':min(r['utc'] for r in rows.values()),'snapshot_last_utc':max(r['utc'] for r in rows.values()),'snapshot_files':len(files),
 'checks':len(checks),'check_names':checks,'inputs':inputs,
 'source_manifest_field_scope':'api_network_entrypoint_executed=false inside the frozen build manifest records the prior local source-build phase, not this later live run.',
 'entry':{'intent_utc':entry_intent['utc'],'result_utc':entry['utc'],'http':200,'owned_id_received':True,'id_value_not_read':True},
 'prepare':{'intent_utc':prepare['utc'],'result_utc':failed['utc'],'intent_to_result_seconds':duration,'method':'PUT','path':prepare['path'],'visible_body':prepare['body'],'http':500,'body':failed['response']['body'],'result_class':'UNKNOWN'},
 'execution_boundary':{'observed_update_write_operations':['entry','prepare','exit'],'cap_uploaded':False,'payload_uploaded':False,'signature_verification_invoked':False,'native_biosversion_invoked':False,'flash_request_sent':False,'verifyimage_request_sent':False,'final_preflight_approved':False},
 'abort':{'explicit_preflash_only':True,'intent_utc':exit_intent['utc'],'result_utc':exit_result['utc'],'intent_to_result_seconds':exit_seconds,'http':200,'body':{'cc':0},'fixed_cleanup_confirmed':True,'unknown_history_retained':True,'atomic_hardware_restoration_proven':False},
 'logout_confirmed_in_snapshot':bool(logout),
 'after_metadata':({'power':after[-1]['power'],'bios':after[-1]['bios'],'update':after[-1]['update'],'boot_equal_to_initial':after[-1]['boot']==initial['boot']} if after else None),
 'inference_limits':[
  'Generic 1373 does not distinguish absent wiring, voltage, JEDEC/read failure, memory/capacity, provider/library failure or manager IPC timeout. No specific cause is assigned.',
  'Prepare/Exit can switch GPIO and load/unload host-SPI providers. No upload/flash request is not a claim that no hardware or temporary state changed.',
  'Successful fixed Exit cleanup is not atomic rollback or independently observed physical restoration. Host recovery/POST must be checked separately.',
  'Numeric FWUPDATEID and passwordStatus are redacted. Their runtime validation/binding is supported by the pinned source and recorded accepted transitions, not an independent reading of secret/session memory.',
  'The recorded intervals span persisted intent and persisted result, including local overhead; they are not packet-level latency measurements.',
  'This snapshot concerns this named runner only and is not an independent capture of all BMC traffic.'
 ],
 'network_or_bmc_access_by_reviewer':False,'private_session_memory_read':False,'frozen_sources_modified':False,
 'script_sha256':sha(Path(__file__).read_bytes()),
}
out=HERE/'live_preflight_review-run-20261108T052648098Z.json'
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':result['status'],'checks':len(checks),'snapshot_files':len(files),'prepare_seconds':duration,'exit_seconds':exit_seconds,'report_sha256':sha(out.read_bytes()),'network_or_bmc_access':False}))
