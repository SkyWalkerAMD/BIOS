"""Freeze the first baseline06 media/session interruption and recovery evidence.
Read-only device evidence only; no controller or network access.
"""
from pathlib import Path
from datetime import datetime
import collections,hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
C10=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/continuation10'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bindings=[]
def bind(p):
 p=Path(p).resolve();r={'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)};bindings.append(r);return r
def get(name):p=HW/name;bind(p);return json.loads(p.read_text(encoding='utf8'))
def ts(s):return datetime.fromisoformat(s.replace('Z','+00:00'))
def main():
 out=HERE/'interrupted_attempt01_review.json';assert not out.exists();HERE.mkdir(exist_ok=True)
 a=get('manager-restart08-capability-1793711779989.json');b=get('manager-restart08-capability-1793712176588.json')
 assert a['system']['PowerState']==b['system']['PowerState']=='Off' and a['power']['data']['power_status']==b['power']['data']['power_status']==0
 assert a['system']['BiosVersion']==b['system']['BiosVersion']=='1904'
 assert a['media']['hd_active_sessions']==a['media']['cd_active_sessions']==b['media']['hd_active_sessions']==b['media']['cd_active_sessions']==128
 for obj in [a,b]:
  for k in ['system','settings']:
   boot=obj[k]['Boot'];assert [boot['BootSourceOverrideEnabled'],boot['BootSourceOverrideMode'],boot['BootSourceOverrideTarget']]==['Disabled','Legacy','None']
 before=a['system']['Boot']['BootOrder'];after=b['system']['Boot']['BootOrder'];assert [x for x in before if x!='Boot0007']==after
 assert before==a['settings']['Boot']['BootOrder'] and after==b['settings']['Boot']['BootOrder']
 power=get('power-on-1793711977509.json');assert power['action']=='On'and power['before_power']=='Off'and power['status']==202 and json.loads(power['body'])['Id']=='27'
 shut=get('power-1793712135455.json');assert shut['command']==5 and shut['before']['data']['power_status']==1 and shut['result']['status']==200
 rawpath=HW/'cd-observer08-1793711928447.jsonl';raw=rawpath.read_bytes();trace=[json.loads(x)for x in raw.splitlines()];bind(rawpath)
 tr=get('cd-observer08-1793711928447.jsonl.json');assert tr['packets']==len(trace)==12 and tr['truncated']is False
 counts=collections.Counter((r.get('direction','event'),r.get('opcode',r.get('event')))for r in trace)
 assert all(r.get('opcode')not in ['28','a8','2a','aa']for r in trace)
 cap=[r for r in trace if r.get('opcode')=='25'and r.get('direction')=='sent'];assert len(cap)==1 and cap[0]['capacity8']=='0000201f00000800'
 last=int(cap[0]['capacity8'][:8],16);block=int(cap[0]['capacity8'][8:],16);assert(last+1)*block==16842752
 assert trace[-2]['opcode']=='f7'and trace[-1]['event']=='closed'and trace[-2]['utc']==trace[-1]['utc']=='2026-11-03T13:20:00.798Z'
 # Preserve a bounded relevant projection from an append-only root log. It is
 # not appropriate to bind the later-mutating live file as immutable evidence.
 conpath=HW/'connection-events.jsonl';con=conpath.read_bytes();selected=[]
 for rawline in con.splitlines():
  r=json.loads(rawline)
  if '2026-11-03T13:19:'in r.get('utc','')or'2026-11-03T13:20:'in r.get('utc',''):
   assert set(r)<=set(['utc','kind','status','path','url'])
   selected.append({'event':r,'original_line_sha256':hashlib.sha256(rawline).hexdigest()})
 assert any(r['event']=={'utc':'2026-11-03T13:19:59.083Z','kind':'http','status':401,'path':'/api/Information'}for r in selected)
 projection=HERE/'attempt01_connection_projection.json';projection.write_text(json.dumps({'source':str(conpath.relative_to(ROOT)).replace('\\','/'),'source_read_bytes':len(con),'source_read_sha256':hashlib.sha256(con).hexdigest(),'scope':'Only the selected 13:19/13:20 UTC event rows; live root log may grow afterwards. No credentials/session/auth payload.','events':selected},indent=2)+'\n',encoding='utf8');bind(projection)
 workcopy=HERE/'attempt01_work_status_snapshot.json';workcopy.write_bytes((C10/'work_status.json').read_bytes());work=json.loads(workcopy.read_text());bind(workcopy)
 assert work['initial_attempt_interrupted']['f8_sent']==0
 for n in ['screen-325-current.png','screen-325-current.json','screen-326-current.png','screen-326-current.json']:bind(HW/n)
 retry=get('power-on-1793712233752.json');assert retry['action']=='On'and retry['before_power']=='Off'and retry['status']==202 and json.loads(retry['body'])['Id']=='28'
 clock_a=a['managers'][0]['DateTime'];clock_b=b['managers'][0]['DateTime']
 clock_delta=(ts(clock_b)-ts(clock_a)).total_seconds();host_delta=(ts(b['utc'])-ts(a['utc'])).total_seconds()
 result={'status':'INTERRUPTED_FIRST_BOOT_ATTEMPT_AND_BOUNDED_RECOVERY_OBSERVED','reviewed_by':'independent local reader; no device actions','candidate_efi_sha256':'2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169','candidate_iso_sha256':'1841d9a227f11ca7cce4270b75a32213a37e4b772f9040f293133554516db5f8','first_attempt':{'on_request_utc':power['utc'],'on_http_status':202,'task':'27','first_information_401_utc':'2026-11-03T13:19:59.083Z','login_navigation_observed':True,'cd_f7_and_close_utc':trace[-1]['utc'],'trace_events':len(trace),'opcode_counts':[{'direction':k[0],'opcode_or_event':k[1],'count':v}for k,v in sorted(counts.items())],'read_28_or_a8_observed':False,'write_2a_or_aa_observed':False,'announced_cd_capacity_bytes':(last+1)*block,'f8':{'sent':0,'viewer_closed_reported':True,'provenance':'Parent controller return reported in task and root work_status snapshot; no separate first-F8 operation result JSON independently located.'},'application_execution_evidence':False},'recovery':{'os_screen':'screen-325-current.png','visual_observation':'Rocky Linux 8.10 login prompt, kernel 4.18.0-553.el8_10.x86_64; not the baseline application.','acpi_shutdown_request_utc':shut['utc'],'acpi_http_status':200,'later_off_readback_utc':b['utc'],'redfish_off':True,'native_power_status':0,'cd_hd_idle_readback':128,'bios_version':'1904','retry_on_request_utc':retry['utc'],'retry_on_task':'28','original_bios_screen':'screen-326-current.png','bios_visual_observation':'Aptio Setup - AMI Main is visibly rendered; BIOS Version1904 x64, build12/03/2025. This screenshot is a subsequent retry boot, not proof of baseline execution.'},'configuration_readback':{'temporary_override_fields_before_and_after':['Disabled','Legacy','None'],'system_and_settings_match_at_both_reads':True,'boot_order_before':before,'boot_order_after':after,'only_removed_reference':'Boot0007','other_reference_order_preserved':True,'scope':'Reference comparison only; option identity is not re-queried by this review and no complete NVRAM equality is inferred.'},'clock_observation':{'manager_before':clock_a,'manager_after':clock_b,'manager_elapsed_seconds':clock_delta,'reviewer_clock_elapsed_seconds':host_delta,'difference_seconds':clock_delta-host_delta,'causal_attribution':'Not established. The clock-offset change and authentication/session interruption are correlated observations, not proof of the expiry mechanism.'},'limits':['The 12 trace records cover this socket observation; absence of READ in this trace is not a global firmware execution trace.','No baseline QR was captured in this first attempt, so this is not an application failure or a successful SendForm result.','HTTP202 On and HTTP200 ACPI are acceptance records; actual Off is separately established by later Redfish/native observations.','Current device state after these historic observations remains owned by the parent; this report is not a live status declaration.','No guard, password, native GUI baseline or firmware release acceptance.'],'bindings':bindings}
 bind(Path(__file__));result['bindings']=bindings;out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':result['status'],'sha256':sha(out),'path':str(out)}))
if __name__=='__main__':main()
