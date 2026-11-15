"""Independent read-only C10 closure and published-scope audit."""
from pathlib import Path
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.parse import unquote
import hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;C10=HERE.parent;READY=C10.parent.parent
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir());HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bindings={}
def bind(p,expected=None,size=None):
 p=Path(p).resolve();assert p.is_relative_to(ROOT);h=sha(p);assert expected is None or h==expected;assert size is None or p.stat().st_size==size
 r={'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':h};bindings[r['path']]=r;return r
def evidence(obj):
 if isinstance(obj,dict):
  if all(k in obj for k in ['path','sha256']):bind(obj['path'],obj['sha256'],obj.get('bytes'))
  else:
   for value in obj.values():evidence(value)
 elif isinstance(obj,list):
  for value in obj:evidence(value)
class Parser(HTMLParser):
 def __init__(self):super().__init__();self.links=[];self.text=[];self.scripts=0
 def handle_starttag(self,tag,attrs):
  if tag=='a':self.links.append(dict(attrs).get('href'))
  if tag=='script':self.scripts+=1
 def handle_data(self,data):self.text.append(data)
def main():
 out=HERE/'independent_review.json';assert not out.exists();snap=HERE/'publication_snapshot';snap.mkdir(exist_ok=True)
 root_files=[READY/'acceptance_status.json',READY/'检查报告.html',C10/'validation10_result.json',C10/'publication10_check.json',C10/'publish_validation10.py',C10/'work_status.json']
 inputs=[]
 for p in root_files:
  dst=snap/p.name;dst.write_bytes(p.read_bytes());inputs.append({'source':str(p.relative_to(ROOT)).replace('\\','/'),'observed_sha256':sha(p),'snapshot':bind(dst)})
 check=json.loads((C10/'publication10_check.json').read_text())
 for name,h in check['files'].items():assert sha(READY/name)==h,name
 summary=json.loads((C10/'validation10_result.json').read_text());status=json.loads((READY/'acceptance_status.json').read_text());work=json.loads((C10/'work_status.json').read_text())
 assert summary==status['latest_remote_validation'];assert summary['release_ready']is False and summary['task_complete']is False and summary['diagnostic_sessions_complete']is True
 assert status['release_ready']is False and status['production_release_completed']is False and status['task_complete']is False
 assert status['latest_completed_validation_round']==10 and status['current_work']=='local_chrome07_provider14_transaction08_integration'
 assert status['latest_internal_image_sha256']==summary['internal_image']['sha256']=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
 for k in ['firmware_uploads','firmware_flashes','password_input_events']:assert summary[k]==0
 assert status['firmware_upload_performed']is False and status['firmware_flashing_performed']is False
 evidence(summary)
 off=json.loads(Path(summary['closure']['off']['path']).read_text());media=json.loads(Path(summary['closure']['media']['path']).read_text());logout=json.loads(Path(summary['closure']['logout']['path']).read_text())
 assert off['utc']=='2026-11-03T13:48:48.874Z' and off['system']['PowerState']=='Off'and off['power']['data']['power_status']==0 and off['system']['BiosVersion']=='1904'
 for view in ['system','settings']:
  b=off[view]['Boot'];assert b['BootNext']is None and[b['BootSourceOverrideEnabled'],b['BootSourceOverrideMode'],b['BootSourceOverrideTarget']]==['Disabled','Legacy','None']
 assert off['system']['Boot']['BootOrder']==off['settings']['Boot']['BootOrder']
 assert off['media']['cd_active_sessions']==129 # CD detach occurred later, not at the earlier Off observation.
 assert media['utc']=='2026-11-03T13:49:19.331Z'and media['power']['data']['power_status']==0 and media['hd_active_sessions']==media['cd_active_sessions']==128
 assert media['media_button']=='Start Media'and media['owned_helper_running']is False
 assert logout['utc']=='2026-11-03T13:49:32.482Z'and logout['operation']=='DELETE /api/session'and logout['status']==200
 assert work['controller_open']is False and work['closure']['controller_exit_code']==0 and summary['closure']['controller_exit_code_reported_by_operator']==0
 power=HW/'inventory-poweroff-1793713708016.json';p=json.loads(power.read_text());bind(power)
 assert p['utc']=='2026-11-03T13:48:28.016Z'and p['result']['status']==200 and p['result']['data']['power_command']==0
 assert p['diagnostic']=={'total':4911,'crc':0xccf8a98c,'page':7,'pages':7,'offset':4608}
 # Independently check the last diagnostic screen used for the shutdown scope.
 decpath=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py';assert sha(decpath)=='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283';bind(decpath)
 spec=importlib.util.spec_from_file_location('publication10_qr',decpath);dec=importlib.util.module_from_spec(spec);spec.loader.exec_module(dec)
 png=Path(p['screenshot']);frame=dec.read_image(png);assert frame==png.with_suffix('.frame').read_bytes();meta=dec.parse_frame(frame);assert(meta['total'],meta['crc'],meta['page'],meta['pages'],meta['offset'])==(4911,0xccf8a98c,7,7,4608);bind(png);bind(png.with_suffix('.frame'))
 parser=Parser();html=(READY/'检查报告.html').read_text();parser.feed(html);assert not parser.scripts
 links=[]
 for href in parser.links:
  assert href and not href.startswith(('http:','https:','javascript:','data:'));target=(READY/unquote(href)).resolve();assert target.is_relative_to(READY)and target.is_file();links.append({'href':href,'sha256':sha(target)})
 text=''.join(parser.text)
 for phrase in ['尚未达到可刷写正式版条件','没有输入或设置实机独立密码','不能由此推断所有OEM内部变量都没有写入','完整清屏恢复尚未通过','尚未证明它就是实机黑屏的唯一原因','不能相互继承验收','13:49:32 UTC','Self和SD读取均为Disabled/Legacy/None']:
  assert phrase in text,phrase
 assert len(links)==9
 # Snapshot C08 was kept as history; current later observations do not rewrite it.
 historical=Path(summary['prior_publication']['path']);old=json.loads(historical.read_text());assert old['latest_completed_validation_round']==8
 for p in root_files:assert sha(p)==next(x['observed_sha256']for x in inputs if x['source']==str(p.relative_to(ROOT)).replace('\\','/'))
 bind(Path(__file__));bind(HERE/'render_local_report.mjs')
 result={'status':'PASS_INDEPENDENT_C10_CLOSURE_AND_PUBLISHED_SCOPE_BINDINGS','utc':datetime.now(timezone.utc).isoformat(),'device_operations_by_reviewer':0,'root_files_modified':False,'publication_inputs':inputs,'bound_reference_files':len(bindings),'closure':{'shutdown_request_utc':'2026-11-03T13:48:28.016Z','shutdown_acceptance_status':200,'actual_off_redfish_and_native_utc':off['utc'],'CD_still_attached_at_earlier_Off_readback':True,'later_media_detached_and_idle_utc':media['utc'],'native_power_still_off_at_media_cleanup':True,'logout_utc':logout['utc'],'logout_http_status':200,'controller_exit_0':'Reported by parent/controller and root closed work status; no separately captured process-wait record was independently located.','Self_and_SD':['Disabled','Legacy','None'],'BootNext_both_null':True,'scope':'Timestamped closing sequence only, not continuous monitoring or a claim about later device state.'},'published_scope_review':['Current acceptance_status.latest_remote_validation equals C10 validation10_result exactly, and all referenced C09/C10 reports/images/manifests/full N12 image digests match.','Mode1 exact rollback success is separate from mode2 attach then black-screen failure; power-off termination is not represented as successful application rollback.','Recovery original identity/private absence is not equated with full cross-boot variable or SPI preservation.','Baseline06 render and return with nine rejected callbacks is explicitly not password/guard acceptance; stale QR background and possible OEM effects are preserved.','Local07 compatibility candidate and future P14/TX08 are not given N12 or hardware acceptance. N12 remains exact internal unsigned image.','User task, release readiness, password operations and firmware deployment remain incomplete; no uploads/flashes reported.','C08 snapshot remains historical, including its older inactive Self/SD mismatch. New C10 matching fields are independently supported by later readback.'],'html':{'local_evidence_links_checked':links,'script_elements':0,'source_scope_phrases_checked':True,'visual_render_independently_completed':False,'render_limitation':'Two isolated headless Edge launches failed before loading the report (first included a long cache path; retry with short isolated workspace profile still exited0xC0000005). No new screenshots or layout pass is claimed. Static HTML/local links were checked and root report bytes remained unchanged.'},'nonblocking_notes':['The process exit0 and absence of all unrecorded mutations remain bounded operator/controller claims; concrete Off/media/session readbacks were independently verified.','This closure review does not accept P14/TX08 or authorize firmware flashing.'],'bindings':list(bindings.values())}
 out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':result['status'],'sha256':sha(out),'bindings':len(bindings),'links':len(links)}))
if __name__=='__main__':main()
