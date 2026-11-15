"""Read-only independent C11 closure/publication audit; no network or device."""
from pathlib import Path
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.parse import unquote
import hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;C11=HERE.parent;READY=C11.parent.parent
ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bindings={}
def bind(p,expected=None,size=None):
 p=Path(p).resolve();assert p.is_relative_to(ROOT)
 h=sha(p);assert expected is None or h==expected,(p,h,expected)
 assert size is None or p.stat().st_size==size
 row={'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':h};bindings[row['path']]=row;return row
def evidence(obj):
 if isinstance(obj,dict):
  if all(k in obj for k in ['path','sha256']):bind(obj['path'],obj['sha256'],obj.get('bytes'))
  for item in obj.values():evidence(item)
 elif isinstance(obj,list):
  for item in obj:evidence(item)
class Parser(HTMLParser):
 def __init__(self):super().__init__();self.links=[];self.text=[];self.scripts=0
 def handle_starttag(self,tag,attrs):
  if tag=='a':self.links.append(dict(attrs).get('href'))
  if tag=='script':self.scripts+=1
 def handle_data(self,data):self.text.append(data)
def main():
 output=HERE/'independent_review.json';assert not output.exists()
 snapshot=HERE/'publication_snapshot';snapshot.mkdir(exist_ok=True)
 rootfiles=[READY/'acceptance_status.json',READY/'检查报告.html',C11/'validation11_result.json',C11/'publication11_check.json',C11/'publish_validation11.py',C11/'work_status.json']
 inputs=[]
 for p in rootfiles:
  copied=snapshot/p.name;assert not copied.exists();copied.write_bytes(p.read_bytes())
  inputs.append({'source':str(p.relative_to(ROOT)).replace('\\','/'),'observed_sha256':sha(p),'snapshot':bind(copied)})
 check=json.loads((C11/'publication11_check.json').read_text())
 for name,digest in check['files'].items():assert sha(READY/name)==digest,name
 summary=json.loads((C11/'validation11_result.json').read_text());status=json.loads((READY/'acceptance_status.json').read_text());work=json.loads((C11/'work_status.json').read_text())
 assert summary==status['latest_remote_validation'] and summary['round']==status['latest_completed_validation_round']==11
 assert summary['diagnostic_session_complete']is True and summary['release_ready']is False and summary['task_complete']is False
 for field in ['release_ready','production_release_completed','task_complete','firmware_upload_performed','firmware_flashing_performed']:assert status[field]is False
 assert status['current_work']=='isolated_request_diagnostics09'
 assert status['latest_internal_image_sha256']==summary['internal_image']['sha256']=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
 for field in ['firmware_uploads','firmware_flashes','password_input_events']:assert summary[field]==0
 assert work['controller_open']is False and work['closure']['controller_exit_code']==summary['closure']['controller_exit_code']==0
 assert 'hardware_actions_this_round'not in work or work['hardware_actions_this_round']!=0
 assert '473-bound-file'in work['local_source_and_identity_tests']
 evidence(summary)
 for row in summary['reviews'].values():evidence(json.loads(Path(row['path']).read_text()))
 # Explicitly bind both module load-base differences; this is text comparison,
 # not a variable-content or persistent-SPI comparison.
 hwreview=READY/'native13_split_candidate/installer_design04/ram_transaction08_independent_review/hardware_review01'
 difference=hwreview/'recovery_initial_log_difference.json';bind(difference,'5ad8e2107eeea43d8bc3a23bbf9b9ee6ec5180d4adf27d49cee10939591d632c')
 d=json.loads(difference.read_text());assert len(d['differences'])==2
 for row in summary['captures'].values():
  p=Path(row['path']);meta=json.loads(p.read_text())
  for name,digest in meta['files'].items():bind(p.parent/name,digest)
 off=json.loads((HW/summary['closure']['off']).read_text());media=json.loads((HW/summary['closure']['media']).read_text());logout=json.loads((HW/summary['closure']['logout']).read_text())
 assert off['utc']=='2026-11-03T14:36:42.523Z' and off['system']['status']==200 and off['system']['PowerState']=='Off'
 assert off['power']['status']==200 and off['power']['data']['power_status']==0 and off['system']['BiosVersion']=='1904'
 for view in ['system','settings']:
  b=off[view]['Boot'];assert b['BootNext']is None
  assert [b[k]for k in ['BootSourceOverrideEnabled','BootSourceOverrideMode','BootSourceOverrideTarget']]==['Disabled','Legacy','None']
 assert off['system']['Boot']['BootOrder']==off['settings']['Boot']['BootOrder']
 assert off['media']['cd_active_sessions']==129
 assert media['utc']=='2026-11-03T14:37:12.809Z' and media['power']['data']['power_status']==0
 assert media['hd_active_sessions']==media['cd_active_sessions']==128 and media['owned_helper_running']is False and media['media_button']=='Start Media'
 assert logout['utc']=='2026-11-03T14:37:31.566Z' and logout['operation']=='DELETE /api/session' and logout['status']==200
 # Shutdown was scoped to the actual final QR; re-decode that saved PNG.
 power=HW/'inventory-poweroff-1793716586320.json';bind(power);p=json.loads(power.read_text())
 assert p['utc']=='2026-11-03T14:36:26.320Z' and p['result']['status']==200 and p['result']['data']['power_command']==0
 assert p['diagnostic']=={'total':1168,'crc':0x397a6a63,'page':2,'pages':2,'offset':768}
 decpath=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py';bind(decpath,'f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283')
 spec=importlib.util.spec_from_file_location('publication11_qr',decpath);dec=importlib.util.module_from_spec(spec);spec.loader.exec_module(dec)
 png=Path(p['screenshot']);frame=dec.read_image(png);assert frame==png.with_suffix('.frame').read_bytes();info=dec.parse_frame(frame)
 assert (info['total'],info['crc'],info['page'],info['pages'],info['offset'])==(1168,0x397a6a63,2,2,768)
 bind(png);bind(png.with_suffix('.frame'))
 parser=Parser();parser.feed((READY/'检查报告.html').read_text());assert parser.scripts==0
 links=[]
 for href in parser.links:
  assert href and not href.startswith(('http:','https:','javascript:','data:'))
  target=(READY/unquote(href)).resolve();assert target.is_relative_to(READY) and target.is_file()
  links.append({'href':href,'sha256':sha(target)})
 assert len(links)==8
 text=''.join(parser.text)
 for phrase in ['尚未达到可刷写正式版条件','独立密码管理页未通过','没有输入或设置实机独立密码','不能仅凭截图判定按键是否被读取、是否反复触发或CPU是否停顿',
  '不是失败运行中由应用完成的原地撤销','恢复日志仅两处加载地址不同','不能相互继承验收','14:37:31.566 UTC','Self和SD的启动覆盖均为Disabled/Legacy/None']:
  assert phrase in text,phrase
 historical=Path(summary['prior_publication']['path']);old=json.loads(historical.read_text());assert old['latest_completed_validation_round']==10
 # Root's already-created publication snapshot must match the current bytes.
 for p in rootfiles:
  expected=next(r['observed_sha256']for r in inputs if r['source']==str(p.relative_to(ROOT)).replace('\\','/'))
  assert sha(p)==expected
  rootcopy=C11/'publication11_snapshot'/p.name
  if rootcopy.exists():bind(rootcopy,expected)
 bind(Path(__file__))
 result={'status':'PASS_INDEPENDENT_C11_CLOSURE_AND_PUBLICATION_SCOPE_REVIEW','utc':datetime.now(timezone.utc).isoformat(),
  'device_operations_by_reviewer':0,'root_files_modified':False,'publication_inputs':inputs,'bound_reference_files':len(bindings),
  'closure':{'shutdown_request_utc':p['utc']if False else '2026-11-03T14:36:26.320Z','shutdown_http':200,'later_off_redfish_native_utc':off['utc'],
   'CD_still_attached_at_earlier_off_observation':True,'later_media_idle_utc':media['utc'],'logout_utc':logout['utc'],'logout_http':200,
   'controller_exit_0_scope':'Parent tool observation and closed work/summary records; this review has not independently located a process-wait export.',
   'Self_and_SD':['Disabled','Legacy','None'],'BootNext_null_both':True,'scope':'Timestamped closing observations, not continuous monitoring or a claim about future device state.'},
  'published_scope_findings':[
   'Current status.latest_remote_validation exactly equals the complete C11 summary; every embedded referenced file hash and captured-manifest member matches.',
   'Current TX08 mode1 installation/restoration and mode2 READY attach are separated from the failed first management display/return stage. The last pre-M variable check is not extended past M.',
   'The displayed unconfigured message is treated as visible/provider-text correlation. No call-stack, input consumption, recurring loop or precise failed native control is established.',
   'The new boot observes current original modules/12 sites and private absence. It is not an application rollback of the interrupted run; two changed load-base lines are the only initial-log differences.',
   'No-password statements describe this C11 candidate/session, not a retrospective claim that all earlier unrelated RAM demonstrations never accepted password input.',
   'Local template07/P14/TX08, future diagnostic09, and permanent NATIVE12 are distinct constructs. The latter full image remains exactb122... internal unsigned and not release-ready.',
   'Historical C10 status snapshot is unchanged. The new diagnostic session is complete while the user task, native password/entry acceptance, update trust and backup/recovery remain incomplete.',
   'Root corrected earlier stale work-status fields; current controller is closed and local473-file review is recorded as completed.'
  ],
  'html':{'local_links_checked':links,'script_elements':0,'static_scope_text_checked':True,'visual_render_independently_completed':False,
   'visual_review_scope':'Parent is responsible for the separate rendered-layout inspection. This review checks current HTML text/links/digests and does not claim a new rendering pass.'},
  'limits':[
   'Controller exit0 and absence of unrecorded actions remain parent/operator claims. Concrete Off/media/logout observations and selected action records were independently bound.',
   'This publication check does not accept another diagnostic executable, persistent firmware protection, update signing, SPI backup or flashing.',
   'No further management retry on unchanged e079 is authorized by the successful install/attach results; the first M stage remains explicitly unaccepted.'
  ],'bindings':list(bindings.values())}
 output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'status':result['status'],'sha256':sha(output),'bindings':len(bindings),'links':len(links)}))
if __name__=='__main__':main()
