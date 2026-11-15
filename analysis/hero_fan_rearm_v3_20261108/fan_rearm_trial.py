"""Fixed .71 RPM[2]=62 plus one target20 visibility-cycle experiment.

DOES mutate SDR visibility, repository metadata and possible BMC persistence.
No PWM/type/mode, firmware, host EC, watchdog or reset setters. The original
RPM map and target visibility are recovered where independently verified.
This is NOT a complete inverse of vendor scanner/repository state.
"""
from pathlib import Path
import argparse,getpass,hashlib,importlib.util,json,sys,time
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('frozen_fan_get',P/'probe_runtime/fan_mapping_get.py')
fan=importlib.util.module_from_spec(spec);spec.loader.exec_module(fan);base=fan.base
LIMIT=384;base.MAX_COMMANDS=LIMIT
IDENTITY=bytes.fromhex('2081010302bf3f0a0093100d000000');MAC=bytes.fromhex('b082e2ac382c')
ORIGINAL=bytes(15);CANDIDATE=bytes([0,0,0x62])+bytes(12)
BASELINE=(b'\0',ORIGINAL,bytes(15),bytes([1])*15)
SDR_REQUEST=bytes.fromhex('0000220000ff')
SDR_RECORD=(P/'fixtures/mb-cha-fan1-sdr.bin').read_bytes()
SDR_HASH='a253da27c190c2973891597bfb1fe61c52c828b420dfb46388916cdcac4784d8'
if len(SDR_RECORD)!=59 or 5+SDR_RECORD[4]!=59 or hashlib.sha256(SDR_RECORD).hexdigest()!=SDR_HASH:
 raise base.PolicyError('fixed original SDR fixture mismatch')
READING_BASE=bytes.fromhex('00a0c000');EVENT_BASE=bytes.fromhex('8070057005')
WRITES={'candidate':(0x30,0x9a,b'\1\1'+CANDIDATE),'restore':(0x30,0x9a,b'\1\1'+ORIGINAL),
 'hide':(0x30,0x94,b'\x20\0'),'unhide':(0x30,0x94,b'\x20\1')}

class Stop(RuntimeError):pass
class Gate:
 def __init__(self):self.armed=None;self.ready=False;self.sent=[]
 def arm(self,stage):
  if self.armed is not None or not self.ready or stage not in WRITES or stage in self.sent:raise Stop('write_arm_rejected')
  if stage=='candidate' and self.sent:raise Stop('write_order_rejected')
  if stage=='hide' and self.sent!=['candidate']:raise Stop('write_order_rejected')
  if stage=='unhide' and ('hide' not in self.sent or self.sent[-1] not in ('hide','restore')):raise Stop('write_order_rejected')
  if stage=='restore' and ('candidate' not in self.sent):raise Stop('write_order_rejected')
  self.armed=stage
 def validate(self,netfn,command,data=(),sensor_ids=()):
  payload=bytes(data);pair=(netfn,command)
  if pair in ((6,1),(6,0x25),(0x0a,0x20)) and not payload:return
  if pair==(0x0c,2) and payload==bytes([1,5,0,0]):return
  if pair==(0x0a,0x23) and len(payload)==6 and payload[:2]==b'\0\0' and payload[4:]==b'\0\xff':return
  if pair==(4,0x2d) and payload in (b'\x20',b'\xfb'):return
  if pair==(4,0x29) and payload==b'\x20':return
  if pair==(0x30,0x9a) and payload in (b'\0\0',b'\1\0',b'\2\0',b'\3\0'):return
  if self.armed and (netfn,command,payload)==WRITES[self.armed]:
   stage=self.armed;self.armed=None;self.sent.append(stage);return
  raise base.PolicyError('Fixed fan rearm trial command denied')

class Trial:
 def __init__(self,exchange,emit,sleep=time.sleep,gate=None):
  self.exchange=exchange;self.emit=emit;self.sleep=sleep;self.gate=gate or Gate();self.sequence=0;self.records=None;self.repo_before=None
  self.result=dict(schema='hero-fan-rearm-3',target=base.HOST,request_limit=LIMIT,
    candidate_attempted=False,restore_attempted=False,hide_attempted=False,unhide_attempted=False,
    map_restored=False,control_tables_restored=False,target_visible=False,record_set_restored=False,
    observable_state_restored=False,complete_rollback=False,configuration_writes_possible=True,
    sdr_metadata_and_persistent_write_possible=True,pwm_type_mode_setters=False,
    samples=[],samples_after_restore=[],state='not_started')
 def req(self,label,n,c,payload=b'',write=False,allow_absent=False):
  self.sequence+=1
  if self.sequence>LIMIT:raise Stop('request_limit')
  payload=bytes(payload);self.emit(dict(type='intent',sequence=self.sequence,label=label,netfn=n,command=c,request_hex=payload.hex(),write=write,retry=False))
  try:r=self.exchange(n,c,payload)
  except Exception as e:
   self.emit(dict(type='response',sequence=self.sequence,label=label,ok=False,error='transport_exception',exception_type=type(e).__name__));raise Stop('transport_exception') from None
  if not isinstance(r,dict) or r.get('netfn')!=n+1 or r.get('command')!=c:
   self.emit(dict(type='response',sequence=self.sequence,label=label,ok=False,error='response_header_mismatch'));raise Stop('response_header_mismatch')
  code=r.get('code')
  try:data=bytes(r.get('data',()))
  except (ValueError,TypeError):raise Stop('invalid_response_data') from None
  if type(code) is not int or not 0<=code<=255 or len(data)>262:raise Stop('invalid_response_shape')
  self.emit(dict(type='response',sequence=self.sequence,label=label,ok=code==0,completion_code=code,response_hex=data.hex()))
  if code==0xcb and allow_absent and not data:return None
  if code:raise Stop('completion_'+format(code,'02X'))
  return data
 def maps(self,label):
  values=tuple(self.req(label+'_'+str(sub),0x30,0x9a,bytes([sub,0])) for sub in range(4))
  if any(len(v)!=(1 if i==0 else 15) for i,v in enumerate(values)):raise Stop('map_length')
  return values
 def repo(self,label):
  data=self.req(label,0x0a,0x20)
  if len(data)!=14 or data[0]!=0x51:raise Stop('repository_shape')
  return data
 def target(self,label):
  data=self.req(label,0x0a,0x23,SDR_REQUEST,allow_absent=True)
  if data is None:return False
  if len(data)!=len(SDR_RECORD)+2 or data[2:]!=SDR_RECORD:raise Stop('target_SDR_changed')
  return True
 def event_enable(self,label):
  data=self.req(label,4,0x29,b'\x20')
  if len(data)!=5:raise Stop('event_enable_shape')
  return data
 def reading(self,label):
  data=self.req(label,4,0x2d,b'\x20')
  if len(data)!=4:raise Stop('sensor20_length')
  usable=not data[1]&0x20 and bool(data[1]&0x40)
  value=dict(raw_hex=data.hex(),raw=data[0],flags_hex=f'{data[1]:02X}',usable=usable,rpm=data[0]*120 if usable else None)
  self.emit(dict(type='sensor20',label=label,**value));return value
 def inventory(self,label):
  before=self.repo(label+'_info_begin');count=int.from_bytes(before[1:3],'little')
  if not 1<=count<=96:raise Stop('SDR_count_out_of_bound')
  rows={};record_id=0
  for i in range(count):
   data=self.req(label+'_record_'+str(i),0x0a,0x23,b'\0\0'+record_id.to_bytes(2,'little')+b'\0\xff')
   if len(data)<7 or len(data)!=7+data[6]:raise Stop('SDR_record_shape')
   next_id=int.from_bytes(data[:2],'little');rid=int.from_bytes(data[2:4],'little')
   if rid in rows or rid==0xffff or (record_id!=0 and rid!=record_id):raise Stop('SDR_duplicate_or_chain_mismatch')
   rows[rid]=data[2:]
   if next_id==0xffff:
    if i+1!=count:raise Stop('SDR_early_end')
    break
   if next_id in rows or i+1==count:raise Stop('SDR_cycle_or_count_mismatch')
   record_id=next_id
  after=self.repo(label+'_info_end')
  if before!=after:raise Stop('SDR_inventory_changed_during_read')
  if rows.get(0x22)!=SDR_RECORD:raise Stop('fixed_target_not_in_complete_SDR')
  self.emit(dict(type='SDR_inventory',label=label,count=count,sha256=hashlib.sha256(b''.join(rows[k] for k in sorted(rows))).hexdigest()))
  return rows,before
 def preflight(self):
  if self.req('device_id',6,1)!=IDENTITY:raise Stop('identity_mismatch')
  mac=self.req('lan1_mac',0x0c,2,bytes([1,5,0,0]))
  if len(mac)!=7 or mac[1:]!=MAC:raise Stop('MAC_mismatch')
  wd=self.req('watchdog',6,0x25)
  if len(wd)!=8 or wd[0]&0x40:raise Stop('watchdog_not_stopped')
  if self.req('version_error',4,0x2d,b'\xfb')!=bytes.fromhex('00c00080'):raise Stop('R3_initialization_not_confirmed')
  if not self.target('target_before'):raise Stop('target_initially_hidden')
  self.result['reading_before']=self.reading('sensor20_before')
  if self.result['reading_before']['raw_hex']!=READING_BASE.hex():raise Stop('sensor20_baseline_changed')
  if self.event_enable('event_enable_before')!=EVENT_BASE:raise Stop('event_enable_baseline_changed')
  self.records,self.repo_before=self.inventory('SDR_before')
  self.result['repository_before']=self.repo_before.hex()
  if self.maps('fresh_baseline')!=BASELINE:raise Stop('baseline_tables_changed')
  self.gate.ready=True;self.result['state']='preflight_passed'
 def write(self,stage):
  self.gate.arm(stage);self.result[stage+'_attempted']=True
  n,c,p=WRITES[stage];data=self.req(stage+'_once',n,c,p,write=True)
  expected=p[2:] if c==0x9a else b''
  if data!=expected:raise Stop(stage+'_echo_mismatch')
 def controls(self,label,rpm):
  if self.maps(label)!=(BASELINE[0],rpm,*BASELINE[2:]):raise Stop(label+'_tables_changed')
 def visibility(self,label,expected):
  visible=self.target(label+'_target');info=self.repo(label+'_repo')
  count=int.from_bytes(info[1:3],'little')
  want=int.from_bytes(self.repo_before[1:3],'little')-(not expected)
  if visible!=expected or count!=want or info[3:5]!=self.repo_before[3:5]:raise Stop(label+'_visibility_or_count_mismatch')
  self.result['target_visible']=visible
 def restore_map(self):
  current=self.maps('restore_gate')
  if current[0]!=BASELINE[0] or current[2:]!=BASELINE[2:]:raise Stop('restore_control_drift_no_write')
  if current[1] not in (ORIGINAL,CANDIDATE):raise Stop('restore_map_drift_no_write')
  if current[1]==CANDIDATE:
   if self.req('restore_RPM_final_compare',0x30,0x9a,b'\1\0')!=CANDIDATE:raise Stop('restore_map_drift_no_write')
   try:self.write('restore')
   except Stop as e:self.emit(dict(type='restore_reply_failed_readback_only',reason=str(e)))
   if self.maps('restore_verify')!=BASELINE:raise Stop('restore_not_verified_no_retry')
  self.result['map_restored']=True;self.result['control_tables_restored']=True
 def cleanup(self):
  if 'candidate' not in self.gate.sent:return
  self.restore_map()
  visible=self.target('cleanup_target_readonly');self.result['target_visible']=visible
  if not visible:
   if 'hide' not in self.gate.sent or 'unhide' in self.gate.sent:raise Stop('target_hidden_no_repeat_unhide')
   # This is the one unhide that has never been sent, after GET proves hide.
   # Recover visibility with the original RPM map. Do not repeat a timed-out SET.
   self.visibility('recovery_hidden_check',False);self.controls('recovery_control_gate',ORIGINAL)
   try:self.write('unhide')
   except Stop as e:self.emit(dict(type='unhide_reply_failed_readback_only',reason=str(e)))
   self.visibility('recovery_visible_check',True)
  self.visibility('final_visible_check',True)
  for i in range(3):
   self.sleep(1.0);self.result['samples_after_restore'].append(self.reading('restored_sample_'+str(i)))
  final_event=self.event_enable('event_enable_after_restore');self.result['event_enable_after_restore']=final_event.hex()
  rows,info=self.inventory('SDR_after');self.result['repository_after']=info.hex()
  if rows!=self.records:raise Stop('SDR_record_set_different')
  self.result['record_set_restored']=True
  self.result['observable_state_restored']=all(x['raw_hex']==READING_BASE.hex() for x in self.result['samples_after_restore']) and final_event==EVENT_BASE
  if not self.result['observable_state_restored']:raise Stop('observable_sensor_state_differs_no_more_sets')
 def run(self):
  error=None;cleanup_error=None
  try:
   self.preflight();self.write('candidate');self.controls('candidate_verify',CANDIDATE)
   self.visibility('pre_hide_check',True);self.write('hide');self.visibility('hidden_check',False)
   self.controls('pre_unhide_control_gate',CANDIDATE);self.write('unhide');self.visibility('visible_check',True)
   for i in range(5):
    self.sleep(1.0);self.result['samples'].append(self.reading('candidate_sample_'+str(i)))
   self.result['state']='observed'
  except Stop as e:error=str(e);self.result['state']='stopped';self.emit(dict(type='stopped',reason=error))
  finally:
   if 'candidate' in self.gate.sent:
    try:self.cleanup()
    except Stop as e:cleanup_error=str(e);self.emit(dict(type='cleanup_stopped',reason=cleanup_error))
   self.gate.armed=None
  self.result.update(error=error,cleanup_error=cleanup_error,sent_writes=list(self.gate.sent),requests=self.sequence)
  self.result['requires_review']=bool(error or cleanup_error or (self.result['candidate_attempted'] and not(self.result['map_restored'] and self.result['target_visible'] and self.result['record_set_restored'] and self.result['observable_state_restored'])))
  self.emit(dict(type='result',**self.result));return self.result

def verify_wrappers():
 for name,digest in json.loads((P/'probe_runtime/manifest.json').read_text()).items():
  if hashlib.sha256((P/'probe_runtime'/name).read_bytes()).hexdigest()!=digest:raise base.PolicyError('frozen wrapper hash mismatch')
 return base.verify_dependencies()
def worker():
 connection=None;password=None;trial=None
 try:
  password=json.loads(sys.stdin.buffer.readline(4097))
  if not isinstance(password,str) or not 0<len(password)<=128:raise base.PolicyError('credential input')
  verify_wrappers();gate=Gate();base.validate_read=gate.validate
  Session=fan.admin_session_class();connection=Session(bmc=base.HOST,userid=base.USER,password=password,port=623,privlevel=4,keepalive=False);password=None
  if connection.ipmiversion!=2.0 or connection.privlevel!=4:raise base.PolicyError('Authenticated ADMIN LAN+ required')
  connection.reads_enabled=True
  trial=Trial(lambda n,c,d:connection.raw_command(netfn=n,command=c,data=tuple(d),retry=False),base.emit,gate=gate)
  return 2 if trial.run()['requires_review'] else 0
 except Exception as e:
  base.emit(dict(type='worker_stopped',exception_type=type(e).__name__,reason=str(e) if isinstance(e,Stop) else 'transport_or_policy',candidate_may_have_been_sent=bool(trial and trial.result['candidate_attempted'])));return 2
 finally:
  password=None
  if connection is not None:
   try:connection.logout();base.emit(dict(type='closed'))
   except Exception:base.emit(dict(type='close_failed'))
def main():
 p=argparse.ArgumentParser();p.add_argument('--worker',action='store_true');p.add_argument('--execute-rearm-target20',action='store_true');p.add_argument('--out');a=p.parse_args()
 if a.worker:return worker()
 if not a.execute_rearm_target20:p.error('Review repository persistence effects, then explicitly select --execute-rearm-target20.')
 out=(P/(a.out or '')).resolve()
 if out.parent!=P or out.exists() or out.suffix!='.json':raise base.PolicyError('New JSON output filename in this directory required')
 verify_wrappers();print('Fixed .71 RPM62 + target20 hide/unhide trial. SDR metadata/persistence writes occur. No complete rollback promised. No PWM/type/mode/host EC writes.')
 password=getpass.getpass('IPMI password (not saved): ');secret=(json.dumps(password)+'\n').encode();password=None
 started=base.utc_now();code,timeout,raw,stderr_count=base.bounded_child([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker'],secret,180);secret=None
 events=[]
 for line in raw.decode('utf-8',errors='replace').splitlines():
  try:r=json.loads(line)
  except ValueError:continue
  if isinstance(r,dict) and 'type' in r:events.append(r)
 report=dict(schema='hero-fan-rearm-run-3',target=base.HOST,started_utc=started,finished_utc=base.utc_now(),return_code=code,hard_timeout=timeout,stderr_bytes_not_saved=stderr_count,events=events,
  limitation='RPM map, target visibility and observable sensor state are checked separately. Repository timestamps/reservations/backing writes and private scanner state are not undone. Hard interruption may leave target hidden. Never rerun without examining retained intents/responses and GET state.')
 with out.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2,ensure_ascii=False)
 print(json.dumps(dict(file=str(out),return_code=code,hard_timeout=timeout,events=len(events))));return code
if __name__=='__main__':raise SystemExit(main())
