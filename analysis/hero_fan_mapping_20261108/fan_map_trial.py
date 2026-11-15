"""Fixed .71 single RPM-map candidate, bounded observation and guarded restore.

No automatic execution on import. No mode/PWM/type/enable/SDR/NVRAM setters.
This diagnostic intentionally restores the original map even if readings work.
"""
from pathlib import Path
import argparse,getpass,hashlib,importlib.util,json,sys,time
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('frozen_fan_get',P/'probe_runtime/fan_mapping_get.py')
fan=importlib.util.module_from_spec(spec);spec.loader.exec_module(fan);base=fan.base
base.MAX_COMMANDS=64
IDENTITY=bytes.fromhex('2081010302bf3f0a0093100d000000')
MAC=bytes.fromhex('b082e2ac382c')
ORIGINAL=bytes(15)
CANDIDATE=bytes([0,0,0x62])+bytes(12)
BASELINE=(b'\0',ORIGINAL,bytes(15),bytes([1])*15)
SDR_REQUEST=bytes.fromhex('0000220000ff')
SDR_RECORD=bytes.fromhex('22005101362000201d017768040105700570070700120000780000000000000038e00dff00faede10003030101000000cb4d425f4348415f46414e31')
WRITES={'candidate':b'\x01\x01'+CANDIDATE,'restore':b'\x01\x01'+ORIGINAL}

class Stop(RuntimeError):pass
class Gate:
 def __init__(self):self.armed=None;self.ready=False;self.sent=[]
 def arm(self,stage):
  if self.armed is not None or not self.ready or stage not in WRITES or stage in self.sent:raise Stop('write_arm_rejected')
  if (stage=='candidate' and self.sent) or (stage=='restore' and self.sent!=['candidate']):raise Stop('write_order_rejected')
  self.armed=stage
 def validate(self,netfn,command,data=(),sensor_ids=()):
  payload=bytes(data);pair=(netfn,command)
  if pair in ((6,1),(6,0x25),(0x0a,0x20)) and not payload:return
  if pair==(0x0c,2) and payload==bytes([1,5,0,0]):return
  if pair==(0x0a,0x23) and payload==SDR_REQUEST:return
  if pair==(4,0x2d) and payload in (b'\x20',b'\xfb'):return
  if pair==(0x30,0x9a) and payload in (b'\0\0',b'\1\0',b'\2\0',b'\3\0'):return
  if pair==(0x30,0x9a) and self.armed and payload==WRITES[self.armed]:
   stage=self.armed;self.armed=None;self.sent.append(stage);return
  raise base.PolicyError('Fixed fan trial command denied')

class Trial:
 def __init__(self,exchange,emit,sleep=time.sleep,gate=None):
  self.exchange=exchange;self.emit=emit;self.sleep=sleep;self.gate=gate or Gate();self.sequence=0
  self.result=dict(schema='hero-fan-map-only-1',target=base.HOST,request_limit=64,candidate_attempted=False,restore_attempted=False,map_restored=False,control_tables_restored=False,sdr_unchanged=False,configuration_writes_possible=True,mode_pwm_type_enable_setters=False,samples=[],state='not_started')
 def req(self,label,netfn,command,payload=b'',write=False):
  self.sequence+=1
  if self.sequence>64:raise Stop('request_limit')
  payload=bytes(payload);event=dict(type='intent',sequence=self.sequence,label=label,netfn=netfn,command=command,request_hex=payload.hex(),write=write,retry=False)
  self.emit(event) # Required before any transmission, including restoration.
  try:r=self.exchange(netfn,command,payload)
  except Exception as e:
   self.emit(dict(type='response',sequence=self.sequence,label=label,ok=False,error='transport_exception',exception_type=type(e).__name__));raise Stop('transport_exception') from None
  if not isinstance(r,dict) or r.get('netfn')!=netfn+1 or r.get('command')!=command:
   self.emit(dict(type='response',sequence=self.sequence,label=label,ok=False,error='response_header_mismatch'));raise Stop('response_header_mismatch')
  code=r.get('code');data=r.get('data',())
  try:data=bytes(data)
  except (ValueError,TypeError):raise Stop('invalid_response_data') from None
  if not isinstance(code,int) or not 0<=code<=255 or len(data)>262:raise Stop('invalid_response_shape')
  self.emit(dict(type='response',sequence=self.sequence,label=label,ok=code==0,completion_code=code,response_hex=data.hex()))
  if code:raise Stop('completion_'+format(code,'02X'))
  return data
 def maps(self,label):
  values=tuple(self.req(label+'_'+str(sub),0x30,0x9a,bytes([sub,0])) for sub in range(4))
  if any(len(v)!=(1 if i==0 else 15) for i,v in enumerate(values)):raise Stop('map_length')
  return values
 def sdr(self,label):
  data=self.req(label,0x0a,0x23,SDR_REQUEST)
  if len(data)!=len(SDR_RECORD)+2 or data[2:]!=SDR_RECORD:raise Stop('target_SDR_changed_or_not_visible')
  return data[2:]
 def repository(self,label):
  data=self.req(label,0x0a,0x20)
  if len(data)!=14:raise Stop('repository_length')
  return data.hex()
 def reading(self,label):
  data=self.req(label,4,0x2d,b'\x20')
  if len(data)!=4:raise Stop('sensor20_length')
  usable=not data[1]&0x20 and bool(data[1]&0x40)
  value=dict(raw_hex=data.hex(),raw=data[0],flags_hex=f'{data[1]:02X}',usable=usable,rpm=data[0]*120 if usable else None)
  self.emit(dict(type='sensor20',label=label,**value));return value
 def preflight(self):
  if self.req('device_id',6,1)!=IDENTITY:raise Stop('identity_mismatch')
  mac=self.req('lan1_mac',0x0c,2,bytes([1,5,0,0]))
  if len(mac)!=7 or mac[1:]!=MAC:raise Stop('MAC_mismatch')
  watchdog=self.req('watchdog',6,0x25)
  if len(watchdog)!=8 or watchdog[0]&0x40:raise Stop('watchdog_not_stopped')
  self.result['repository_before']=self.repository('repository_before')
  self.sdr('target_SDR_before')
  if self.req('version_error',4,0x2d,b'\xfb')!=bytes.fromhex('00c00080'):raise Stop('R3_initialization_not_confirmed')
  self.result['reading_before']=self.reading('sensor20_before')
  if self.result['reading_before']['raw_hex']!='00a0c000':raise Stop('sensor20_baseline_changed')
  if self.maps('fresh_baseline')!=BASELINE:raise Stop('baseline_tables_changed')
  self.gate.ready=True;self.result['state']='preflight_passed'
 def restore(self):
  if 'candidate' not in self.gate.sent:return
  current=self.maps('restore_gate')
  if current[0]!=BASELINE[0] or current[2:]!=BASELINE[2:]:raise Stop('restore_control_drift_no_write')
  if current[1]==ORIGINAL:
   self.result['map_restored']=True;self.result['control_tables_restored']=True;self.emit(dict(type='restore_original_already_present'))
  elif current[1]==CANDIDATE:
   # Recheck the array immediately before its only restoration attempt. This
   # is not an atomic compare-and-swap; a concurrent writer still cannot be
   # excluded by this protocol. Stop if any detectable change has occurred.
   if self.req('restore_RPM_final_compare',0x30,0x9a,b'\x01\x00')!=CANDIDATE:raise Stop('restore_map_drift_no_write')
   self.gate.arm('restore');self.result['restore_attempted']=True
   echo_ok=False
   try:echo_ok=self.req('restore_original_RPM_once',0x30,0x9a,WRITES['restore'],write=True)==ORIGINAL
   except Stop as e:self.emit(dict(type='restore_reply_failed_readback_only',reason=str(e)))
   after=self.maps('restore_verify')
   if after!=BASELINE:raise Stop('restore_not_verified_no_retry')
   self.result['map_restored']=True;self.result['control_tables_restored']=True;self.result['restore_echo_ok']=echo_ok
  else:raise Stop('restore_map_drift_no_write')
  self.result['reading_after_restore']=self.reading('sensor20_after_restore')
  self.sdr('target_SDR_after_restore');self.result['sdr_unchanged']=True
  self.result['repository_after']=self.repository('repository_after')
 def run(self):
  error=None;restore_error=None
  try:
   self.preflight();self.gate.arm('candidate');self.result['candidate_attempted']=True
   if self.req('candidate_RPM_once',0x30,0x9a,WRITES['candidate'],write=True)!=CANDIDATE:raise Stop('candidate_echo_mismatch')
   if self.maps('candidate_verify')!=(BASELINE[0],CANDIDATE,*BASELINE[2:]):raise Stop('candidate_tables_mismatch')
   for i in range(5):
    if i:self.sleep(1.0)
    self.result['samples'].append(self.reading('candidate_sample_'+str(i)))
   self.result['state']='observed'
  except Stop as e:error=str(e);self.result['state']='stopped';self.emit(dict(type='stopped',reason=error))
  finally:
   if 'candidate' in self.gate.sent:
    try:self.restore()
    except Stop as e:restore_error=str(e);self.emit(dict(type='restore_stopped',reason=restore_error))
   self.gate.armed=None
  self.result.update(error=error,restore_error=restore_error,sent_writes=list(self.gate.sent),requests=self.sequence)
  self.result['requires_review']=bool(error or restore_error or (self.result['candidate_attempted'] and not self.result['map_restored']))
  self.emit(dict(type='result',**self.result));return self.result

def verify_wrappers():
 manifest=json.loads((P/'probe_runtime/manifest.json').read_text())
 for name,digest in manifest.items():
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
  r=trial.run();return 2 if r['requires_review'] else 0
 except Exception as e:
  base.emit(dict(type='worker_stopped',exception_type=type(e).__name__,reason=str(e) if isinstance(e,Stop) else 'transport_or_policy',candidate_may_have_been_sent=bool(trial and trial.result['candidate_attempted'])));return 2
 finally:
  password=None
  if connection is not None:
   try:connection.logout();base.emit(dict(type='closed'))
   except Exception:base.emit(dict(type='close_failed'))

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--worker',action='store_true');parser.add_argument('--execute-map-only',action='store_true');parser.add_argument('--out');a=parser.parse_args()
 if a.worker:return worker()
 if not a.execute_map_only:parser.error('Review the plan, then explicitly select --execute-map-only; importing does nothing.')
 out=(P/(a.out or '')).resolve()
 if out.parent!=P or out.exists() or out.suffix!='.json':raise base.PolicyError('New JSON output filename in this directory required')
 verify_wrappers();print('Fixed .71 fan RPM[2]=62 trial; observe five samples; restore exact original map if unchanged. No mode/PWM/type/enable setters.')
 password=getpass.getpass('IPMI password (not saved): ');secret=(json.dumps(password)+'\n').encode();password=None
 started=base.utc_now();code,timeout,raw,stderr_count=base.bounded_child([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker'],secret,120);secret=None
 events=[]
 for line in raw.decode('utf-8',errors='replace').splitlines():
  try:r=json.loads(line)
  except ValueError:continue
  if isinstance(r,dict) and 'type' in r:events.append(r)
 report=dict(schema='hero-fan-map-only-run-1',target=base.HOST,started_utc=started,finished_utc=base.utc_now(),return_code=code,hard_timeout=timeout,stderr_bytes_not_saved=stderr_count,events=events,limitation='Restores RPM configuration only; scanner internal state and RPM values may differ. Hard interruption can prevent restoration; inspect retained intent/response events before any next action.')
 with out.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2,ensure_ascii=False)
 print(json.dumps(dict(file=str(out),return_code=code,hard_timeout=timeout,events=len(events))));return code
if __name__=='__main__':raise SystemExit(main())
