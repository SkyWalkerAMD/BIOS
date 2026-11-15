"""Apply and KEEP the one live-verified fan RPM map on fixed .71.

At most one exact RPM SET. No hide/unhide, map-to-zero, PWM/type/mode, event
enable, watchdog, firmware, EC or reset setters. Imports never open sockets.
"""
from pathlib import Path
import argparse,getpass,hashlib,importlib.util,json,sys,time
P=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('frozen_fan_get',P/'probe_runtime/fan_mapping_get.py')
fan=importlib.util.module_from_spec(spec);spec.loader.exec_module(fan);base=fan.base
LIMIT=256;base.MAX_COMMANDS=LIMIT
IDENTITY=bytes.fromhex('2081010302bf3f0a0093100d000000');MAC=bytes.fromhex('b082e2ac382c')
ORIGINAL=bytes(15);CANDIDATE=bytes([0,0,0x62])+bytes(12)
BASELINE=(b'\0',ORIGINAL,bytes(15),bytes([1])*15)
WANTED=(b'\0',CANDIDATE,bytes(15),bytes([1])*15);SET_PAYLOAD=b'\1\1'+CANDIDATE
SDR_REQUEST=bytes.fromhex('0000220000ff')
def fixture(name,sha,length=None):
 b=(P/'fixtures'/name).read_bytes()
 if (length is not None and len(b)!=length) or hashlib.sha256(b).hexdigest()!=sha:raise base.PolicyError('fixed evidence fixture mismatch')
 return b
SDR_RECORD=fixture('mb-cha-fan1-sdr.bin','a253da27c190c2973891597bfb1fe61c52c828b420dfb46388916cdcac4784d8',59)
READING_BASE=fixture('reading-current.bin','e6e22ec5a2e4d2e4ae78456e0c65b7e39094979ec05312a7963f353851c6ede6',4)
EVENT_BASE=fixture('event-current.bin','169600e259aa1f0245891915d036d58ecd492907205f1e49669439ced00a814f',5)
CATALOG=json.loads(fixture('sdr-records.json','cd37bc060a8e87467640c23975697ffd6d2ee9faffc7afe3167dfa4eddba5cd4'))
EXPECTED_RECORDS={int(k):bytes.fromhex(v) for k,v in CATALOG['records'].items()}
assert len(EXPECTED_RECORDS)==58 and EXPECTED_RECORDS[0x22]==SDR_RECORD

class Stop(RuntimeError):pass
class Gate:
 def __init__(self):self.armed=False;self.ready=False;self.sent=False
 def arm(self):
  if not self.ready or self.armed or self.sent:raise Stop('write_arm_rejected')
  self.armed=True
 def validate(self,n,c,data=(),sensor_ids=()):
  p=bytes(data)
  if (n,c) in ((6,1),(6,0x25),(10,0x20)) and not p:return
  if (n,c)==(12,2) and p==bytes([1,5,0,0]):return
  if (n,c)==(10,0x23) and len(p)==6 and p[:2]==b'\0\0' and p[4:]==b'\0\xff':return
  if (n,c)==(4,0x2d) and p in (b'\x20',b'\xfb'):return
  if (n,c)==(4,0x29) and p==b'\x20':return
  if (n,c)==(48,0x9a) and p in (b'\0\0',b'\1\0',b'\2\0',b'\3\0'):return
  if self.armed and not self.sent and (n,c)==(48,0x9a) and p==SET_PAYLOAD:
   self.armed=False;self.sent=True;return
  raise base.PolicyError('Only one exact verified RPM map SET is allowed')

class Apply:
 def __init__(self,exchange,emit,sleep=time.sleep,gate=None):
  self.exchange=exchange;self.emit=emit;self.sleep=sleep;self.gate=gate or Gate();self.sequence=0;self.repo_before=None
  self.result=dict(schema='hero-fan-keep-known-map-1',target=base.HOST,state='not_started',set_attempted=False,set_sent=False,
   set_acknowledged=False,map_verified=False,other_control_tables_unchanged=False,sdr_unchanged=False,
   reading_normal=False,event_enable_unchanged=False,keep_verified_mapping=True,no_automatic_restore_to_zero=True,
   hide_unhide_allowed=False,pwm_type_mode_setters=False,samples=[])
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
  mac=self.req('lan1_mac',12,2,bytes([1,5,0,0]))
  if len(mac)!=7 or mac[1:]!=MAC:raise Stop('MAC_mismatch')
  wd=self.req('watchdog',6,0x25)
  if len(wd)!=8 or wd[0]&0x40:raise Stop('watchdog_not_stopped')
  if self.req('version_error',4,0x2d,b'\xfb')!=bytes.fromhex('00c00080'):raise Stop('R3_initialization_not_confirmed')
  if not self.target('target_before'):raise Stop('target_not_visible')
  before=self.reading('sensor20_before');self.result['reading_before']=before
  if before['raw_hex']!=READING_BASE.hex():raise Stop('current_sensor_state_changed')
  if self.event_enable('event_enable_before')!=EVENT_BASE:raise Stop('current_event_enable_changed')
  rows,info=self.inventory('SDR_before')
  if rows!=EXPECTED_RECORDS:raise Stop('full_original_SDR_set_mismatch')
  self.repo_before=info;self.result['repository_before']=info.hex()
  if self.maps('current_tables')!=BASELINE:raise Stop('current_tables_changed_no_overwrite')
  # Final comparisons after complete inventory; no wildcard baseline.
  if self.req('fresh_RPM_before_SET',48,0x9a,b'\1\0')!=ORIGINAL:raise Stop('RPM_changed_before_SET')
  if self.reading('fresh_sensor_before_SET')['raw_hex']!=READING_BASE.hex():raise Stop('sensor_changed_before_SET')
  if self.event_enable('fresh_event_before_SET')!=EVENT_BASE:raise Stop('event_changed_before_SET')
  self.gate.ready=True
 def observe(self):
  maps=self.maps('applied_tables');self.result['map_verified']=maps[1]==CANDIDATE
  self.result['other_control_tables_unchanged']=maps[0]==BASELINE[0] and maps[2:]==BASELINE[2:]
  if maps!=WANTED:raise Stop('map_or_controls_not_verified_no_retry')
  for i in range(5):
   self.sleep(1.0);self.result['samples'].append(self.reading('applied_sample_'+str(i)))
  self.result['event_enable_after']=self.event_enable('event_enable_after').hex()
  self.result['event_enable_unchanged']=self.result['event_enable_after']==EVENT_BASE.hex()
  rows,info=self.inventory('SDR_after');self.result['repository_after']=info.hex()
  self.result['sdr_unchanged']=rows==EXPECTED_RECORDS and info==self.repo_before
  self.result['reading_normal']=all(x['usable'] and x['raw']>0 and not(bytes.fromhex(x['raw_hex'])[2]&0x3f) for x in self.result['samples'])
  if not self.result['sdr_unchanged']:raise Stop('SDR_changed_no_rewrite')
  if not self.result['event_enable_unchanged']:raise Stop('event_enable_changed_no_SET')
  if not self.result['reading_normal']:raise Stop('reading_not_yet_normal_no_more_SET')
 def run(self):
  error=None;observe_error=None
  try:
   self.preflight();self.gate.arm();self.result['set_attempted']=True
   response=self.req('apply_verified_RPM_once',48,0x9a,SET_PAYLOAD,write=True)
   if response!=CANDIDATE:raise Stop('SET_echo_mismatch')
   self.result['set_acknowledged']=True
  except Stop as e:error=str(e);self.emit(dict(type='stopped',reason=error))
  finally:
   self.gate.armed=False
   if self.gate.sent:
    try:self.observe()
    except Stop as e:observe_error=str(e);self.emit(dict(type='observation_stopped',reason=observe_error))
  self.result.update(set_sent=self.gate.sent,error=error,observe_error=observe_error,requests=self.sequence,
   requires_review=bool(error or observe_error or not self.result['reading_normal']))
  self.result['state']='configured_and_kept' if not self.result['requires_review'] else 'stopped_for_review'
  self.emit(dict(type='result',**self.result));return self.result

def verify_wrappers():
 for name,digest in json.loads((P/'probe_runtime/manifest.json').read_text()).items():
  if hashlib.sha256((P/'probe_runtime'/name).read_bytes()).hexdigest()!=digest:raise base.PolicyError('frozen wrapper hash mismatch')
 return base.verify_dependencies()
def worker():
 connection=None;password=None;operation=None
 try:
  password=json.loads(sys.stdin.buffer.readline(4097))
  if not isinstance(password,str) or not 0<len(password)<=128:raise base.PolicyError('credential input')
  verify_wrappers();gate=Gate();base.validate_read=gate.validate
  Session=fan.admin_session_class();connection=Session(bmc=base.HOST,userid=base.USER,password=password,port=623,privlevel=4,keepalive=False);password=None
  if connection.ipmiversion!=2.0 or connection.privlevel!=4:raise base.PolicyError('Authenticated ADMIN LAN+ required')
  connection.reads_enabled=True
  operation=Apply(lambda n,c,d:connection.raw_command(netfn=n,command=c,data=tuple(d),retry=False),base.emit,gate=gate)
  return 2 if operation.run()['requires_review'] else 0
 except Exception as e:
  base.emit(dict(type='worker_stopped',exception_type=type(e).__name__,reason=str(e) if isinstance(e,Stop) else 'transport_or_policy',set_may_have_been_sent=bool(operation and operation.result['set_attempted'])));return 2
 finally:
  password=None
  if connection is not None:
   try:connection.logout();base.emit(dict(type='closed'))
   except Exception:base.emit(dict(type='close_failed'))
def main():
 p=argparse.ArgumentParser();p.add_argument('--worker',action='store_true');p.add_argument('--apply-and-keep-verified-cha1',action='store_true');p.add_argument('--out');a=p.parse_args()
 if a.worker:return worker()
 if not a.apply_and_keep_verified_cha1:p.error('Explicit --apply-and-keep-verified-cha1 required; at most one RPM map SET.')
 out=(P/(a.out or '')).resolve()
 if out.parent!=P or out.exists() or out.suffix!='.json':raise base.PolicyError('New JSON output filename in this directory required')
 verify_wrappers();print('Fixed .71: one RPM[2]=62 SET, keep configuration, no hide/unhide or zero-map restore.')
 password=getpass.getpass('IPMI password (not saved): ');secret=(json.dumps(password)+'\n').encode();password=None
 started=base.utc_now();code,timeout,raw,stderr_count=base.bounded_child([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker'],secret,180);secret=None
 events=[]
 for line in raw.decode('utf-8',errors='replace').splitlines():
  try:r=json.loads(line)
  except ValueError:continue
  if isinstance(r,dict) and 'type' in r:events.append(r)
 report=dict(schema='hero-fan-keep-known-map-run-1',target=base.HOST,started_utc=started,finished_utc=base.utc_now(),return_code=code,hard_timeout=timeout,stderr_bytes_not_saved=stderr_count,events=events,
  limitation='One verified RPM mapping is intentionally retained. Unknown reply is inspected with GET only; no retry, hide/unhide or restore to zero. No atomic comparison against simultaneous administrators.')
 with out.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2,ensure_ascii=False)
 print(json.dumps(dict(file=str(out),return_code=code,hard_timeout=timeout,events=len(events))));return code
if __name__=='__main__':raise SystemExit(main())
