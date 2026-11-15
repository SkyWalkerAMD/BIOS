"""Offline only: exact live baseline, one SET, no zero-map restoration."""
from pathlib import Path
import ast,hashlib,importlib.util,json,socket
P=Path(__file__).resolve().parent;socket_calls=[]
def denied(*a,**k):socket_calls.append(1);raise AssertionError('socket forbidden')
socket.socket=denied
spec=importlib.util.spec_from_file_location('tested_apply',P/'fan_apply_known.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake:
 def __init__(self):
  self.gate=m.Gate();self.events=[];self.requests=[];self.tables=list(m.BASELINE);self.hook=None;self.label=None;self.effect=True;self.sample=bytes.fromhex('17c0c000');self.sleeps=[]
  j=json.loads((P/'fixtures/fan-rearm-v3b-01.json').read_text());self.replies={e['label']:e for e in j['events'] if e['type']=='response'}
  self.rows={int.from_bytes(bytes.fromhex(self.replies['SDR_after_record_'+str(i)]['response_hex'])[2:4],'little'):bytes.fromhex(self.replies['SDR_after_record_'+str(i)]['response_hex'])[2:] for i in range(58)}
  self.repo=bytes.fromhex(next(e for e in j['events'] if e['type']=='result')['repository_after'])
  self.op=m.Apply(self.exchange,self.emit,self.sleeps.append,self.gate)
 def emit(self,e):
  self.events.append(e)
  if e['type']=='intent':self.label=e['label']
 def exchange(self,n,c,p):
  self.gate.validate(n,c,p);self.requests.append((self.label,n,c,p));code=0
  if (n,c)==(6,1):data=m.IDENTITY
  elif (n,c)==(6,0x25):data=bytes(8)
  elif (n,c)==(12,2):data=b'\x11'+m.MAC
  elif (n,c)==(10,0x20):data=self.repo
  elif (n,c)==(10,0x23):
   ids=sorted(self.rows);rid=int.from_bytes(p[2:4],'little');rid=ids[0] if not rid else rid
   if rid not in ids:code=0xcb;data=b''
   else:i=ids.index(rid);nxt=ids[i+1] if i+1<len(ids) else 0xffff;data=nxt.to_bytes(2,'little')+self.rows[rid]
  elif (n,c)==(4,0x29):data=bytes.fromhex('c005000500')
  elif (n,c)==(4,0x2d):
   if p==b'\xfb':data=bytes.fromhex('00c00080')
   elif self.label.startswith('applied_sample_'):data=self.sample
   else:data=bytes.fromhex('00c0c700')
  elif (n,c)==(48,0x9a):
   if len(p)==2:data=self.tables[p[0]]
   else:
    assert p==m.SET_PAYLOAD
    if self.effect:self.tables[1]=m.CANDIDATE
    data=m.CANDIDATE
  else:raise AssertionError((n,c,p))
  response=dict(netfn=n+1,command=c,code=code,data=data)
  if self.hook:response=self.hook(self,response) or response
  return response
 def run(self):
  r=self.op.run();assert len(self.requests)<=m.LIMIT
  sets=[(n,c,p) for _,n,c,p in self.requests if (n,c)==(48,0x9a) and len(p)>2]
  assert sets in ([],[(48,0x9a,m.SET_PAYLOAD)])
  assert all((n,c) not in ((48,0x94),(4,0x28),(6,2),(6,3),(6,0x24)) for _,n,c,_ in self.requests)
  assert all(e['retry'] is False for e in self.events if e['type']=='intent')
  return r
cases=[]
def check(name,fn):fn();cases.append(dict(case=name,passed=True))
def success():
 f=Fake();r=f.run();assert r['state']=='configured_and_kept' and not r['requires_review'],r
 assert f.tables==list(m.WANTED) and f.sleeps==[1.0]*5 and all(x['rpm']==2760 for x in r['samples'])
 assert r['sdr_unchanged'] and r['event_enable_unchanged'] and r['set_acknowledged']
check('one_SET_positive_readings_map_retained',success)
def preflight(label,value,code=0):
 f=Fake();f.hook=lambda s,r:dict(r,data=value,code=code) if s.label==label else r
 r=f.run();assert r['requires_review'] and not f.gate.sent and f.tables==list(m.BASELINE),r
for label,value,code in [
 ('device_id',bytes(15),0),('lan1_mac',bytes(7),0),('watchdog',b'\x40'+bytes(7),0),
 ('version_error',bytes.fromhex('00c01080'),0),('target_before',b'',0xcb),
 ('sensor20_before',bytes.fromhex('00a0c000'),0),('event_enable_before',bytes.fromhex('8005000500'),0),
 ('current_tables_0',b'\1',0),('current_tables_1',m.CANDIDATE,0),('current_tables_2',b'\x66'+bytes(14),0),('current_tables_3',bytes(15),0),
 ('fresh_RPM_before_SET',m.CANDIDATE,0),('fresh_sensor_before_SET',bytes.fromhex('01c0c700'),0),
 ('fresh_event_before_SET',bytes.fromhex('c004000500'),0),('SDR_before_info_end',bytes(14),0)]:
 check('no_SET_on_'+label,lambda l=label,v=value,c=code:preflight(l,v,c))
def full_row_diff():
 f=Fake();r=bytearray(f.rows[1]);r[-1]^=1;f.rows[1]=bytes(r);result=f.run()
 assert not f.gate.sent and result['error']=='full_original_SDR_set_mismatch'
check('unrelated_full_SDR_byte_change_blocks_SET',full_row_diff)
def unknown(kind,applied=True):
 f=Fake();f.effect=applied
 def hook(s,r):
  if s.label=='apply_verified_RPM_once':
   if kind=='timeout':raise TimeoutError('mock')
   if kind=='completion':return dict(r,code=0xc0)
   if kind=='header':return dict(r,command=0)
   if kind=='echo':return dict(r,data=bytes(15))
  return r
 f.hook=hook;r=f.run();assert f.gate.sent and r['requires_review']
 assert r['map_verified']==applied and f.tables[1]==(m.CANDIDATE if applied else m.ORIGINAL)
 assert sum(l=='apply_verified_RPM_once' for l,*_ in f.requests)==1
for kind in ('timeout','completion','header','echo'):
 check('unknown_'+kind+'_applied_GET_only',lambda k=kind:unknown(k))
check('lost_REPLY_not_applied_no_repeat',lambda:unknown('timeout',False))
def bad_reading(value):
 f=Fake();f.sample=value;r=f.run();assert r['requires_review'] and r['map_verified'] and not r['reading_normal'] and f.tables==list(m.WANTED)
check('still_zero_keeps_map_no_hide_or_restore',lambda:bad_reading(bytes.fromhex('00c0c700')))
check('temporarily_unavailable_keeps_map_no_reset',lambda:bad_reading(bytes.fromhex('17a0c000')))
check('positive_alarm_bits_recorded_as_not_normal',lambda:bad_reading(bytes.fromhex('17c0c100')))
def post_error(label):
 f=Fake()
 def hook(s,r):
  if s.label==label:raise TimeoutError('mock GET timeout')
  return r
 f.hook=hook;r=f.run();assert r['requires_review'] and f.gate.sent and f.tables==list(m.WANTED)
for label in ('applied_tables_1','applied_sample_1','event_enable_after','SDR_after_record_5'):check('post_GET_error_'+label,lambda l=label:post_error(l))
def drift(table):
 f=Fake()
 def hook(s,r):
  if s.label=='apply_verified_RPM_once':s.tables[table]=b'\1' if table==0 else bytes([0x67])*15
  return r
 f.hook=hook;r=f.run();assert r['requires_review'] and r['observe_error']=='map_or_controls_not_verified_no_retry'
for table in range(4):check('concurrent_table_'+str(table)+'_not_overwritten',lambda t=table:drift(t))
def fixed_event_and_reading_bytes():
 for label,data in [('sensor20_before',m.READING_BASE),('event_enable_before',m.EVENT_BASE)]:
  for i in range(len(data)):
   b=bytearray(data);b[i]^=1;preflight(label,bytes(b))
check('each_current_reading_and_event_byte_matters',fixed_event_and_reading_bytes)
def gate():
 g=m.Gate()
 for sub in (0,2,3):
  for x in range(256):
   try:g.validate(48,0x9a,bytes([sub,1,x]))
   except m.base.PolicyError:pass
   else:raise AssertionError('unrelated setter admitted')
 for n,c,p in ((48,0x94,b'\x20\0'),(48,0x94,b'\x20\1'),(48,0x9a,b'\1\1'+bytes(15)),(4,0x28,b'\x20\xc0'),(6,2,b'')):
  try:g.validate(n,c,p)
  except m.base.PolicyError:pass
  else:raise AssertionError('forbidden command admitted')
 g.ready=True;g.arm();g.validate(48,0x9a,m.SET_PAYLOAD)
 try:g.arm()
 except m.Stop:pass
 else:raise AssertionError('rearm admitted')
check('wire_policy_one_exact_SET_768_other_control_SETs_denied',gate)
def real_wire():
 assert m.verify_wrappers()['wheels']==4
 g=m.Gate();m.base.validate_read=g.validate;cls=m.fan.admin_session_class();raw=cls.__bases__[0].__bases__[0];orig=raw._send_ipmi_net_payload;sent=[]
 try:
  raw._send_ipmi_net_payload=lambda self,*a,**k:sent.append((a,k))
  i=object.__new__(cls);i.reads_enabled=True;i.ipmiversion=2.0;i.sent_reads=0
  i._send_ipmi_net_payload(6,0x38,[0x8e,4],retry=True);i._send_ipmi_net_payload(6,0x3b,[4],retry=True)
  g.ready=True;g.arm();i._send_ipmi_net_payload(48,0x9a,m.SET_PAYLOAD,retry=False)
  for n,c,p in ((48,0x94,b'\x20\0'),(48,0x94,b'\x20\1'),(48,0x9a,m.SET_PAYLOAD),(48,0x9a,b'\1\1'+bytes(15))):
   try:i._send_ipmi_net_payload(n,c,p,retry=False)
   except m.base.PolicyError:pass
   else:raise AssertionError('real guard admitted extra SET')
  assert len(sent)==3
 finally:raw._send_ipmi_net_payload=orig
check('actual_pinned_ADMIN_wire_guard_without_sockets',real_wire)
def unchanged_get_helpers():
 origin=json.loads((P/'read-helper-origin.json').read_text());old=P.parents[1]/origin['source']
 assert hashlib.sha256(old.read_bytes()).hexdigest()==origin['sha256']
 a=next(x for x in ast.parse(old.read_text()).body if isinstance(x,ast.ClassDef) and x.name=='Trial')
 b=next(x for x in ast.parse((P/'fan_apply_known.py').read_text()).body if isinstance(x,ast.ClassDef) and x.name=='Apply')
 for name in origin['methods']:
  x=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name==name);y=next(n for n in b.body if isinstance(n,ast.FunctionDef) and n.name==name)
  assert ast.dump(x,include_attributes=False)==ast.dump(y,include_attributes=False)
check('seven_read_helpers_unchanged_from_tested_V3b',unchanged_get_helpers)
assert not socket_calls
report=dict(passed=True,count=len(cases),cases=cases,socket_calls=0,hardware_test=False,
 live_prefix_source='fixtures/fan-rearm-v3b-01.json',scope='One exact RPM SET intentionally retained; all effects and post-readings in tests are mocked.')
(P/'offline-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(passed=True,count=len(cases),socket_calls=0)))
