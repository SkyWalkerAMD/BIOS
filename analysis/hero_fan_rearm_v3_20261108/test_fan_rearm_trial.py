"""Offline state transitions and command allowlist. All sockets forbidden."""
from pathlib import Path
import hashlib,importlib.util,json,socket
P=Path(__file__).resolve().parent;socket_calls=[]
def denied(*a,**k):socket_calls.append(1);raise AssertionError('offline sockets forbidden')
socket.socket=denied
spec=importlib.util.spec_from_file_location('tested_rearm',P/'fan_rearm_trial.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Fake:
 def __init__(self,count=58):
  self.gate=m.Gate();self.events=[];self.requests=[];self.tables=list(m.BASELINE);self.label=None;self.hook=None
  self.visible=True;self.sample=bytes.fromhex('16c00000');self.restored=m.READING_BASE;self.effect={x:True for x in m.WRITES}
  self.sleep_calls=[];self.stamp=0;self.rows={}
  for i in range(1,count+1):
   r=bytearray(m.SDR_RECORD);r[0:2]=i.to_bytes(2,'little');r[7]=(i+100)&255;self.rows[i]=bytes(r)
  self.rows[0x22]=(P/'fixtures/mb-cha-fan1-sdr.bin').read_bytes()
  self.trial=m.Trial(self.exchange,self.emit,self.sleep_calls.append,self.gate)
 def emit(self,e):
  self.events.append(e)
  if e['type']=='intent':self.label=e['label']
 def exchange(self,n,c,p):
  self.gate.validate(n,c,p);self.requests.append((self.label,n,c,p));cc=0;data=b''
  if (n,c)==(6,1):data=m.IDENTITY
  elif (n,c)==(6,0x25):data=bytes(8)
  elif (n,c)==(0x0c,2):data=b'\x11'+m.MAC
  elif (n,c)==(0x0a,0x20):
   data=b'\x51'+(len(self.rows)-(not self.visible)).to_bytes(2,'little')+b'\xc0\x12'+self.stamp.to_bytes(4,'little')+self.stamp.to_bytes(4,'little')+b'\x27'
  elif (n,c)==(0x0a,0x23):
   rid=int.from_bytes(p[2:4],'little');ids=sorted(k for k in self.rows if k!=0x22 or self.visible)
   rid=ids[0] if not rid else rid
   if rid not in ids:cc=0xcb
   else:
    i=ids.index(rid);nxt=ids[i+1] if i+1<len(ids) else 0xffff;data=nxt.to_bytes(2,'little')+self.rows[rid]
  elif (n,c)==(4,0x2d):
   if p==b'\xfb':data=bytes.fromhex('00c00080')
   elif self.label=='sensor20_before':data=m.READING_BASE
   elif self.label.startswith('candidate_sample_'):data=self.sample
   else:data=self.restored
  elif (n,c)==(4,0x29):data=m.EVENT_BASE
  elif (n,c)==(0x30,0x9a) and len(p)==2:data=self.tables[p[0]]
  elif (n,c,p) in m.WRITES.values():
   stage=self.gate.sent[-1]
   if self.effect[stage]:
    if c==0x9a:self.tables[1]=p[2:]
    else:self.visible=p[1]==1;self.stamp+=1
   data=p[2:] if c==0x9a else b''
  else:raise AssertionError((n,c,p))
  response=dict(netfn=n+1,command=c,code=cc,data=data)
  if self.hook:response=self.hook(self,response) or response
  return response
 def run(self):
  r=self.trial.run()
  assert len(self.requests)<=m.LIMIT
  writes=[(n,c,p) for _,n,c,p in self.requests if (n,c,p) in m.WRITES.values()]
  assert len(writes)==len(set(writes))<=4
  assert all(e['retry'] is False for e in self.events if e['type']=='intent')
  assert all((n,c) not in ((6,2),(6,3),(6,0x24),(4,0x28)) for _,n,c,_ in self.requests)
  return r
cases=[]
def check(name,fn):fn();cases.append(dict(case=name,passed=True))
def success(unavailable=False,count=58):
 f=Fake(count)
 if unavailable:f.sample=m.READING_BASE
 r=f.run();assert not r['requires_review'] and r['state']=='observed',r
 assert r['sent_writes']==['candidate','hide','unhide','restore'] and f.tables==list(m.BASELINE)
 assert r['record_set_restored'] and r['observable_state_restored'] and not r['complete_rollback']
 assert r['repository_before']!=r['repository_after'] and f.visible and f.sleep_calls==[1.0]*8
 assert len(r['samples'])==5 and all(x['usable']!=unavailable for x in r['samples'])
check('normal_four_sets_positive_samples_and_observable_restore',success)
check('zero_samples_no_extra_rearm_or_map_guess',lambda:success(True))
check('96_record_inventory_bound',lambda:success(False,96))
def baseline_bad(label,value,code=0):
 f=Fake();f.hook=lambda s,r:dict(r,data=value,code=code) if s.label==label else r
 r=f.run();assert r['requires_review'] and not f.gate.sent,r
for label,value,code in [
 ('device_id',bytes(15),0),('lan1_mac',bytes(7),0),('watchdog',b'\x40'+bytes(7),0),
 ('version_error',bytes.fromhex('00c01080'),0),('target_before',b'',0xcb),
 ('target_before',b'\x23\0'+m.SDR_RECORD[:-1],0),('sensor20_before',bytes(4),0),
 ('event_enable_before',b'\xc0'+m.EVENT_BASE[1:],0),('SDR_before_info_begin',bytes(14),0),
 ('SDR_before_info_begin',b'\x51\x61\0'+bytes(11),0),('SDR_before_record_0',bytes(8),0),
 ('SDR_before_record_0',b'\xff\xff'+m.SDR_RECORD,0),
 ('SDR_before_info_end',b'\x51\x3a\0'+bytes(11),0),
 ('fresh_baseline_0',b'\1',0),('fresh_baseline_1',m.CANDIDATE,0),('fresh_baseline_2',b'\1'+bytes(14),0),
 ('fresh_baseline_3',bytes(15),0),('event_enable_before',b'',0xd4)]:
 check('preflight_reject_'+label+'_'+str(code),lambda l=label,v=value,c=code:baseline_bad(l,v,c))
def lost(stage,applied=True,kind='timeout'):
 f=Fake();f.effect[stage]=applied
 def hook(s,r):
  if s.label==stage+'_once':
   if kind=='timeout':raise TimeoutError('mock reply lost')
   if kind=='completion':return dict(r,code=0xd5)
   if kind=='header':return dict(r,command=0)
   if kind=='echo':return dict(r,data=b'\x99')
  return r
 f.hook=hook;r=f.run()
 assert sum(x==stage for x in r['sent_writes'])==1,r
 assert r['map_restored'] and f.tables==list(m.BASELINE),r
 if stage=='hide':
  assert not r['samples'] and r['requires_review']
  assert ('unhide' in r['sent_writes'])==applied and f.visible
 elif stage=='unhide':
  assert not r['samples'] and r['requires_review']
  assert f.visible==applied and r['target_visible']==applied
 elif stage=='candidate':assert r['sent_writes']==(['candidate','restore'] if applied else ['candidate']) and f.visible
 elif stage=='restore':
  assert f.visible
  if not applied:raise AssertionError('separate test for unverified restoration')
for stage in ('candidate','hide','unhide','restore'):
 for kind in ('timeout','completion','header','echo'):
  check('unknown_'+stage+'_'+kind+'_GET_only_decision',lambda s=stage,k=kind:lost(s,True,k))
for stage in ('candidate','hide','unhide'):check('not_applied_'+stage+'_never_retry',lambda s=stage:lost(s,False))
def restore_not_applied():
 f=Fake();f.effect['restore']=False;r=f.run()
 assert r['requires_review'] and not r['map_restored'] and r['sent_writes']==['candidate','hide','unhide','restore']
check('restore_not_applied_stops_without_repeat',restore_not_applied)
def observable_diff():
 f=Fake();f.restored=bytes.fromhex('00c00000');r=f.run()
 assert r['requires_review'] and r['cleanup_error']=='observable_sensor_state_differs_no_more_sets'
 assert r['record_set_restored'] and r['map_restored'] and r['target_visible'] and not r['observable_state_restored']
check('private_state_not_forced_back_no_second_hide_cycle',observable_diff)
def concurrent(table):
 f=Fake()
 def hook(s,r):
  if s.label=='candidate_sample_4':s.tables[table]=b'\x77' if table==0 else bytes([0x77])*15
  return r
 f.hook=hook;r=f.run();assert r['requires_review'] and 'restore' not in r['sent_writes'] and not r['map_restored']
for table in range(4):check('concurrent_table_'+str(table)+'_not_overwritten',lambda t=table:concurrent(t))
def post_diff():
 f=Fake()
 def hook(s,r):
  if s.label=='SDR_after_record_0':
   x=bytearray(r['data']);x[-1]^=1;return dict(r,data=bytes(x))
  return r
 f.hook=hook;r=f.run();assert r['requires_review'] and r['cleanup_error']=='SDR_record_set_different' and r['map_restored']
check('unrelated_SDR_change_detected_without_rewrite',post_diff)
def hide_ack_no_effect():
 f=Fake();f.effect['hide']=False;r=f.run()
 assert r['requires_review'] and r['sent_writes']==['candidate','hide','restore'] and f.visible and not r['samples']
check('OEM_ACK_without_effect_stops',hide_ack_no_effect)
def malformed(stage):
 f=Fake()
 def hook(s,r):
  if s.label==stage:raise TimeoutError('mock GET lost')
  return r
 f.hook=hook;r=f.run();assert r['requires_review']
 assert r['sent_writes'].count('hide')<=1 and r['sent_writes'].count('unhide')<=1
for stage in ('candidate_verify_1','hidden_check_target','hidden_check_repo','visible_check_target','candidate_sample_2','restore_gate_1','cleanup_target_readonly','SDR_after_record_7'):
 check('GET_error_'+stage,lambda s=stage:malformed(s))
def allowlist():
 g=m.Gate()
 for n,c,p in ((6,2,b''),(6,0x24,bytes(6)),(4,0x28,b'\x20\xc0'),(0x30,0x94,b'\x21\0'),(0x30,0x94,b'\x20\1')):
  try:g.validate(n,c,p)
  except m.base.PolicyError:pass
  else:raise AssertionError('unarmed/unrelated write admitted')
 for sub in (0,2,3):
  for b in range(256):
   try:g.validate(0x30,0x9a,bytes([sub,1,b]))
   except m.base.PolicyError:pass
   else:raise AssertionError('control setter admitted')
 g.ready=True
 for stage in ('hide','unhide','restore'):
  try:g.arm(stage)
  except m.Stop:pass
  else:raise AssertionError('wrong order accepted')
 for stage in ('candidate','hide','unhide','restore'):
  g.arm(stage);g.validate(*m.WRITES[stage])
  try:g.arm(stage)
  except m.Stop:pass
  else:raise AssertionError('write retry accepted')
check('strict_single_use_allowlist_and_768_control_setters_denied',allowlist)
def real_wire_guard():
 deps=m.verify_wrappers();assert deps['wheels']==4 and deps['executable_files_checked']>0
 g=m.Gate();m.base.validate_read=g.validate;cls=m.fan.admin_session_class()
 raw=cls.__bases__[0].__bases__[0];original=raw._send_ipmi_net_payload;sent=[]
 try:
  raw._send_ipmi_net_payload=lambda self,*a,**k:sent.append((a,k))
  instance=object.__new__(cls);instance.reads_enabled=True;instance.ipmiversion=2.0;instance.sent_reads=0
  instance._send_ipmi_net_payload(6,0x38,[0x8e,4],retry=True)
  instance._send_ipmi_net_payload(6,0x3b,[4],retry=True)
  instance._send_ipmi_net_payload(4,0x29,b'\x20',retry=False)
  g.ready=True
  for stage in ('candidate','hide','unhide','restore'):
   g.arm(stage);n,c,p=m.WRITES[stage];instance._send_ipmi_net_payload(n,c,p,retry=False)
   try:instance._send_ipmi_net_payload(n,c,p,retry=False)
   except m.base.PolicyError:pass
   else:raise AssertionError('actual wire accepted repeat')
  assert len(sent)==7
  for kw in ({'retry':True},{'retry':False,'bridge_request':{}},{'retry':False,'rslun':1}):
   try:instance._send_ipmi_net_payload(0x30,0x9a,b'\1\0',**kw)
   except m.base.PolicyError:pass
   else:raise AssertionError('actual wire accepted retry or bridge')
  instance.sent_reads=m.LIMIT
  try:instance._send_ipmi_net_payload(6,1,b'',retry=False)
  except m.base.PolicyError:pass
  else:raise AssertionError('actual wire accepted excess request')
 finally:raw._send_ipmi_net_payload=original
check('actual_pinned_ADMIN_session_wire_guard_no_sockets',real_wire_guard)
def quota():
 f=Fake();f.trial.sequence=m.LIMIT
 try:f.trial.req('excess',6,1)
 except m.Stop as e:assert str(e)=='request_limit'
 else:raise AssertionError('request count overflow')
 assert not f.requests
check('request_limit_before_transport',quota)
def record_mutations():
 for i in range(59):
  x=bytearray(m.SDR_RECORD);x[i]^=1
  baseline_bad('target_before',b'\x23\0'+x)
check('each_59_original_SDR_bytes_checked_before_any_set',record_mutations)
assert not socket_calls
(P/'offline-verification.json').write_text(json.dumps(dict(passed=True,count=len(cases),cases=cases,socket_calls=0,hardware_test=False),indent=2)+'\n')
print(json.dumps(dict(passed=True,count=len(cases),socket_calls=0)))
