"""Offline-only original/corrected reset guard review, with lowest transport stubbed."""
from pathlib import Path
import hashlib,importlib.util,json,sys
from unittest.mock import patch
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
path=ROOT/'analysis/hero_ipmi_complete_live_20261108/probe/reset_bmc_for_r4_v2.py'
expected='06486ba52e6aaaf138734642ca5585cbbd791a591dae5e3372384fb1a652da6f'
assert hashlib.sha256(path.read_bytes()).hexdigest()==expected
spec=importlib.util.spec_from_file_location('reset_v2_offline_review',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=m.base
base.verify_dependencies()
Raw=m.old.fan.admin_session_class().__mro__[2]
rows=[]
def fixture(gate,fail=False,old=False):
 base.validate_read=gate.validate
 cls=m.old.fan.admin_session_class() if old else m.session_class(gate)
 c=object.__new__(cls);c.reads_enabled=True;c.ipmiversion=2.0;c.sent_reads=0
 return c,base.Collector(c,lambda e:None)
calls=[]
def raw(self,netfn=None,command=None,data=(),retry=None):
 return self._send_ipmi_net_payload(netfn,command,data,retry=retry)
def bottom(self,netfn=None,command=None,data=(),*args,**kw):
 calls.append((netfn,command,bytes(data)))
 if getattr(self,'test_failure',False):raise TimeoutError('synthetic unknown result')
 return dict(netfn=netfn+1,command=command,code=0,data=[])
def denied(name,fn,expected_count=0):
 before=len(calls)
 try:fn()
 except (base.PolicyError,base.ProbeStop):pass
 else:raise AssertionError(name+' allowed')
 assert len(calls)-before==expected_count,name
 rows.append(dict(case=name,passed=True,wire_stub_calls=len(calls)-before))
with patch.object(Raw,'_send_ipmi_net_payload',bottom),patch.object(Raw,'raw_command',raw):
 gate=m.old.Gate();gate.armed=True;c,col=fixture(gate,old=True)
 denied('original consumes before guarded transport',lambda:col.read('original',6,2))
 gate=m.Gate();c,col=fixture(gate)
 denied('new unarmed denied',lambda:col.read('unarmed',6,2))
 gate.armed=True
 col.read('first',6,2)
 assert calls==[(6,2,b'')] and c.reset_transport_attempted and not gate.armed
 rows.append(dict(case='new armed only one wire call',passed=True,wire_stub_calls=1))
 gate.armed=True
 denied('rearm cannot repeat same session',lambda:col.read('again',6,2))
 gate=m.Gate();gate.armed=True;c,col=fixture(gate);c.test_failure=True
 denied('unknown wire result makes one attempt',lambda:col.read('timeout',6,2),1)
 assert c.reset_transport_attempted and not gate.armed
 gate.armed=True
 denied('unknown result cannot be retried',lambda:col.read('timeout_repeat',6,2))
 for field,value in [('retry',True),('code',1),('bridge_request',{}),('rslun',1)]:
  gate=m.Gate();gate.armed=True;c,col=fixture(gate)
  args=dict(netfn=6,command=2,data=(),retry=False);args[field]=value
  denied('reject reset '+field,lambda:c._send_ipmi_net_payload(**args))
 for netfn,cmd,data in [(6,2,[0]),(12,1,[1,4,1]),(6,0x24,[0]*6),(0x0a,0x47,[0]*6),(0,2,[3]),(0x30,0x99,[1,2])]:
  gate=m.Gate();gate.armed=True;c,col=fixture(gate)
  denied(f'reject nonallowed mutation {netfn:02x}/{cmd:02x}/{bytes(data).hex()}',lambda:col.read('bad',netfn,cmd,data))
result=dict(passed=True,cases=len(rows),source_sha256=expected,network_access=False,instantiated_real_sessions=False,results=rows,limitations=['Only guard and Collector flow modeled; no BMC reset sent. Main source-evidence asserts require nonoptimized Python.'],config_writes_allowed=[])
(OUT/'reset-v2-independent.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps(result,indent=2))
