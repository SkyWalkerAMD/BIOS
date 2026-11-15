"""Exercise the delivered I3D PE's engine/menu with a bounded inventory transport double.

Only private_tls_inventory_exchange is replaced in emulated RAM. Identity checks,
the native continuation engine, menu confirmations, log and state code are actual PE.
TLS/certificate handling is tested separately; this test opens no network device.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys
import types

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
base=types.ModuleType('i3d_identity_machine')
base.__file__=str(HERE/'verify_i3d_pe.py')
source=Path(base.__file__).read_text(encoding='utf-8').split('\nrows=[]',1)[0]
exec(compile(source,base.__file__,'exec'),base.__dict__)
from unicorn.x86_const import *
ERR=lambda n:(1<<63)|n
catalog=(HERE/'source/catalog71.h').read_text(encoding='utf-8')
payloads={int(i):json.loads(json.loads(s)) for i,s in re.findall(r'inv71_body_([0-5])\[\]=(.*);',catalog)}
assert set(payloads)==set(range(6))
paths={0:'/redfish/v1/',1:'/redfish/v1/Systems/Self',
       2:'/redfish/v1/Systems/Self/Processors',3:'/redfish/v1/Systems/Self/Memory',
       7:'/redfish/v1/Systems/Self/Processors/DevType1_CPU0',
       12:'/redfish/v1/Systems'}
for i in range(4):paths[8+i]='/redfish/v1/Systems/Self/Memory/DevType2_DIMM'+str(i)


class Machine(base.Machine):
 def __init__(self,keys,case='orphan',identity='correct'):
  super().__init__(keys,identity)
  self.scenario=case;self.requests=[];self.read_count={};self.etag_count=1
  self.objects={7:dict(payloads[1])}
  self.summary={'Count':0,'Model':''}
  if case=='all_present':
   for item in range(2,6):self.objects[item+6]=dict(payloads[item])
  if case=='cpu_missing':self.objects.clear()
  if case=='cpu_conflict':self.objects[7]['Model']='Different CPU'
  if case=='dimm_conflict':self.objects[9]={**payloads[3],'SerialNumber':'OTHER'}
  addr=base.symbols['private_tls_inventory_exchange']
  self.u.mem_write(addr,b'\xc3');self.stubs[addr]='InventoryExchangeDouble'
  self.u.hook_add(base.base.UC_HOOK_CODE,self.hook,begin=addr,end=addr)
 def c_string(self,p):
  if not p:return None
  data=bytearray()
  for i in range(4096):
   b=bytes(self.u.mem_read(p+i,1))
   if b==b'\0':return data.decode('ascii')
   data.extend(b)
  raise AssertionError('unbounded mock string')
 def response(self,method,rid,body,ifmatch):
  self.requests.append({'method':method,'resource':rid,'body':body,'if_match':ifmatch})
  if method==0:
   assert body is None and ifmatch is None
   self.read_count[rid]=self.read_count.get(rid,0)+1
   if rid==0:return 0,200,{'@odata.id':paths[0],'RedfishVersion':'1.8.0','Oem':{'Ami':{'RtpVersion':'1.8.a'}},'Systems':{'@odata.id':paths[12]}}
   if rid==12:return 0,200,{'@odata.id':paths[12],'Members@odata.count':1,'Members':[{'@odata.id':paths[1]}]}
   if rid==1:return 0,200,{'@odata.id':paths[1],**payloads[0],'@odata.etag':f'"e{self.etag_count}"','Processors':{'@odata.id':paths[2]},'Memory':{'@odata.id':paths[3]},'ProcessorSummary':self.summary}
   if rid in (2,3):
    members=[]
    if self.scenario=='indexed':
     members=[{'@odata.id':paths[k]} for k in sorted(self.objects) if (rid==2 and k==7) or (rid==3 and k>=8)]
    return 0,200,{'@odata.id':paths[rid],'Members@odata.count':len(members),'Members':members}
   assert rid in range(7,12),rid
   if self.scenario=='race_matching_dimm' and rid==8 and self.read_count[rid]>=2:self.objects[8]=dict(payloads[2])
   if rid not in self.objects:return 0,404,{'error':{'code':'Base.1.0.ResourceMissingAtURI'}}
   return 0,200,{'@odata.id':paths[rid],**self.objects[rid]}
  assert rid!=2,'Known CPU orphan must never be POSTed again'
  if method==1:
   assert rid==3 and ifmatch is None
   item=next(i for i in range(2,6) if body==payloads[i])
   direct=item+6
   assert direct not in self.objects,'Existing resource must not be duplicated'
   prior=self.requests[:-1]
   assert any(r['method']==0 and r['resource']==direct for r in prior)
   if self.scenario=='post_rejected':return 0,500,{'error':{'code':'InternalError'}}
   self.objects[direct]=dict(body)
   if self.scenario=='post_uncertain':return ERR(18),0,{}
   return 0,201,{'@odata.id':paths[direct],**body}
  assert method==2 and rid==1
  assert ifmatch==f'"e{self.etag_count}"','Summary needs fresh If-Match'
  assert body=={'ProcessorSummary':{'Count':1,'Model':payloads[1]['Model']}}
  if self.scenario=='summary_rejected':return 0,500,{'error':{'code':'InternalError'}}
  self.summary=body['ProcessorSummary'];self.etag_count+=1
  return 0,204,None
 def hook(self,u,address,size,data):
  if self.stubs.get(address)!='InventoryExchangeDouble':return super().hook(u,address,size,data)
  rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
  method,rid,b,n=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  assert n<=4096
  body=json.loads(bytes(u.mem_read(b,n)).decode('ascii')) if n else None
  ifmatch=self.c_string(self.r64(rsp+40));reply=self.r64(rsp+48)
  status,http,value=self.response(method,rid,body,ifmatch)
  raw=b'' if value is None else json.dumps(value,separators=(',',':')).encode('ascii')
  p=self.alloc(raw+b'\0')
  u.mem_write(reply,struct.pack('<I4xQQ',http,p,len(raw)))
  u.reg_write(UC_X86_REG_RAX,status)
  for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)


def run(name,keys,case='orphan',identity='correct'):
 m=Machine(keys,case,identity);s,output=m.run();assert s==0 and not m.keys
 assert 'HERO Inventory I3d RETURNING TO FIRMWARE' in output
 log=m.audit_bytes();writes=[r for r in m.requests if r['method']]
 return m,log,writes,{'name':name,'passed':True,'requests':len(m.requests),'writes':writes}


rows=[]
m,log,writes,row=run('readonly_preflight_cpu_orphan', 'iqq')
assert not writes and len(m.objects)==1 and b'I3D_PREFLIGHT_READY_NO_WRITES_SENT' in log
rows.append(row)
m,log,writes,row=run('known_cpu_orphan_four_dimms_then_separate_summary','iwwwwwwwwwwssqq')
assert [w['method'] for w in writes]==[1,1,1,1,2] and [w['resource'] for w in writes]==[3,3,3,3,1]
assert set(m.objects)==set(range(7,12)) and m.summary['Count']==1
assert b'I3D_INVENTORY_DONE_MASK=0x000000000000003F' in log and b'I3D_INVENTORY_STATE=0x0000000000000004' in log
assert any(b'COLLECTION' in line and (b'PENDING' in line or b'NOT_INDEXED' in line) for line in log.splitlines())
rows.append(row)
m,log,writes,row=run('one_confirmed_step_never_sequences','iwwqq')
assert len(writes)==1 and writes[0]['body']==payloads[2] and set(m.objects)=={7,8}
rows.append(row)
m,log,writes,row=run('cancelled_write_and_summary','iw\x1bs\x1bqq')
assert not writes
rows.append(row)
m,log,writes,row=run('direct_200_matching_objects_reused','iwwssqq','all_present')
assert len(writes)==1 and writes[0]['method']==2 and m.summary['Count']==1
rows.append(row)
for scenario in ('cpu_missing','cpu_conflict','dimm_conflict'):
 m,log,writes,row=run('preflight_refuses_'+scenario,'iwwssqq',scenario)
 assert not writes
 rows.append(row)
m,log,writes,row=run('direct_404_to_200_race_reuses_without_post','iwwqq','race_matching_dimm')
assert not writes and 8 in m.objects
rows.append(row)
for scenario in ('post_rejected','post_uncertain'):
 m,log,writes,row=run('no_replay_after_'+scenario,'iwwwwissqq',scenario)
 assert len(writes)==1 and writes[0]['method']==1
 rows.append(row)
m,log,writes,row=run('summary_rejected_never_replayed','issssqq','summary_rejected')
assert len(writes)==1 and writes[0]['method']==2
rows.append(row)
for scenario in ('cpu','dimm','uuid','watchdog_failure'):
 m,log,writes,row=run('source_or_runtime_gate_'+scenario,'iwwssqq',identity=scenario)
 assert not writes
 rows.append(row)
report={'all_passed':True,'count':len(rows),'app_sha256':hashlib.sha256((HERE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
        'cases':rows,'limits':['Actual delivered PE engine/menu with exact captured SMBIOS; synthetic inventory transport only.','No hardware, BMC, network or firmware operations.','Certificate/TLS and network tests are separate; this does not establish live publication or persistence.']}
(HERE/'continuation-pe-tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'cases':len(rows),'app_sha256':report['app_sha256']}))
