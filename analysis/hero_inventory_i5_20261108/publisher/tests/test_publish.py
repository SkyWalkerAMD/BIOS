"""Execute the C coordinator with actual local identity/catalogue fixtures.
The responder is a deterministic model, not a BMC or transport simulator.
"""
from pathlib import Path
import copy,ctypes as c,hashlib,json,unittest,zlib
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[2]
SYSTEM='/redfish/v1/Systems/Self';CHASSIS='/redfish/v1/Chassis/Self';NONE=0xffffffff
def enc(x):return json.dumps(x,separators=(',',':'),ensure_ascii=True).encode()
class Resource(c.Structure):
 _fields_=[(k,c.c_uint32) for k in ('kind','parent_index','post_to_collection','reserved')]+[('member_uri',c.c_char*192),('collection_uri',c.c_char*192),('body',c.c_void_p),('body_bytes',c.c_uint32),('body_crc32',c.c_uint32)]
class Link(c.Structure):_fields_=[('field',c.c_uint32),('parent_index',c.c_uint32),('member_uri',c.c_char*192)]
class Plan(c.Structure):
 _fields_=[(k,c.c_uint32) for k in ('version','resource_count','link_count','source_crc32','hardware_crc32')]+[('system_uri',c.c_char*192),('chassis_uri',c.c_char*192),('resources',Resource*320),('links',Link*640)]
class Request(c.Structure):
 _fields_=[(k,c.c_uint32) for k in ('sequence','method','resource_index','body_bytes')]+[(k,c.c_void_p) for k in ('uri','body','if_match')]+[('if_match_bytes',c.c_uint32)]
class Response(c.Structure):
 _fields_=[(k,c.c_uint32) for k in ('sequence','transport_result','http_status','body_bytes')]+[(k,c.c_void_p) for k in ('body','etag','location')]+[('etag_bytes',c.c_uint32),('location_bytes',c.c_uint32)]
class State(c.Structure):_fields_=[(k,c.c_uint32) for k in ('version','result','phase','inflight','requests','writes','verified','indexed','current_resource','current_link_group','last_http','unknown_write','resource_count','link_count','extra_collection_members','reserved')]
lib=c.CDLL(str(BASE/'build/publish.dll'))
lib.HeroInventoryPublishInit.argtypes=[c.c_void_p,c.c_uint32,c.POINTER(Plan),c.c_uint64,c.c_uint32,c.c_uint32]
lib.HeroInventoryPublishNext.argtypes=[c.c_void_p,c.c_uint64,c.c_int,c.c_uint32,c.POINTER(Request)]
lib.HeroInventoryPublishAccept.argtypes=[c.c_void_p,c.POINTER(Response)]
lib.HeroInventoryPublishAuthorize.argtypes=[c.c_void_p,c.POINTER(Request),c.c_uint64,c.c_int,c.c_uint32]
lib.HeroInventoryPublishState.argtypes=[c.c_void_p,c.POINTER(State)]
def official(name):return json.loads((ROOT/'analysis/hero_ipmi_complete_live_20261108/responses'/name).read_text())['result']['body']
root=json.loads((ROOT/'analysis/hero_ipmi_continued_live_20261108/responses/147-get.json').read_text())['result']['body']

class Fixture:
 def __init__(self,full=True):
  self.plan=Plan();self.plan.version=1;self.plan.source_crc32=0x97f9e765;self.plan.hardware_crc32=0x12345;self.plan.system_uri=SYSTEM.encode();self.plan.chassis_uri=CHASSIS.encode();self.buffers=[];self.rows=[];self.links=[]
  legacy=ROOT/'analysis/hero_inventory_20261108/hero71-legacy'
  self.add(1,SYSTEM,'/redfish/v1/Systems',json.loads((legacy/'system.patch.json').read_text()),NONE,0)
  for name,kind,collection in [('DevType1_CPU0',2,'Processors')]+[(f'DevType2_DIMM{i}',3,'Memory') for i in range(4)]:self.add(kind,SYSTEM+'/'+collection+'/'+name,SYSTEM+'/'+collection,json.loads((legacy/(name+'.post.json')).read_text()),0,1)
  if full:
   hpc=json.loads((ROOT/'analysis/hero_hardware_source_20261108/live-fixture-catalog.json').read_text())
   for item in hpc['items']:
    kind={1:4,2:5,3:6}[item['kind']];parent=NONE if kind==4 else (self.index(item['collection'].rsplit('/PCIeFunctions',1)[0]) if kind==5 else 0)
    self.add(kind,item['uri'],item['collection'],item['body'],parent,item['method']==2)
   for item in hpc['merge_only_additions']:
    self.link({1:1,2:2,3:4,4:3}[item['kind']],self.index(item['parent']),item['member'])
   hsc=json.loads((ROOT/'analysis/hero_pcie_catalog_20261108/sata/hero71-sata-proposal.json').read_text())
   for item in hsc['items']:self.add(7,item['uri'],item['collection'],item['body'],self.index(item['collection'].rsplit('/Drives',1)[0]),0)
   for item in hsc['merge_only_additions']:self.link({1:5,2:6,3:7}[item['kind']],self.index(item['parent']),item['member'])
  self.plan.resource_count=len(self.rows);self.plan.link_count=len(self.links)
 def index(self,uri):return next(i for i,r in enumerate(self.rows) if r['uri']==uri)
 def add(self,kind,uri,collection,body,parent,post):
  raw=enc(body);buf=c.create_string_buffer(raw);self.buffers.append(buf);idx=len(self.rows);r=self.plan.resources[idx]
  r.kind=kind;r.parent_index=parent;r.post_to_collection=post;r.member_uri=uri.encode();r.collection_uri=collection.encode();r.body=c.addressof(buf);r.body_bytes=len(raw);r.body_crc32=zlib.crc32(raw);self.rows.append(dict(kind=kind,uri=uri,collection=collection,body=body,parent=parent,post=post))
 def link(self,field,parent,member):
  l=self.plan.links[len(self.links)];l.field=field;l.parent_index=parent;l.member_uri=member.encode();self.links.append(dict(field=field,parent=parent,member=member))

class Server:
 def __init__(self,f,empty=False,all_existing=False,stale=False):
  self.f=f;self.objects={SYSTEM:official('011-get.json'),CHASSIS:official('012-get.json')};self.version=1;self.posts={};self.calls=[];self.stale=stale;self.cache={};self.mutate=None
  if empty:
   for key in ('Model','Manufacturer','BiosVersion','UUID'):self.objects[SYSTEM][key]=''
  else:
   for row in f.rows[1:6]:self.objects[row['uri']]={**copy.deepcopy(row['body']),'@odata.id':row['uri'],'@odata.etag':'"1"'}
  if all_existing:
   for row in f.rows[6:]:self.objects[row['uri']]={**copy.deepcopy(row['body']),'@odata.id':row['uri'],'@odata.etag':'"1"'}
   for item in f.links:
    parent=f.rows[item['parent']]['uri'];key={1:'PCIeDevices',2:'PCIeFunctions',3:'Chassis',4:'PCIeFunctions',5:'Drives',6:'Drives',7:'StorageControllers'}[item['field']]
    obj=self.objects[parent];dest=obj.setdefault('Links',{}) if item['field'] in (3,4,6,7) else obj;dest.setdefault(key,[]).append({'@odata.id':item['member']})
  if stale:
   for row in f.rows[1:]:self.cache[row['collection']]=[]
 def collection(self,uri):
  ids=[r['uri'] for r in self.f.rows[1:] if r['kind']!=7 and r['collection']==uri and r['uri'] in self.objects]
  return {'@odata.id':uri,'@odata.etag':f'"{self.version}"','Members':[{'@odata.id':x} for x in self.cache.get(uri,ids)],'Members@odata.count':len(self.cache.get(uri,ids))}
 def execute(self,req):
  uri=c.string_at(req.uri).decode();body=json.loads(c.string_at(req.body,req.body_bytes)) if req.body_bytes else None;tag=c.string_at(req.if_match,req.if_match_bytes).decode() if req.if_match_bytes else None
  record=dict(method=req.method,uri=uri,body=body,if_match=tag);self.calls.append(record)
  if self.mutate:
   result=self.mutate(self,record)
   if result:return result
  if req.method==0:
   if uri=='/redfish/v1/':return 200,root,None,0
   if uri=='/redfish/v1/Systems':return 200,{'@odata.id':uri,'Members':[{'@odata.id':SYSTEM}],'Members@odata.count':1},None,0
   if uri=='/redfish/v1/GlobalLuaTables':
    paths=sorted(set(r['collection'] for r in self.f.rows[1:] if r['kind']!=7));return 200,{'@odata.id':uri,'@odata.etag':f'"{self.version}"','Members':[{'@odata.id':x} for x in paths],'Members@odata.count':len(paths)},None,0
   if uri in self.objects:return 200,self.objects[uri],None,0
   if any(uri==r['collection'] and r['kind']!=7 for r in self.f.rows[1:]):return 200,self.collection(uri),None,0
   return 404,{'error':{'code':'ResourceMissingAtURI'}},None,0
  if req.method==1:
   row=self.f.rows[req.resource_index];assert uri==(row['collection'] if row['post'] else row['uri']);assert body==row['body'];assert row['uri'] not in self.objects
   self.posts[row['uri']]=self.posts.get(row['uri'],0)+1;self.objects[row['uri']]={**copy.deepcopy(body),'@odata.id':row['uri'],'@odata.etag':f'"{self.version}"'};return 201,{},row['uri'],0
  if req.method==2:
   assert uri in self.objects;assert tag==self.objects[uri]['@odata.etag'];self.objects[uri].update(copy.deepcopy(body));self.version+=1;self.objects[uri]['@odata.etag']=f'"{self.version}"';return 204,None,None,0
  if req.method==3:
   assert uri=='/redfish/v1/GlobalLuaTables' and tag==f'"{self.version}"';assert set(body)=={'Prefixes'} and len(body['Prefixes'])==1
   key=body['Prefixes'][0];assert key.startswith('Redfish:') and key.endswith(':SRK');path='/redfish/v1/'+key[8:-4].replace(':','/');assert path in self.cache;del self.cache[path];return 204,None,None,0
  raise AssertionError(req.method)

class Engine:
 def __init__(self,f,budget=8192,ms=600000):
  self.f=f;self.ctx=c.create_string_buffer(lib.HeroInventoryPublishContextSize());self.init=lib.HeroInventoryPublishInit(self.ctx,len(self.ctx),c.byref(f.plan),71,budget,ms);self.t=0;self.result=self.init
 def state(self):s=State();assert lib.HeroInventoryPublishState(self.ctx,c.byref(s))==0;return s
 def next(self,source=1,epoch=71):
  req=Request();self.t+=1;result=lib.HeroInventoryPublishNext(self.ctx,epoch,source,self.t,c.byref(req));return result,req
 def respond(self,req,response):
  status,body,location,transport=response;raw=enc(body) if body is not None else b'';buf=c.create_string_buffer(raw);loc=c.create_string_buffer(location.encode()) if location else None
  reply=Response(req.sequence,transport,status,len(raw),c.addressof(buf),0,c.addressof(loc) if loc else 0,0,len(location) if location else 0)
  self.result=lib.HeroInventoryPublishAccept(self.ctx,c.byref(reply));return self.result
 def run(self,server):
  assert self.init==0,self.init
  for _ in range(8192):
   status,req=self.next()
   if status:return status
   duplicate=Request();assert lib.HeroInventoryPublishNext(self.ctx,71,1,self.t,c.byref(duplicate))==1 and not duplicate.uri
   assert lib.HeroInventoryPublishAuthorize(self.ctx,c.byref(req),71,1,self.t)==0
   status=self.respond(req,server.execute(req))
   if status:return status
  raise AssertionError('Unbounded state machine')

class Tests(unittest.TestCase):
 def test_pending_request_authorization_is_exact_and_fresh(self):
  for mode,expected in [('method',22),('uri',22),('body',22),('sequence',22),('source',12),('epoch',12),('deadline',13),('mutable_uri',12)]:
   f=Fixture(False);e=Engine(f);ret,req=e.next();self.assertEqual(ret,0);epoch=71;source=1;elapsed=e.t
   if mode=='method':req.method=2
   elif mode=='uri':req.uri=c.addressof(c.create_string_buffer(b'/redfish/v1/Bios'))
   elif mode=='body':req.body_bytes=1
   elif mode=='sequence':req.sequence+=1
   elif mode=='source':source=0
   elif mode=='epoch':epoch=72
   elif mode=='deadline':elapsed=600000
   else:c.memmove(req.uri,b'/Redfish/v1/',12)
   self.assertEqual(lib.HeroInventoryPublishAuthorize(e.ctx,c.byref(req),epoch,source,elapsed),expected)
   self.assertEqual(e.next()[0],expected)
 def test_actual_core_baseline_no_reposts(self):
  f=Fixture(False);s=Server(f);e=Engine(f);self.assertEqual(e.run(s),2);self.assertEqual(e.state().writes,0);self.assertEqual(e.state().verified,6)
 def test_actual_all_catalogues_create_and_merge(self):
  f=Fixture();s=Server(f);e=Engine(f);self.assertEqual(e.run(s),2);self.assertEqual(e.state().verified,len(f.rows));self.assertTrue(all(n==1 for n in s.posts.values()));self.assertEqual(len(s.posts),len(f.rows)-6)
  self.assertEqual(s.objects[SYSTEM]['Links'],official('011-get.json')['Links'])
  self.assertFalse(any(x['method']==3 for x in s.calls));(BASE/'tests/actual-plan-success.json').write_text(json.dumps({'resources':len(f.rows),'links':len(f.links),'requests':e.state().requests,'writes':e.state().writes,'posts':len(s.posts),'state_result':2,'scope':'C engine; actual catalogue fixtures; deterministic responder, no hardware'},indent=2)+'\n')
 def test_stale_index_one_exact_cache_refresh_not_post_replay(self):
  f=Fixture();s=Server(f,all_existing=True,stale=True);e=Engine(f);self.assertEqual(e.run(s),2);self.assertFalse(s.posts)
  clears=[x for x in s.calls if x['method']==3];self.assertEqual(len(clears),len(set(r['collection'] for r in f.rows[1:] if r['kind']!=7)))
  self.assertTrue(all(set(x['body'])=={'Prefixes'} and len(x['body']['Prefixes'])==1 for x in clears))
 def test_empty_system_is_fresh_etag_patched_and_verified(self):
  f=Fixture(False);s=Server(f,empty=True);e=Engine(f);self.assertEqual(e.run(s),2);self.assertEqual(s.objects[SYSTEM]['UUID'],f.rows[0]['body']['UUID'])
 def test_actual_cold_reset_empty_system_and_cpu_summary(self):
  f=Fixture(False);s=Server(f,empty=True);s.objects[SYSTEM]=official('896-get.json');e=Engine(f)
  self.assertEqual(e.run(s),2);self.assertEqual(len(s.posts),5)
  writes=[x for x in s.calls if x['method']==2]
  self.assertEqual(len(writes),2);self.assertEqual(set(writes[1]['body']),{'ProcessorSummary'})
  self.assertEqual(s.objects[SYSTEM]['ProcessorSummary']['Count'],1)
  self.assertEqual(s.objects[SYSTEM]['ProcessorSummary']['Model'],f.rows[1]['body']['Model'])
 def test_link_arrays_can_reorder_without_losing_existing_members(self):
  f=Fixture();s=Server(f)
  prior='/redfish/v1/Chassis/Self/PCIeDevices/OtherKnownDevice'
  s.objects[SYSTEM]['PCIeDevices']=[{'@odata.id':prior,'Oem':{'Origin':'existing'}}]
  def reorder(srv,request):
   if request['method']==0 and request['uri'] in srv.objects:
    obj=copy.deepcopy(srv.objects[request['uri']])
    for parent in (obj,obj.get('Links',{})):
     for k,v in parent.items():
      if isinstance(v,list) and v and isinstance(v[0],dict) and '@odata.id' in v[0]:parent[k]=list(reversed(v))
    return 200,obj,None,0
  s.mutate=reorder;e=Engine(f);self.assertEqual(e.run(s),2)
  kept=next(x for x in s.objects[SYSTEM]['PCIeDevices'] if x['@odata.id']==prior)
  self.assertEqual(kept['Oem'],{'Origin':'existing'})
 def test_link_readback_rejects_duplicate_or_removed_prior_member(self):
  for mode in ('duplicate','removed'):
   f=Fixture();s=Server(f);prior='/redfish/v1/Chassis/Self/PCIeDevices/OtherKnownDevice'
   s.objects[SYSTEM]['PCIeDevices']=[{'@odata.id':prior}]
   def mutate(srv,request):
    obj=srv.objects[SYSTEM]
    if request['method']==0 and request['uri']==SYSTEM and len(obj.get('PCIeDevices',[]))>1:
     obj=copy.deepcopy(obj)
     if mode=='duplicate':obj['PCIeDevices'].append(copy.deepcopy(obj['PCIeDevices'][0]))
     else:obj['PCIeDevices']=[x for x in obj['PCIeDevices'] if x['@odata.id']!=prior]
     return 200,obj,None,0
   s.mutate=mutate;e=Engine(f);self.assertEqual(e.run(s),18)
   self.assertTrue(all(n==1 for n in s.posts.values()))
 def test_changed_etag_patch_rejection_is_not_retried(self):
  f=Fixture(False);s=Server(f,empty=True)
  s.mutate=lambda srv,r:(412,{'error':{'code':'PreconditionFailed'}},None,0) if r['method']==2 else None
  e=Engine(f);self.assertEqual(e.run(s),20);self.assertEqual(e.next()[0],20)
  self.assertEqual(sum(x['method']==2 for x in s.calls),1)
 def test_other_system_identity_never_overwritten(self):
  for k,v in [('UUID','00000000-0000-0000-0000-000000000001'),('Model','Other board'),('Manufacturer','Other vendor'),('BiosVersion','Other BIOS')]:
   f=Fixture(False);s=Server(f);s.objects[SYSTEM][k]=v;e=Engine(f);self.assertEqual(e.run(s),18);self.assertFalse(any(x['method'] for x in s.calls))
 def test_existing_object_mismatch_refused(self):
  f=Fixture(False);s=Server(f);s.objects[f.rows[1]['uri']]['TotalCores']=99;e=Engine(f);self.assertEqual(e.run(s),18);self.assertFalse(s.posts)
 def test_source_and_budget_stop(self):
  for kwargs,source,expect in [({},0,12),({'budget':8},1,13),({'ms':1000},1,13)]:
   f=Fixture();e=Engine(f,**kwargs);s=Server(f)
   if source==0:self.assertEqual(e.next(source=0)[0],expect)
   elif 'ms' in kwargs:e.t=999;self.assertEqual(e.next()[0],expect)
   else:self.assertEqual(e.run(s),expect)
   self.assertNotEqual(e.next()[0],0)
 def test_transport_unknown_and_http_failure_never_replay(self):
  for outcome in [(0,None,None,18),(500,{'error':{}},None,0),(202,{},None,0),(201,{},'/wrong',0)]:
   f=Fixture();s=Server(f);s.mutate=lambda srv,r:outcome if r['method']==1 else None;e=Engine(f);self.assertEqual(e.run(s),20);self.assertEqual(e.state().unknown_write,1)
   n=len(s.calls);self.assertEqual(e.next()[0],20);self.assertEqual(len(s.calls),n);self.assertEqual(sum(x['method']==1 for x in s.calls),1)
 def test_plan_and_body_changes_refused(self):
  f=Fixture(False);e=Engine(f);f.plan.resources[1].member_uri=b'/redfish/v1/Systems/Self/Bios/Settings';self.assertEqual(e.next()[0],12)
  f=Fixture(False);e=Engine(f);f.buffers[1][0]=ord('[');self.assertEqual(e.next()[0],12)
 def test_post_ack_without_object_stops(self):
  f=Fixture();s=Server(f);s.mutate=lambda srv,r:(201,{},f.rows[6]['uri'],0) if r['method']==1 else None;e=Engine(f);self.assertEqual(e.run(s),20);self.assertEqual(sum(x['method']==1 for x in s.calls),1)
 def test_summary_setting_and_route_injection_rejected(self):
  f=Fixture(False);f.plan.resources[1].collection_uri=(SYSTEM+'/Bios').encode();self.assertEqual(Engine(f).init,11)
  f=Fixture(False);raw=enc({'Model':'X','Boot':{'BootSourceOverrideTarget':'Pxe'}});buf=c.create_string_buffer(raw);f.buffers.append(buf);r=f.plan.resources[0];r.body=c.addressof(buf);r.body_bytes=len(raw);r.body_crc32=zlib.crc32(raw);self.assertEqual(Engine(f).init,11)

if __name__=='__main__':unittest.main()
