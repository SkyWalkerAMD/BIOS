"""Run all three native catalogue builders on parent-acquired real captures,
then flatten their actual C outputs through the native publish-plan builder.
No live collection, network request, firmware load, or frozen-source edits.
"""
from pathlib import Path
import ctypes as C, hashlib, importlib.util, json, sys
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[2]
sys.path.insert(0,str(BASE/'tests'))
import test_publish as pub
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
sm=module('current_catalog_fixture',ROOT/'analysis/hero_inventory_i5_20261108/capture_fix/tests/test_dynamic_catalog.py')
sa=module('current_sata_fixture',ROOT/'analysis/hero_pcie_catalog_20261108/sata/test_sata.py')
lib=C.CDLL(str(ROOT/'analysis/hero_inventory_i5_20261108/capture_fix/build/catalog.dll'))
lib.HeroInventoryBuild.argtypes=[C.c_void_p,C.c_uint32,C.c_uint8,C.c_uint8,C.c_void_p,C.c_void_p]
raw=sm.block((ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-i1-current.TXT').read_text('ascii'),'TABLE')
buf=C.create_string_buffer(raw);catalog=sm.Catalog();scratch=C.create_string_buffer(lib.HeroInventoryScratchSize())
assert lib.HeroInventoryBuild(buf,len(raw),3,5,C.byref(catalog),scratch)==0
source,result,records,pci=sa.offline_typed_fixture(ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-i4-pcie-storage.TXT')
code,sata,_,_=sa.invoke(source,result,records,pci);assert code==0
pub.lib.HeroInventoryPlanBuild.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_char_p,C.c_char_p,C.c_void_p]
cases=[]
def rows_from(plan):
 rows=[]
 for r in plan.resources[:plan.resource_count]:
  rows.append({'kind':r.kind,'parent':r.parent_index,'post':r.post_to_collection,'uri':r.member_uri.decode(),'collection':r.collection_uri.decode(),'body':json.loads(C.string_at(r.body,r.body_bytes))})
 links=[{'field':l.field,'parent':l.parent_index,'member':l.member_uri.decode()} for l in plan.links[:plan.link_count]]
 return rows,links
for side in ('left','right'):
 guard=sa.pc.Guard(C.sizeof(pub.Plan),side=side)
 try:
  before=(bytes(catalog),bytes(pci),bytes(sata))
  assert pub.lib.HeroInventoryPlanBuild(C.byref(catalog),C.byref(pci),C.byref(sata),pub.SYSTEM.encode(),pub.CHASSIS.encode(),guard.address)==0
  assert before==(bytes(catalog),bytes(pci),bytes(sata))
  plan=pub.Plan.from_buffer_copy(guard.read());rows,links=rows_from(plan);f=pub.Fixture()
  assert rows==f.rows and links==f.links and plan.source_crc32==0x8b120398
  f.plan=plan;f.rows=rows;f.links=links;e=pub.Engine(f);server=pub.Server(f,empty=True);server.objects[pub.SYSTEM]=pub.official('896-get.json')
  assert e.run(server)==2 and e.state().verified==69
  cases.append({'name':'three_actual_native_catalogues_to_native_plan_'+side,'passed':True,'resources':len(rows),'links':len(links),'requests':e.state().requests})
 finally:guard.close()
def bad(name,change):
 cc=sm.Catalog.from_buffer_copy(bytes(catalog));pp=type(pci).from_buffer_copy(bytes(pci));ss=type(sata).from_buffer_copy(bytes(sata));out=pub.Plan();change(cc,pp,ss)
 ret=pub.lib.HeroInventoryPlanBuild(C.byref(cc),C.byref(pp),C.byref(ss),pub.SYSTEM.encode(),pub.CHASSIS.encode(),C.byref(out))
 assert ret==11 and out.version==0 and out.resource_count==out.link_count==0,(name,ret)
 cases.append({'name':name,'passed':True})
bad('invalid_smbios',lambda s,p,a:setattr(s,'valid',0))
bad('missing_cpu',lambda s,p,a:setattr(s,'cpu_count',0))
bad('smbios_item_pool_offset',lambda s,p,a:setattr(s.items[0],'json_offset',1))
bad('smbios_item_pool_bound',lambda s,p,a:setattr(s.items[0],'json_bytes',0xffffffff))
bad('invalid_pci',lambda s,p,a:setattr(p,'valid',0))
bad('invalid_pci_method',lambda s,p,a:setattr(p.items[0],'method',2))
bad('invalid_pci_link_parent',lambda s,p,a:setattr(p.links[0],'parent_uri',b'/redfish/v1/Systems/Other'))
bad('invalid_sata',lambda s,p,a:setattr(a,'valid',0))
bad('invalid_sata_method',lambda s,p,a:setattr(a.items[0],'method',2))
bad('invalid_sata_link_flag',lambda s,p,a:setattr(a.links[0],'flags',0))
# Overlap is rejected before touching the actual native source.
before=bytes(catalog)
assert pub.lib.HeroInventoryPlanBuild(C.byref(catalog),None,None,pub.SYSTEM.encode(),pub.CHASSIS.encode(),C.byref(catalog))==10
assert bytes(catalog)==before;cases.append({'name':'overlap_leaves_source_intact','passed':True})
out=pub.Plan();assert pub.lib.HeroInventoryPlanBuild(C.byref(catalog),None,None,pub.SYSTEM.encode(),pub.CHASSIS.encode(),C.byref(out))==0 and out.resource_count==6 and out.link_count==0
cases.append({'name':'optional_hardware_omitted_not_deleted','passed':True})
report={'passed':True,'cases':len(cases),'results':cases,'no_hardware_or_network':True,'sources':{'smbios_raw_sha256':hashlib.sha256(raw).hexdigest(),'publish_dll_sha256':hashlib.sha256((BASE/'build/publish.dll').read_bytes()).hexdigest()},'scope':'Parent-acquired local captures -> native C HIC/HPC/HSC -> native plan -> deterministic responder.'}
(BASE/'tests/native-plan-catalogues.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='results'}))
