"""Native DLL/guard-page tests. I4 fixtures checked against the independent
Python observation decoder. No network, device, firmware or settings access.
"""
from pathlib import Path
import ctypes as C,json,hashlib,struct,zlib,random,sys,importlib.util
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
U32=C.c_uint32;U64=C.c_uint64;U16=C.c_uint16;U8=C.c_uint8
class Record(C.Structure):
 _fields_=[('source_index',U32),('flags',U32),('config_crc32',U32),('path_crc32',U32),('path_bytes',U32),('reserved',U32),('source_handle',U64),('segment',U16),('bus',U8),('device',U8),('function',U8),('pad',U8*3),('config',U8*256),('path',U8*1024)]
class Routes(C.Structure):_fields_=[('system',C.c_void_p),('chassis',C.c_void_p),('system_bytes',U32),('chassis_bytes',U32)]
class Capture(C.Structure):_fields_=[('version',U32),('pci_declared',U32),('pci_captured',U32),('pci_complete',U32),('pci_truncated',U32),('reserved',U32),('pci_status',U64),('cleanup_status',U64),('source_crc32',U32),('source_bytes',U32)]
class Item(C.Structure):
 _fields_=[(x,U32) for x in ('kind','method','source_index','device_index','config_crc32','path_crc32','json_offset','json_bytes')]+[('segment',U16),('bus',U8),('device',U8),('function',U8),('reserved',U8*3),('collection_uri',C.c_char*192),('member_uri',C.c_char*192)]
class Link(C.Structure):_fields_=[(x,U32) for x in ('kind','flags','source_item','reserved')]+[('parent_uri',C.c_char*192),('member_uri',C.c_char*192)]
class Catalog(C.Structure):
 _fields_=[(x,U32) for x in ('version','valid','result','error_index','source_crc32','source_bytes','item_count','device_count','function_count','storage_count','link_count','json_bytes','warnings','reserved')]+[('items',Item*224),('links',Link*512),('json',C.c_char*131072)]
lib=C.CDLL(str(OUT/'catalog.dll'))
lib.HeroPcieCatalogBuild.argtypes=[C.c_void_p,U32,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p];lib.HeroPcieCatalogBuild.restype=C.c_int
for name in ('HeroPcieCatalogSize','HeroPcieScratchSize','HeroPcieRecordSize'):getattr(lib,name).restype=U32
assert lib.HeroPcieCatalogSize()==C.sizeof(Catalog) and lib.HeroPcieRecordSize()==C.sizeof(Record)
k32=C.WinDLL('kernel32',use_last_error=True)
k32.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,U32,U32];k32.VirtualAlloc.restype=C.c_void_p
k32.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,U32,C.POINTER(U32)];k32.VirtualProtect.restype=C.c_int
k32.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,U32];k32.VirtualFree.restype=C.c_int
class Guard:
 def __init__(self,n,data=None,side='right'):
  self.n=n;self.middle=(n+4095)&~4095;self.base=k32.VirtualAlloc(None,self.middle+8192,0x3000,4);assert self.base
  old=U32();assert k32.VirtualProtect(self.base,4096,1,C.byref(old));assert k32.VirtualProtect(self.base+4096+self.middle,4096,1,C.byref(old))
  self.address=self.base+4096+(self.middle-n if side=='right' else 0)
  C.memset(self.address,0xA5,n)
  if data is not None:assert len(data)==n;C.memmove(self.address,data,n)
 def read(self):return C.string_at(self.address,self.n)
 def close(self):
  if self.base:assert k32.VirtualFree(self.base,0,0x8000);self.base=None
 def __del__(self):self.close()

def record(index,bus=0,device=0,function=0,segment=0,header=0,klass=0x060000):
 r=Record();r.source_index=index;r.flags=7;r.source_handle=0x1000+index*16;r.segment=segment;r.bus=bus;r.device=device;r.function=function
 p=bytearray(256);struct.pack_into('<HH',p,0,0x1234,0x5678);p[8]=7;p[9:12]=klass.to_bytes(3,'little');p[14]=header;p[44:48]=b'\x11\x22\x33\x44';r.config[:]=p;r.config_crc32=zlib.crc32(p)
 path=bytes.fromhex('02010c00d041030a')+struct.pack('<I',segment*256+bus)+bytes([1,1,6,0,function,device])+b'\x7f\xff\x04\0'
 r.path[:len(path)]=path;r.path_bytes=len(path);r.path_crc32=zlib.crc32(path);return r
def invoke(records,routes=None,capture=None,side='right'):
 raw=b''.join(bytes(x) for x in records);n=len(records)
 # Empty captures still point to a mapped byte but count is zero.
 rg=Guard(max(len(raw),1),raw or b'\0',side);out=Guard(C.sizeof(Catalog),side=side);scratch=Guard(lib.HeroPcieScratchSize(),side=side)
 system,chassis=routes or (b'/redfish/v1/Systems/Self',b'/redfish/v1/Chassis/Self')
 sg,cg=Guard(max(len(system),1),system or b'\0',side),Guard(max(len(chassis),1),chassis or b'\0',side)
 rt=Routes(sg.address,cg.address,len(system),len(chassis));cap=capture or Capture(1,n,n,1,0,0,0,0,0x12345678,1000)
 rtg,capg=Guard(C.sizeof(rt),bytes(rt),side),Guard(C.sizeof(cap),bytes(cap),side)
 try:
  status=lib.HeroPcieCatalogBuild(rg.address,n,rtg.address,capg.address,out.address,scratch.address)
  assert rg.read()==(raw or b'\0') and rtg.read()==bytes(rt) and capg.read()==bytes(cap)
  result=Catalog.from_buffer_copy(out.read());items=[];links=[]
  if status==0:
   assert result.valid==1 and result.result==0
   for item in result.items[:result.item_count]:
    body=C.string_at(out.address+Catalog.json.offset+item.json_offset,item.json_bytes)
    assert C.string_at(out.address+Catalog.json.offset+item.json_offset+item.json_bytes,1)==b'\0'
    assert len(body)<=8192
    value=json.loads(body);uri=item.member_uri.decode();collection=item.collection_uri.decode()
    assert value['Id']==uri.rsplit('/',1)[1] and uri.startswith(collection+'/')
    items.append(dict(kind=item.kind,method=item.method,source_index=item.source_index,device_index=item.device_index,collection=collection,uri=uri,body=value))
   for link in result.links[:result.link_count]:
    assert link.flags==1 and link.source_item<result.item_count
    links.append(dict(kind=link.kind,parent=link.parent_uri.decode(),member=link.member_uri.decode(),merge_required=True))
  elif status not in (1,2):assert result.valid==0 and result.result==status
  return status,result,items,links
 finally:
  for g in (rg,out,scratch,sg,cg,rtg,capg):g.close()

def from_i4(path):
 spec=importlib.util.spec_from_file_location('root_i4',ROOT/'analysis/hero_ipmi_complete_live_20261108/decode_i4_inventory.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 raw=path.read_bytes();groups,_=mod.parse_catalog(raw);decoded=mod.decode(raw);pci=groups['PCI'];assert int(pci['ENUM_STATUS'],16)==0 and int(pci['ENUM_COUNT'],16)==len(pci['records'])
 records=[]
 for x,ob in zip(pci['records'],decoded['pci']):
  assert ob['valid'];r=Record();r.source_index=ob['index'];r.source_handle=int(x['HANDLE'],16);r.flags=7
  r.segment=int(x['SEGMENT'],16);r.bus=int(x['BUS'],16);r.device=int(x['DEVICE'],16);r.function=int(x['FUNCTION'],16)
  config=bytes.fromhex(x['CONFIG_HEX']);pathraw=bytes.fromhex(x['PATH_FIRST_HEX']);r.config[:]=config;r.config_crc32=int(x['CONFIG_CRC32'],16)
  r.path[:len(pathraw)]=pathraw;r.path_bytes=len(pathraw);r.path_crc32=zlib.crc32(pathraw);records.append(r)
 cap=Capture(1,len(records),len(records),1,0,0,0,0,zlib.crc32(raw),len(raw));return records,cap,decoded

def main():
 rows=[]
 def passed(name,extra=None):rows.append(dict(case=name,passed=True,**(extra or {})));print(name,'PASS',flush=True)
 for folder in ('vm','vm-nvme-first'):
  path=ROOT/'analysis/hero_pcie_collect_i4_20261108'/folder/'OVMF-PCIE-I4.TXT';records,cap,decoded=from_i4(path)
  for side in ('left','right'):
   status,cat,items,links=invoke(records,capture=cap,side=side);assert status==0 and cat.device_count==4 and cat.function_count==6 and cat.storage_count==2
   for item in items:
    ob=decoded['pci'][item['source_index']];value=item['body']
    assert not any(k in value for k in ('Health','Model','SerialNumber','PhysicalLocation','FunctionType','DeviceClass','DeviceType'))
    if item['kind']==2:
     for a,b in [('VendorId','vendor_id'),('DeviceId','device_id'),('ClassCode','class_code'),('RevisionId','revision_id')]:assert value[a]==ob[b]
     assert value['FunctionId']==records[item['source_index']].function
     assert ('SubsystemVendorId' in value)==(ob['header_type_raw']==0)
     if 'SubsystemVendorId' in value:assert value['SubsystemVendorId']==ob['subsystem_vendor_id'] and value['SubsystemId']==ob['subsystem_id']
    if item['kind']==3:assert value['StorageControllers']==[{'MemberId':'0','Name':value['Name'],'Status':{}}]
   assert all('Links' not in i['body'] for i in items)
   passed(folder+'_'+side+'_guard_pages',{'devices':cat.device_count,'functions':cat.function_count,'controllers':cat.storage_count,'links_proposed':cat.link_count})
  (OUT/(folder+'-catalog.json')).write_text(json.dumps({'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'items':items,'merge_only_additions':links,'not_published':True},indent=2)+'\n')
 for name,change,expected in [
  ('bad_config_crc',lambda r:setattr(r,'config_crc32',1),4),('bad_path_crc',lambda r:setattr(r,'path_crc32',1),4),
  ('partial_flags',lambda r:setattr(r,'flags',3),5),('zero_handle',lambda r:setattr(r,'source_handle',0),5),
  ('path_bound',lambda r:setattr(r,'path_bytes',1025),3),('function_range',lambda r:setattr(r,'function',8),5),('device_range',lambda r:setattr(r,'device',32),5),
  ('index_range',lambda r:setattr(r,'source_index',1),5),('reserved',lambda r:setattr(r,'reserved',1),5)]:
  r=record(0);change(r);assert invoke([r])[0]==expected;passed(name)
 for name,field,value in [('truncated','pci_truncated',1),('incomplete','pci_complete',0),('count_mismatch','pci_declared',2),('status_error','pci_status',0x8000000000000007),('cleanup_error','cleanup_status',0x8000000000000007)]:
  cap=Capture(1,1,1,1,0,0,0,0,0,100);setattr(cap,field,value);assert invoke([record(0)],capture=cap)[0]==6;passed(name)
 for field in ('source_handle','source_index'):
  a,b=record(0),record(1,device=1);setattr(b,field,getattr(a,field));assert invoke([a,b])[0]==7;passed('duplicate_'+field)
 a,b=record(0),record(1);assert invoke([a,b])[0]==7;passed('duplicate_bdf')
 a,b=record(0),record(1,bus=1);b.path[:]=a.path[:];b.path_crc32=a.path_crc32;assert invoke([a,b])[0]==7;passed('duplicate_path')
 for name,raw in [('missing_end',bytes.fromhex('010106000000')),('multi_instance',bytes.fromhex('0101060000007f0104007fff0400')),('zero_node_length',bytes.fromhex('010100007fff0400')),('wrong_final_function',bytes.fromhex('0101060001007fff0400')),('media_child',bytes.fromhex('010106000000040104007fff0400'))]:
  r=record(0);r.path[:len(raw)]=raw;r.path_bytes=len(raw);r.path_crc32=zlib.crc32(raw);assert invoke([r])[0]==8;passed(name)
 for name,mut in [('vendor_zero',lambda p:p.__setitem__(slice(0,2),b'\0\0')),('vendor_ffff',lambda p:p.__setitem__(slice(0,2),b'\xff\xff')),('cap_cycle',lambda p:(p.__setitem__(6,16),p.__setitem__(52,64),p.__setitem__(64,1),p.__setitem__(65,64)))]:
  r=record(0);p=bytearray(r.config);mut(p);r.config[:]=p;r.config_crc32=zlib.crc32(p);assert invoke([r])[0]==9;passed(name)
 for system in (b'/redfish/v1/Systems/../X',b'/redfish/v1/Systems/..',b'/redfish/v1/Systems/%53elf',b'/redfish/v1/Systems/X?x=1',b'/redfish/v1/Systems/X\0Y',b'/redfish/v1/Systems/' + b'X'*65):
  assert invoke([record(0)],routes=(system,b'/redfish/v1/Chassis/Self'))[0]==10
 passed('route_segment_allowlist')
 r=record(0,header=1);status,catalog,items,_=invoke([r]);assert not any('SubsystemVendorId' in i['body'] for i in items);passed('type1_omits_subsystem_fields')
 records=[record(i,bus=i//64,device=(i//2)%32,function=i%2) for i in range(128)]
 status,cat,items,links=invoke(records);assert status==0 and (cat.device_count,cat.function_count)==(64,128) and cat.json_bytes<=131072;passed('maximum_128_functions_64_devices',{'json_bytes':cat.json_bytes,'catalog_bytes':C.sizeof(Catalog)})
 assert invoke(list(reversed(records)))[2:]==(items,links);passed('input_order_does_not_change_catalogue')
 assert invoke([record(i,bus=i//32,device=i%32) for i in range(65)])[0]==11;passed('device_capacity_rejects_entire_catalog')
 assert invoke([record(i,bus=i//32,device=i%32,klass=0x010601) for i in range(33)])[0]==11;passed('controller_capacity_rejects_entire_catalog')
 assert invoke([],capture=Capture(1,0,0,1,0,0,0x800000000000000e,0,0,100))[0]==0;passed('empty_not_found_is_observation_no_deletes')
 rng=random.Random(73021)
 for i in range(1000):
  r=record(0);raw=bytearray(r.path[:r.path_bytes]);raw[rng.randrange(len(raw))]=rng.randrange(256);r.path[:len(raw)]=raw;r.path_crc32=zlib.crc32(raw);invoke([r],side='right')
 passed('1000_seeded_path_mutations_guard_pages')
 # Alias failure must not wipe source storage masquerading as an output.
 out=Guard(C.sizeof(Catalog));scratch=Guard(lib.HeroPcieScratchSize());system=C.create_string_buffer(b'/redfish/v1/Systems/Self');chassis=C.create_string_buffer(b'/redfish/v1/Chassis/Self')
 routes=Routes(C.addressof(system),C.addressof(chassis),len(system.value),len(chassis.value));cap=Capture(1,1,1,1,0,0,0,0,0,100)
 before=out.read();status=lib.HeroPcieCatalogBuild(out.address,1,C.byref(routes),C.byref(cap),out.address,scratch.address);assert status==2 and out.read()==before
 status=lib.HeroPcieCatalogBuild(None,1,C.byref(routes),C.byref(cap),out.address,scratch.address);assert status==1 and out.read()==before
 out.close();scratch.close();passed('argument_and_overlap_no_output_clobber')
 report={'all_passed':True,'count':len(rows),'cases':rows,'dll_sha256':hashlib.sha256((OUT/'catalog.dll').read_bytes()).hexdigest(),'struct_bytes':{'record':C.sizeof(Record),'catalog':C.sizeof(Catalog),'scratch':lib.HeroPcieScratchSize()},'limitations':['No resource has been sent to a BMC.','Current PCIe IDs use observed BDF and may change across boots.','Storage objects describe PCI class01 controllers only; no physical drives are emitted.']}
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL PASS',len(rows))
if __name__=='__main__':main()
