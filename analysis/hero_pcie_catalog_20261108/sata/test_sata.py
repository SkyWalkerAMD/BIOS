"""Native C + guard-page replay of verified I4 observations. No real IO."""
from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,struct,sys,zlib,random
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'analysis/hero_hardware_source_20261108'))
import abi_types as A
import test_live_fixture as live
pc=live.catalog
U32=C.c_uint32;U64=C.c_uint64;U16=C.c_uint16;U8=C.c_uint8
class Block(C.Structure):
 _fields_=[(x,U32) for x in ('source_index','path_bytes','path_crc32','media_bytes','media_crc32','reserved')]+[('source_handle',U64),('revision',U64),('path',U8*1024),('media',U8*48)]
class Disk(C.Structure):
 _fields_=[(x,U32) for x in ('source_index','path_bytes','path_crc32','identify_crc32')]+[('source_handle',U64),('path',U8*1024),('identify',U8*512)]
class Source(C.Structure):
 _fields_=[(x,U32) for x in ('version','rejected','block_seen','disk_seen','ata_count')]+[('reserved',U32*3),('blocks',Block*128),('ata',Disk*64)]
class Item(C.Structure):
 _fields_=[(x,U32) for x in ('method','disk_index','block_index','pci_index','path_crc32','identify_crc32','logical_sector_bytes','json_offset','json_bytes','reserved')]+[('capacity_bytes',U64),('source_handle',U64)]+[(x,U16) for x in ('segment','port','pmp','lun')]+[(x,U8) for x in ('bus','device','function','pad')]+[('collection_uri',C.c_char*192),('member_uri',C.c_char*192)]
class Link(C.Structure):_fields_=[(x,U32) for x in ('kind','flags','item_index','reserved')]+[('parent_uri',C.c_char*192),('member_uri',C.c_char*192)]
class Catalog(C.Structure):
 _fields_=[(x,U32) for x in ('version','valid','result','error_index','item_count','link_count','json_bytes','skipped')]+[('source_crc32',U32*3),('reserved',U32),('items',Item*32),('links',Link*96),('json',C.c_char*32768)]
lib=C.CDLL(str(OUT/'sata.dll'));lib.HeroSataSourceSize.restype=U32;lib.HeroSataCatalogSize.restype=U32
lib.HeroSataSourceInit.argtypes=[C.c_void_p];lib.HeroSataSourceInit.restype=C.c_int
lib.HeroSataVisit.argtypes=[C.c_void_p,C.c_void_p];lib.HeroSataVisit.restype=C.c_int
lib.HeroSataCatalogBuild.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,U32,C.c_void_p,C.c_void_p,C.c_void_p];lib.HeroSataCatalogBuild.restype=C.c_int
assert lib.HeroSataSourceSize()==C.sizeof(Source) and lib.HeroSataCatalogSize()==C.sizeof(Catalog)
class Replay(live.Replay):
 def __init__(self):
  super().__init__();self.sata_guard=pc.Guard(C.sizeof(Source));assert lib.HeroSataSourceInit(self.sata_guard.address)==0
 def visit(self,user,p):
  if super().visit(user,p):return 1
  s=lib.HeroSataVisit(self.sata_guard.address,p)
  if s:self.errors.append('SATA visitor '+str(s))
  return s
 def close(self):self.sata_guard.close();super().close()
def acquire():
 p=Replay()
 try:
  assert p.run()==0 and p.result.complete
  cap=A.Capture();assert live.base.lib.HeroHardwarePciCapture(C.byref(p.sink),C.byref(p.result),C.byref(cap))==0
  records=[pc.Record.from_buffer_copy(bytes(x)) for x in p.records]
  status,catalog,_,_=pc.invoke(records,capture=pc.Capture.from_buffer_copy(bytes(cap)));assert status==0
  return Source.from_buffer_copy(p.sata_guard.read()),A.Result.from_buffer_copy(bytes(p.result)),records,catalog
 finally:p.close()
def clone(x):return type(x).from_buffer_copy(bytes(x))
def invoke(source,result,records,catalog,side='right',system=b'/redfish/v1/Systems/Self',chassis=b'/redfish/v1/Chassis/Self'):
 guards=[pc.Guard(C.sizeof(source),bytes(source),side),pc.Guard(C.sizeof(result),bytes(result),side),pc.Guard(max(1,len(records)*C.sizeof(pc.Record)),b''.join(bytes(x) for x in records) or b'\0',side),pc.Guard(C.sizeof(catalog),bytes(catalog),side),pc.Guard(max(1,len(system)),system or b'\0',side),pc.Guard(max(1,len(chassis)),chassis or b'\0',side),pc.Guard(C.sizeof(Catalog),side=side)]
 try:
  s,r,p,c,sy,ch,out=guards;routes=pc.Routes(sy.address,ch.address,len(system),len(chassis));before=[g.read() for g in guards[:-1]]
  ret=lib.HeroSataCatalogBuild(s.address,r.address,p.address,len(records),c.address,C.byref(routes),out.address)
  assert [g.read() for g in guards[:-1]]==before
  obj=Catalog.from_buffer_copy(out.read());items=[];links=[]
  if not ret:
   assert obj.valid==1 and obj.result==0
   for it in obj.items[:obj.item_count]:
    body=C.string_at(out.address+Catalog.json.offset+it.json_offset,it.json_bytes);assert it.json_bytes<=1024
    assert C.string_at(out.address+Catalog.json.offset+it.json_offset+it.json_bytes,1)==b'\0'
    value=json.loads(body);assert value['Id']==it.member_uri.decode().rsplit('/',1)[-1]
    items.append(dict(method='POST_INSTANCE',uri=it.member_uri.decode(),collection=it.collection_uri.decode(),body=value,disk_index=it.disk_index,block_index=it.block_index,pci_index=it.pci_index,identify_crc32=f'{it.identify_crc32:08X}',path_crc32=f'{it.path_crc32:08X}',port=it.port,pmp=it.pmp,lun=it.lun,capacity_bytes=it.capacity_bytes,logical_sector_bytes=it.logical_sector_bytes))
   for li in obj.links[:obj.link_count]:assert li.flags==1;links.append(dict(kind=li.kind,merge_required=True,parent=li.parent_uri.decode(),member=li.member_uri.decode()))
  elif ret not in (1,2):assert obj.valid==0 and obj.result==ret
  return ret,obj,items,links
 finally:
  for g in guards:g.close()
def ata_mutate(s,change,checksum=True):
 p=bytearray(s.ata[0].identify);change(p)
 if checksum and p[510]==0xa5:p[511]=0;p[511]=(-sum(p))&255
 s.ata[0].identify[:]=p;s.ata[0].identify_crc32=zlib.crc32(p)
def media_mutate(s,change):
 b=s.blocks[3];p=bytearray(b.media[:b.media_bytes]);change(p);b.media[:len(p)]=p;b.media_crc32=zlib.crc32(p)
def offline_typed_fixture(path):
 raw=path.read_bytes();groups,_=live.decoder.parse_catalog(raw);decoded=live.decoder.decode(raw);assert not decoded['collection_partial'] and decoded['cleanup_status']=='0000000000000000'
 source=Source();assert lib.HeroSataSourceInit(C.byref(source))==0;result=A.Result();result.version=1;result.bytes=C.sizeof(result);result.complete=1
 records,cap,_=pc.from_i4(path);status,catalog,_,_=pc.invoke(records,capture=cap);assert status==0
 for gi,label in enumerate(('PCI','BLOCK','DISK')):
  xs=groups[label]['records'];g=result.groups[gi];g.kind=gi+1;g.limit=64 if gi==2 else 128;g.declared=g.captured=len(xs);g.complete=g.stable=1;g.valid_records=len(xs)
  g.source_bytes=len(raw);g.source_crc32=zlib.crc32(raw)
  if not gi:continue
  for x in xs:
   rr=A.Record();rr.version=1;rr.bytes=C.sizeof(rr);rr.kind=gi+1;rr.source_index=int(x['INDEX'],16);rr.source_handle=int(x['HANDLE'],16);rr.protocol_readable=rr.valid=1
   p=bytes.fromhex(x['PATH_FIRST_HEX']);assert int(x['PATH_STABLE'],16)==1 and len(p)==int(x['PATH_SECOND_BYTES'],16);pbuf=C.create_string_buffer(p)
   rr.path.valid=rr.path.stable=1;rr.path.first_bytes=rr.path.second_bytes=len(p);rr.path.first_crc32=rr.path.second_crc32=zlib.crc32(p);rr.path.first=rr.path.second=C.addressof(pbuf)
   if gi==1:
    b=bytes.fromhex(x['MEDIA_FIRST_HEX']);assert b==bytes.fromhex(x['MEDIA_SECOND_HEX']);bbuf=C.create_string_buffer(b);v=rr.data.block
    v.first=v.second=C.addressof(bbuf);v.media_pointer=v.media_pointer_after=C.addressof(bbuf);v.media_bytes=len(b);v.readable=v.stable=1;v.revision=v.revision_after=int(x['REVISION'],16)
   else:
    v=rr.data.disk;v.interface_guid_le[:]=bytes.fromhex(x['INTERFACE_GUID_LE_HEX'])
    if 'IDENTIFY_HEX' in x:
     b=bytes.fromhex(x['IDENTIFY_HEX']);bbuf=C.create_string_buffer(b);v.identify=C.addressof(bbuf);v.expected_bytes=v.returned_bytes=v.captured_bytes=len(b);v.crc32=zlib.crc32(b);v.allowlisted=v.buffer_guards_ok=v.format_size_match=1
    else:rr.valid=0;v.skip=1;g.valid_records-=1
   assert lib.HeroSataVisit(C.byref(source),C.byref(rr))==0
 return source,result,records,catalog
def main():
 source,result,records,catalog=acquire();assert (source.block_seen,source.disk_seen,source.ata_count)==(7,2,1)
 rows=[]
 def passed(name):rows.append(dict(case=name,passed=True))
 for side in ('left','right'):
  code,out,items,links=invoke(source,result,records,catalog,side);assert code==0 and len(items)==1 and len(links)==3
  value=items[0]['body'];assert value=={'Id':'SATA_P4_MFFFF_L0','Name':'SATA drive port 4','Protocol':'SATA','CapacityBytes':240057409536,'BlockSizeBytes':512,'Model':'SAMSUNG MZ7LH240HAHQ-00005','SerialNumber':'S45RNC0R912005','Revision':'HXT7A04Q','MediaType':'SSD'}
  assert items[0]['block_index']==3 and items[0]['disk_index']==1 and '0000_00_17_F0' in items[0]['uri']
  assert not any(x in value for x in ('Health','Status','PhysicalLocation','Manufacturer','FailurePredicted'))
  passed('actual_i4_native_collector_visitor_catalogue_'+side+'_guard_pages')
 (OUT/'hero71-sata-proposal.json').write_text(json.dumps(dict(source_sha256=hashlib.sha256(live.raw).hexdigest(),items=items,merge_only_additions=links,published=False,physical_capacity_supported_by='ATA Identify + unique direct AHCI path + matching nonpartition BlockIo'),indent=2)+'\n')
 # Independent frozen log still has one exact ATA checksum and source capacity.
 ata=bytes(source.ata[0].identify);assert ata[510]==0xa5 and sum(ata)%256==0 and hashlib.sha256(ata).hexdigest()=='15b8f6124ff99cf005c21e347af1ce2b0171e7c43d32c3d6e88e28981d15502c';passed('identify_checksum_and_exact_source_sha')
 def bad(name,mutate,wanted=None):
  s,r,p,c=clone(source),clone(result),[clone(x) for x in records],clone(catalog);mutate(s,r,p,c);ret,_,_,_=invoke(s,r,p,c);assert ret and (wanted is None or ret==wanted),(name,ret,wanted);passed(name)
 for name,mutate,e in [
  ('path_crc',lambda s,r,p,c:setattr(s.ata[0],'path_crc32',0),4),('identify_crc',lambda s,r,p,c:setattr(s.ata[0],'identify_crc32',0),4),
  ('source_rejected',lambda s,r,p,c:setattr(s,'rejected',1),6),('block_count_overflow',lambda s,r,p,c:setattr(s,'block_seen',129),6),('disk_count_overflow',lambda s,r,p,c:setattr(s,'disk_seen',65),6),
  ('cleanup_failure',lambda s,r,p,c:setattr(r.groups[1],'cleanup_status',0x8000000000000007),6),('enumeration_incomplete',lambda s,r,p,c:setattr(r.groups[2],'complete',0),6),('enumeration_u64_overflow',lambda s,r,p,c:setattr(r.groups[1],'declared',0x100000007),6),
  ('global_incomplete',lambda s,r,p,c:setattr(r,'complete',0),6),('global_failed',lambda s,r,p,c:setattr(r,'status',0x8000000000000007),6),
  ('media_revision_length_mismatch',lambda s,r,p,c:setattr(s.blocks[3],'revision',0x10000),3),
  ('pci_capture_crc_binding',lambda s,r,p,c:setattr(c,'source_crc32',1),14),('pci_capture_invalid',lambda s,r,p,c:setattr(c,'valid',0),14),('pci_path_changed',lambda s,r,p,c:p[0].path.__setitem__(0,1),14),
  ('no_matching_block',lambda s,r,p,c:setattr(s.ata[0],'source_handle',0x9999),12),('block_media_crc',lambda s,r,p,c:setattr(s.blocks[3],'media_crc32',0),4),
  ('block_capacity_mismatch',lambda s,r,p,c:media_mutate(s,lambda b:struct.pack_into('<Q',b,24,1000)),13),('block_capacity_overflow',lambda s,r,p,c:media_mutate(s,lambda b:struct.pack_into('<Q',b,24,0xffffffffffffffff)),13),
  ('block_sector_size_mismatch',lambda s,r,p,c:media_mutate(s,lambda b:struct.pack_into('<I',b,12,4096)),13),
  ('ata_atapi',lambda s,r,p,c:ata_mutate(s,lambda b:b.__setitem__(1,b[1]|128)),9),('ata_removable',lambda s,r,p,c:ata_mutate(s,lambda b:b.__setitem__(0,b[0]|128)),9),
  ('ata_bad_checksum',lambda s,r,p,c:ata_mutate(s,lambda b:b.__setitem__(511,b[511]^1),False),9),('ata_lba48_zero',lambda s,r,p,c:ata_mutate(s,lambda b:b.__setitem__(slice(200,208),bytes(8))),9),
  ('ata_lba48_overflow',lambda s,r,p,c:ata_mutate(s,lambda b:b.__setitem__(slice(206,208),b'\x01\x00')),9),
  ('ata_sector_count_invalid',lambda s,r,p,c:ata_mutate(s,lambda b:(struct.pack_into('<H',b,212,0x5000),struct.pack_into('<I',b,234,0xffffffff))),9),
  ('ata_nonpower_sector',lambda s,r,p,c:ata_mutate(s,lambda b:(struct.pack_into('<H',b,212,0x5000),struct.pack_into('<I',b,234,257))),9),
 ]:bad(name,mutate,e)
 bad('duplicate_block_handle',lambda s,r,p,c:setattr(s.blocks[4],'source_handle',s.blocks[3].source_handle),7)
 def duplicate_disk(s,r,p,c):s.ata[1]=s.ata[0];s.ata_count=2
 bad('duplicate_disk',duplicate_disk,7)
 for name,field,value in [('partition',6,1),('no_media',5,0),('removable',4,1),('read_only',7,1)]:
  s=clone(source);media_mutate(s,lambda b,f=field,v=value:b.__setitem__(f,v));ret,out,items,_=invoke(s,result,records,catalog);assert ret==0 and not items and out.skipped==1;passed(name+'_not_a_drive')
 for name,offset,value in [('nonzero_lun',26,1),('port_multiplier',24,3),('hba_port_out_of_range',22,32)]:
  s=clone(source);p=bytearray(s.ata[0].path[:s.ata[0].path_bytes]);struct.pack_into('<H',p,offset,value);s.ata[0].path[:len(p)]=p;s.ata[0].path_crc32=zlib.crc32(p)
  ret,out,items,_=invoke(s,result,records,catalog);assert ret==0 and not items and out.skipped==1;passed(name+'_excluded')
 for name,offset in [('unknown_model',54),('unknown_revision',46),('unknown_serial',20)]:
  s=clone(source);ata_mutate(s,lambda b,o=offset:b.__setitem__(o,0));ret,_,items,_=invoke(s,result,records,catalog);assert ret==0
  key={'unknown_model':'Model','unknown_revision':'Revision','unknown_serial':'SerialNumber'}[name];assert key not in items[0]['body'];passed(name+'_omitted')
 s=clone(source);ata_mutate(s,lambda b:struct.pack_into('<H',b,434,0));ret,_,items,_=invoke(s,result,records,catalog);assert ret==0 and 'MediaType' not in items[0]['body'];passed('unknown_rotation_omits_media_type')
 s=clone(source)
 def quote_model(b):b[54:58]=b'"A\\B'
 ata_mutate(s,quote_model);ret,_,items,_=invoke(s,result,records,catalog);assert ret==0 and items[0]['body']['Model'].startswith('A"B\\');passed('ata_strings_are_json_escaped')
 for baduri in (b'/redfish/v1/Systems/../X',b'/redfish/v1/Systems/%53elf',b'/redfish/v1/Systems/Self?X=1',b'/redfish/v1/Systems/Self\0X'):
  assert invoke(source,result,records,catalog,system=baduri)[0]==10
 passed('route_allowlist')
 # A true >512 logical sector size must agree with BlockIo and is used in capacity.
 s=clone(source);ata_mutate(s,lambda b:(struct.pack_into('<H',b,212,0x5000),struct.pack_into('<I',b,234,2048)));media_mutate(s,lambda b:struct.pack_into('<I',b,12,4096));ret,_,items,_=invoke(s,result,records,catalog);assert ret==0 and items[0]['body']['BlockSizeBytes']==4096 and items[0]['body']['CapacityBytes']==468862128*4096;passed('4kn_capacity_uses_proven_logical_size')
 for folder in ('vm','vm-nvme-first'):
  args=offline_typed_fixture(ROOT/'analysis/hero_pcie_collect_i4_20261108'/folder/'OVMF-PCIE-I4.TXT');ret,out,items,_=invoke(*args);assert ret==0
  if folder=='vm':assert not items
  else:assert len(items)==1 and items[0]['body']['Model']=='QEMU HARDDISK' and items[0]['body']['CapacityBytes']==67108864 and items[0]['port']==1
  passed(folder+'_only_direct_SATA_disk_optical_and_NVMe_namespace_excluded')
 # Full public output capacity: 32 SATA ports, then an additional controller.
 for n in (32,33):
  prs=[pc.record(0,device=23,klass=0x010601),pc.record(1,device=24,klass=0x010601)]
  cap=pc.Capture(1,2,2,1,0,0,0,0,0xABCD,123);ret,pcc,_,_=pc.invoke(prs,capture=cap);assert ret==0
  ss=Source();lib.HeroSataSourceInit(C.byref(ss));ss.block_seen=ss.disk_seen=ss.ata_count=n;rr=clone(result)
  for k,g in enumerate(rr.groups):g.declared=g.captured=g.valid_records=(2 if k==0 else n)
  rr.groups[0].source_crc32=cap.source_crc32;rr.groups[0].source_bytes=cap.source_bytes
  for k in range(n):
   pp=prs[k//32];path=bytes(pp.path[:pp.path_bytes-4])+struct.pack('<BBHHHH',3,18,10,k%32,65535,0)+b'\x7f\xff\x04\0'
   bb=clone(source.blocks[3]);dd=clone(source.ata[0]);bb.source_index=dd.source_index=k;bb.source_handle=dd.source_handle=0x100000+k
   for obj in (bb,dd):obj.path_bytes=len(path);obj.path_crc32=zlib.crc32(path);obj.path[:len(path)]=path
   ss.blocks[k]=bb;ss.ata[k]=dd
  ret,out,items,links=invoke(ss,rr,prs,pcc)
  if n==32:assert ret==0 and len(items)==32 and len(links)==96
  else:assert ret==11 and out.valid==0
  passed('drive_capacity_'+str(n)+'_all_or_nothing')
 # Input/output overlap and argument failures cannot clobber the source.
 sg=pc.Guard(C.sizeof(Source),bytes(source));rg=pc.Guard(C.sizeof(result),bytes(result));cg=pc.Guard(C.sizeof(catalog),bytes(catalog));pg=pc.Guard(len(records)*C.sizeof(pc.Record),b''.join(bytes(x) for x in records));sy=C.create_string_buffer(b'/redfish/v1/Systems/Self');ch=C.create_string_buffer(b'/redfish/v1/Chassis/Self');routes=pc.Routes(C.addressof(sy),C.addressof(ch),len(sy.value),len(ch.value))
 try:
  before=sg.read();assert lib.HeroSataCatalogBuild(sg.address,rg.address,pg.address,len(records),cg.address,C.byref(routes),sg.address)==2 and sg.read()==before
  assert lib.HeroSataCatalogBuild(None,rg.address,pg.address,len(records),cg.address,C.byref(routes),sg.address)==1 and sg.read()==before
  assert lib.HeroSataSourceInit(None)==1;passed('argument_and_overlap_preserve_inputs')
 finally:
  for g in (sg,rg,cg,pg):g.close()
 # Random identify changes with valid CRC/checksum exercise parser and JSON edges.
 rng=random.Random(61108)
 for k in range(300):
  s=clone(source);ata_mutate(s,lambda b:b.__setitem__(rng.randrange(510),rng.randrange(256)));invoke(s,result,records,catalog)
 passed('300_seeded_identify_mutations_guard_pages')
 report=dict(all_passed=True,count=len(rows),cases=rows,dll_sha256=hashlib.sha256((OUT/'sata.dll').read_bytes()).hexdigest(),source_bytes=C.sizeof(Source),catalog_bytes=C.sizeof(Catalog),current_host_source_sha256=hashlib.sha256(live.raw).hexdigest(),no_network_or_hardware=True,publication_performed=False,limits=['Native typed-collector replay consumes parent-acquired I4 bytes; not an additional live hardware run.','Only unique direct AHCI SATA disk paths are emitted; NVMe namespaces and unknown interfaces are omitted.','No stale inventory is removed and merge-only links still require fresh GET validation.'])
 (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('SATA NATIVE ALL PASS',len(rows))
if __name__=='__main__':main()
