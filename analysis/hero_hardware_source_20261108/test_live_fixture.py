"""Replay a captured I4 observation into native C service fakes, then the
frozen PCI catalogue. This is offline regression, NOT an HHS hardware run.
"""
from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,struct,zlib
import test_native_source as base
from abi_types import *
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
decoder=module('i4_decoder',ROOT/'analysis/hero_ipmi_complete_live_20261108/decode_i4_inventory.py')
catalog=module('frozen_catalog_test',ROOT/'analysis/hero_pcie_catalog_20261108/test_catalog.py')
raw=(ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-i4-pcie-storage.TXT').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='ba97c22fb996e8b3534be82e6056affa1c493e63fa8bbb7d7e8718b9f564e8c7'
groups,_=decoder.parse_catalog(raw);decoded=decoder.decode(raw)
assert not decoded['collection_partial'] and decoded['cleanup_status']=='0000000000000000'

class Replay(base.Peer):
 def __init__(self):
  super().__init__();self.byproto={};self.hw={};self.paths={};self.buffers=[];self.seen=[]
  for kind,label in enumerate(('PCI','BLOCK','DISK'),1):
   for x in groups[label]['records']:
    handle=int(x['HANDLE'],16);proto=C.create_string_buffer(160 if kind==1 else 48)
    self.hw[kind,handle]=(proto,x);self.byproto[C.addressof(proto)]=(kind,x)
    path=bytes.fromhex(x['PATH_FIRST_HEX']);buf=C.create_string_buffer(path)
    if handle in self.paths:assert self.paths[handle].raw==buf.raw
    else:self.paths[handle]=buf
    if kind==1:
     self.bind(proto,0x30,'config',C.CFUNCTYPE(U64,PTR,U32,U32,U64,PTR),self.readconfig)
     self.bind(proto,0x70,'location',C.CFUNCTYPE(U64,PTR,C.POINTER(U64),C.POINTER(U64),C.POINTER(U64),C.POINTER(U64)),self.location)
    elif kind==2:
     b=bytes.fromhex(x['MEDIA_FIRST_HEX']);assert b==bytes.fromhex(x['MEDIA_SECOND_HEX'])
     media=base.Guard(len(b));self.buffers.append(media);C.memmove(media.ptr,b,len(b))
     self.write(proto,0,int(x['REVISION'],16));self.write(proto,8,media.ptr)
    else:
     C.memmove(C.addressof(proto),bytes.fromhex(x['INTERFACE_GUID_LE_HEX']),16)
     self.bind(proto,24,'identify',C.CFUNCTYPE(U64,PTR,PTR,C.POINTER(U32)),self.identify)
  self.records=(HpcRecord*35)();self.sink=Sink();assert base.lib.HeroHardwarePciSinkInit(C.byref(self.sink),self.records,35)==0
 def handles(self,search,guid,key,count,handles):
  assert search==2 and not key;g=C.string_at(guid,16);kind=next(i+1 for i,n in enumerate(('pci','block','disk')) if base.guids[n]==g)
  values=[h for k,h in self.hw if k==kind];a=(PTR*len(values))(*values);self.refs.append(a)
  p=C.addressof(a);self.owned.add(p);count[0]=len(values);handles[0]=p;return 0
 def handle(self,handle,guid,out):
  g=C.string_at(guid,16)
  if g==base.guids['path']:out[0]=C.addressof(self.paths[handle]);return 0
  kind=next(i+1 for i,n in enumerate(('pci','block','disk')) if base.guids[n]==g)
  out[0]=C.addressof(self.hw[kind,handle][0]);return 0
 def readconfig(self,proto,width,offset,count,out):
  kind,x=self.byproto[proto];assert kind==1 and (width,offset,count)==(0,0,256)
  b=bytes.fromhex(x['CONFIG_HEX']);assert len(b)==256;C.memmove(out,b,256);return 0
 def location(self,proto,seg,bus,dev,fn):
  kind,x=self.byproto[proto];assert kind==1
  for p,k in zip((seg,bus,dev,fn),('SEGMENT','BUS','DEVICE','FUNCTION')):p[0]=int(x[k],16)
  return 0
 def identify(self,proto,out,size):
  kind,x=self.byproto[proto];assert kind==3 and 'IDENTIFY_HEX' in x
  b=bytes.fromhex(x['IDENTIFY_HEX']);assert size[0]==len(b)==512;C.memmove(out,b,len(b));return 0
 def visit(self,user,ptr):
  if super().visit(user,ptr):return 1
  try:
   r=ptr.contents;label=('PCI','BLOCK','DISK')[r.kind-1];x=groups[label]['records'][r.source_index]
   assert r.source_handle==int(x['HANDLE'],16) and r.protocol_status==0 and r.protocol_readable and not r.incomplete and not r.issues
   assert r.path.valid and r.path.stable and C.string_at(r.path.first,r.path.first_bytes)==bytes.fromhex(x['PATH_FIRST_HEX'])
   if r.kind==1:
    assert r.valid and C.string_at(r.data.pci.config,256)==bytes.fromhex(x['CONFIG_HEX'])
    assert base.lib.HeroHardwarePciVisit(C.byref(self.sink),ptr)==0
   elif r.kind==2:
    assert r.valid and r.data.block.stable and C.string_at(r.data.block.first,r.data.block.media_bytes)==bytes.fromhex(x['MEDIA_FIRST_HEX'])
   else:
    d=r.data.disk;assert bytes(d.interface_guid_le)==bytes.fromhex(x['INTERFACE_GUID_LE_HEX'])
    if 'IDENTIFY_HEX' in x:assert r.valid and d.captured_bytes==512 and C.string_at(d.identify,512)==bytes.fromhex(x['IDENTIFY_HEX'])
    else:assert not r.valid and d.skip==1 and not d.allowlisted and not d.captured_bytes
   self.seen.append((label,r.source_index));return 0
  except Exception as e:self.errors.append(repr(e));return 1
 def close(self):
  for b in self.buffers:b.close()
  super().close()

def main():
 p=Replay()
 try:
  assert p.run()==0 and p.result.complete and not p.result.incomplete
  assert [(g.declared,g.captured,g.valid_records,g.complete,g.stable) for g in p.result.groups]==[(35,35,35,1,1),(7,7,7,1,1),(2,2,1,1,1)]
  assert p.result.visitor_calls==44 and len(p.seen)==44 and p.calls.count('identify')==1 and p.calls.count('free')==3
  cap=Capture();assert base.lib.HeroHardwarePciCapture(C.byref(p.sink),C.byref(p.result),C.byref(cap))==0
  cat_records=[catalog.Record.from_buffer_copy(bytes(x)) for x in p.records]
  cat_cap=catalog.Capture.from_buffer_copy(bytes(cap));status,result,items,links=catalog.invoke(cat_records,capture=cat_cap)
  assert status==0 and result.valid and result.function_count==35
  for item in items:
   assert not any(k in item['body'] for k in ('Health','Model','SerialNumber','PhysicalLocation','FunctionType','DeviceClass','DeviceType'))
   if item['kind']==2:
    ob=decoded['pci'][item['source_index']]
    for a,b in [('VendorId','vendor_id'),('DeviceId','device_id'),('ClassCode','class_code'),('RevisionId','revision_id')]:assert item['body'][a]==ob[b]
  disk=groups['DISK']['records'][1];block=groups['BLOCK']['records'][3]
  assert disk['HANDLE']==block['HANDLE'] and disk['PATH_FIRST_HEX']==block['PATH_FIRST_HEX']
  sata=[x for x in groups['PCI']['records'] if int(x['BUS'],16)==0 and int(x['DEVICE'],16)==0x17 and int(x['FUNCTION'],16)==0]
  assert len(sata)==1 and bytes.fromhex(disk['PATH_FIRST_HEX']).startswith(bytes.fromhex(sata[0]['PATH_FIRST_HEX'])[:-4])
  report=dict(passed=True,hardware_test=False,description='Native C replay of parent-acquired I4 .71 observations; no live services.',source_bytes=len(raw),source_sha256=hashlib.sha256(raw).hexdigest(),dll_sha256=hashlib.sha256((P/'hardware_source.dll').read_bytes()).hexdigest(),catalog_dll_sha256=hashlib.sha256((ROOT/'analysis/hero_pcie_catalog_20261108/catalog.dll').read_bytes()).hexdigest(),visitor_records=44,pci_records=35,block_records=7,disk_records=2,disk_identify_valid=1,disk_unknown_interface_skipped=1,all_handle_arrays_freed=True,sata_parent='0000:00:17.0',sata_disk_index=1,sata_block_index=3,catalog=dict(devices=result.device_count,functions=result.function_count,controllers=result.storage_count,items=result.item_count,merge_only_additions=result.link_count),source_groups=[dict(kind=g.kind,count=g.captured,valid=g.valid_records,complete=g.complete,source_bytes=g.source_bytes,source_crc32=f'{g.source_crc32:08X}') for g in p.result.groups],published=False)
  (P/'live-fixture-verification.json').write_text(json.dumps(report,indent=2)+'\n')
  (P/'live-fixture-catalog.json').write_text(json.dumps(dict(items=items,merge_only_additions=links,published=False),indent=2)+'\n')
  print(json.dumps(report,indent=2))
 finally:p.close()
if __name__=='__main__':main()
