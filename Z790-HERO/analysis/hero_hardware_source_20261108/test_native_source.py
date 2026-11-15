"""Native typed source/service fake, real caller-buffer guards and adapter tests."""
from pathlib import Path
import ctypes as C,hashlib,json,struct,uuid,zlib
from abi_types import *
P=Path(__file__).resolve().parent
lib=C.CDLL(str(P/'hardware_source.dll'))
lib.HeroHardwareSourceWorkspaceSize.restype=C.c_size_t
W=lib.HeroHardwareSourceWorkspaceSize()
lib.HeroHardwareSourceInit.argtypes=[PTR,C.c_size_t];lib.HeroHardwareSourceInit.restype=C.c_int
lib.HeroHardwareSourceCollect.argtypes=[PTR,PTR,C.c_size_t,C.POINTER(Visitor),C.POINTER(Result)];lib.HeroHardwareSourceCollect.restype=U64
lib.HeroHardwarePciSinkInit.argtypes=[C.POINTER(Sink),C.POINTER(HpcRecord),U32];lib.HeroHardwarePciSinkInit.restype=C.c_int
lib.HeroHardwarePciVisit.argtypes=[PTR,C.POINTER(Record)];lib.HeroHardwarePciVisit.restype=C.c_int
lib.HeroHardwarePciCapture.argtypes=[C.POINTER(Sink),C.POINTER(Result),C.POINTER(Capture)];lib.HeroHardwarePciCapture.restype=C.c_int
ERR=lambda n:0x8000000000000000|n
guids={name:uuid.UUID(g).bytes_le for name,g in [('pci','4cf5b200-68b8-4ca5-9eec-b23e3f50029a'),('block','964e5b21-6459-11d2-8e39-00a0c969723b'),('disk','d432a67f-14dc-484b-b3bb-3f0291849327'),('path','09576e91-6d3f-11d2-8e39-00a0c969723b')]}
k=C.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.argtypes=[PTR,C.c_size_t,U32,U32];k.VirtualAlloc.restype=PTR
k.VirtualProtect.argtypes=[PTR,C.c_size_t,U32,C.POINTER(U32)];k.VirtualProtect.restype=C.c_int
k.VirtualFree.argtypes=[PTR,C.c_size_t,U32];k.VirtualFree.restype=C.c_int
class Guard:
 def __init__(self,size):
  self.size=size;pages=(size+4095)&~4095;self.base=k.VirtualAlloc(None,pages+4096,0x3000,4);assert self.base
  old=U32();assert k.VirtualProtect(self.base+pages,4096,1,C.byref(old));self.ptr=self.base+pages-size
 def close(self):assert k.VirtualFree(self.base,0,0x8000)
class Peer:
 def __init__(self,scenario='normal',media_revision=0x2001f):
  self.scenario=scenario;self.refs=[];self.calls=[];self.errors=[];self.owned=set();self.audits=[bytearray(),bytearray(),bytearray()];self.reentry=[]
  self.work=Guard(W);assert self.work.ptr%16==0;assert lib.HeroHardwareSourceInit(self.work.ptr,W)==0
  self.bs=C.create_string_buffer(0x178);self.st=C.create_string_buffer(0x78)
  self.write(self.st,0x60,C.addressof(self.bs));self.protos={1:C.create_string_buffer(160),2:C.create_string_buffer(48),3:C.create_string_buffer(48)}
  self.path=C.create_string_buffer(bytes.fromhex('0101060000007FFF0400'));self.config=bytearray(256);struct.pack_into('<HH',self.config,0,0x8086,0x1234);self.config[9:12]=b'\x02\x08\x01'
  n=48 if media_revision>=0x2001f else 44 if media_revision>=0x20001 else 32
  self.media=Guard(n);raw=struct.pack('<I5B3xII4xQQII',3,0,1,0,1,0,512,1,100,0,1,0);C.memmove(self.media.ptr,raw,n)
  self.write(self.protos[2],0,media_revision);self.write(self.protos[2],8,self.media.ptr)
  C.memmove(C.addressof(self.protos[3]),uuid.UUID('3ab14680-5d3f-4a4d-bcdc-cc380018c7f7').bytes_le,16)
  self.bind(self.bs,0x38,'map',C.CFUNCTYPE(U64,C.POINTER(U64),PTR,C.POINTER(U64),C.POINTER(U64),C.POINTER(U32)),self.getmap)
  self.bind(self.bs,0x138,'handles',C.CFUNCTYPE(U64,U32,PTR,PTR,C.POINTER(U64),C.POINTER(PTR)),self.handles)
  self.bind(self.bs,0x98,'handle',C.CFUNCTYPE(U64,PTR,PTR,C.POINTER(PTR)),self.handle)
  self.bind(self.bs,0x48,'free',C.CFUNCTYPE(U64,PTR),self.free)
  self.bind(self.protos[1],0x30,'config',C.CFUNCTYPE(U64,PTR,U32,U32,U64,PTR),self.readconfig)
  self.bind(self.protos[1],0x70,'location',C.CFUNCTYPE(U64,PTR,C.POINTER(U64),C.POINTER(U64),C.POINTER(U64),C.POINTER(U64)),self.location)
  self.bind(self.protos[3],24,'identify',C.CFUNCTYPE(U64,PTR,PTR,C.POINTER(U32)),self.identify)
  self.result=Result();self.child_result=Result();self.callback=VISIT(self.visit);self.visitor=Visitor(1,C.sizeof(Visitor),None,self.callback)
 def write(self,buf,off,value):C.memmove(C.addressof(buf)+off,struct.pack('<Q',value),8)
 def bind(self,buf,off,name,typ,fn):
  def safe(*args):
   self.calls.append(name)
   try:return fn(*args)
   except Exception as e:self.errors.append(repr(e));return ERR(7)
  f=typ(safe);self.refs.append(f);self.write(buf,off,C.cast(f,PTR).value)
 def getmap(self,size,buf,key,ds,version):
  data=struct.pack('<IIQQQQ',4,0,0x10000,0,(0x800000000000-0x10000)//4096,0)+bytes(8)
  assert size[0]>=len(data);C.memmove(buf,data,len(data));size[0]=len(data);key[0]=1;ds[0]=48;version[0]=1;return 0
 def handles(self,search,guid,key,count,handles):
  assert search==2 and not key;g=C.string_at(guid,16);kind=next(i+1 for i,n in enumerate(('pci','block','disk')) if guids[n]==g)
  a=(PTR*1)(kind);self.refs.append(a);p=C.addressof(a);self.owned.add(p);count[0]=1;handles[0]=p;return 0
 def handle(self,handle,guid,out):
  g=C.string_at(guid,16)
  if g==guids['path']:out[0]=C.addressof(self.path);return 0
  assert handle in self.protos and g==guids[('pci','block','disk')[handle-1]];out[0]=C.addressof(self.protos[handle]);return 0
 def free(self,p):assert p in self.owned;self.owned.remove(p);return 0
 def readconfig(self,proto,width,offset,count,out):
  assert proto==C.addressof(self.protos[1]) and (width,offset,count)==(0,0,256);C.memmove(out,bytes(self.config),256);return 0
 def location(self,proto,seg,bus,dev,fn):assert proto==C.addressof(self.protos[1]);seg[0]=0;bus[0]=1;dev[0]=0;fn[0]=0;return 0
 def identify(self,proto,out,size):
  assert proto==C.addressof(self.protos[3]) and size[0]==4096
  if self.scenario=='disk_failure':return ERR(7)
  C.memset(out,0x6a,4096);return 0
 def visit(self,user,ptr):
  try:
   r=ptr.contents;assert not user and r.version==1 and r.bytes==C.sizeof(Record)
   b=struct.pack('<IIQQII',r.kind,r.source_index,r.source_handle,r.protocol_status,r.issues,r.path.first_bytes)
   if r.path.first_bytes:b+=C.string_at(r.path.first,r.path.first_bytes)
   if r.kind==1:
    v=r.data.pci;b+=struct.pack('<4Q',v.segment,v.bus,v.device,v.function)+C.string_at(v.config,v.config_bytes)
   elif r.kind==2:
    v=r.data.block;b+=struct.pack('<Q',v.revision)
    if v.readable:b+=C.string_at(v.first,v.media_bytes)+C.string_at(v.second,v.media_bytes)
   else:
    v=r.data.disk;b+=bytes(v.interface_guid_le)
    if v.captured_bytes:b+=C.string_at(v.identify,v.captured_bytes)
   self.audits[r.kind-1]+=b
   if self.scenario=='reentrant':
    before=len(self.calls);code=lib.HeroHardwareSourceCollect(C.addressof(self.st),self.work.ptr,W,C.byref(self.visitor),C.byref(self.child_result))
    init=lib.HeroHardwareSourceInit(self.work.ptr,W);assert len(self.calls)==before;self.reentry.append((code,init))
   if self.scenario=='visitor_abort':return 1
   return 0
  except Exception as e:self.errors.append(repr(e));return 1
 def run(self):
  s=lib.HeroHardwareSourceCollect(C.addressof(self.st),self.work.ptr,W,C.byref(self.visitor),C.byref(self.result));assert not self.errors,self.errors;assert not self.owned
  assert self.result.bytes==C.sizeof(Result) and self.result.status==s
  for g,b in zip(self.result.groups,self.audits):assert g.source_bytes==len(b) and g.source_crc32==zlib.crc32(b)
  return s
 def close(self):self.work.close();self.media.close()

def main():
 rows=[]
 for scenario,rev in [('normal',0x10000),('normal',0x20001),('normal',0x2001f),('reentrant',0x2001f),('visitor_abort',0x2001f),('disk_failure',0x2001f)]:
  p=Peer(scenario,rev)
  try:
   code=p.run();wanted=ERR(21) if scenario=='visitor_abort' else ERR(6) if scenario=='disk_failure' else 0;assert code==wanted
   if scenario=='reentrant':assert p.reentry==[(ERR(20),2)]*3
   if scenario=='visitor_abort':assert p.calls.count('handles')==1 and p.calls.count('free')==1 and p.result.visitor_aborted
   if scenario=='disk_failure':assert p.result.groups[0].complete and p.result.groups[1].complete and not p.result.groups[2].complete
   rows.append(dict(case=scenario+'_'+hex(rev),passed=True,status=f'{code:016X}',calls=p.calls))
  finally:p.close()
 work=Guard(W)
 try:
  C.memset(work.ptr,0xa5,W);before=C.string_at(work.ptr,32)
  assert lib.HeroHardwareSourceInit(work.ptr,W-1)==1 and C.string_at(work.ptr,32)==before;rows.append(dict(case='workspace_one_byte_short_no_write',passed=True))
  assert lib.HeroHardwareSourceInit(work.ptr+1,W-1)==1;rows.append(dict(case='workspace_unaligned_rejected',passed=True))
  assert lib.HeroHardwareSourceInit(work.ptr,W)==0;rows.append(dict(case='workspace_exact_end_guard',passed=True))
  v=Visitor(1,C.sizeof(Visitor),None,VISIT(lambda *_:0));r=Result();C.memset(C.byref(r),0x4c,C.sizeof(r));saved=bytes(r)
  assert lib.HeroHardwareSourceCollect(None,work.ptr,W,C.byref(v),C.byref(r))==ERR(2) and bytes(r)==saved;rows.append(dict(case='invalid_system_preserves_result',passed=True))
  assert lib.HeroHardwareSourceCollect(1,work.ptr,W,C.byref(v),C.cast(work.ptr,C.POINTER(Result)))==ERR(2);rows.append(dict(case='result_workspace_overlap_rejected_before_ST_read',passed=True))
 finally:work.close()
 # Exact one-record destination at a real inaccessible page, plus scalar errors.
 config=C.create_string_buffer(bytes(256));path=C.create_string_buffer(bytes.fromhex('0101060000007FFF0400'))
 r=Record();r.version=1;r.bytes=C.sizeof(r);r.kind=1;r.source_handle=1;r.protocol_readable=r.valid=1
 r.path.valid=r.path.stable=1;r.path.first_bytes=r.path.second_bytes=10;r.path.first=r.path.second=C.addressof(path);r.path.first_crc32=r.path.second_crc32=zlib.crc32(path.raw[:10])
 r.data.pci.flags=7;r.data.pci.config_bytes=256;r.data.pci.config=C.addressof(config);r.data.pci.config_crc32=zlib.crc32(config.raw[:256])
 dst=Guard(C.sizeof(HpcRecord));sink=Sink()
 try:
  assert lib.HeroHardwarePciSinkInit(C.byref(sink),C.cast(dst.ptr,C.POINTER(HpcRecord)),1)==0
  assert lib.HeroHardwarePciVisit(C.byref(sink),C.byref(r))==0 and sink.used==1;rows.append(dict(case='adapter_exact_record_at_guard',passed=True))
  mutations=[('segment_overflow','segment',65536),('bus_overflow','bus',256),('device_overflow','device',32),('function_overflow','function',8),('config_crc','config_crc32',123)]
  for name,field,value in mutations:
   lib.HeroHardwarePciSinkInit(C.byref(sink),C.cast(dst.ptr,C.POINTER(HpcRecord)),1);old=getattr(r.data.pci,field);setattr(r.data.pci,field,value);saved=C.string_at(dst.ptr,C.sizeof(HpcRecord))
   assert lib.HeroHardwarePciVisit(C.byref(sink),C.byref(r))==1 and sink.rejected and C.string_at(dst.ptr,C.sizeof(HpcRecord))==saved;setattr(r.data.pci,field,old);rows.append(dict(case=name+'_no_narrowing_or_write',passed=True))
  lib.HeroHardwarePciSinkInit(C.byref(sink),C.cast(dst.ptr,C.POINTER(HpcRecord)),1);assert lib.HeroHardwarePciVisit(C.byref(sink),C.byref(r))==0
  result=Result();result.version=1;result.bytes=C.sizeof(result);g=result.groups[0];g.kind=1;g.limit=128;g.declared=g.captured=g.valid_records=g.complete=g.stable=1
  cap=Capture();assert lib.HeroHardwarePciCapture(C.byref(sink),C.byref(result),C.byref(cap))==0;rows.append(dict(case='complete_pci_capture_accepted_independent_of_other_groups',passed=True))
  for name,field,value in [('truncated','truncated',1),('incomplete','complete',0),('u64_count','declared',0x100000001),('cleanup_failed','cleanup_status',ERR(7)),('source_bytes_overflow','source_bytes',0x100000000)]:
   old=getattr(g,field);setattr(g,field,value);saved=bytes(cap);assert lib.HeroHardwarePciCapture(C.byref(sink),C.byref(result),C.byref(cap))==1 and bytes(cap)==saved;setattr(g,field,old);rows.append(dict(case=name+'_preserves_capture',passed=True))
 finally:dst.close()
 report=dict(passed=True,cases=rows,caller_buffers_and_media_at_real_noaccess_boundary=True,all_guard_allocations_freed=True,dll_sha256=hashlib.sha256((P/'hardware_source.dll').read_bytes()).hexdigest(),workspace_bytes=W)
 (P/'native-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows)}))
if __name__=='__main__':main()
