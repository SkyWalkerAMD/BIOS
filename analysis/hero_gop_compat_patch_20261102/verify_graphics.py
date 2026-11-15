"""Exercise the compiled C transport via x64 UEFI ABI service doubles.

No physical device or firmware is accessed. Every protocol mutation and runtime
service is forbidden. QR success uses the same source object as the patch.
"""
from pathlib import Path
import ctypes as c,hashlib,json,struct,sys,zlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image
import zxingcpp
U64=c.c_uint64;P=c.c_void_p;ERR=lambda n:0x8000000000000000|n
lib=c.CDLL(str(OUT/'kvm_test.dll'))
original=c.CDLL(str(ROOT/'analysis/hero_display_m1e/capture_test.dll'))
lib.kvm_present.argtypes=[P,P,U64,c.c_uint];lib.kvm_present.restype=U64
lib.kvm_make_frame.argtypes=[P,U64,c.c_uint,P,U64];lib.kvm_make_frame.restype=U64
original.kvm_make_frame.argtypes=lib.kvm_make_frame.argtypes;original.kvm_make_frame.restype=U64
DATA=b'HERO-HII-M1E-KVM\r\nRUN=000000233C6EA304\r\n#001 GOP_COMPAT_TEST=0x0000000000000000\r\nSNAPSHOT_END\r\n'

class Machine:
 def __init__(self,case):
  self.case=case;self.keep=[];self.callbacks=[];self.calls=[];self.errors=[];self.allocated={};self.free_attempts=[];self.draws=[];self.output='';self.query_count=0
  self.st=self.block(128);self.bs=self.block(0x178);self.out=self.block(80);self.inp=self.block(24);self.textmode=self.block(24)
  self.gop=self.block(32);self.mode=self.block(40);self.rawinfo=self.block(36)
  self.w64(self.st+0x60,self.bs);self.w64(self.st+0x40,self.out);self.w64(self.st+0x30,self.inp);self.w64(self.st+0x38,0x31d7c118)
  self.w64(self.out+72,self.textmode);self.w32(self.textmode,4);self.w32(self.textmode+4,0)
  self.w64(self.gop+24,0 if case=='null_mode' else self.mode)
  self.w32(self.mode,0 if case=='zero_max' else 4);self.w32(self.mode+4,4 if case=='bad_current' else 3)
  self.w64(self.mode+8,0 if case=='null_info' else 1 if case=='unreadable_live_info' else self.rawinfo)
  self.w64(self.mode+16,36 if case=='normal_info' else 4 if case=='short_live_info' else 0)
  self.write(self.rawinfo,struct.pack('<9I',0,1024,768,1,0,0,0,0,1024))
  for off in range(0x18,0x178,8):self.stub(self.bs+off,'FORBIDDEN_BS_'+hex(off),4)
  self.stub(self.bs+0x40,'Allocate',3);self.stub(self.bs+0x48,'Free',1);self.stub(self.bs+0x98,'HandleProtocol',3);self.stub(self.bs+0x140,'LocateProtocol',3)
  for off,name,n in ((8,'Output',2),(0x18,'TextQuery',4),(0x20,'FORBIDDEN_TEXT_MODE',2),(0x28,'Attribute',2),(0x30,'Clear',1),(0x40,'Cursor',2)):
   self.stub(self.out+off,name,n)
  self.stub(self.inp+8,'Key',2)
  self.stub(self.gop,'QueryMode',4);self.stub(self.gop+8,'FORBIDDEN_GOP_MODE',2);self.stub(self.gop+16,'Blt',10)
  if case=='null_query':self.w64(self.gop,0)
  if case=='null_blt':self.w64(self.gop+16,0)
  self.original={p:c.string_at(p,n) for p,n in ((self.gop,32),(self.mode,40),(self.rawinfo,36))}
 def block(self,n):
  buf=c.create_string_buffer(n+32);p=c.addressof(buf)+16
  c.memset(p-16,0xa5,16);c.memset(p+n,0xa5,16);self.keep.append((buf,p,n));return p
 def write(self,p,data):c.memmove(p,data,len(data))
 def w64(self,p,x):self.write(p,struct.pack('<Q',x))
 def w32(self,p,x):self.write(p,struct.pack('<I',x))
 def stub(self,slot,name,n):
  def fn(*args):
   self.calls.append(name)
   try:return self.call(name,*args)
   except Exception as e:self.errors.append((name,str(e)));return ERR(7)
  cb=c.CFUNCTYPE(U64,*([U64]*n))(fn);self.callbacks.append(cb);self.w64(slot,c.cast(cb,P).value)
 def call(self,name,*a):
  assert not name.startswith('FORBIDDEN'),name
  case=self.case
  if name=='Output':
   chars=[]
   for i in range(1024):
    v=c.c_uint16.from_address(a[1]+i*2).value
    if not v:break
    chars.append(chr(v))
   self.output+=''.join(chars);return 0
  if name=='TextQuery':self.w64(a[2],80);self.w64(a[3],25);return 0
  if name in ('Attribute','Clear','Cursor'):return 0
  if name=='Key':self.write(a[1],struct.pack('<HH',0x17,0));return 0
  if name=='HandleProtocol':
   assert a[0]==0x31d7c118
   if case in ('no_gop','no_conout_gop'):return ERR(14)
   self.w64(a[2],self.gop);return 0
  if name=='LocateProtocol':
   if case=='no_gop':return ERR(14)
   self.w64(a[2],self.gop);return 0
  if name=='QueryMode':
   assert a[0]==self.gop and a[1]==3
   self.query_count+=1
   if case=='query_error':return ERR(7)
   if case=='query_null':self.w64(a[2],36);return 0
   if case=='query_alias':self.w64(a[2],36);self.w64(a[3],self.rawinfo);return 0
   width,height={'too_small':(639,768),'too_short':(1024,479),'too_wide':(4097,768),'too_tall':(1024,2161),'max_valid':(4096,2160),'min_valid':(640,480)}.get(case,(1024,768))
   info=struct.pack('<9I',0,width,height,1,0,0,0,0,width)
   size=4 if case=='query_short' else 36
   ptr=self.block(size);self.write(ptr,info[:size]);self.allocated[ptr]='query'
   self.w64(a[2],size);self.w64(a[3],ptr)
   return ERR(7) if case=='query_error_allocated' else 0
  if name=='Allocate':
   assert a[0]==4
   if case=='allocate_error':return ERR(9)
   if case=='allocate_null':return 0
   ptr=self.block(a[1]);self.allocated[ptr]='pixels';self.w64(a[2],ptr);return 0
  if name=='Free':
   ptr=a[0];self.free_attempts.append(ptr)
   assert ptr in self.allocated,('free non-owned',hex(ptr))
   if case=='query_free_error' and self.allocated[ptr]=='query':return ERR(7)
   del self.allocated[ptr];return 0
  if name=='Blt':
   assert a[0]==self.gop and self.allocated[a[1]]=='pixels'
   assert a[2:7]==(2,0,0,0,0)
   assert 640<=a[7]<=4096 and 480<=a[8]<=2160 and a[9]==a[7]*4
   self.draws.append((a[7],a[8]))
   if case in ('target_zero_info','unreadable_live_info'):
    image=Image.frombytes('RGB',(a[7],a[8]),c.string_at(a[1],a[7]*a[8]*4),'raw','BGRX')
    codes=zxingcpp.read_barcodes(image,formats=zxingcpp.BarcodeFormat.QRCode)
    assert len(codes)==1
    raw=c.create_string_buffer(4096);src=c.create_string_buffer(DATA)
    n=original.kvm_make_frame(src,len(DATA),0,raw,4096)
    assert bytes(codes[0].bytes)==bytes(raw[:n]),'rendered code bytes changed'
    if case=='target_zero_info':image.save(OUT/'target-zero-info-qr.png')
   return ERR(7) if case=='blt_error' else 0
  raise AssertionError(name)
 def run(self):
  src=c.create_string_buffer(DATA)
  e=lib.kvm_present(self.st,src,len(DATA),2 if self.case=='forced_text' else 0)
  assert e==0,(self.case,e)
  assert not self.errors,self.errors
  for _,p,n in self.keep:
   assert c.string_at(p-16,16)==b'\xa5'*16 and c.string_at(p+n,16)==b'\xa5'*16
  for p,data in self.original.items():assert c.string_at(p,len(data))==data,'modified borrowed firmware metadata'
  if self.case=='query_free_error':assert len(self.allocated)==1 and set(self.allocated.values())=={'query'}
  else:assert not self.allocated,self.allocated
  if self.case not in ('no_gop','no_conout_gop'):assert 'LocateProtocol' not in self.calls,'switched away from original ConOut GOP'
  return self

def main():
 rows=[]
 for length in (1,512,513,3074,65536):
  data=c.create_string_buffer(bytes((i*13+17)%256 for i in range(length)))
  for page in range((length+511)//512):
   a=c.create_string_buffer(4096);b=c.create_string_buffer(4096)
   an=lib.kvm_make_frame(data,length,page,a,4096);bn=original.kvm_make_frame(data,length,page,b,4096)
   assert an==bn and a[:an]==b[:bn],('frame changed',length,page)
  rows.append({'case':f'original_frame_compatibility_{length}','passed':True})
  print('original_frame_compatibility',length,'PASS',flush=True)
 cases=['normal_info','target_zero_info','short_live_info','null_info','unreadable_live_info','null_query','zero_max','bad_current','null_mode','null_blt','query_error','query_null','query_short','query_error_allocated','query_alias','query_free_error','too_small','too_short','too_wide','too_tall','min_valid','max_valid','allocate_error','allocate_null','blt_error','no_gop','no_conout_gop','forced_text']
 qr_cases={'normal_info','target_zero_info','short_live_info','null_info','unreadable_live_info','min_valid','max_valid','no_conout_gop'}
 no_query={'normal_info','null_query','zero_max','bad_current','null_mode','null_blt','no_gop','forced_text'}
 for name in cases:
  m=Machine(name).run()
  assert m.query_count==(0 if name in no_query else 1),(name,m.query_count)
  if name in qr_cases:assert m.draws and 'TEXT PAGE' not in m.output
  else:assert 'TEXT PAGE' in m.output
  if name=='forced_text':assert not set(m.calls)&{'HandleProtocol','LocateProtocol','Allocate','Blt','QueryMode'}
  if name=='blt_error':assert m.draws and 'TEXT PAGE' in m.output
  if name=='target_zero_info':assert m.draws==[(1024,768)]
  rows.append({'case':name,'passed':True,'query_calls':m.query_count,'draws':m.draws});print(name,'PASS',flush=True)
 report=dict(dll_sha256=hashlib.sha256((OUT/'kvm_test.dll').read_bytes()).hexdigest(),original_codec_dll_sha256=hashlib.sha256((ROOT/'analysis/hero_display_m1e/capture_test.dll').read_bytes()).hexdigest(),count=len(rows),all_passed=True,cases=rows,
  limits=['Native test DLL executes the same patched C transport and QR encoder, but is not a complete bootable EFI integration test.','No target HERO or BMC execution was performed.','A firmware FreePool failure remains an unreleased allocation; the tested branch falls back to text without drawing.'])
 (OUT/'graphics-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL PASS',len(rows))

if __name__=='__main__':main()
