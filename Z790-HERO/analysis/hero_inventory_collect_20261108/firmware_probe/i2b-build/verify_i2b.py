"""Run delivered I2B PE under strict UEFI doubles and validate QR export."""
from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,re,struct,sys,uuid,zlib
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[3]
for name in ['tools/pydeps','tools/kvm-pydeps']:sys.path.insert(0,str(ROOT/name))
import decode_captures as decoder
from unicorn.x86_const import *
from PIL import Image
import zxingcpp
spec=importlib.util.spec_from_file_location('base_verify',ROOT/'analysis/hero_ipmi_p6_20261104/collector/verify_app.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);base.P=P
R2='89924765-f984-4ad3-839b-51fdce378d88';P5='261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
P1API='4c8dd4ac-6827-4431-b9c7-0ad41e871db1'
LI='5b1b31a1-9562-11d2-8e3f-00a0c969723b';FV='220e73b6-6bdb-4413-8405-b974b108619a'
def makepe(marker):
 b=bytearray(256);b[:2]=b'MZ';struct.pack_into('<I',b,60,64);b[64:68]=b'PE\0\0';struct.pack_into('<H',b,68,0x8664);b[-1]=marker;return bytes(b)
PE={R2:makepe(0x52),P5:makepe(0x50)}
def section(kind,payload):
 b=(len(payload)+4).to_bytes(3,'little')+bytes([kind])+payload
 return b+bytes(-len(b)%4)
BODY={g:section(0x13,b'\x06\x08')+section(0x10,p)+section(0x15,b'T\0\0\0') for g,p in PE.items()}

class Machine(base.Machine):
 def __init__(self,keys='fr\x1bqq',scenario='normal',**kw):
  super().__init__(keys=keys,resident=False,p6_resident=False,**kw)
  assert self.pe.OPTIONAL_HEADER.SizeOfImage<0x200000,'PE overlaps fixture services'
  self.scenario=scenario;self.images={}
  self.stub(self.bs+56,'GetMap')
  for guid in [R2,P5]:
   path=self.alloc(b'\x04\x06\x14\x00'+uuid.UUID(guid).bytes_le+b'\x7f\xff\x04\x00');data=self.alloc(PE[guid])
   image=bytearray(96);struct.pack_into('<I',image,0,0x1000);struct.pack_into('<Q',image,32,path);struct.pack_into('<QQ',image,64,data,len(PE[guid]))
   ptr=self.alloc(bytes(image));self.images[ptr]=guid
  self.image_handles=self.alloc(b''.join(struct.pack('<Q',a) for a in self.images))
  self.fv=self.alloc(bytes(80));self.stub(self.fv+16,'FvReadFile');self.stub(self.fv+24,'FvReadSection');self.fv_handles=self.alloc(struct.pack('<Q',self.fv))
 def hook(self,u,address,size,unused):
  name=self.stubs.get(address)
  if name and (name.startswith('R2') or name.startswith('P6')):raise AssertionError('Resident driver APIs forbidden')
  handled={'Locate','GetMap','Handles','Handle','FvReadFile','FvReadSection','FileOpen','FileRead'}
  if name not in handled:return super().hook(u,address,size,unused)
  self.calls.append(name);rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
  a,b,c,d=[u.reg_read(x) for x in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];status=0
  if name=='Locate':
   guid=self.guid(a);assert guid in [base.API,P1API,base.P6API,base.GOP]
   if self.scenario=='api_present' and guid!=base.GOP:self.w64(c,self.svc if guid==base.API else self.p6svc)
   else:status=base.ERR(14)
  elif name=='GetMap':
   if self.scenario=='map_error':self.w64(a,131073);status=base.ERR(5)
   else:
    mapping=struct.pack('<IIQQQQ',4,0,0x100000,0,0xf00,0)+bytes(8)
    assert self.r64(a)>=len(mapping);u.mem_write(b,mapping);self.w64(a,len(mapping));self.w64(c,1);self.w64(d,48);u.mem_write(self.r64(rsp+40),struct.pack('<I',1))
  elif name=='Handles':
   assert a==2;guid=self.guid(b);out=self.r64(rsp+40)
   if guid==LI:
    self.w64(d,1025 if self.scenario=='oversize_handles' else (1 if self.scenario in ['fv_only','absent_r2'] else 2))
    self.w64(out,self.image_handles+(8 if self.scenario in ['fv_only','absent_r2'] else 0))
   elif guid==FV:self.w64(d,1);self.w64(out,self.fv_handles)
   elif guid==base.GOP:status=base.ERR(14)
   else:raise AssertionError(guid)
  elif name=='Handle':
   guid=self.guid(b)
   if guid==LI and a in self.images:self.w64(c,a)
   elif guid==FV and a==self.fv:self.w64(c,self.fv)
   elif a==base.IMAGE and guid==LI:self.w64(c,self.loaded)
   elif a==0x7777 and guid=='964e5b22-6459-11d2-8e39-00a0c969723b':self.w64(c,self.fs)
   else:status=base.ERR(14)
  elif name=='FvReadFile':
   assert a==self.fv;guid=self.guid(b);assert guid in BODY
   if self.scenario=='absent_r2' and guid==R2:status=base.ERR(14)
   else:
    u.mem_write(self.r64(rsp+40),b'\x07');u.mem_write(self.r64(rsp+48),struct.pack('<I',0x200))
    if not c:self.w64(d,1048577 if self.scenario=='large_file' else len(BODY[guid]))
    else:
     allocated=self.r64(c)==0
     if not allocated and self.scenario in ['allocate_only','alloc_size_changed','alloc_error']:status=base.ERR(2)
     elif allocated and self.scenario=='alloc_error':status=base.ERR(15)
     elif self.scenario=='body_warning':self.w64(d,len(BODY[guid])+1);status=4
     elif self.scenario=='body_changed':self.w64(d,len(BODY[guid])+1)
     else:
      if allocated:self.w64(c,self.alloc(BODY[guid]))
      else:
       assert self.r64(d)==len(BODY[guid]);u.mem_write(self.r64(c),BODY[guid])
      if self.scenario=='bad_sections':u.mem_write(self.r64(c),bytes(4))
      self.w64(d,len(BODY[guid])+(1 if self.scenario=='alloc_size_changed' else 0));u.mem_write(self.r64(rsp+56),bytes(4))
  elif name=='FvReadSection':raise AssertionError('ReadSection must not be called by I2B')
  elif name=='FileRead':
   assert a==self.marker;value=b'WRONG\r\n' if self.bad_marker else b'HERO-FW-ID-I2B\r\n'
   assert self.r64(b)>=len(value);self.w64(b,len(value));u.mem_write(c,value)
  elif name=='FileOpen':
   path=self.wide(c)
   if path=='\\HERO_ID.TAG':assert d==1;self.w64(b,self.marker)
   elif re.fullmatch(r'\\FID[0-9]{3}\.TXT',path):
    if d==1:
     if path in self.files:self.w64(b,self.file)
     else:status=base.ERR(14)
    else:
     assert d==0x8000000000000003 and path not in self.files
     if self.writable:self.created=True;self.files[path]=bytearray();self.file_name=path;self.pos=0;self.w64(b,self.file)
     else:status=base.ERR(8)
   else:raise AssertionError(path)
  u.reg_write(UC_X86_REG_RAX,status)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)

def main():
 rows=[];samples=[]
 cases=[('startup_no_actions_enter_escape',{'keys':'\r\x1bq\rqq'},0),
  ('normal_f_text',{},0),('normal_f_qr_fallback',{'keys':'fc\x1bqq'},0),
  ('fv_present_not_loaded',{'scenario':'fv_only'},0),('r2_absent_no_version_claim',{'scenario':'absent_r2'},0),
  ('map_error_preserves_diagnostics',{'scenario':'map_error'},base.ERR(33)),
  ('file_over_bound',{'scenario':'large_file'},base.ERR(33)),('body_warning_no_hash',{'scenario':'body_warning'},base.ERR(33)),
  ('changed_body_size_no_hash',{'scenario':'body_changed'},base.ERR(33)),
  ('readfile_null_allocate_compatibility',{'scenario':'allocate_only'},0),
  ('allocated_size_changed_free_without_hash',{'scenario':'alloc_size_changed'},base.ERR(33)),
  ('allocated_read_error_no_hash',{'scenario':'alloc_error'},base.ERR(33)),
  ('bad_section_stream_preserves_body_crc',{'scenario':'bad_sections'},base.ERR(33)),
  ('api_presence_no_methods',{'scenario':'api_present'},0),
  ('handles_over_bound',{'scenario':'oversize_handles'},base.ERR(33)),
  ('explicit_l_usb_two_new_files',{'keys':'fllqq','writable':True},0),
  ('iso_l_write_protected',{'keys':'flqq'},0),('wrong_marker_no_write',{'keys':'flqq','writable':True,'bad_marker':True},0)]
 for name,opts,wanted in cases:
  m=Machine(**opts);status,out=m.run();assert status==wanted,(name,hex(status),out[-500:])
  assert 'HERO FW ID I2B - FIRST TEXT / WAITING FOR F' in out and 'HERO FW ID I2B RETURNING TO FIRMWARE' in out and not m.keys
  assert not any(x.startswith(('FORBIDDEN','R2','P6')) for x in m.calls) and 'FvReadSection' not in m.calls
  if 'startup' in name:assert not any(x in m.calls for x in ['GetMap','FvReadFile','FvReadSection'])
  if 'KVM_LOG_BEGIN\r\n' in out:
   log=out.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode()
   assert log.startswith(b'HERO-FW-ID-I2B\r\nRUN=') and log.endswith(b'END FW ID SNAPSHOT\r\n');samples.append(log)
   if name=='normal_f_text':
    assert b'FP_R2_FV_FILES=0000000000000001' in log and f'FP_FV_PE_CRC32={zlib.crc32(PE[R2]):016X}'.encode() in log
   if 'warning' in name or 'changed_body' in name:assert b'FP_FV_PE_CRC32=' not in log and b'FP_FV_BODY_CRC32=' not in log
   if name=='readfile_null_allocate_compatibility':
    assert b'FP_FV_BODY_ALLOC_STATUS=0000000000000000' in log and b'FP_FV_BODY_ALLOC_FREE_STATUS=0000000000000000' in log
   if name.startswith('allocated_'):
    assert b'FP_FV_BODY_CRC32=' not in log and b'FP_FV_PE_CRC32=' not in log
    if name=='allocated_size_changed_free_without_hash':assert b'FP_FV_BODY_ALLOC_FREE_STATUS=0000000000000000' in log
   if name=='bad_section_stream_preserves_body_crc':assert b'FP_FV_BODY_CRC32=' in log and b'FP_FV_PE_CRC32=' not in log
   if name=='api_presence_no_methods':assert b'FP_API_LOCATE_STATUS=0000000000000000' in log and b'FP_API_METHODS_NOT_CALLED' in log
  if name=='explicit_l_usb_two_new_files':assert set(m.files)=={'\\FID000.TXT','\\FID001.TXT'} and m.files['\\FID000.TXT']==m.files['\\FID001.TXT']
  else:assert not m.files and 'FileWrite' not in m.calls and 'FileFlush' not in m.calls
  rows.append({'case':name,'passed':True,'status':f'{status:016X}','calls':sorted(set(m.calls))})
  print(name+' PASS',flush=True)
 lib=C.CDLL(str(P/'capture_test.dll'))
 lib.kvm_make_frame.argtypes=[C.c_void_p,C.c_size_t,C.c_uint,C.c_void_p,C.c_size_t];lib.kvm_make_frame.restype=C.c_size_t
 lib.kvm_encode_frame.argtypes=[C.c_void_p,C.c_size_t,C.c_uint,C.c_void_p,C.c_void_p];lib.kvm_encode_frame.restype=C.c_int
 lib.qrcodegen_getSize.argtypes=[C.c_void_p];lib.qrcodegen_getSize.restype=C.c_int
 lib.qrcodegen_getModule.argtypes=[C.c_void_p,C.c_int,C.c_int];lib.qrcodegen_getModule.restype=C.c_bool
 def frame(data,page):
  source=C.create_string_buffer(data);dest=C.create_string_buffer(4096);n=lib.kvm_make_frame(source,len(data),page,dest,len(dest));assert n;return bytes(dest[:n])
 for sample in samples:assert decoder.assemble([frame(sample,i) for i in reversed(range((len(sample)+511)//512))])[0]==sample
 rows.append({'case':'all_actual_pe_snapshots_exact_QR_frame_roundtrip','passed':True,'samples':len(samples)})
 sample=samples[0];source=C.create_string_buffer(sample);qr=C.create_string_buffer(4096);scratch=C.create_string_buffer(4096)
 assert lib.kvm_encode_frame(source,len(sample),0,qr,scratch);size=lib.qrcodegen_getSize(qr);scale=4
 image=Image.new('RGB',((size+8)*scale,)*2,'white')
 for y in range(size):
  for x in range(size):
   if lib.qrcodegen_getModule(qr,x,y):
    for dx in range(scale):
     for dy in range(scale):image.putpixel(((x+4)*scale+dx,(y+4)*scale+dy),(0,0,0))
 image.save(P/'synthetic-qr.png');found=zxingcpp.read_barcodes(image,formats=zxingcpp.BarcodeFormat.QRCode)
 assert len(found)==1 and bytes(found[0].bytes)==frame(sample,0)
 (P/'synthetic-capture.TXT').write_bytes(sample);rows.append({'case':'compiled_QR_png_decodes_exact_I2B_frame','passed':True})
 report={'passed':True,'scope':'Actual delivered PE in Unicorn with strict UEFI doubles; host QR encode/decode. No physical hardware.',
  'app_sha256':hashlib.sha256((P/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),'iso_sha256':hashlib.sha256((P/'HERO-FW-ID-I2B-READONLY.iso').read_bytes()).hexdigest(),
  'cases':rows,'writes':'No writes on capture/view/exit paths. Only explicit L may create a new file on a matching marked writable volume.',
  'forbidden':['NV writes','FV writes','driver initialization','LoadImage','StartImage','Reset','BMC/PCI','watchdog changes']}
 (P/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows),'app_sha256':report['app_sha256']}))
if __name__=='__main__':main()
