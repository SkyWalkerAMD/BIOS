"""Actual C/SHA/CRC codec + independent Python reconstruction, no UEFI or hardware."""
from pathlib import Path
import base64,ctypes as C,hashlib,json,struct,subprocess,sys,uuid,zlib
from decode_packet import decode,CPU,UNKNOWN,NVME,SOCKET
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';ROOT=HERE.parents[3]
BASE=(HERE.parent/'foreign_hii05/blobs/GetCpuInfo_0.forms.bin').read_bytes();SOURCE=hashlib.sha256(b'SYNTHETIC source; not physical HII06').digest();SELECTION=hashlib.sha256(b'SYNTHETIC selection; not deployable').digest()
class Meta(C.Structure):_fields_=[(k,C.c_uint32) for k in ('kind','artifact_id','package_index','expected_length','observed_instances','instance_index')]+[('current_hii',C.c_uint64),('package_guid',C.c_ubyte*16),('source_log_sha',C.c_ubyte*32),('selection_sha',C.c_ubyte*32),('expected_sha',C.c_ubyte*32)]
class Result(C.Structure):_fields_=[(k,C.c_uint32) for k in ('required','body_bytes','prefix','suffix','flags','body_crc')]+[('packet_sha',C.c_ubyte*32)]
class Forms(C.Structure):_fields_=[(k,C.c_uint32) for k in ('offset','bytes','form_count')]+[('sha',C.c_ubyte*32)]
dll=C.CDLL(str(OUT/'delta_core_test.dll'));dll.d7_packet.argtypes=[C.POINTER(Meta),C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.POINTER(Result)];dll.d7_select_forms.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_uint32,C.POINTER(Forms)];dll.d7_b64_size.argtypes=[C.c_size_t];dll.d7_b64_size.restype=C.c_size_t;dll.d7_base64.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]
checks=[];artifacts=[]
def record(name):checks.append({'case':name,'passed':True})
def current_cpu(count):
 body=BASE[4:132]+b''.join(struct.pack('<BBHHH',3,8,0x40+i,0,0) for i in range(count))+BASE[132:];return struct.pack('<I',len(body)+4|(2<<24))+body
def unknown_forms():
 fset=b'\x0e\x97'+uuid.UUID(UNKNOWN).bytes_le+b'\0'*5;body=fset+b''.join(b'\x01\x86'+struct.pack('<HH',0x3100+i,1)+b'\x29\x02' for i in range(4))+b'\x29\x02';return struct.pack('<I',len(body)+4|(2<<24))+body
def meta(data,kind=1,index=0):
 m=Meta();m.kind=kind;m.artifact_id=(1 if kind==1 else 2)+index;m.expected_length=len(data);m.observed_instances=1 if kind==1 else 2;m.instance_index=index;m.current_hii=(0x123450 if kind==1 else 0x223450)+index*0x100
 m.package_guid[:]=uuid.UUID(CPU if kind==1 else UNKNOWN).bytes_le;m.source_log_sha[:]=SOURCE;m.selection_sha[:]=SELECTION;m.expected_sha[:]=hashlib.sha256(data).digest();return m
def target(m):return {'kind':m.kind,'package_list_guid':str(uuid.UUID(bytes_le=bytes(m.package_guid))),'package_index':m.package_index,'result_bytes':m.expected_length,'result_sha256':bytes(m.expected_sha).hex(),'expected_instances':m.observed_instances,'artifact_base':1 if m.kind==1 else 2}
def call(m,data,baseline=BASE,cap=None,expect=0):
 r=Result();need=Result();bn=len(baseline) if baseline is not None else 0
 status=dll.d7_packet(C.byref(m),baseline,bn,data,len(data),None,0,C.byref(need))
 if expect not in (0,5):assert status==expect,(status,expect);record('preflight_reject_'+str(expect));return b'',need
 assert status==5;size=need.required if cap is None else cap;buf=C.create_string_buffer(b'\xa5'*(size+32),size+32)
 status=dll.d7_packet(C.byref(m),baseline,bn,data,len(data),C.addressof(buf)+16,size,C.byref(r));assert status==expect,(status,expect)
 assert buf.raw[:16]==b'\xa5'*16 and buf.raw[-16:]==b'\xa5'*16
 if status!=0:assert buf.raw==b'\xa5'*(size+32);return b'',r
 packet=buf.raw[16:16+r.required];assert bytes(r.packet_sha)==hashlib.sha256(packet).digest()
 result,info=decode(packet,baseline,SOURCE,SELECTION,len(packet),target(m));assert result==data
 n=dll.d7_b64_size(len(packet));text=C.create_string_buffer(b'\xa5'*(n+32),n+32);assert dll.d7_base64(packet,len(packet),C.addressof(text)+16,n)==1
 assert text.raw[:16]==text.raw[-16:]==b'\xa5'*16 and text.raw[16:16+n]==base64.b64encode(packet)
 assert dll.d7_base64(packet,len(packet),C.addressof(text)+16,n-1)==0
 return packet,r
def guarded_child():
 # The entire string payload's middle page is PAGE_NOACCESS. Native C must skip it.
 k=C.WinDLL('kernel32',use_last_error=True);k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32];k.VirtualAlloc.restype=C.c_void_p;k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.POINTER(C.c_uint32)];k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32]
 address=k.VirtualAlloc(None,12288,0x3000,4);assert address
 try:
  n=8192+len(BASE)+4;header=uuid.UUID(CPU).bytes_le+struct.pack('<I',n)+struct.pack('<I',(8192-20)|(4<<24));C.memmove(address,header,len(header));C.memmove(address+8192,BASE+b'\4\0\0\xdf',len(BASE)+4)
  old=C.c_uint32();assert k.VirtualProtect(address+4096,4096,1,C.byref(old));r=Forms()
  assert dll.d7_select_forms(address,n,uuid.UUID(CPU).bytes_le,0,C.byref(r))==0 and r.offset==8192 and r.bytes==len(BASE) and bytes(r.sha)==hashlib.sha256(BASE).digest()
 finally:assert k.VirtualFree(address,0,0x8000)
 print('PAGE_NOACCESS string body skipped by actual C',flush=True)
def main():
 if '--guarded-child' in sys.argv:guarded_child();return
 for count in (0,1,7,14,63,128):
  data=current_cpu(count);m=meta(data);packet,r=call(m,data);assert r.flags==3;record(f'cpu_text_{count}_exact_roundtrip');artifacts.append((f'cpu_{count}',packet,target(m)))
  for cap in (0,1,r.required-1):call(m,data,cap=cap,expect=5);record(f'cpu_{count}_budget_{cap}_no_partial_write')
 data=bytearray(current_cpu(7));data[103]=4;data=bytes(data);packet,r=call(meta(data),data);assert r.flags==1;record('unexpected_structure_preserved_but_not_text_only')
 raw=unknown_forms()
 for index in (0,1):
  packet,r=call(meta(raw,2,index),raw,None);assert r.flags==5;record('unknown_instance_'+str(index));artifacts.append(('unknown_'+str(index),packet,target(meta(raw,2,index))))
 assert artifacts[-1][1]!=artifacts[-2][1]
 from verify_efi import contents,BASE as BASES
 for guid in (NVME,SOCKET):
  for huge in (False,True):
   data=contents(huge)[guid];m=meta(data);m.kind=3;m.artifact_id=2;m.package_guid[:]=uuid.UUID(guid).bytes_le
   packet,r=call(m,data,BASES[guid]);assert r.flags==1;record('fixed_original_'+guid+'_huge_'+str(huge)+'_actual_SHA_roundtrip')
   for cap in (0,1,r.required-1):call(m,data,BASES[guid],cap,5);record('fixed_budget_'+guid+'_'+str(huge)+'_'+str(cap))
   call(m,data,b'X'+BASES[guid][1:],expect=4)
   blob=uuid.UUID(guid).bytes_le+struct.pack('<I',24+len(data))+data+b'\4\0\0\xdf';found=Forms()
   assert dll.d7_select_forms(blob,len(blob),uuid.UUID(guid).bytes_le,0,C.byref(found))==0 and found.bytes==len(data);record('fixed_selected_'+guid+'_'+str(huge))
 bad=meta(raw,2);bad.expected_sha[0]^=1;call(bad,raw,None,expect=3)
 bad=meta(raw,2);bad.package_guid[0]^=1;call(bad,raw,None,expect=2)
 bad=meta(BASE);bad.source_log_sha[:]=bytes(32);call(bad,BASE,expect=1)
 bad=meta(BASE);bad.instance_index=1;call(bad,BASE,expect=1)
 call(meta(BASE),BASE,baseline=b'X'+BASE[1:],expect=4)
 for i,body in enumerate((BASE[:-1],b'\0'*4,BASE[:5]+b'\xff'+BASE[6:])):call(meta(body),body,expect=1);record('invalid_forms_'+str(i))
 for index in (0,1):
  body=BASE+BASE;blob=uuid.UUID(CPU).bytes_le+struct.pack('<I',24+len(body))+body+b'\4\0\0\xdf';r=Forms();assert dll.d7_select_forms(blob,len(blob),uuid.UUID(CPU).bytes_le,index,C.byref(r))==0;assert r.offset==20+index*len(BASE);record('per_package_ordinal_'+str(index))
 for body in (blob[:-1],blob+b'X',blob[:16]+b'\xff'*4+blob[20:]):
  r=Forms();assert dll.d7_select_forms(body,len(body),uuid.UUID(CPU).bytes_le,0,C.byref(r))!=0 and bytes(r)==bytes(C.sizeof(r));record('invalid_package_list_no_result')
 subprocess.run([sys.executable,'-X','utf8',str(Path(__file__).resolve()),'--guarded-child'],check=True,cwd=ROOT);record('noaccess_string_payload_not_read')
 for name,packet,t in artifacts:
  folder=OUT/'synthetic';folder.mkdir(exist_ok=True);(folder/(name+'.bin')).write_bytes(packet);(folder/(name+'.target.json')).write_text(json.dumps(t,indent=2)+'\n')
 report={'status':'LOCAL_CODEC_TESTS_ONLY_NO_REAL_TARGET_SELECTION','passed':True,'count':len(checks),'checks':checks,'dll_sha256':hashlib.sha256((OUT/'delta_core_test.dll').read_bytes()).hexdigest(),'source_log_sha':SOURCE.hex(),'selection_sha':SELECTION.hex(),'all_test_contents_are_synthetic':True};(OUT/'core_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(checks)},indent=2))
if __name__=='__main__':main()
