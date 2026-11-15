"""Compiled C replacement: preserve all functional controls and stable page count."""
from pathlib import Path
import ctypes as c,struct,subprocess,json,uuid
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
subprocess.run([str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
 '/export:native_form_bounds','/export:native_splice','/out:'+str(P/'native_test.dll'),str(P/'native_splice.obj'),str(P/'common.obj')],check=True)
lib=c.CDLL(str(P/'native_test.dll'));bounds=lib.native_form_bounds
bounds.argtypes=[c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t),c.POINTER(c.c_size_t)];bounds.restype=c.c_int
splice=lib.native_splice;splice.argtypes=[c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t,c.c_uint16,c.c_uint16,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)];splice.restype=c.c_int
raw=(P/'reference/HERO-3107-forms.bin').read_bytes();b=c.create_string_buffer(raw);at=c.c_size_t();end=c.c_size_t();used=c.c_size_t()
assert bounds(b,len(raw),c.byref(at),c.byref(end)) and at.value==0xd899
out=c.create_string_buffer(len(raw)+24)
assert splice(b,len(raw),None,0,123,124,out,len(out),c.byref(used))
actual=out.raw[:used.value];a=at.value
assert actual[3:a]==raw[3:a] and actual[a+33:]==raw[a+9:]
assert raw[a:a+9]==bytes.fromhex('028702000000002902')
assert len(actual)==len(raw)+24 and int.from_bytes(actual[:3],'little')==len(actual)
ref=actual[a:a+33];assert ref[:2]==b'\x0f\x21'
assert ref[6:17]==bytes.fromhex('00310000ffff0000310000')
assert ref[17:33]==uuid.UUID('491ef9f7-625c-48dc-b140-2c8577ba47f1').bytes_le
def walk(b,start=4):
 p=start;stack=[];forms=[];controls={};current=None
 while p<len(b):
  op,n=b[p],b[p+1]&127;scope=b[p+1]>>7;assert n>=2 and p+n<=len(b)
  if op==1:
   assert stack and stack[0]==0xe and 1 not in stack;current=struct.unpack_from('<H',b,p+2)[0];forms.append(current);controls[current]=[]
  if current is not None and op in (2,3,5,6,7,8,12,15,28,35):controls[current].append(op)
  if op==0x29:
   assert n==2 and not scope and stack
   if stack.pop()==1:current=None
  elif scope:stack.append(op)
  p+=n
 assert not stack and p==len(b)
 return forms,controls
f0,c0=walk(raw);f1,c1=walk(actual)
assert f1==f0 and len(f1)==292
assert len(c0[10005])==len(c1[10005])==38
assert c0[10005][:-1]==c1[10005][:-1] and c0[10005][-1]==2 and c1[10005][-1]==15
# DynamicPageCount condition and original blank self-reference remain untouched.
assert actual[0xd87e:0xd899]==raw[0xd87e:0xd899]
hii=(P/'HERO-P3-HII.bin').read_bytes();n=int.from_bytes(hii[20:23],'little')
pages,controls=walk(hii[20:20+n]);assert pages==list(range(0x3100,0x3105))
checks=0
for pos in [0,1,2,3,4,5,6,0xd430,0xd899,0xd89a,0xd8a0,len(raw)-2,len(raw)-1]:
 d=bytearray(raw);d[pos]^=1;assert not bounds(c.create_string_buffer(bytes(d)),len(d),c.byref(at),c.byref(end));checks+=1
for size in [0,1,3,20,len(raw)-1]:assert not bounds(b,size,c.byref(at),c.byref(end));checks+=1
for cap in [0,1,len(out)-1]:assert not splice(b,len(raw),None,0,123,124,out,cap,c.byref(used));checks+=1
assert not bounds(out,len(actual),c.byref(at),c.byref(end))
report={'passed':True,'malformed_cases':checks,'native_forms':len(f1),'advanced_controls_before':38,'advanced_controls_after':38,'only_blank_subtitle_replaced':True,'original_dynamic_placeholder_preserved':True,'new_pages_in_separate_package':pages,'reference':'REF3 / separate formset / form 3100','new_native_bytes':len(actual)}
(P/'native-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(report)
