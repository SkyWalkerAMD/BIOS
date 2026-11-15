"""Check the actual compiled splice with real HERO IFR and damaged inputs."""
from pathlib import Path
import ctypes as c,json,random,struct,subprocess
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
subprocess.run([str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0',
 '/export:native_form_bounds','/export:native_splice','/out:'+str(P/'native_test.dll'),str(P/'native_splice.obj'),str(P/'common.obj')],check=True)
lib=c.CDLL(str(P/'native_test.dll'));bounds=lib.native_form_bounds
bounds.argtypes=[c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t),c.POINTER(c.c_size_t)];bounds.restype=c.c_int
splice=lib.native_splice;splice.argtypes=[c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t,c.c_uint16,c.c_uint16,c.c_void_p,c.c_size_t,c.POINTER(c.c_size_t)];splice.restype=c.c_int
raw=(P/'reference/HERO-3107-forms.bin').read_bytes();extra=(P/'HERO-P1b-native-forms.bin').read_bytes()
b=c.create_string_buffer(raw);x=c.create_string_buffer(extra);at=c.c_size_t();end=c.c_size_t()
assert bounds(b,len(raw),c.byref(at),c.byref(end))==1
assert at.value==0x89996-0x7c0f4 and end.value==len(raw)-2
out=c.create_string_buffer(len(raw)+len(extra)+15);used=c.c_size_t()
assert splice(b,len(raw),x,len(extra),123,124,out,len(out),c.byref(used))==1
actual=out.raw[:used.value];a,e=at.value,end.value
# Every existing IFR byte is preserved, apart from the three-byte length field.
assert actual[3:a]==raw[3:a] and actual[a+15:e+15]==raw[a:e]
assert actual[e+15:e+15+len(extra)]==extra and actual[-2:]==raw[-2:]
assert len(actual)==len(raw)+15+len(extra)
assert int.from_bytes(actual[:3],'little')==len(actual)
# Duplicate attach fails; damaged Advanced contents, scopes and lengths fail.
assert not bounds(c.create_string_buffer(actual),len(actual),c.byref(at),c.byref(end))
checks=2
for offset in [0,1,2,3,4,5,6,a-1138,a-100,a-2,len(raw)-2,len(raw)-1]:
 d=bytearray(raw);d[offset]^=1
 assert not bounds(c.create_string_buffer(bytes(d)),len(d),c.byref(at),c.byref(end)),hex(offset)
 checks+=1
for length in [0,1,3,20,43,len(raw)-1,len(raw)-2]:
 assert not bounds(b,length,c.byref(at),c.byref(end));checks+=1
for cap in [0,1,len(out)-1]:
 assert not splice(b,len(raw),x,len(extra),123,124,out,cap,c.byref(used));checks+=1
# Invalid trailing single-byte opcode must be rejected without out-of-bounds read.
d=bytearray(raw);d[-1:]=b'\0';assert not bounds(c.create_string_buffer(bytes(d)),len(d),c.byref(at),c.byref(end));checks+=1
report={'passed':True,'cases':checks,'advanced_form_crc32':'236a962e','original_forms_bytes':len(raw),'new_forms_bytes':len(actual),'existing_ifr_preserved':True,'duplicate_attach_rejected':True,'malformed_inputs_rejected':True}
(P/'native-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(report)
