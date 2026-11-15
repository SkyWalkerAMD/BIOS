from pathlib import Path
import ctypes as C,json,hashlib,uuid,re
H=Path(__file__).resolve().parent;O=H/'build';catalog=json.loads((H/'native_variable_catalog.json').read_text())['items'];D=C.CDLL(str(O/'W890WritePolicy04.TESTONLY.dll'))
U8=C.c_uint8;U16=C.c_uint16;U32=C.c_uint32;U64=C.c_uint64;P=C.c_void_p
class Intent(C.Structure):_fields_=[('guid',U8*16),('name',U16*40),('attrs',U32),('oldattrs',U32),('size',U32),('oldsize',U32),('before',P),('after',P),('route',U32),('reserved',U32)]
class Result(C.Structure):_fields_=[('result',U32),('first',U32),('changed',U32),('protected',U32)]
def bind(d,name,args,ret=C.c_int):f=getattr(d,name);f.argtypes=args;f.restype=ret;return f
pre=bind(D,'ws04_preflight',[P,C.c_size_t,U32,P]);desc=bind(D,'ws04_descriptor',[P,P]);header=bind(D,'ws04_route_header',[P,C.c_size_t,P,P,P]);apply=bind(D,'ws04_route_apply',[P,C.c_size_t,C.c_size_t,P,C.c_size_t,P,C.c_size_t]);ib=bind(D,'ws04_intent_bytes',[],C.c_size_t)
cases=[];keep=[]
def check(name,ok,**detail):assert ok,(name,detail);cases.append(dict(name=name,pass_=True,**detail))
def intent(index,changes=(),route=1):
 e=catalog[index];n=e['declared_size'];before=(U8*n)();after=(U8*n)()
 for k,v in changes:after[k]=v
 v=Intent();v.guid[:]=uuid.UUID(e['guid']).bytes_le;v.name[:len(e['name'])]=list(map(ord,e['name']));v.attrs=v.oldattrs=e['attributes'];v.size=v.oldsize=n;v.before=C.addressof(before);v.after=C.addressof(after);v.route=route;keep.extend([before,after,v]);return v
def run(items,flags=3):a=(Intent*len(items))(*items);r=Result();return pre(a,len(items),flags,C.byref(r)),r
check('x64 intent ABI',ib()==C.sizeof(Intent),size=ib())
for index in [1,2,5]:
 v=intent(index,[(0,1)]);code,r=run([v]);check('ordinary exact identity '+str(index),code==0 and r.changed==1 and r.protected==0)
oc=intent(94,[(100,1)]);code,r=run([oc]);check('OC locked rejects actual diff',code==1 and r.first==0)
for flags in [7,11]:check('OC granted or disabled '+str(flags),run([oc],flags)[0]==0)
for flags in [0,1,2,3|16,3|32,3|64,3|128,15]:check('invalid provider flags '+str(flags),run([intent(2,[(0,1)])],flags)[0]==1)
check('unchanged OC does not need unlock',run([intent(94)])[0]==0)
text=(H.parent/'password/w890_policy_data.h').read_text();offs=[int(n,0)for n in re.search(r'w890_memory_offsets\[\].*?\{(.*?)\}',text,re.S).group(1).replace('\n','').split(',')if n.strip()]
unprotected=next(i for i in range(1219)if i not in offs)
check('Memory protected byte blocked',run([intent(99,[(offs[0],1)])])[0]==1)
check('Memory ordinary byte retained',run([intent(99,[(unprotected,1)])])[0]==0,offset=unprotected)
for field,value in [('attrs',3),('oldattrs',3),('size',1),('oldsize',1),('reserved',1),('route',3)]:
 v=intent(2,[(0,1)]);setattr(v,field,value);check('exact reject '+field,run([v])[0]==2)
for kind in ['guid','name']:
 v=intent(2);getattr(v,kind)[0]^=1;check('spoofed '+kind+' denied',run([v])[0]==2)
v=intent(2,[(0,1)]);w=intent(2,[(0,2)]);check('conflicting duplicate identity denied',run([v,w])[0]==2)
check('identical duplicate is consistent',run([v,v])[0]==0)
for items,label,first in [([intent(2,[(0,1)]),oc],'late OC',1),([oc,intent(2,[(0,1)])],'early OC',0)]:
 code,r=run(items);writer_calls=0
 if code==0:writer_calls+=len(items)
 check('whole-batch '+label+' performs zero writes',code==1 and r.first==first and writer_calls==0)
v=intent(2);v.guid[0]^=1;code,r=run([intent(1),v]);check('late unknown zero writes',code==2 and r.first==1)
check('empty batch rejected',run([])[0]==1)
check('excess batch rejected',run([intent(2)]*257)[0]==1)
def config(index,blocks,path='7FFF0400'):
 e=catalog[index];return 'GUID='+uuid.UUID(e['guid']).bytes_le.hex()+'&NAME='+''.join(f'{ord(c):04X}'for c in e['name'])+'&PATH='+path+blocks
def u16(text):return (U16*(len(text)+1))(*map(ord,text),0)
def parse(text,size=2):
 s=u16(text);g=(U8*16)();name=(U16*40)();at=C.c_size_t();code=header(s,len(s),g,name,C.byref(at));b=(U8*size)();a=(U8*size)(*([0x55]*size));r=apply(s,len(s),at.value,b,size,a,size)if code==0 else code;return code,r,bytes(g),''.join(chr(x)for x in name if x),bytes(a)
valid=config(2,'&OFFSET=0&WIDTH=2&VALUE=3412');code,r,g,n,a=parse(valid)
check('strict route original GUID NAME and little-endian VALUE',code==0 and r==0 and g==uuid.UUID(catalog[2]['guid']).bytes_le and n=='Timeout' and a==b'\x12\x34')
check('disjoint multi-block decode',parse(config(2,'&OFFSET=0&WIDTH=1&VALUE=12&OFFSET=1&WIDTH=1&VALUE=34'))[4]==b'\x12\x34')
bad=[('&OFFSET=0&WIDTH=1&VALUE=12&OFFSET=0&WIDTH=1&VALUE=34','overlap'),('&OFFSET=0&WIDTH=1&VALUE=12&OFFSET=1&WIDTH=2&VALUE=1234','later out-of-bounds'),('&OFFSET=0&WIDTH=2&VALUE=GG00','nonhex'),('&OFFSET=0&WIDTH=0&VALUE=','zero width'),('&OFFSET=FFFFFFFFFFFFFFFF&WIDTH=1&VALUE=01','offset overflow'),('&OFFSET=0&WIDTH=FFFFFFFFFFFFFFFF&VALUE=01','width overflow'),('&OFFSET=0&WIDTH=2&VALUE=123','truncated'),('&OFFSET=0&WIDTH=1&VALUE=12&GUID='+('0'*32),'multiple GUID'),('&OFFSET=0&WIDTH=1&VALUE=12&ALTCFG=00','unknown extension')]
for block,label in bad:
 code,r,_,_,a=parse(config(2,block));check('route reject '+label+' leaves output unchanged',r!=0 and a==b'\x55\x55')
for src,label in [(valid.replace('GUID=','guid='),'case'),(valid.replace('&NAME=','&NAME=0000'),'embedded NUL'),(config(2,'&OFFSET=0&WIDTH=1&VALUE=12','0'),'odd PATH'),(valid+'\0junk','embedded terminator')]:check('header/route rejects '+label,parse(src)[1]!=0)
for path,label in [('7fff0300','short node'),('01010400','missing end'),('7f0104007fff0400','multi-instance path')]:check('path syntax rejects '+label,parse(config(2,'&OFFSET=0&WIDTH=1&VALUE=12',path))[1]!=0)
s=u16(valid);g=(U8*16)();n=(U16*40)();at=C.c_size_t();header(s,len(s),g,n,C.byref(at));old=(U8*2)();check('output/input alias rejected',apply(s,len(s),at.value,old,2,C.addressof(s),2)!=0)
for index in [2,94,99]:
 raw=(U8*124).from_buffer_copy(bytes.fromhex(catalog[index]['descriptor_hex']));v=Intent();check('native descriptor exact '+str(index),desc(raw,C.byref(v))==0 and v.size==catalog[index]['declared_size'])
report={'status':'PASS','checks':len(cases),'dll_sha256':hashlib.sha256((O/'W890WritePolicy04.TESTONLY.dll').read_bytes()).hexdigest(),'cases':cases,'limits':['Actual compiled x64 policy called in host process.','No UEFI services or native owner acquisition; writer counters are explicit harness observations.','Preflight success alone never grants native dispatch.']}
(O/'policy_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='cases'}))
