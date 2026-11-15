"""Original 0603 machine bytes + compiled policy, explicit service models.
No vendor entry, original Save routine, physical variables or live owner runs.
"""
from pathlib import Path
import sys,json,ctypes as C,uuid,struct,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path[:0]=[str(R/'tools/pydeps'),str(R/'tools/kvm-pydeps')]
import pefile,unicorn
from unicorn.x86_const import *
O=H/'build';catalog=json.loads((H/'native_variable_catalog.json').read_text());items=catalog['items'];D=C.CDLL(str(O/'W890WritePolicy04.TESTONLY.dll'))
class Intent(C.Structure):_fields_=[('guid',C.c_uint8*16),('name',C.c_uint16*40),('attrs',C.c_uint32),('oldattrs',C.c_uint32),('size',C.c_uint32),('oldsize',C.c_uint32),('before',C.c_void_p),('after',C.c_void_p),('route',C.c_uint32),('reserved',C.c_uint32)]
class Result(C.Structure):_fields_=[('result',C.c_uint32),('first',C.c_uint32),('changed',C.c_uint32),('protected',C.c_uint32)]
pre=D.ws04_preflight;pre.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_void_p];pre.restype=C.c_int
apply=D.ws04_route_apply;apply.argtypes=[C.c_void_p,C.c_size_t,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t];apply.restype=C.c_int
BASE=0x10000000;STACK=0x20000000;MEM=0x30000000;STOP=0x40000000;SERVICE=STOP+0x100
pe=pefile.PE(str(H.parent/'navigation/modules/AMITSE.efi'));original=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0')
cases=[]
def check(label,ok,**detail):assert ok,(label,detail);cases.append(dict(name=label,pass_=True,**detail))
def machine():
 u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);u.mem_map(BASE,(len(original)+4095)&~4095);u.mem_write(BASE,original);u.mem_map(STACK,0x20000);u.mem_map(MEM,0x200000);u.mem_map(STOP,4096);u.mem_write(STOP,b'\xc3');return u
def call(u,rva,args):
 sp=STACK+0x1ff08;u.mem_write(sp,struct.pack('<Q',STOP));u.reg_write(UC_X86_REG_RSP,sp)
 for reg,value in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],args):u.reg_write(reg,value)
 for i,value in enumerate(args[4:]):u.mem_write(sp+0x28+i*8,struct.pack('<Q',value))
 u.emu_start(BASE+rva,STOP,count=300000);return u.reg_read(UC_X86_REG_RAX)
def intent(index):
 e=items[index];size=e['declared_size'];before=(C.c_uint8*size)();after=(C.c_uint8*size)();after[0]=1;v=Intent();v.guid[:]=uuid.UUID(e['guid']).bytes_le;v.name[:len(e['name'])]=list(map(ord,e['name']));v.attrs=v.oldattrs=e['attributes'];v.size=v.oldsize=size;v.before=C.addressof(before);v.after=C.addressof(after);v.route=1;return v,before,after
def dispatch(index,data):
 u=machine();source=(H/'inputs/AMITSESetupData.bin').read_bytes();at=catalog['variable_table_offset'];table=source[at:at+488+121*124]
 u.mem_write(MEM,table);u.mem_write(BASE+0xbaaf8,struct.pack('<Q',MEM));u.mem_write(BASE+0xafbd8,struct.pack('<Q',MEM+0x10000));u.mem_write(MEM+0x10058,struct.pack('<Q',SERVICE));u.mem_write(MEM+0x20000,data);writes=[];bookkeeping=[]
 def hook(u,address,size,user):
  if address==SERVICE:
   nameptr=u.reg_read(UC_X86_REG_RCX);guidptr=u.reg_read(UC_X86_REG_RDX);attrs=u.reg_read(UC_X86_REG_R8)&0xffffffff;n=u.reg_read(UC_X86_REG_R9);sp=u.reg_read(UC_X86_REG_RSP);p=struct.unpack('<Q',u.mem_read(sp+0x28,8))[0]
   units=[]
   for i in range(40):
    c=struct.unpack('<H',u.mem_read(nameptr+i*2,2))[0]
    if not c:break
    units.append(chr(c))
   writes.append(dict(name=''.join(units),guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(guidptr,16)))),attrs=attrs,size=n,data_sha256=hashlib.sha256(bytes(u.mem_read(p,n))).hexdigest()))
  elif address==BASE+0x1d594:bookkeeping.append(u.reg_read(UC_X86_REG_RCX))
  else:return
  sp=u.reg_read(UC_X86_REG_RSP);ret=struct.unpack('<Q',u.mem_read(sp,8))[0];u.reg_write(UC_X86_REG_RAX,0);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,ret)
 u.hook_add(unicorn.UC_HOOK_CODE,hook);status=call(u,0x1c958,[index,MEM+0x20000,len(data)]);return status,writes,bookkeeping
for index in [2,5,94,99]:
 v,old,new=intent(index);a=(Intent*1)(v);r=Result();flags=7 if index in [94,99] else 3;code=pre(a,1,flags,C.byref(r));status,writes,b=dispatch(index,bytes(new)) if code==0 else (None,[],[])
 check('compiled preflight to original commit '+str(index),code==0 and status==0 and len(writes)==1 and b==[index] and writes[0]['name']==items[index]['name'] and writes[0]['guid']==items[index]['guid'] and writes[0]['attrs']==7 and writes[0]['size']==len(new),observed=writes)
v,a,b=intent(94);r=Result();code=pre(C.byref(v),1,3,C.byref(r));check('locked OCMR prevents original native dispatch',code==1)
v,a,b=intent(2);w,c,d=intent(94);r=Result();batch=(Intent*2)(v,w);code=pre(batch,2,3,C.byref(r));writes=[]
if code==0:
 for i,data in [(2,bytes(b)),(94,bytes(d))]:writes.extend(dispatch(i,data)[1])
check('full batch denies ordinary-first plus locked OC before all original calls',code==1 and not writes and r.first==1)
# Counterexample: per-item denial alone does not make native Save transactional.
partial=[]
for index,v,data in [(2,v,bytes(b)),(94,w,bytes(d))]:
 r=Result()
 if pre(C.byref(v),1,3,C.byref(r))==0:partial.extend(dispatch(index,data)[1])
check('counterexample per-item guarding already writes ordinary value',len(partial)==1 and partial[0]['name']=='Timeout',this_is_not_the_implemented_save=True)
for data in [b'\x12',b'\x12\x34',bytes(range(8)),bytes(range(40))]:
 u=machine();u.mem_write(MEM,data);u.mem_write(MEM+0x1000,struct.pack('<Q',len(data)*2+1));status=call(u,0x10950,[MEM+0x2000,MEM+0x1000,MEM,len(data)]);text=bytes(u.mem_read(MEM+0x2000,len(data)*4)).decode('utf-16le');blocks='&OFFSET=0&WIDTH='+format(len(data),'X')+'&VALUE='+text;s=(C.c_uint16*(len(blocks)+1))(*map(ord,blocks),0);old=(C.c_uint8*len(data))();after=(C.c_uint8*len(data))();rc=apply(s,len(s),0,old,len(data),after,len(data))
 check('original 10950 VALUE roundtrip '+str(len(data)),status==0 and rc==0 and bytes(after)==data,encoded=text)
report={'status':'PASS','checks':len(cases),'amitse_sha256':hashlib.sha256((H.parent/'navigation/modules/AMITSE.efi').read_bytes()).hexdigest(),'policy_sha256':hashlib.sha256((O/'W890WritePolicy04.TESTONLY.dll').read_bytes()).hexdigest(),'cases':cases,'models':['Runtime SetVariable returns success and records exact args; no variable is physically written.','Native1D594 bookkeeping is stubbed and counted; its unknown side effects are not approved.','Original commit1C958 and VALUE formatter10950 execute their actual PE bytes in Unicorn.','Owner and batch exclusion are not modeled as proof. Original Save1FCB4 is not executed.','Whole-cache effect graph remains incomplete; deny-only production bridge never executes original commit.']}
(O/'native_byte_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='cases'}))
