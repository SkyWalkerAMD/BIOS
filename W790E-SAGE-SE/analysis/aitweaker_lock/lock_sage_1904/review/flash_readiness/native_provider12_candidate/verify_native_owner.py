"""Execute actual EFI owner, provider and persistence adapters in Unicorn.

The two modified OEM PE images are mapped/relocated. Native page-table walks
run against synthetic identity page tables; only standard UEFI protocol I/O is
mocked. No BMC, physical device or real firmware variable is accessed.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
OUT=HERE/'build';EFI=OUT/'AiTweakerNativeProvider1904.UNSIGNED.review.efi'
binding=json.loads((HERE/'guard_binding.json').read_text());BIND=binding['modules']
ERR=lambda n:0x8000000000000000|n
BASE=0x18000000;TSE=0x20000000;SETUP=0x30000000;HEAP=0x40000000;STACK=0x50000000;STUB=0x60000000;STOP=STUB+0xff00
u32=lambda x:struct.pack('<I',x);u64=lambda x:struct.pack('<Q',x)
maptext=(OUT/'provider.map').read_text();preferred=pefile.PE(str(EFI)).OPTIONAL_HEADER.ImageBase
SY={name:BASE+int(address,16)-preferred for name,address in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',maptext,re.M)}
PW=b'unit-test-only-password'
def credential():
    b=bytearray(128);b[:8]=b'AITWKP01';b[8]=1;b[10]=128;struct.pack_into('<IIIQ',b,12,1,1,600000,1)
    b[32:64]=bytes(range(1,33));b[64:96]=hashlib.pbkdf2_hmac('sha256',PW,b[32:64],600000);b[96:]=hashlib.sha256(b[:96]).digest();return bytes(b)
RECORD=credential();rows=[]
class VM:
 def __init__(self,initialize=True):
    self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.regions=[];self.callbacks={};self.stop=STOP;self.calls=[]
    self.record=RECORD;self.attributes=3;self.variable_read_error=False;self.variable_write_error=False
    self.variable_commit=True;self.variable_write_corrupt=False;self.variable_readback_error=False;self.variable_writes=0;self.gets=0
    self.wrong_loaded_guid=False;self.duplicate_loaded=False;self.raise_tpl=4;self.free_fail=False;self.heap_next=HEAP+0x10000
    self.map(0x100000,0x200000);self.pt_next=0x101000;self.tables={};self.u.reg_write(UC_X86_REG_CR3,0x100000);self.u.reg_write(UC_X86_REG_CR4,0x600);self.u.reg_write(UC_X86_REG_CR0,0x11)
    for addr,size in [(HEAP,0x400000),(STACK,0x200000),(STUB,0x10000)]:self.map(addr,size)
    self.w(STOP,b'\xf4')
    self.map_image(EFI,BASE)
    for name,base in [('AMITSE',TSE),('Setup',SETUP)]:
        p=Path(BIND[name]['module_file']);assert hashlib.sha256(p.read_bytes()).hexdigest()==BIND[name]['module_sha256'];self.map_image(p,base)
    self.st=HEAP+0x1000;self.bs=HEAP+0x2000;self.rt=HEAP+0x3000;self.handles=HEAP+0x4000
    self.li1=HEAP+0x5000;self.li2=HEAP+0x5100;self.dp1=HEAP+0x6000;self.dp2=HEAP+0x6100
    self.w(self.st+0x58,u64(self.rt)+u64(self.bs));self.w(self.handles,u64(0x111)+u64(0x222))
    import uuid
    self.w(self.dp1,b'\x04\x06\x14\x00'+uuid.UUID('b1da0adf-4f77-4070-a88e-bffe1c60529a').bytes_le)
    self.w(self.dp2,b'\x04\x06\x14\x00'+uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le)
    for li,dp,base,name in [(self.li1,self.dp1,TSE,'AMITSE'),(self.li2,self.dp2,SETUP,'Setup')]:
        self.w(li+0x20,u64(dp));self.w(li+0x40,u64(base)+u64(BIND[name]['image_bytes']))
    self.bsfn(0x18,'raise_tpl',lambda:self.raise_tpl);self.bsfn(0x20,'restore_tpl',lambda:0)
    self.bsfn(0x40,'allocate_pool',self.alloc);self.bsfn(0x48,'free_pool',lambda:ERR(7)if self.free_fail else 0)
    self.bsfn(0x98,'handle_protocol',self.handle);self.bsfn(0x138,'locate_handles',self.handles_fn)
    self.bsfn(0x140,'locate_protocol',lambda:ERR(14));self.bsfn(0xf8,'stall',lambda:0)
    self.fn(self.rt+0x48,'get_variable',self.getvar);self.fn(self.rt+0x58,'set_variable',self.setvar)
    self.u.hook_add(UC_HOOK_CODE,self.hook,begin=STUB,end=STUB+0xffff)
    if initialize:assert self.call('initialize_native_services',[self.st])==1
 def w(self,a,b):self.u.mem_write(a,bytes(b))
 def r(self,a,n):return bytes(self.u.mem_read(a,n))
 def q(self,a):return int.from_bytes(self.r(a,8),'little')
 def d(self,a):return int.from_bytes(self.r(a,4),'little')
 def map(self,addr,size):
    size=(size+4095)&~4095;self.u.mem_map(addr,size);self.regions.append((addr,size))
    if hasattr(self,'pt_next'):
        for a in range(addr,addr+size,4096):self.page(a)
 def page(self,a):
    table=0x100000
    for shift in [39,30,21]:
        idx=(a>>shift)&511;key=(table,idx)
        if key not in self.tables:
            self.tables[key]=self.pt_next;self.pt_next+=4096;self.w(table+idx*8,u64(self.tables[key]|3))
        table=self.tables[key]
    self.w(table+((a>>12)&511)*8,u64(a|3))
 def leaf(self,a):
    table=0x100000
    for shift in [39,30,21]:table=self.q(table+((a>>shift)&511)*8)&~4095
    return table+((a>>12)&511)*8
 def map_image(self,path,base):
    p=pefile.PE(str(path));self.map(base,p.OPTIONAL_HEADER.SizeOfImage);p.relocate_image(base);self.w(base,p.get_memory_mapped_image())
 def fn(self,address,name,callback):
    stub=STUB+len(self.callbacks)*0x20;self.callbacks[stub]=(name,callback);self.w(stub,b'\xc3');self.w(address,u64(stub))
 def bsfn(self,off,name,callback):self.fn(self.bs+off,name,callback)
 def arg(self,n):
    regs=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
    return self.u.reg_read(regs[n])if n<4 else self.q(self.u.reg_read(UC_X86_REG_RSP)+40+(n-4)*8)
 def alloc(self):
    n=self.arg(1);assert 0<n<=4*1024*1024;addr=self.heap_next;self.heap_next+=(n+15)&~15;assert self.heap_next<HEAP+0x400000;self.w(self.arg(2),u64(addr));return 0
 def handles_fn(self):
    self.w(self.arg(3),u64(3 if self.duplicate_loaded else 2));self.w(self.arg(4),u64(self.handles))
    if self.duplicate_loaded:self.w(self.handles+16,u64(0x111))
    return 0
 def handle(self):
    h=self.arg(0);li=self.li1 if h==0x111 else self.li2 if h==0x222 else 0
    if not li:return ERR(14)
    if self.wrong_loaded_guid:self.w(self.dp1+4,bytes(16))
    self.w(self.arg(2),u64(li));return 0
 def getvar(self):
    self.gets+=1
    if self.variable_read_error or(self.variable_readback_error and self.variable_writes):return ERR(7)
    if self.record is None:self.w(self.arg(3),u64(0));return ERR(14)
    n=self.q(self.arg(3));self.w(self.arg(3),u64(len(self.record)));self.w(self.arg(2),u32(self.attributes))
    if n<len(self.record):return ERR(5)
    self.w(self.arg(4),self.record);return 0
 def setvar(self):
    assert self.arg(2)==3 and self.arg(3)==128;self.variable_writes+=1
    if self.variable_commit:self.record=self.r(self.arg(4),128)
    if self.variable_write_corrupt:self.record=b'X'*128
    return ERR(7)if self.variable_write_error else 0
 def hook(self,u,address,size,unused):
    if address==self.stop:u.emu_stop();return
    if address in self.callbacks:
        name,callback=self.callbacks[address];self.calls.append(name);result=callback();u.reg_write(UC_X86_REG_RAX,result)
        sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def call(self,name,args=(),ret=STOP):
    self.stop=ret;sp=STACK+0x180000-0x108;self.w(sp,u64(ret)+bytes(0x100))
    self.u.reg_write(UC_X86_REG_RSP,sp)
    for i,r in enumerate([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]):self.u.reg_write(r,args[i]if i<len(args)else 0)
    for i,x in enumerate(args[4:]):self.w(sp+40+i*8,u64(x))
    stop_hook=self.u.hook_add(UC_HOOK_CODE,self.hook,begin=ret,end=ret)if ret!=STOP else None
    # Repeated HII mutation-boundary identity hashes exceed the previous 20M
    # instruction fixture budget. This remains a finite execution bound.
    try:self.u.emu_start(SY[name],0,count=50000000)
    except Exception:
        print('FIXTURE_EXCEPTION',name,hex(self.u.reg_read(UC_X86_REG_RIP)),hex(self.u.reg_read(UC_X86_REG_RSP)),self.calls[-8:]);raise
    finally:
        if stop_hook:self.u.hook_del(stop_hook)
    assert self.u.reg_read(UC_X86_REG_RIP)==ret,(name,hex(self.u.reg_read(UC_X86_REG_RIP)))
    return self.u.reg_read(UC_X86_REG_RAX)
 def frame(self,depth=1,previous=0,provider=None,token=0,address=None):
    address=address or STACK+depth*0x1000
    b=struct.pack('<QIIQQQII',0x343039314d524647,1,48,previous,SY['native_provider']if provider is None else provider,token,depth,1)
    self.w(address,b);self.w(TSE+BIND['AMITSE']['context_head_rva'],u64(address));return address
 def begin(self,f,expected=0,ret=None):
    r=self.call('provider_begin',[SY['native_provider'],f+32],ret or TSE+BIND['AMITSE']['begin_return_rva']);assert r==expected,hex(r);return self.q(f+32)
 def end(self,t,expected=0):
    r=self.call('provider_end',[SY['native_provider'],t],TSE+BIND['AMITSE']['end_return_rva']);assert r==expected,hex(r)
 def query(self):return self.call('provider_query',[SY['native_provider']])
 def check(self,name,condition):assert condition,name;rows.append({'check':name,'passed':True})

def main():
 v=VM();f=v.frame();t=v.begin(f);v.check('genuine outer wrapper gains owner',t==1 and v.query()==3)
 v.check('LoadedImage discovery executed',v.calls.count('locate_handles')==1 and v.calls.count('handle_protocol')==2)
 g=v.frame(2,f);v.begin(g);v.check('native nested chain accepted',v.query()==3 and v.q(g+32)==t)
 v.end(t);v.w(TSE+BIND['AMITSE']['context_head_rva'],u64(f));v.check('inner pop retains owner',v.query()==3)
 v.end(t);v.w(TSE+BIND['AMITSE']['context_head_rva'],u64(0));v.check('outer end revokes',v.query()==1)
 f=v.frame();new=v.begin(f);v.check('new outer token differs',new==2)
 v.end(new+1,ERR(15));v.check('wrong end token faults with authentic caller',v.query()==33)
 
 v=VM();f=v.frame(provider=0);g=v.frame(2,f);v.begin(g,ERR(15));v.check('late provider inside missing outer cannot acquire',v.query()==1)
 v=VM();f=v.frame();t=v.begin(f);g=v.frame(2,f);v.check('nested frame lacking successful Begin denies owned flag',v.query()==1);v.w(TSE+BIND['AMITSE']['context_head_rva'],u64(f));v.check('popping unowned nested frame restores outer owner',v.query()==3)
 v=VM();f=v.frame();v.begin(f,ERR(15),STOP);v.check('wrong return address cannot acquire',v.query()==1)
 v=VM();f=v.frame();other=HEAP+0x8000;r=v.call('provider_begin',[SY['native_provider'],other],TSE+BIND['AMITSE']['begin_return_rva']);v.check('token output must be native frame member',r==ERR(15) and v.query()==1)
 for field,offset,value in [('magic',0,u64(0)),('revision',8,u32(2)),('size',12,u32(40)),('depth',40,u32(2)),('flags',44,u32(0)),('provider',24,u64(0))]:
     v=VM();f=v.frame();v.w(f+offset,value);v.begin(f,ERR(15));v.check('invalid frame '+field+' rejected',v.query()==1)
 v=VM();f=v.frame();t=v.begin(f);v.w(f+16,u64(f));v.check('cyclic frame does not authorize',v.query()==1)
 v=VM();f=v.frame();t=v.begin(f);v.w(f+32,u64(t+1));v.check('foreign frame token does not authorize',v.query()==1)
 v=VM();f=v.frame();t=v.begin(f);g=v.frame(2,f,token=t);v.check('unregistered frame copied token denied',v.query()==1)
 v=VM();f=v.frame();leaf=v.leaf(f);v.w(leaf,u64(v.q(leaf)&~2));v.begin(f,ERR(15));v.check('read-only token page denied by actual page walk',v.query()==1)
 v=VM();f=v.frame();leaf=v.leaf(f);v.w(leaf,u64(0));v.begin(f,ERR(15));v.check('unmapped token page denied by actual page walk',v.query()==1)
 v=VM();f=v.frame();v.raise_tpl=8;v.begin(f,ERR(15));v.check('TPL callback cannot start interactive session',v.query()==1)
 v=VM();f=v.frame();v.duplicate_loaded=True;v.begin(f,ERR(15));v.check('duplicate OEM identity refused',v.query()==1)
 v=VM();f=v.frame();v.wrong_loaded_guid=True;v.begin(f,ERR(15));v.check('wrong FFS path cannot identify wrapper',v.query()==1)
 v=VM();f=v.frame();v.free_fail=True;v.begin(f,ERR(15));v.check('discovery cleanup failure refused',v.query()==1)
 v=VM();f=v.frame();v.w(TSE+BIND['AMITSE']['payload_rva'],b'\xcc');v.begin(f,ERR(15));v.check('mutated AMITSE guard hash refused',v.query()==1)
 v=VM();f=v.frame();v.w(SETUP+BIND['Setup']['payload_rva'],b'\xcc');v.begin(f,ERR(15));v.check('mutated Setup guard hash refused',v.query()==1)
 v=VM();f=v.frame();t=v.begin(f);v.call('provider_end_boot');before=len(v.calls);v.check('EBS query returns ENDED',v.query()==64);v.begin(f,ERR(15));v.check('no UEFI calls after EBS',len(v.calls)==before)
 
 # Execute the production persistence adapter itself (AP_CORE PBKDF2 is covered
 # by the full native DLL tests). Synthetic replacement record is valid bytes.
 replacement=bytearray(RECORD);struct.pack_into('<Q',replacement,24,2);replacement[96:]=hashlib.sha256(replacement[:96]).digest();replacement=bytes(replacement)
 for name,settings,expected,writes,fault in [
  ('successful verified commit',{},0,1,False),
  ('clean SetVariable error',{'variable_commit':False,'variable_write_error':True},1,1,False),
  ('success without commit faults',{'variable_commit':False},1,1,True),
  ('error with changed record faults',{'variable_write_error':True},1,1,True),
  ('corrupt committed readback faults',{'variable_write_corrupt':True},1,1,True),
  ('readback error faults',{'variable_readback_error':True},1,1,True),
  ('before-read error blocks write',{'variable_read_error':True},1,0,True),
  ('unexpected attributes block write',{'attributes':7},1,0,True),
  ('deleted credential blocks old authentication',{'record':None},1,0,True),
  ('externally replaced credential blocks write',{'record':replacement},1,0,True),
 ]:
     v=VM();f=v.frame();v.begin(f)
     for key,value in settings.items():setattr(v,key,value)
     data=HEAP+0x9000;v.w(data,replacement)
     got=v.call('persist_record',[0,data,128]);v.check(name,got==expected and v.variable_writes==writes and ((v.query()&32)!=0)==fault)
 v=VM();data=HEAP+0x9000;v.w(data,replacement);v.check('outside-owner persistence blocked',v.call('persist_record',[0,data,128])==1 and not v.variable_writes)
 v=VM();f=v.frame();v.begin(f);data=HEAP+0x9000;v.w(data,b'X'*128);v.check('malformed proposed record blocked',v.call('persist_record',[0,data,128])==1 and not v.variable_writes)
 
 report={'status':'PASS_ACTUAL_EFI_OWNER_AND_PERSISTENCE_SYNTHETIC_UEFI','checks':rows,'check_count':len(rows),
  'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'binding_sha256':hashlib.sha256((HERE/'guard_binding.json').read_bytes()).hexdigest(),
  'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'scope':'Actual compiled EFI page walks, owner identity/discovery, frame chain and NVRAM transaction logic. Modified OEM images mapped, but browser loop not executed by this fixture.',
  'limitations':['UEFI services, page tables, loaded-image handles and variable store are synthetic.','No BMC or physical flash operation.','No real console password UI or HII package mutation exercised here.']}
 (OUT/'native_owner_verification.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'checks':len(rows)}))

if __name__=="__main__":main()
