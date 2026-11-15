"""Execute S22 discovery/transport machine code with bounded PCI service fakes.
No BMC or physical device is accessed. Independent review supplies a separate
multi-interface model; this suite emphasizes exact malformed-input rejection.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('s22runtime',BASE/'verify_runtime.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
from unicorn.x86_const import *

REAL=bytes.fromhex('031a0224020010020101070c0000000000000078000010780000000000000000000000000000000000000000031a022400000000400000000000000000000000')
assert len(REAL)==64
class Machine(v.Machine):
 def __init__(self,**kw):
  super().__init__();self.config[:]=REAL;self.opts=kw;self.enumerated=[];self.handle_pool=0;self.resource_pool=0;self.pci_full=0
  self.configs=[bytearray(REAL)]
  if kw.get('duplicate'):self.configs.append(bytearray(REAL))
  if kw.get('duplicate_bad_subsystem'):self.configs.append(bytearray(REAL));self.configs[-1][44]^=1
  if kw.get('unrelated'):self.configs.append(bytearray(64))
  for off,val in kw.get('config_edits',[]):self.config[off]=val
  self.configs[0]=self.config
  for off in kw.get('null_method',[]):self.w64(self.pci+off,0)
 def hook(self,u,addr,size,user):
  name=self.stubs.get(addr)
  if name is None:return
  sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=self.r64(sp+0x28);result=0;o=self.opts
  if name=='LocateHandles':
   assert a==2
   n=o.get('count',len(self.configs));self.w64(d,n)
   self.handle_pool=self.alloc(b''.join(struct.pack('<Q',0x5555+i) for i in range(min(n,4096))))
   self.w64(e,0 if o.get('null_handles') else self.handle_pool);result=v.ERR(7) if o.get('enum_error') else 0
  elif name=='HandleProtocol':
   if 0x5555<=a<0x5555+len(self.configs):
    self.current_index=a-0x5555;self.enumerated.append(self.current_index)
    result=v.ERR(7) if o.get('handle_error')==self.current_index else 0
    self.w64(c,0 if o.get('null_interface') else self.pci)
   else:return super().hook(u,addr,size,user)
  elif name=='PciRead' and b==0:
   assert a==self.pci and c==0 and d==64
   self.pci_full+=1;i=getattr(self,'current_index',0)
   if o.get('read_error')==i:result=v.ERR(7)
   else:u.mem_write(e,bytes(self.configs[i]))
  elif name=='Location':
   for ptr,val in zip((b,c,d,e),o.get('location',(0,0x74,1,0))):self.w64(ptr,val)
   result=v.ERR(7) if o.get('location_error') else 0
  elif name=='BarAttributes':
   assert a==self.pci and b==1
   desc=bytearray(46);desc[0]=0x8a;desc[1]=43
   struct.pack_into('<Q',desc,14,o.get('base',0x78100000));struct.pack_into('<Q',desc,38,o.get('length',0x40000))
   for off,val in o.get('descriptor_edits',[]):desc[off]=val
   self.resource_pool=self.alloc(desc);self.w64(c,0);self.w64(d,0 if o.get('null_resource') else self.resource_pool)
   result=v.ERR(7) if o.get('resource_error') else 0
  elif name=='FreePool':
   self.freed.append(a)
   if (a==self.handle_pool and o.get('free_handles_error')) or (a==self.resource_pool and o.get('free_resource_error')):result=v.ERR(7)
  else:return super().hook(u,addr,size,user)
  self.ret(u,result,name)

rows=[]
def case(name,expected,**kw):
 m=Machine(**kw);r=m.call('discover');assert r==expected,(name,r)
 assert not m.dev.packets and not m.pci_writes and not m.nv_writes
 assert not any(x in m.calls for x in ('MemRead','MemWrite','PciWrite','SetVariable'))
 if m.handle_pool and not kw.get('null_handles'):assert m.handle_pool in m.freed
 if m.resource_pool and not kw.get('null_resource'):assert m.resource_pool in m.freed
 rows.append(name)
for bus in (0,4,0x74,255):case('accept dynamic bus '+str(bus),1,location=(0,bus,1,0))
case('unique plus unrelated PCI interface',1,unrelated=True)
for loc in ((1,0x74,1,0),(0,256,1,0),(0,2**63,1,0),(0,0x74,2,0),(0,0x74,1,1)):
 case('reject UINTN location '+str(loc),0,location=loc)
for off in (0,2,8,9,10,11,14,44,45,46,47):case('reject identity byte '+str(off),0,config_edits=[(off,REAL[off]^1)])
for name,kw in [('duplicate',{'duplicate':True}),('duplicate wrong subsystem',{'duplicate_bad_subsystem':True}),('unreadable later unrelated',{'unrelated':True,'read_error':1}),('failed later handle',{'unrelated':True,'handle_error':1}),('null interface',{'null_interface':True}),('zero count',{'count':0}),('overlarge count',{'count':4097}),('null handles',{'null_handles':True}),('enum error with allocation',{'enum_error':True}),('free handles error',{'free_handles_error':True}),('location error',{'location_error':True}),('resource error with allocation',{'resource_error':True}),('free resource error',{'free_resource_error':True}),('null resource',{'null_resource':True})]:case(name,0,**kw)
for off in (0x10,0x18,0x30,0x38,0x70,0x80):case('null PCI method '+hex(off),0,null_method=[off])
for name,kw in [('wrong descriptor tag',{'descriptor_edits':[(0,0x89)]}),('wrong descriptor length',{'descriptor_edits':[(1,42)]}),('descriptor IO type',{'descriptor_edits':[(3,1)]}),('base mismatch',{'base':0x78101000}),('BAR short',{'length':0xe8c}),('BAR overflow',{'length':2**64-1}),('BAR above4G',{'base':0x178100000})]:case(name,0,**kw)
case('minimum covering last KCS byte',1,length=0xe8d)
case('BAR ends exactly4G',1,length=0x100000000-0x78100000)
for bus,cmd in ((4,0),(0x74,2)):
 m=Machine(location=(0,bus,1,0));m.config[4]=cmd
 assert m.call('p1_collect')==0
 assert m.config[4]==cmd and not m.dev.oem_packets and not m.dev.mutations and not m.nv_writes
 assert len(m.pci_writes)==(2 if cmd==0 else 0)
 rows.append('full standard GET collection bus '+str(bus)+' original cmd '+str(cmd))
report={'passed':True,'cases':len(rows),'rows':rows,'driver_sha256':hashlib.sha256((BASE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),'fixture':'Actual host-read-01.json management config64; service returns synthetic','scope':'Actual compiled discovery and p1_collect, no physical device or native AMI UI'}
(BASE/'tests/pci-discovery-pe.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
