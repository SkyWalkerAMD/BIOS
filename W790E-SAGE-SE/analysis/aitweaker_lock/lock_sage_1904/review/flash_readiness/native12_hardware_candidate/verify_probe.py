"""Actual EFI collect() bytes; synthetic EFI services; original relocated images.

No live firmware, filesystem protocol, network or hardware interaction.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_PROT_ALL,UC_PROT_READ
from unicorn.x86_const import *
BUILD=HERE/'build';EFI=BUILD/'SageNative12ReadOnlyPreflight.efi';BASE=0x140000000;HEAP=0x1000000;STACK=0x2000000;TSE=0x3000000;SETUP=0x4000000;STOP=HEAP+0xff0;ERR=lambda n:(1<<63)|n
q=lambda n:struct.pack('<Q',n);d=lambda n:struct.pack('<I',n)
sy={m[0]:int(m[1],16)for m in re.findall(r'^\s+\d{4}:[0-9a-f]+\s+(\S+)\s+([0-9a-f]{16})', (BUILD/'probe.map').read_text(),re.M)}
def guid(s):return uuid.UUID(s).bytes_le
LOADED=guid('5b1b31a1-9562-11d2-8e3f-00a0c969723b');ATTR=guid('f4560cf6-40ec-4b4a-a192-bf1d57d0b189');HII=guid('ef9fc172-a1b2-4693-b327-6d32fc416042');BROWSER=guid('b9d4c360-bcfb-4f9b-9298-53c136982258')
binding=json.loads((HERE/'identity_binding.json').read_text());RESULTS=[]
class VM:
 def __init__(self):
    self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.calls=[];self.protected_writes=[];self.outside_image_reads=[];self.callbacks={};self.cursor=HEAP+0x10000;self.hii_count=1;self.inventory=[1,2];self.freed=[];self.live=set();self.map_fail=False;self.map_bad_version=False;self.no_attr=False;self.malformed_stride=False;self.allocate_fail=False
    for base,size in [(HEAP,0x100000),(STACK,0x100000),(TSE,0xb0000),(SETUP,0x1b0000)]:self.u.mem_map(base,size)
    pe=pefile.PE(str(EFI));self.u.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(BASE,pe.get_memory_mapped_image())
    for index,(name,base)in enumerate([('AMITSE',TSE),('Setup',SETUP)]):
        p=pefile.PE(str(CASE/'analysis/modules'/f'{name}.efi'));p.relocate_image(base);self.w(base,p.get_memory_mapped_image())
    self.desc=[(4,HEAP,0x100000,0),(4,STACK,0x100000,0),(3,BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095,0),(3,TSE,0xa2000,0),(7,TSE+0xa2000,0x5000,0),(3,SETUP,0x1a6000,0),(6,SETUP+0x1a6000,0x4000,0)]
    self.st=HEAP+0x2000;self.bs=HEAP+0x3000;self.rt=HEAP+0x4000;self.w(self.st+0x58,q(self.rt)+q(self.bs));self.w(self.rt,b'R'*0x88)
    self.lis=[HEAP+0x5000,HEAP+0x5100];self.paths=[HEAP+0x5200,HEAP+0x5300]
    for index,base in enumerate([TSE,SETUP]):
        self.w(self.lis[index]+0x20,q(self.paths[index]));self.w(self.lis[index]+0x40,q(base)+q(binding['modules'][index]['original_size']))
        g=guid('b1da0adf-4f77-4070-a88e-bffe1c60529a'if index==0 else'899407d7-99fe-43d8-9a21-79ec328cac21');self.w(self.paths[index],b'\x04\x06\x14\0'+g+b'\x7f\xff\x04\0')
    table=bytearray(b'\x00\x06\0\0\0\x01' + b'1904\0\0' + b'\x02\x06\0\0\0\x01' + b'Pro WS W790E-SAGE SE\0\0'+b'\x7f\x04\0\0\0\0');self.w(HEAP+0x6000,table)
    sm=bytearray(24);sm[:5]=b'_SM3_';sm[6]=24;sm[12:16]=d(len(table));sm[16:24]=q(HEAP+0x6000);sm[5]=(-sum(sm))&255;self.w(HEAP+0x6100,sm)
    self.w(HEAP+0x6200,guid('f2fd1544-9794-4a2c-992e-e5bbcf20e394')+q(HEAP+0x6100));self.w(self.st+0x68,q(1)+q(HEAP+0x6200))
    for off,name,fn in [(0x38,'GetMemoryMap',self.memorymap),(0x40,'AllocatePool',self.allocate),(0x48,'FreePool',self.free),(0x98,'HandleProtocol',self.handle),(0x138,'LocateHandleBuffer',self.handles),(0x140,'LocateProtocol',self.locate)]:self.w(self.bs+off,q(self.callback(name,fn)))
    self.ma=HEAP+0x7000;self.db=HEAP+0x7100;self.browser=HEAP+0x7200;self.cfg=HEAP+0x7300
    self.w(self.ma,q(self.callback('GetMemoryAttributes',self.attr)))
    self.w(self.db+24,q(self.callback('HiiList',self.hiilist)));self.w(self.db+80,q(self.callback('HiiGetDriver',self.hiidriver)))
    self.w(self.browser,q(TSE+0x20ee4)+q(0));self.w(self.cfg+8,q(SETUP+0x152c)+q(SETUP+0x1534))
    self.before=[self.r(self.bs,0x178),self.r(self.rt,0x88),self.r(TSE,0xa1f40),self.r(SETUP,0x1a5ca0)]
    self.u.hook_add(UC_HOOK_CODE,self.hook,begin=HEAP,end=HEAP+0xffff)
    for start,end in [(TSE,TSE+0xb0000),(SETUP,SETUP+0x1b0000),(self.bs,self.bs+0x178),(self.rt,self.rt+0x88)]:self.u.hook_add(UC_HOOK_MEM_WRITE,self.writehook,begin=start,end=end-1)
    for start,end in [(TSE+0xa1f40,TSE+0xb0000),(SETUP+0x1a5ca0,SETUP+0x1b0000)]:self.u.hook_add(UC_HOOK_MEM_READ,lambda u,access,a,n,v,data:self.outside_image_reads.append([a,n]),begin=start,end=end-1)
    self.u.mem_protect(TSE,0xb0000,UC_PROT_READ);self.u.mem_protect(SETUP,0x1b0000,UC_PROT_READ)
 def r(self,a,n):return bytes(self.u.mem_read(a,n))
 def w(self,a,b):self.u.mem_write(a,bytes(b))
 def q(self,a):return int.from_bytes(self.r(a,8),'little')
 def arg(self,n):return self.u.reg_read([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9][n])if n<4 else self.q(self.u.reg_read(UC_X86_REG_RSP)+40+8*(n-4))
 def callback(self,name,fn):a=HEAP+0x8000+16*len(self.callbacks);self.callbacks[a]=(name,fn);self.w(a,b'\xc3');return a
 def hook(self,u,a,n,_):
    if a==STOP:u.emu_stop();return
    if a in self.callbacks:
        name,fn=self.callbacks[a];self.calls.append(name);result=fn();u.reg_write(UC_X86_REG_RAX,result);sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,self.q(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def writehook(self,u,access,a,n,v,_):
    if TSE<=a<TSE+0xb0000 or SETUP<=a<SETUP+0x1b0000 or self.bs<=a<self.bs+0x178 or self.rt<=a<self.rt+0x88:self.protected_writes.append([a,n])
 def pool(self,n):a=self.cursor;self.cursor=(a+n+15)&~15;assert self.cursor<HEAP+0xf0000;self.live.add(a);return a
 def allocate(self):
    if self.allocate_fail:return ERR(9)
    self.w(self.arg(2),q(self.pool(self.arg(1))));return 0
 def free(self):a=self.arg(0);assert a in self.live;self.live.remove(a);self.freed.append(a);return 0
 def memorymap(self):
    if self.map_fail:return ERR(7)
    data=b''.join(struct.pack('<IIQQQQ',typ,0,addr,0,size//4096,attr)for typ,addr,size,attr in self.desc);capacity=self.q(self.arg(0));self.w(self.arg(0),q(len(data)));self.w(self.arg(2),q(42));self.w(self.arg(3),q(8 if self.malformed_stride else 40));self.w(self.arg(4),d(0 if self.map_bad_version else 1))
    if not self.arg(1)or capacity<len(data):return ERR(5)
    self.w(self.arg(1),data);return 0
 def handles(self):
    a=self.pool(8*len(self.inventory));self.w(a,b''.join(q(i)for i in self.inventory));self.w(self.arg(3),q(len(self.inventory)));self.w(self.arg(4),q(a));return 0
 def handle(self):
    handle=self.arg(0);g=self.r(self.arg(1),16)
    p=self.lis[handle-1]if g==LOADED and handle in [1,2]else self.cfg if handle==0x777 else 0
    if not p:return ERR(14)
    self.w(self.arg(2),q(p));return 0
 def locate(self):
    g=self.r(self.arg(0),16);p={ATTR:0 if self.no_attr else self.ma,HII:self.db,BROWSER:self.browser}.get(g,0)
    if not p:return ERR(14)
    self.w(self.arg(2),q(p));return 0
 def attr(self):self.w(self.arg(3),q(0x20000));return 0
 def hiilist(self):
    cap=self.q(self.arg(3));self.w(self.arg(3),q(self.hii_count*8))
    if not self.arg(4)or cap<self.hii_count*8:return ERR(5)
    self.w(self.arg(4),b''.join(q(0x9000+i)for i in range(self.hii_count)));return 0
 def hiidriver(self):self.w(self.arg(2),q(0x777));return 0
 def reenter(self):
    # Actual x64 callback wrapper reenters collect(), then calls original map.
    old=self.q(self.bs+0x38);slot=HEAP+0x7400;a=HEAP+0x9000
    code=bytes.fromhex('4883ec6848894c242048895424284c894424304c894c2438488b8424900000004889442440')
    code+=b'\x48\xb9'+q(self.st)+b'\x48\xb8'+q(sy['collect'])+b'\xff\xd0\x49\xba'+q(slot)+b'\x49\x89\x02'
    code+=bytes.fromhex('488b4c2420488b5424284c8b4424304c8b4c2438488b4424404889442420')+b'\x48\xb8'+q(old)+bytes.fromhex('ffd04883c468c3')
    self.w(a,code);self.w(self.bs+0x38,q(a));self.before[0]=self.r(self.bs,0x178);self.w(slot,q(0xdead))
 def protect_text(self,index,typ=None,attrs=None,split=False,overlap=False):
    base=[TSE,SETUP][index];i=next(i for i,x in enumerate(self.desc)if x[1]==base);old=self.desc[i]
    if overlap:self.desc.append((4,base+4096,4096,0))
    elif split:self.desc[i:i+1]=[(old[0],base,4096,old[3]),(old[0],base+4096,old[2]-4096,old[3])]
    else:self.desc[i]=(typ if typ is not None else old[0],base,old[2],attrs if attrs is not None else old[3])
 def run(self,name,verify):
    self.u.reg_write(UC_X86_REG_RSP,STACK+0xf0008);self.w(STACK+0xf0008,q(STOP));self.u.reg_write(UC_X86_REG_RCX,self.st)
    self.u.emu_start(sy['collect'],STOP+1,count=100000000);assert self.u.reg_read(UC_X86_REG_RIP)==STOP,name
    size=self.q(sy['probe_log_bytes']);log=self.r(sy['probe_log'],size).decode('ascii');assert size<24576
    assert log.endswith('SAGE_NATIVE12_PREFLIGHT_END\r\n');assert 'INSTALLATION_AUTHORIZED_BY_PROBE=NO' in log
    assert not self.protected_writes and not self.outside_image_reads and not self.live,(name,self.protected_writes,self.outside_image_reads,self.live)
    assert self.r(self.bs,0x178)==self.before[0] and self.r(self.rt,0x88)==self.before[1]
    assert verify(log),name+'\n'+log
    (HERE/'tests'/f'{name}.log').write_bytes(log.encode());RESULTS.append({'case':name,'passed':True,'log_bytes':size,'calls':len(self.calls),'protected_memory_writes':0,'outside_original_image_reads':0,'outstanding_pool_allocations':0,'log_sha256':hashlib.sha256(log.encode()).hexdigest()})
def main():
 (HERE/'tests').mkdir(exist_ok=True)
 v=VM();v.run('exact_original_12_sites',lambda s:s.count('ORIGINAL_OK')==12 and s.count('original relocation-free text SHA256')==2 and'PASS SMBIOS'in s and 'PASS exactly one original Setup HII interface'in s and s.count('EXTENSION_PAGE_NO_CONTENT_READ')==9)
 v=VM();v.protect_text(0,split=True);v.protect_text(1,split=True);v.run('cross_descriptor_text_hash',lambda s:s.count('ORIGINAL_OK')==12)
 v=VM();v.protect_text(0,overlap=True);v.run('overlapping_map_refused',lambda s:'PATCH gate_render'not in s)
 for name,typ,attrs in [('reserved_text',0,0),('mmio_text',11,0),('read_protected_text',3,0x2000)]:
    v=VM();v.protect_text(0,typ=typ,attrs=attrs);v.run(name,lambda s:'PATCH gate_render'not in s)
 v=VM();v.w(TSE+0x400,b'\x99');v.run('wrong_text_hash',lambda s:'WARN original relocation-free text SHA256'in s and'PATCH gate_render'not in s)
 v=VM();v.inventory=[1,1,2];v.run('duplicate_loaded_image',lambda s:'PATCH gate_render'not in s)
 v=VM();v.w(v.lis[0]+0x48,q(0xffffffffffffffff));v.run('malformed_image_size',lambda s:'WARN original image range'in s)
 v=VM();v.w(v.lis[0]+0x20,q(0xfffffffffffffff0));v.run('overflow_device_path',lambda s:'PATCH gate_render'not in s)
 v=VM();v.w(v.paths[0]+2,b'\x02\0');v.run('short_device_path',lambda s:'PATCH gate_render'not in s)
 v=VM();v.w(TSE+0x6b928,q(TSE+1));v.run('relocated_slot_mismatch',lambda s:'PATCH gate_render RVA=000000000006B928 ORIGINAL_MISMATCH'in s)
 v=VM();v.no_attr=True;v.run('missing_memory_attribute_protocol',lambda s:'ACTUAL_PERMISSIONS_UNKNOWN'in s and s.count('ORIGINAL_OK')==12)
 v=VM();v.hii_count=1025;v.run('oversized_hii_list_refused',lambda s:'WARN bounded HII list'in s)
 v=VM();v.hii_count=1024;v.run('log_overflow_explicit',lambda s:'LOG_OVERFLOW=YES'in s and'LOG_COMPLETE=NO'in s and'LOG_COMPLETE=YES'not in s)
 v=VM();v.reenter();v.run('nested_collect_refused',lambda s:v.q(HEAP+0x7400)==0 and s.count('SAGE_NATIVE12_READONLY_PREFLIGHT')==1 and s.count('ORIGINAL_OK')==12)
 for name,field in [('memorymap_failure','map_fail'),('bad_map_version','map_bad_version'),('bad_descriptor_stride','malformed_stride'),('allocate_failure','allocate_fail')]:
    v=VM();setattr(v,field,True);v.run(name,lambda s:'WARN memory map readable bounds available'in s)
 report={'status':'PASS_ACTUAL_EFI_BYTES_SYNTHETIC_UEFI','case_count':len(RESULTS),'cases':RESULTS,'efi_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Original relocated OEM images are read-only data; EFI memory map and read-only protocol services synthetic. No OEM code execution, no hardware, no installer.'}
 (HERE/'tests/verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'case_count':len(RESULTS)}))
if __name__=='__main__':main()
